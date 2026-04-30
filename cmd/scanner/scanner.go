package main

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/joho/godotenv"
	gocron "github.com/netresearch/go-cron"
	"github.com/tlsentinel/tlsentinel-scanner/internal"
)

const (
	retryInterval      = 15 * time.Second
	configPollInterval = 30 * time.Second

	// defaultMaxConcurrency is the hard local ceiling on per-cycle scan
	// concurrency when TLSENTINEL_SCANNER_MAX_CONCURRENCY is unset. Sized
	// to leave headroom for the host's FD limit on a default Linux box.
	defaultMaxConcurrency = 64
)

// loadMaxConcurrency reads TLSENTINEL_SCANNER_MAX_CONCURRENCY and returns the
// hard local ceiling on per-cycle concurrency. The server config also supplies
// a concurrency value; this cap clamps it so a misconfigured (or compromised)
// server can't push the scanner past what its host can handle without FD or
// goroutine exhaustion. Falls back to defaultMaxConcurrency on unset, empty,
// or invalid input.
func loadMaxConcurrency() int {
	raw := os.Getenv("TLSENTINEL_SCANNER_MAX_CONCURRENCY")
	if raw == "" {
		return defaultMaxConcurrency
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		slog.Warn("ignoring invalid TLSENTINEL_SCANNER_MAX_CONCURRENCY",
			"value", raw, "default", defaultMaxConcurrency)
		return defaultMaxConcurrency
	}
	return n
}

// clampConcurrency caps the server-supplied value at the local ceiling. A
// non-positive server value is passed through unchanged so runScanCycle can
// apply its own default — the cap only pulls absurd values down, it does not
// override a missing config.
func clampConcurrency(server, ceiling int) int {
	if server > 0 && server > ceiling {
		return ceiling
	}
	return server
}

// buildClient loads env and returns a configured API client.
// Shared by interactive mode (main) and service mode (service_windows.go).
func buildClient() *internal.APIClient {
	_ = godotenv.Load()
	apiURL := os.Getenv("TLSENTINEL_API_URL")
	apiToken := os.Getenv("TLSENTINEL_API_TOKEN")
	if apiURL == "" || apiToken == "" {
		slog.Error("TLSENTINEL_API_URL and TLSENTINEL_API_TOKEN must be set")
	os.Exit(1)
	}
	return internal.NewAPIClient(apiURL, apiToken)
}

// discoverySweepJob returns a cron callback that runs a discovery sweep for
// the given network, guarded against overlap. Each returned closure has its
// own atomic flag — a slow sweep for one network does not block sweeps on
// others, but the same network will not stack concurrent sweeps.
func discoverySweepJob(ctx context.Context, client *internal.APIClient, n internal.ScannerDiscoveryNetwork) func() {
	var running atomic.Bool
	return func() {
		if !running.CompareAndSwap(false, true) {
			slog.Warn("skipping discovery sweep: previous sweep still running",
				"network_id", n.ID, "range", n.Range)
			return
		}
		defer running.Store(false)
		runDiscoverySweep(ctx, client, n)
	}
}

// run is the main scan loop. Retries until the API is reachable, then hands
// scheduling to go-cron and polls for config changes until ctx is cancelled.
func run(ctx context.Context, client *internal.APIClient) {
	cfg, err := client.GetConfig(ctx)
	for err != nil {
		slog.Warn("API server unreachable, will retry",
			"error", err,
			"retry_in", retryInterval,
		)
		select {
		case <-ctx.Done():
			slog.Info("scanner stopped before initial config was fetched")
			return
		case <-time.After(retryInterval):
		}
		cfg, err = client.GetConfig(ctx)
	}

	maxConcurrency := loadMaxConcurrency()

	slog.Info("scanner started",
		"id", cfg.ID,
		"name", cfg.Name,
		"schedule", cfg.ScanCronExpression,
		"concurrency", cfg.ScanConcurrency,
		"max_concurrency", maxConcurrency,
	)

	// current holds the live config; mu protects it from concurrent access
	// between the cron goroutine and the config-poll ticker below.
	var mu sync.Mutex
	current := cfg

	// scanRunning prevents overlapping scan cycles: if a cycle is still in
	// flight when the next cron tick fires, the new invocation is skipped
	// rather than queued. Keeps goroutine count bounded when a cycle takes
	// longer than the configured interval.
	var scanRunning atomic.Bool
	scanFunc := func() {
		if !scanRunning.CompareAndSwap(false, true) {
			slog.Warn("skipping scan cycle: previous cycle still running")
			return
		}
		defer scanRunning.Store(false)

		mu.Lock()
		serverConcurrency := current.ScanConcurrency
		mu.Unlock()
		concurrency := clampConcurrency(serverConcurrency, maxConcurrency)
		if concurrency != serverConcurrency && serverConcurrency > 0 {
			slog.Warn("clamping server-supplied concurrency to local cap",
				"requested", serverConcurrency, "cap", concurrency)
		}
		runScanCycle(ctx, client, concurrency)
	}

	c := gocron.New()
	entryID, err := c.AddFunc(cfg.ScanCronExpression, scanFunc)
	if err != nil {
		slog.Error("invalid cron expression, defaulting to hourly",
			"expr", cfg.ScanCronExpression,
			"error", err,
		)
		entryID, _ = c.AddFunc("0 * * * *", scanFunc)
	}

	// networkEntries tracks the cron entry for each discovery network by ID.
	type networkEntry struct {
		network internal.ScannerDiscoveryNetwork
		entryID gocron.EntryID
	}
	networkEntries := map[string]networkEntry{}

	// Register jobs for any networks already present in the initial config.
	for _, n := range cfg.Networks {
		n := n
		eid, addErr := c.AddFunc(n.CronExpression, discoverySweepJob(ctx, client, n))
		if addErr != nil {
			slog.Error("invalid cron expression for network",
				"network_id", n.ID, "expr", n.CronExpression, "error", addErr)
			continue
		}
		networkEntries[n.ID] = networkEntry{network: n, entryID: eid}
		slog.Info("discovery network scheduled", "network_id", n.ID, "range", n.Range, "schedule", n.CronExpression)
	}

	c.Start()
	defer c.Stop()

	ticker := time.NewTicker(configPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("scanner stopped")
			return
		case <-ticker.C:
			// ── Refresh host scan config ──────────────────────────────────
			updated, err := client.GetConfig(ctx)
			if err != nil {
				slog.Warn("failed to refresh config, keeping previous values", "error", err)
			} else {
				mu.Lock()
				if updated.ScanCronExpression != current.ScanCronExpression {
					// Add the new entry first. Only remove the old one on
					// success — otherwise a bad expression leaves the scanner
					// with no schedule at all, despite the "keeping previous
					// schedule" log message.
					newID, addErr := c.AddFunc(updated.ScanCronExpression, scanFunc)
					if addErr != nil {
						slog.Error("invalid updated cron expression, keeping previous schedule",
							"expr", updated.ScanCronExpression,
							"error", addErr,
						)
					} else {
						slog.Info("scan schedule updated",
							"from", current.ScanCronExpression,
							"to", updated.ScanCronExpression,
						)
						c.Remove(entryID)
						entryID = newID
					}
				}
				current = updated
				mu.Unlock()

				// ── Reconcile discovery network jobs ──────────────────────────
				// Networks are embedded in the config response — no separate API call needed.
				fresh := make(map[string]internal.ScannerDiscoveryNetwork, len(updated.Networks))
				for _, n := range updated.Networks {
					fresh[n.ID] = n
				}

				// Remove jobs for networks that no longer exist in the config.
				for id, entry := range networkEntries {
					if _, exists := fresh[id]; !exists {
						c.Remove(entry.entryID)
						delete(networkEntries, id)
						slog.Info("discovery network removed", "network_id", id)
					}
				}

				// Reschedule networks whose cron expression changed. Add new
				// entry first and only remove the old one on success — a bad
				// expression must not leave the network unscheduled.
				for id, entry := range networkEntries {
					n, exists := fresh[id]
					if !exists || n.CronExpression == entry.network.CronExpression {
						continue
					}
					newID, addErr := c.AddFunc(n.CronExpression, discoverySweepJob(ctx, client, n))
					if addErr != nil {
						slog.Error("invalid cron expression for network, keeping previous schedule",
							"network_id", n.ID, "expr", n.CronExpression, "error", addErr)
						continue
					}
					c.Remove(entry.entryID)
					networkEntries[id] = networkEntry{network: n, entryID: newID}
					slog.Info("discovery network rescheduled",
						"network_id", n.ID, "range", n.Range, "schedule", n.CronExpression)
				}

				// Add jobs for networks not yet scheduled.
				for id, n := range fresh {
					if _, scheduled := networkEntries[id]; scheduled {
						continue
					}
					n := n
					eid, addErr := c.AddFunc(n.CronExpression, discoverySweepJob(ctx, client, n))
					if addErr != nil {
						slog.Error("invalid cron expression for network",
							"network_id", n.ID, "expr", n.CronExpression, "error", addErr)
						continue
					}
					networkEntries[id] = networkEntry{network: n, entryID: eid}
					slog.Info("discovery network scheduled", "network_id", n.ID, "range", n.Range, "schedule", n.CronExpression)
				}
			}
		}
	}
}

// runScanCycle fetches hosts and SAML endpoints and scans everything with
// bounded concurrency. Blocks until all in-flight scans complete.
func runScanCycle(ctx context.Context, client *internal.APIClient, concurrency int) {
	if concurrency <= 0 {
		concurrency = 5
	}

	hosts, err := client.GetHosts(ctx)
	if err != nil {
		slog.Error("failed to fetch hosts", "error", err)
		return
	}

	samlEndpoints, err := client.GetSAMLEndpoints(ctx)
	if err != nil {
		slog.Error("failed to fetch SAML endpoints", "error", err)
		return
	}

	if len(hosts)+len(samlEndpoints) == 0 {
		slog.Info("no endpoints to scan")
		return
	}
	slog.Info("starting scan cycle", "hosts", len(hosts), "saml", len(samlEndpoints))

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, h := range hosts {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(host internal.ScannerHost) {
			defer wg.Done()
			defer func() { <-sem }()
			scanAndReport(ctx, client, host)
		}(h)
	}

	for _, ep := range samlEndpoints {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(endpoint internal.ScannerSAMLEndpoint) {
			defer wg.Done()
			defer func() { <-sem }()
			scanAndReportSAML(ctx, client, endpoint)
		}(ep)
	}

	wg.Wait()
	slog.Info("scan cycle complete")
}

func scanAndReport(ctx context.Context, client *internal.APIClient, host internal.ScannerHost) {
	log := slog.With(
		"host_id", host.ID,
		"dns_name", host.DNSName,
		"port", host.Port,
	)

	result := internal.ScanHost(ctx, host)

	payload := internal.ScanResultPayload{
		ActiveFingerprint: result.Fingerprint,
		ResolvedIP:        result.ResolvedIP,
		TLSVersion:        result.TLSVersion,
		Error:             result.Err,
		PEMs:              result.PEMs,
	}

	if err := client.PostResult(ctx, host.ID, payload); err != nil {
		log.Error("failed to post scan result", "error", err)
		return
	}

	if result.Err != nil {
		log.Warn("scan error", "error", *result.Err)
	} else {
		log.Info("scan successful",
			"fingerprint", result.Fingerprint,
			"tls_version", result.TLSVersion,
			"resolved_ip", result.ResolvedIP,
		)
	}

	// Run TLS profile probe even if cert scan errored — host may still respond.
	tlsProfile := internal.ProbeTLSProfile(ctx, host)
	if err := client.PostTLSProfile(ctx, host.ID, tlsProfile); err != nil {
		log.Error("failed to post TLS profile", "error", err)
		return
	}

	if tlsProfile.ScanError != nil {
		log.Warn("TLS profile probe error", "error", *tlsProfile.ScanError)
	} else {
		log.Info("TLS profile posted",
			"tls10", tlsProfile.TLS10,
			"tls11", tlsProfile.TLS11,
			"tls12", tlsProfile.TLS12,
			"tls13", tlsProfile.TLS13,
			"ciphers", len(tlsProfile.CipherSuites),
		)
	}
}

func scanAndReportSAML(ctx context.Context, client *internal.APIClient, endpoint internal.ScannerSAMLEndpoint) {
	log := slog.With(
		"endpoint_id", endpoint.ID,
		"url", endpoint.URL,
	)

	result := internal.ScanSAML(ctx, endpoint)

	payload := internal.SAMLResultPayload{
		Error: result.Err,
		Certs: result.Certs,
	}
	if result.Err == nil {
		xml, sha := result.XML, result.Sha256
		payload.MetadataXML = &xml
		payload.MetadataXMLSha256 = &sha
		payload.Metadata = result.Metadata
	}

	if err := client.PostSAMLResult(ctx, endpoint.ID, payload); err != nil {
		log.Error("failed to post SAML scan result", "error", err)
		return
	}

	if result.Err != nil {
		log.Warn("SAML scan error", "error", *result.Err)
	} else {
		log.Info("SAML scan successful", "certs", len(result.Certs))
	}
}
