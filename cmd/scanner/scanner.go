package main

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/joho/godotenv"
	gocron "github.com/netresearch/go-cron"
	"github.com/tlsentinel/tlsentinel-scanner/internal"
)

const (
	retryInterval      = 15 * time.Second
	configPollInterval = 30 * time.Second
)

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

// run is the main scan loop. Retries until the API is reachable, then hands
// scheduling to go-cron and polls for config changes until ctx is cancelled.
func run(ctx context.Context, client *internal.APIClient) {
	cfg, err := client.GetConfig()
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
		cfg, err = client.GetConfig()
	}

	slog.Info("scanner started",
		"id", cfg.ID,
		"name", cfg.Name,
		"schedule", cfg.ScanCronExpression,
		"concurrency", cfg.ScanConcurrency,
	)

	// current holds the live config; mu protects it from concurrent access
	// between the cron goroutine and the config-poll ticker below.
	var mu sync.Mutex
	current := cfg

	scanFunc := func() {
		mu.Lock()
		concurrency := current.ScanConcurrency
		mu.Unlock()
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
		eid, addErr := c.AddFunc(n.CronExpression, func() { runDiscoverySweep(n) })
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
			updated, err := client.GetConfig()
			if err != nil {
				slog.Warn("failed to refresh config, keeping previous values", "error", err)
			} else {
				mu.Lock()
				if updated.ScanCronExpression != current.ScanCronExpression {
					slog.Info("scan schedule updated",
						"from", current.ScanCronExpression,
						"to", updated.ScanCronExpression,
					)
					c.Remove(entryID)
					newID, addErr := c.AddFunc(updated.ScanCronExpression, scanFunc)
					if addErr != nil {
						slog.Error("invalid updated cron expression, keeping previous schedule",
							"expr", updated.ScanCronExpression,
							"error", addErr,
						)
					} else {
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

				// Remove jobs for networks that are gone or have a changed schedule.
				for id, entry := range networkEntries {
					n, exists := fresh[id]
					if !exists || n.CronExpression != entry.network.CronExpression {
						c.Remove(entry.entryID)
						delete(networkEntries, id)
						if !exists {
							slog.Info("discovery network removed", "network_id", id)
						}
					}
				}

				// Add jobs for networks not yet scheduled.
				for id, n := range fresh {
					if _, scheduled := networkEntries[id]; scheduled {
						continue
					}
					n := n
					eid, addErr := c.AddFunc(n.CronExpression, func() { runDiscoverySweep(n) })
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

	hosts, err := client.GetHosts()
	if err != nil {
		slog.Error("failed to fetch hosts", "error", err)
		return
	}

	samlEndpoints, err := client.GetSAMLEndpoints()
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

	result := internal.ScanHost(host)

	payload := internal.ScanResultPayload{
		ActiveFingerprint: result.Fingerprint,
		ResolvedIP:        result.ResolvedIP,
		TLSVersion:        result.TLSVersion,
		Error:             result.Err,
		PEMs:              result.PEMs,
	}

	if err := client.PostResult(host.ID, payload); err != nil {
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
	tlsProfile := internal.ProbeTLSProfile(host)
	if err := client.PostTLSProfile(host.ID, tlsProfile); err != nil {
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

	result := internal.ScanSAML(endpoint)

	if err := client.PostSAMLResult(endpoint.ID, internal.SAMLResultPayload{
		Error: result.Err,
		Certs: result.Certs,
	}); err != nil {
		log.Error("failed to post SAML scan result", "error", err)
		return
	}

	if result.Err != nil {
		log.Warn("SAML scan error", "error", *result.Err)
	} else {
		log.Info("SAML scan successful", "certs", len(result.Certs))
	}
}
