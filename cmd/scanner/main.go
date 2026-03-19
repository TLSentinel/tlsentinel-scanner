package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/tlsentinel/tlsentinel-scanner/internal"
	"github.com/tlsentinel/tlsentinel-scanner/internal/logger"
	"go.uber.org/zap"
)

func main() {
	_ = godotenv.Load()

	log, err := logger.Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialise logger: %v\n", err)
		os.Exit(1)
	}
	zap.ReplaceGlobals(log)
	defer log.Sync() //nolint:errcheck

	apiURL := os.Getenv("TLSENTINEL_API_URL")
	apiToken := os.Getenv("TLSENTINEL_API_TOKEN")

	if apiURL == "" || apiToken == "" {
		log.Fatal("TLSENTINEL_API_URL and TLSENTINEL_API_TOKEN must be set")
	}

	client := internal.NewAPIClient(apiURL, apiToken)

	// Set up graceful shutdown before the retry loop so SIGTERM/SIGINT can
	// interrupt a waiting scanner without needing a full scan interval.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Info("received signal, shutting down", zap.String("signal", sig.String()))
		cancel()
	}()

	// Fetch initial config — retry indefinitely if the API server is not yet
	// reachable (e.g. scanner starts before the server in a compose stack).
	const retryInterval = 15 * time.Second
	cfg, err := client.GetConfig()
	for err != nil {
		log.Warn("API server unreachable, will retry",
			zap.Error(err),
			zap.Duration("retry_in", retryInterval),
		)
		select {
		case <-ctx.Done():
			log.Info("scanner stopped before initial config was fetched")
			return
		case <-time.After(retryInterval):
		}
		cfg, err = client.GetConfig()
	}
	log.Info("scanner started",
		zap.String("id", cfg.ID),
		zap.String("name", cfg.Name),
		zap.Int("interval_seconds", cfg.ScanIntervalSeconds),
		zap.Int("concurrency", cfg.ScanConcurrency),
	)

	// configPollInterval is how often the scanner checks for config changes
	// while waiting between scan cycles.
	const configPollInterval = 30 * time.Second

	for {
		runScanCycle(ctx, log, client, cfg.ScanConcurrency)

		// Record when this cycle finished so the deadline is anchored to it.
		cycleFinishedAt := time.Now()

		// Refresh config immediately after the scan cycle.
		if updated, err := client.GetConfig(); err != nil {
			log.Warn("failed to refresh config, keeping previous values", zap.Error(err))
		} else {
			cfg = updated
		}

		// Wait for the next cycle, polling config every 30 s so that a
		// shortened interval takes effect within the next poll tick rather
		// than requiring the full old interval to elapse.
		for {
			deadline := cycleFinishedAt.Add(time.Duration(cfg.ScanIntervalSeconds) * time.Second)
			remaining := time.Until(deadline)
			if remaining <= 0 {
				break
			}
			sleep := configPollInterval
			if remaining < sleep {
				sleep = remaining
			}
			select {
			case <-ctx.Done():
				log.Info("scanner stopped")
				return
			case <-time.After(sleep):
			}
			if updated, err := client.GetConfig(); err != nil {
				log.Warn("failed to refresh config, keeping previous values", zap.Error(err))
			} else {
				if updated.ScanIntervalSeconds != cfg.ScanIntervalSeconds {
					log.Info("scan interval updated",
						zap.Int("from_seconds", cfg.ScanIntervalSeconds),
						zap.Int("to_seconds", updated.ScanIntervalSeconds),
					)
				}
				cfg = updated
			}
		}
	}
}

// runScanCycle fetches the host list and scans every host with bounded concurrency.
// It blocks until all in-flight scans complete, then returns.
func runScanCycle(ctx context.Context, log *zap.Logger, client *internal.APIClient, concurrency int) {
	if concurrency <= 0 {
		concurrency = 5
	}

	hosts, err := client.GetHosts()
	if err != nil {
		log.Error("failed to fetch hosts", zap.Error(err))
		return
	}
	if len(hosts) == 0 {
		log.Info("no hosts to scan")
		return
	}
	log.Info("starting scan cycle", zap.Int("hosts", len(hosts)))

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

			scanAndReport(ctx, log, client, host)
		}(h)
	}

	wg.Wait()
	log.Info("scan cycle complete")
}

// scanAndReport scans a single host and posts the result back to the API.
func scanAndReport(ctx context.Context, log *zap.Logger, client *internal.APIClient, host internal.ScannerHost) {
	log = log.With(
		zap.String("host_id", host.ID),
		zap.String("dns_name", host.DNSName),
		zap.Int("port", host.Port),
	)

	result := internal.ScanHost(host)

	// Ingest certificates into the API.
	// Track whether the leaf cert (index 0) was stored — active_fingerprint is a
	// foreign key into certificates, so we must not reference it if ingest failed.
	leafIngested := false
	for i, pemData := range result.PEMs {
		if err := client.IngestCertificate(pemData); err != nil {
			log.Warn("failed to ingest certificate", zap.Int("index", i), zap.Error(err))
		} else if i == 0 {
			leafIngested = true
		}
	}

	fingerprint := result.Fingerprint
	if !leafIngested {
		fingerprint = nil
	}

	payload := internal.ScanResultPayload{
		ActiveFingerprint: fingerprint,
		ResolvedIP:        result.ResolvedIP,
		TLSVersion:        result.TLSVersion,
		Error:             result.Err,
	}

	if err := client.PostResult(host.ID, payload); err != nil {
		log.Error("failed to post scan result", zap.Error(err))
		return
	}

	if result.Err != nil {
		log.Warn("scan error", zap.String("error", *result.Err))
	} else {
		fp := ""
		if result.Fingerprint != nil {
			fp = *result.Fingerprint
		}
		tlsVersion := ""
		if result.TLSVersion != nil {
			tlsVersion = *result.TLSVersion
		}
		resolvedIP := ""
		if result.ResolvedIP != nil {
			resolvedIP = *result.ResolvedIP
		}
		log.Info("scan successful",
			zap.String("fingerprint", fp),
			zap.String("tls_version", tlsVersion),
			zap.String("resolved_ip", resolvedIP),
		)
	}

	// ── TLS profile probe ──────────────────────────────────────────────────
	// Run even if the cert scan errored — the host might still answer TLS
	// probes (e.g. expired cert, wrong cert) and the profile data is useful.
	tlsProfile := internal.ProbeTLSProfile(host)
	if err := client.PostTLSProfile(host.ID, tlsProfile); err != nil {
		log.Error("failed to post TLS profile", zap.Error(err))
		return
	}

	if tlsProfile.ScanError != nil {
		log.Warn("TLS profile probe error", zap.String("error", *tlsProfile.ScanError))
	} else {
		log.Info("TLS profile posted",
			zap.Bool("tls10", tlsProfile.TLS10),
			zap.Bool("tls11", tlsProfile.TLS11),
			zap.Bool("tls12", tlsProfile.TLS12),
			zap.Bool("tls13", tlsProfile.TLS13),
			zap.Int("ciphers", len(tlsProfile.CipherSuites)),
		)
	}
}
