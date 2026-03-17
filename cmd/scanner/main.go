package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/tlsentinel/tlsentinel-scanner/internal"
)

func main() {
	_ = godotenv.Load()

	apiURL := os.Getenv("TLSENTINEL_API_URL")
	apiToken := os.Getenv("TLSENTINEL_API_TOKEN")

	if apiURL == "" || apiToken == "" {
		slog.Error("TLSENTINEL_API_URL and TLSENTINEL_API_TOKEN must be set")
		os.Exit(1)
	}

	client := internal.NewAPIClient(apiURL, apiToken)

	// Fetch initial config — fatal if unreachable on startup.
	cfg, err := client.GetConfig()
	if err != nil {
		slog.Error("failed to fetch scanner config", "error", err)
		os.Exit(1)
	}
	slog.Info("scanner started",
		"id", cfg.ID,
		"name", cfg.Name,
		"interval_seconds", cfg.ScanIntervalSeconds,
		"concurrency", cfg.ScanConcurrency,
	)

	// Set up graceful shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		slog.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	for {
		runScanCycle(ctx, client, cfg.ScanConcurrency)

		// Re-fetch config so UI changes take effect without a restart.
		if updated, err := client.GetConfig(); err != nil {
			slog.Warn("failed to refresh config, keeping previous values", "error", err)
		} else {
			cfg = updated
		}

		select {
		case <-ctx.Done():
			slog.Info("scanner stopped")
			return
		case <-time.After(time.Duration(cfg.ScanIntervalSeconds) * time.Second):
		}
	}
}

// runScanCycle fetches the host list and scans every host with bounded concurrency.
// It blocks until all in-flight scans complete, then returns.
func runScanCycle(ctx context.Context, client *internal.APIClient, concurrency int) {
	if concurrency <= 0 {
		concurrency = 5
	}

	hosts, err := client.GetHosts()
	if err != nil {
		slog.Error("failed to fetch hosts", "error", err)
		return
	}
	if len(hosts) == 0 {
		slog.Info("no hosts to scan")
		return
	}
	slog.Info("starting scan cycle", "hosts", len(hosts))

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

	wg.Wait()
	slog.Info("scan cycle complete")
}

// scanAndReport scans a single host and posts the result back to the API.
func scanAndReport(ctx context.Context, client *internal.APIClient, host internal.ScannerHost) {
	log := slog.With("host_id", host.ID, "dns_name", host.DNSName, "port", host.Port)

	result := internal.ScanHost(host)

	// Ingest certificates into the API.
	// Track whether the leaf cert (index 0) was stored — active_fingerprint is a
	// foreign key into certificates, so we must not reference it if ingest failed.
	leafIngested := false
	for i, pemData := range result.PEMs {
		if err := client.IngestCertificate(pemData); err != nil {
			log.Warn("failed to ingest certificate", "index", i, "error", err)
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
		log.Error("failed to post scan result", "error", err)
		return
	}

	if result.Err != nil {
		log.Warn("scan error", "error", *result.Err)
	} else {
		fingerprint := ""
		if result.Fingerprint != nil {
			fingerprint = *result.Fingerprint
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
			"fingerprint", fingerprint,
			"tls_version", tlsVersion,
			"resolved_ip", resolvedIP,
		)
	}

	// ── TLS profile probe ──────────────────────────────────────────────────
	// Run even if the cert scan errored — the host might still answer TLS
	// probes (e.g. expired cert, wrong cert) and the profile data is useful.
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
