package main

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"github.com/tlsentinel/tlsentinel-scanner/internal"
	"go.uber.org/zap"
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
		zap.L().Fatal("TLSENTINEL_API_URL and TLSENTINEL_API_TOKEN must be set")
	}
	return internal.NewAPIClient(apiURL, apiToken)
}

// run is the main scan loop. Retries until the API is reachable, then runs
// scan cycles until ctx is cancelled.
func run(ctx context.Context, client *internal.APIClient) {
	log := zap.L()

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

	for {
		runScanCycle(ctx, client, cfg.ScanConcurrency)
		cfg = refreshConfig(client, cfg)
		if !waitForNextCycle(ctx, client, &cfg) {
			return
		}
	}
}

// refreshConfig fetches updated config, falling back to the previous value on error.
func refreshConfig(client *internal.APIClient, current internal.ScannerConfig) internal.ScannerConfig {
	updated, err := client.GetConfig()
	if err != nil {
		zap.L().Warn("failed to refresh config, keeping previous values", zap.Error(err))
		return current
	}
	return updated
}

// waitForNextCycle blocks until the next scan is due, polling config periodically.
// Returns false if ctx was cancelled.
func waitForNextCycle(ctx context.Context, client *internal.APIClient, cfg *internal.ScannerConfig) bool {
	log := zap.L()
	cycleFinishedAt := time.Now()

	for {
		deadline := cycleFinishedAt.Add(time.Duration(cfg.ScanIntervalSeconds) * time.Second)
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return true
		}

		sleep := configPollInterval
		if remaining < sleep {
			sleep = remaining
		}

		select {
		case <-ctx.Done():
			log.Info("scanner stopped")
			return false
		case <-time.After(sleep):
		}

		updated, err := client.GetConfig()
		if err != nil {
			log.Warn("failed to refresh config, keeping previous values", zap.Error(err))
			continue
		}
		if updated.ScanIntervalSeconds != cfg.ScanIntervalSeconds {
			log.Info("scan interval updated",
				zap.Int("from_seconds", cfg.ScanIntervalSeconds),
				zap.Int("to_seconds", updated.ScanIntervalSeconds),
			)
		}
		*cfg = updated
	}
}

// runScanCycle fetches hosts and SAML endpoints and scans everything with
// bounded concurrency. Blocks until all in-flight scans complete.
func runScanCycle(ctx context.Context, client *internal.APIClient, concurrency int) {
	log := zap.L()
	if concurrency <= 0 {
		concurrency = 5
	}

	hosts, err := client.GetHosts()
	if err != nil {
		log.Error("failed to fetch hosts", zap.Error(err))
		return
	}

	samlEndpoints, err := client.GetSAMLEndpoints()
	if err != nil {
		log.Error("failed to fetch SAML endpoints", zap.Error(err))
		return
	}

	if len(hosts)+len(samlEndpoints) == 0 {
		log.Info("no endpoints to scan")
		return
	}
	log.Info("starting scan cycle", zap.Int("hosts", len(hosts)), zap.Int("saml", len(samlEndpoints)))

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
	log.Info("scan cycle complete")
}

func scanAndReport(ctx context.Context, client *internal.APIClient, host internal.ScannerHost) {
	log := zap.L().With(
		zap.String("host_id", host.ID),
		zap.String("dns_name", host.DNSName),
		zap.Int("port", host.Port),
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
		log.Error("failed to post scan result", zap.Error(err))
		return
	}

	if result.Err != nil {
		log.Warn("scan error", zap.String("error", *result.Err))
	} else {
		log.Info("scan successful",
			zap.Stringp("fingerprint", result.Fingerprint),
			zap.Stringp("tls_version", result.TLSVersion),
			zap.Stringp("resolved_ip", result.ResolvedIP),
		)
	}

	// Run TLS profile probe even if cert scan errored — host may still respond.
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

func scanAndReportSAML(ctx context.Context, client *internal.APIClient, endpoint internal.ScannerSAMLEndpoint) {
	log := zap.L().With(
		zap.String("endpoint_id", endpoint.ID),
		zap.String("url", endpoint.URL),
	)

	result := internal.ScanSAML(endpoint)

	if err := client.PostSAMLResult(endpoint.ID, internal.SAMLResultPayload{
		Error: result.Err,
		Certs: result.Certs,
	}); err != nil {
		log.Error("failed to post SAML scan result", zap.Error(err))
		return
	}

	if result.Err != nil {
		log.Warn("SAML scan error", zap.String("error", *result.Err))
	} else {
		log.Info("SAML scan successful", zap.Int("certs", len(result.Certs)))
	}
}
