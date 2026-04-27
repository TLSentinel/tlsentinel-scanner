package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tlsentinel/tlsentinel-scanner/internal"
)

const (
	discoveryConcurrency = 50
	// maxDiscoveryRangeSize caps the number of IPs any single network can
	// expand to. Prevents OOM from misconfigured ranges like /8 or 0.0.0.0/0
	// — at 4 bytes per IP plus overhead, /8 (16M IPs) would allocate ~600MB
	// before enumeration even begins. 65,536 = /16, which is the largest
	// subnet a single discovery sweep can reasonably handle.
	maxDiscoveryRangeSize = 65536

	// Retry policy for posting discovery findings. A brief transient outage
	// (API restart, flaky link) must not silently lose a discovery result —
	// the next sweep could be hours away. 4 attempts with doubling backoff
	// gives ~3.5s total wait (0.5 + 1 + 2) before giving up.
	discoveryPostMaxAttempts    = 4
	discoveryPostInitialBackoff = 500 * time.Millisecond
)

// runDiscoverySweep enumerates every IP:port in the network, probes each for
// TLS, and posts any findings to the server discovery inbox. Honors ctx so
// in-flight probes are cancelled when the scanner is shutting down.
func runDiscoverySweep(ctx context.Context, client *internal.APIClient, network internal.ScannerDiscoveryNetwork) {
	if len(network.Ports) == 0 {
		slog.Warn("discovery network has no ports configured, skipping sweep",
			"network_id", network.ID,
			"range", network.Range,
		)
		return
	}

	slog.Info("discovery sweep starting",
		"network_id", network.ID,
		"range", network.Range,
		"ports", network.Ports,
	)

	ips, err := enumerateRange(network.Range)
	if err != nil {
		slog.Error("failed to enumerate range",
			"network_id", network.ID,
			"range", network.Range,
			"error", err,
		)
		return
	}

	sem := make(chan struct{}, discoveryConcurrency)
	var (
		wg    sync.WaitGroup
		found atomic.Int64
	)

	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		for _, port := range network.Ports {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(ip string, port int) {
				defer wg.Done()
				defer func() { <-sem }()

				result := internal.ProbeDiscoveryTarget(ctx, ip, port)
				if !result.TLSFound {
					return
				}

				rdns := internal.ReverseLookup(ctx, ip)

				log := slog.With("network_id", network.ID, "ip", ip, "port", port)
				if rdns != nil {
					log = log.With("rdns", *rdns)
				}
				if result.CommonName != nil {
					log = log.With("common_name", *result.CommonName)
				}
				log.Info("TLS service discovered")

				item := internal.DiscoveryReportItem{
					IP:          ip,
					Port:        port,
					RDNS:        rdns,
					Fingerprint: result.Fingerprint,
					CommonName:  result.CommonName,
					SANs:        result.SANs,
					NotAfter:    result.NotAfter,
				}
				if err := postDiscoveryWithRetry(ctx, client, network.ID, []internal.DiscoveryReportItem{item}); err != nil {
					slog.Error("failed to post discovery result after retries",
						"network_id", network.ID,
						"ip", ip,
						"port", port,
						"error", err,
					)
					return
				}
				found.Add(1)
			}(ip, port)
		}
	}

	wg.Wait()

	slog.Info("discovery sweep complete",
		"network_id", network.ID,
		"targets", len(ips)*len(network.Ports),
		"tls_found", found.Load(),
	)
}

// enumerateRange returns every host IP in a CIDR block or hyphenated range.
// CIDR:  "10.0.0.0/24"               → 10.0.0.1 … 10.0.0.254
// Range: "192.168.1.1-192.168.1.50"
func enumerateRange(s string) ([]string, error) {
	if strings.Contains(s, "/") {
		return enumerateCIDR(s)
	}
	if strings.Contains(s, "-") {
		return enumerateHyphenated(s)
	}
	return nil, fmt.Errorf("unrecognised range format: %q", s)
}

func enumerateCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	// Work with 4-byte representation throughout.
	start := ipNet.IP.To4()
	if start == nil {
		return nil, fmt.Errorf("only IPv4 CIDR ranges are supported")
	}

	first := ipToUint32(start) + 1         // skip network address
	last := first + networkSize(ipNet) - 3 // skip broadcast address

	return uint32RangeToStrings(first, last)
}

func enumerateHyphenated(s string) ([]string, error) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid hyphenated range: %q", s)
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0])).To4()
	endIP := net.ParseIP(strings.TrimSpace(parts[1])).To4()
	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("invalid IPs in range %q", s)
	}

	first := ipToUint32(startIP)
	last := ipToUint32(endIP)
	if first > last {
		return nil, fmt.Errorf("range start must not exceed range end: %q", s)
	}

	return uint32RangeToStrings(first, last)
}

func ipToUint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(n uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip.String()
}

func networkSize(ipNet *net.IPNet) uint32 {
	var buf bytes.Buffer
	buf.Write(ipNet.Mask)
	mask := binary.BigEndian.Uint32(buf.Bytes())
	return ^mask + 1
}

// postDiscoveryWithRetry posts discovery items with bounded exponential
// backoff. Returns nil on success, the last error after all attempts fail,
// or the current error immediately if ctx is cancelled (shutdown must not
// be delayed by retries).
func postDiscoveryWithRetry(ctx context.Context, client *internal.APIClient, networkID string, items []internal.DiscoveryReportItem) error {
	backoff := discoveryPostInitialBackoff
	var err error
	for attempt := 1; attempt <= discoveryPostMaxAttempts; attempt++ {
		err = client.PostDiscoveryResults(ctx, networkID, items)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return err
		}
		if attempt == discoveryPostMaxAttempts {
			break
		}
		slog.Warn("failed to post discovery result, retrying",
			"network_id", networkID,
			"attempt", attempt,
			"next_retry_in", backoff,
			"error", err,
		)
		select {
		case <-ctx.Done():
			return err
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return err
}

func uint32RangeToStrings(first, last uint32) ([]string, error) {
	size := uint64(last) - uint64(first) + 1
	if size > maxDiscoveryRangeSize {
		return nil, fmt.Errorf("range too large: %d IPs exceeds limit of %d (max /16)", size, maxDiscoveryRangeSize)
	}
	ips := make([]string, 0, size)
	for n := first; n <= last; n++ {
		ips = append(ips, uint32ToIP(n))
	}
	return ips, nil
}
