package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/tlsentinel/tlsentinel-scanner/internal"
)

const discoveryConcurrency = 50

// runDiscoverySweep enumerates every IP:port in the network, probes each for
// TLS, and posts any findings to the server discovery inbox.
func runDiscoverySweep(client *internal.APIClient, network internal.ScannerDiscoveryNetwork) {
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
		wg      sync.WaitGroup
		mu      sync.Mutex
		found   []internal.DiscoveryReportItem
	)

	for _, ip := range ips {
		for _, port := range network.Ports {
			wg.Add(1)
			sem <- struct{}{}
			go func(ip string, port int) {
				defer wg.Done()
				defer func() { <-sem }()

				result := internal.ProbeDiscoveryTarget(ip, port)
				if !result.TLSFound {
					return
				}

				slog.Info("TLS service discovered",
					"network_id", network.ID,
					"ip", ip,
					"port", port,
				)
				mu.Lock()
				found = append(found, internal.DiscoveryReportItem{IP: ip, Port: port})
				mu.Unlock()
			}(ip, port)
		}
	}

	wg.Wait()

	slog.Info("discovery sweep complete",
		"network_id", network.ID,
		"targets", len(ips)*len(network.Ports),
		"tls_found", len(found),
	)

	if len(found) > 0 {
		if err := client.PostDiscoveryResults(network.ID, found); err != nil {
			slog.Error("failed to post discovery results",
				"network_id", network.ID,
				"error", err,
			)
		}
	}
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

	return uint32RangeToStrings(first, last), nil
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

	return uint32RangeToStrings(first, last), nil
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

func uint32RangeToStrings(first, last uint32) []string {
	ips := make([]string, 0, last-first+1)
	for n := first; n <= last; n++ {
		ips = append(ips, uint32ToIP(n))
	}
	return ips
}
