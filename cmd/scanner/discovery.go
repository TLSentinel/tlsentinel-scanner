package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/tlsentinel/tlsentinel-scanner/internal"
)

// runDiscoverySweep is the stub discovery job. It enumerates every IP address
// in the network's range and logs each target. Real sweep logic (dial, TLS
// handshake, inbox reporting) will replace the log calls.
func runDiscoverySweep(network internal.ScannerDiscoveryNetwork) {
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

	for _, ip := range ips {
		slog.Info("discovery target", "ip", ip, "ports", network.Ports)
	}

	slog.Info("discovery sweep complete",
		"network_id", network.ID,
		"targets", len(ips),
	)
}

// enumerateRange returns every host IP in a CIDR block or hyphenated range.
// CIDR:  "10.0.0.0/24"           → 10.0.0.1 … 10.0.0.254
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
