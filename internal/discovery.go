package internal

import (
	"net"
	"strconv"
	"strings"
	"time"

	ztls "github.com/runZeroInc/excrypto/crypto/tls"
)

const (
	discoveryDialTimeout = 3 * time.Second
)

// DiscoveryResult is the outcome of probing a single IP:port for TLS.
type DiscoveryResult struct {
	IP       string
	Port     int
	TLSFound bool
}

// DiscoveryReportItem is a confirmed TLS-bearing IP:port, ready to post to the server.
type DiscoveryReportItem struct {
	IP   string  `json:"ip"`
	Port int     `json:"port"`
	RDNS *string `json:"rdns,omitempty"`
}

// ReverseLookup returns the first PTR record for ip, or nil if none is found.
func ReverseLookup(ip string) *string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return nil
	}
	// PTR records are returned with a trailing dot — strip it.
	name := strings.TrimSuffix(names[0], ".")
	return &name
}

// ProbeDiscoveryTarget dials ip:port and attempts a TLS/SSL handshake.
// Returns TLSFound=false when the port is closed, filtered, or does not speak TLS.
//
// InsecureSkipVerify is intentional — we are detecting TLS presence, not validating certs.
// IP addresses are not sent as SNI (RFC 6066 prohibits IP literals in server_name),
// so ServerName is left empty.
// MinVersion is SSL 3.0 so that ancient servers are also detected; the excrypto
// fork exposes VersionSSL30 specifically for this scanning use case.
func ProbeDiscoveryTarget(ip string, port int) DiscoveryResult {
	target := net.JoinHostPort(ip, strconv.Itoa(port))

	dialer := &net.Dialer{Timeout: discoveryDialTimeout}
	conn, err := ztls.DialWithDialer(dialer, "tcp", target, &ztls.Config{
		InsecureSkipVerify: true,              //nolint:gosec // Intentional: detecting TLS, not validating
		MinVersion:         ztls.VersionSSL30, // reach even SSL 3.0 legacy endpoints
		CipherSuites:       allCipherSuiteIDs, // full suite list (secure + insecure) from probe.go
	})
	if err != nil {
		// Port closed, filtered, or not TLS — not an error for discovery purposes.
		return DiscoveryResult{IP: ip, Port: port, TLSFound: false}
	}
	conn.Close()

	return DiscoveryResult{IP: ip, Port: port, TLSFound: true}
}
