package internal

import (
	"net"
	"strconv"
	"strings"
	"time"

	ztls "github.com/runZeroInc/excrypto/crypto/tls"
	zx509 "github.com/runZeroInc/excrypto/crypto/x509"
)

const (
	discoveryDialTimeout = 3 * time.Second
)

// DiscoveryResult is the outcome of probing a single IP:port for TLS.
type DiscoveryResult struct {
	IP          string
	Port        int
	TLSFound    bool
	Fingerprint *string
	CommonName  *string
	SANs        []string
	NotAfter    *time.Time
}

// DiscoveryReportItem is a confirmed TLS-bearing IP:port, ready to post to the server.
type DiscoveryReportItem struct {
	IP          string     `json:"ip"`
	Port        int        `json:"port"`
	RDNS        *string    `json:"rdns,omitempty"`
	Fingerprint *string    `json:"fingerprint,omitempty"`
	CommonName  *string    `json:"commonName,omitempty"`
	SANs        []string   `json:"sans,omitempty"`
	NotAfter    *time.Time `json:"notAfter,omitempty"`
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
// On success, the leaf certificate's fingerprint, common name, SANs, and expiry are populated.
//
// InsecureSkipVerify is intentional — we are detecting TLS presence, not validating certs.
// IP addresses are not sent as SNI (RFC 6066 prohibits IP literals in server_name),
// so ServerName is left empty.
// MinVersion is SSL 3.0 so that ancient servers are also detected; the excrypto
// fork exposes VersionSSL30 specifically for this scanning use case.
func ProbeDiscoveryTarget(ip string, port int) DiscoveryResult {
	target := net.JoinHostPort(ip, strconv.Itoa(port))
	result := DiscoveryResult{IP: ip, Port: port}

	dialer := &net.Dialer{Timeout: discoveryDialTimeout}
	conn, err := ztls.DialWithDialer(dialer, "tcp", target, &ztls.Config{
		InsecureSkipVerify: true,              //nolint:gosec // Intentional: detecting TLS, not validating
		MinVersion:         ztls.VersionSSL30, // reach even SSL 3.0 legacy endpoints
		CipherSuites:       allCipherSuiteIDs, // full suite list (secure + insecure) from probe.go
	})
	if err != nil {
		return result
	}
	defer conn.Close()

	result.TLSFound = true

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return result
	}

	leaf := certs[0]
	fp := certFingerprint(leaf.Raw)
	cn := leaf.Subject.CommonName
	notAfter := leaf.NotAfter

	result.Fingerprint = &fp
	result.CommonName = &cn
	result.NotAfter = &notAfter
	result.SANs = leafSANs(leaf)

	return result
}

// leafSANs returns the DNS names and IP addresses from a certificate's SANs.
func leafSANs(cert *zx509.Certificate) []string {
	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	return sans
}
