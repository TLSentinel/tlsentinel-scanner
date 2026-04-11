package internal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"strconv"
	"time"

	ztls "github.com/runZeroInc/excrypto/crypto/tls"
)

// ScanResult holds the outcome of scanning a single host.
type ScanResult struct {
	// Fingerprint is the hex-encoded SHA-256 of the leaf certificate's DER bytes.
	// Nil when the scan failed before a certificate was retrieved.
	Fingerprint *string
	// PEMs contains PEM-encoded certificates in chain order (leaf first).
	PEMs []string
	// ResolvedIP is the address actually dialled (may differ from DNSName when
	// an explicit IP override is configured).
	ResolvedIP *string
	// TLSVersion is the negotiated TLS protocol version string (e.g. "TLS 1.3").
	TLSVersion *string
	// Err holds a human-readable error string if the scan failed.
	Err *string
}

// tlsVersionString maps the crypto/tls version constants to human-readable strings.
func tlsVersionString(v uint16) string {
	switch v {
	case ztls.VersionTLS10:
		return "TLS 1.0"
	case ztls.VersionTLS11:
		return "TLS 1.1"
	case ztls.VersionTLS12:
		return "TLS 1.2"
	case ztls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", v)
	}
}

// certFingerprint returns the hex-encoded SHA-256 fingerprint of a DER-encoded certificate.
func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// certToPEM encodes a DER certificate to PEM format.
func certToPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}))
}

// ScanHost opens a TLS connection to host and collects certificate chain data.
// InsecureSkipVerify is intentional — we are collecting certs, not validating them.
func ScanHost(host ScannerHost) ScanResult {
	addr := host.DNSName
	if host.IPAddress != nil && *host.IPAddress != "" {
		addr = *host.IPAddress
	}
	target := net.JoinHostPort(addr, strconv.Itoa(host.Port))

	// Build a full cipher suite list (secure + insecure) so we can reach
	// legacy servers that only offer RSA key exchange ciphers. Go 1.22+
	// removed these from its default advertised list, which causes a
	// handshake failure against servers that have no ECDHE/DHE support.
	allSuites := make([]uint16, 0)
	for _, s := range append(ztls.CipherSuites(), ztls.InsecureCipherSuites()...) {
		allSuites = append(allSuites, s.ID)
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := ztls.DialWithDialer(dialer, "tcp", target, &ztls.Config{
		ServerName:         host.DNSName,
		InsecureSkipVerify: true,             //nolint:gosec // Intentional: collecting certs, not validating
		MinVersion:         ztls.VersionTLS10, // reach TLS 1.0/1.1 legacy endpoints
		CipherSuites:       allSuites,        // include RSA key exchange for legacy servers
	})
	if err != nil {
		errStr := err.Error()
		return ScanResult{Err: &errStr}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		errStr := "no certificates returned by server"
		return ScanResult{Err: &errStr}
	}

	// Build PEM list (leaf first, then intermediates/root).
	pems := make([]string, 0, len(certs))
	for _, c := range certs {
		pems = append(pems, certToPEM(c.Raw))
	}

	fp := certFingerprint(certs[0].Raw)
	tlsVer := tlsVersionString(state.Version)

	// Resolved IP is the remote address of the connection.
	resolvedIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	return ScanResult{
		Fingerprint: &fp,
		PEMs:        pems,
		ResolvedIP:  &resolvedIP,
		TLSVersion:  &tlsVer,
	}
}
