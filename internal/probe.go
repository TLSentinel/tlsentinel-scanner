package internal

import (
	"crypto/tls"
	"net"
	"strconv"
	"time"
)

const probeTimeout = 5 * time.Second

// ProbeTLSProfile probes the host for supported TLS versions and cipher suites.
// It is a best-effort operation; individual sub-probes that fail are silently
// skipped and represented as "not supported".
//
// InsecureSkipVerify is intentional throughout — we are probing capabilities,
// not validating certificate chains.
func ProbeTLSProfile(host ScannerHost) TLSProfilePayload {
	addr := host.DNSName
	if host.IPAddress != nil && *host.IPAddress != "" {
		addr = *host.IPAddress
	}
	target := net.JoinHostPort(addr, strconv.Itoa(host.Port))

	payload := TLSProfilePayload{
		CipherSuites: []string{},
	}

	// ── TLS version support ────────────────────────────────────────────────
	// Each probe pins both MinVersion and MaxVersion so the server must accept
	// exactly that version or reject the handshake.
	payload.TLS10 = probeVersion(target, host.DNSName, tls.VersionTLS10)
	payload.TLS11 = probeVersion(target, host.DNSName, tls.VersionTLS11)
	payload.TLS12 = probeVersion(target, host.DNSName, tls.VersionTLS12)
	payload.TLS13 = probeVersion(target, host.DNSName, tls.VersionTLS13)

	if !payload.TLS10 && !payload.TLS11 && !payload.TLS12 && !payload.TLS13 {
		errStr := "no TLS version accepted by server"
		payload.ScanError = &errStr
		return payload
	}

	// ── TLS 1.2 cipher suite enumeration ──────────────────────────────────
	// Offer each suite individually with a pinned TLS 1.2 connection.
	// TLS 1.3 cipher suites are not client-negotiable via crypto/tls —
	// the library always advertises all TLS 1.3 suites automatically.
	if payload.TLS12 {
		allSuites := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
		for _, suite := range allSuites {
			if probeOneCipher(target, host.DNSName, suite.ID) {
				// suite.Name is the IANA name (e.g. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256).
				payload.CipherSuites = append(payload.CipherSuites, suite.Name)
			}
		}
	}

	// ── Selected cipher from default handshake ────────────────────────────
	// Let the Go TLS stack negotiate freely and record what the server chose.
	if selected, err := probeSelectedCipher(target, host.DNSName); err == nil {
		payload.SelectedCipher = &selected
	}

	return payload
}

// probeVersion returns true if the host accepts a TLS handshake pinned to version.
func probeVersion(target, serverName string, version uint16) bool {
	dialer := &net.Dialer{Timeout: probeTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // Intentional: probing version support
		MinVersion:         version,
		MaxVersion:         version,
	})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// probeOneCipher returns true if the host accepts a TLS 1.2 handshake when
// exactly suiteID is offered. The server must negotiate that suite or the
// handshake will fail, so a successful connection confirms support.
func probeOneCipher(target, serverName string, suiteID uint16) bool {
	dialer := &net.Dialer{Timeout: probeTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // Intentional: probing cipher support
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       []uint16{suiteID},
	})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// probeSelectedCipher dials with default TLS settings and returns the IANA
// name of the cipher suite the server chose.
func probeSelectedCipher(target, serverName string) (string, error) {
	dialer := &net.Dialer{Timeout: probeTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // Intentional: probing cipher selection
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	// CipherSuiteName returns IANA-standard names for both TLS 1.2 and 1.3 suites.
	return tls.CipherSuiteName(conn.ConnectionState().CipherSuite), nil
}
