package internal

import (
	"crypto/tls"
	"net"
	"strconv"
	"time"
)

const probeTimeout = 5 * time.Second

// allCipherSuiteIDs is the full set of cipher suite IDs known to crypto/tls
// (secure + insecure). Built once at init time and reused across all probes.
// Advertising the full set ensures we can reach legacy servers that only
// offer RSA key exchange ciphers, which Go 1.22+ dropped from its defaults.
var allCipherSuiteIDs = func() []uint16 {
	suites := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
	ids := make([]uint16, len(suites))
	for i, s := range suites {
		ids[i] = s.ID
	}
	return ids
}()

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

	// ── Cipher suite enumeration ──────────────────────────────────────────
	// Offer each suite individually for every supported legacy version.
	// TLS 1.3 cipher suites are not client-negotiable via crypto/tls —
	// the library always advertises all TLS 1.3 suites automatically.
	// Note: crypto/tls only knows suites it implements; suites outside
	// that set (e.g. RC4, export-grade) cannot be detected this way.
	allSuites := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
	seen := make(map[uint16]bool)

	for _, ver := range []struct {
		supported bool
		version   uint16
	}{
		{payload.TLS12, tls.VersionTLS12},
		{payload.TLS11, tls.VersionTLS11},
		{payload.TLS10, tls.VersionTLS10},
	} {
		if !ver.supported {
			continue
		}
		for _, suite := range allSuites {
			if seen[suite.ID] {
				continue
			}
			if probeOneCipher(target, host.DNSName, suite.ID, ver.version) {
				payload.CipherSuites = append(payload.CipherSuites, suite.Name)
				seen[suite.ID] = true
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
		CipherSuites:       allCipherSuiteIDs,
	})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// probeOneCipher returns true if the host accepts a handshake pinned to
// version when exactly suiteID is offered. The server must negotiate that
// suite or the handshake will fail, so a successful connection confirms support.
func probeOneCipher(target, serverName string, suiteID uint16, version uint16) bool {
	dialer := &net.Dialer{Timeout: probeTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // Intentional: probing cipher support
		MinVersion:         version,
		MaxVersion:         version,
		CipherSuites:       []uint16{suiteID},
	})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// probeSelectedCipher dials with a full cipher list and returns the IANA
// name of the cipher suite the server chose.
func probeSelectedCipher(target, serverName string) (string, error) {
	dialer := &net.Dialer{Timeout: probeTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // Intentional: probing cipher selection
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       allCipherSuiteIDs,
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	// CipherSuiteName returns IANA-standard names for both TLS 1.2 and 1.3 suites.
	return tls.CipherSuiteName(conn.ConnectionState().CipherSuite), nil
}
