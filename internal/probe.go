package internal

import (
	"context"
	"net"
	"strconv"
	"time"

	ztls "github.com/runZeroInc/excrypto/crypto/tls"
)

const probeTimeout = 5 * time.Second

// allCipherSuiteIDs is the full set of cipher suite IDs known to crypto/tls
// (secure + insecure). Built once at init time and reused across all probes.
// Advertising the full set ensures we can reach legacy servers that only
// offer RSA key exchange ciphers, which Go 1.22+ dropped from its defaults.
var allCipherSuiteIDs = func() []uint16 {
	suites := append(ztls.CipherSuites(), ztls.InsecureCipherSuites()...)
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
func ProbeTLSProfile(ctx context.Context, host ScannerHost) TLSProfilePayload {
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
	// exactly that version or reject the handshake. SSL 3.0 is probed via the
	// excrypto fork (stdlib crypto/tls has removed SSL 3.0 entirely) so that
	// SSLv3-POODLE can be flagged from the version set alone.
	payload.SSL30 = probeVersion(ctx, target, host.DNSName, ztls.VersionSSL30)
	payload.TLS10 = probeVersion(ctx, target, host.DNSName, ztls.VersionTLS10)
	payload.TLS11 = probeVersion(ctx, target, host.DNSName, ztls.VersionTLS11)
	payload.TLS12 = probeVersion(ctx, target, host.DNSName, ztls.VersionTLS12)
	payload.TLS13 = probeVersion(ctx, target, host.DNSName, ztls.VersionTLS13)

	if !payload.SSL30 && !payload.TLS10 && !payload.TLS11 && !payload.TLS12 && !payload.TLS13 {
		errStr := "no TLS version accepted by server"
		payload.ScanError = &errStr
		return payload
	}

	// ── Cipher suite enumeration ──────────────────────────────────────────
	// Offer each suite individually for every supported legacy version.
	// TLS 1.3 cipher suites are not client-negotiable via crypto/tls —
	// the library always advertises all TLS 1.3 suites automatically.
	// Note: crypto/tls only knows suites it implements — any suite not in
	// ztls.CipherSuites()+ztls.InsecureCipherSuites() cannot be detected.
	// Known gap: 0x003D TLS_RSA_WITH_AES_256_CBC_SHA256 is unimplemented
	// in Go's stdlib and will never appear in enumeration results.
	allSuites := append(ztls.CipherSuites(), ztls.InsecureCipherSuites()...)
	seen := make(map[uint16]bool)

	for _, ver := range []struct {
		supported bool
		version   uint16
	}{
		{payload.TLS12, ztls.VersionTLS12},
		{payload.TLS11, ztls.VersionTLS11},
		{payload.TLS10, ztls.VersionTLS10},
	} {
		if !ver.supported {
			continue
		}
		for _, suite := range allSuites {
			if seen[suite.ID] {
				continue
			}
			if probeOneCipher(ctx, target, host.DNSName, suite.ID, ver.version) {
				payload.CipherSuites = append(payload.CipherSuites, suite.Name)
				seen[suite.ID] = true
			}
		}
	}

	// ── Selected cipher from default handshake ────────────────────────────
	// Let the Go TLS stack negotiate freely and record what the server chose.
	if selected, err := probeSelectedCipher(ctx, target, host.DNSName); err == nil {
		payload.SelectedCipher = &selected
	}

	return payload
}

// probeVersion returns true if the host accepts a TLS handshake pinned to version.
func probeVersion(ctx context.Context, target, serverName string, version uint16) bool {
	conn, err := dialTLSContext(ctx, probeTimeout, "tcp", target, &ztls.Config{
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
func probeOneCipher(ctx context.Context, target, serverName string, suiteID uint16, version uint16) bool {
	conn, err := dialTLSContext(ctx, probeTimeout, "tcp", target, &ztls.Config{
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
func probeSelectedCipher(ctx context.Context, target, serverName string) (string, error) {
	conn, err := dialTLSContext(ctx, probeTimeout, "tcp", target, &ztls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // Intentional: probing cipher selection
		MinVersion:         ztls.VersionTLS10,
		CipherSuites:       allCipherSuiteIDs,
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	// CipherSuiteName returns IANA-standard names for both TLS 1.2 and 1.3 suites.
	return ztls.CipherSuiteName(conn.ConnectionState().CipherSuite), nil
}
