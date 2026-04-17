package internal

import (
	"context"
	"net"
	"time"

	ztls "github.com/runZeroInc/excrypto/crypto/tls"
)

// dialTLSContext performs a context-aware TCP dial followed by a context-aware
// TLS handshake. Callers that need to cancel long-running probes on shutdown
// should use this instead of ztls.DialWithDialer, which has no ctx support.
func dialTLSContext(ctx context.Context, timeout time.Duration, network, addr string, cfg *ztls.Config) (*ztls.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tlsConn := ztls.Client(rawConn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}
