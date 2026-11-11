package relay_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beamfall/relay/internal/relay"
	"github.com/beamfall/relay/internal/tunnel"
)

func TestAbruptPublicDisconnectReleasesAllSlotsForEveryTransport(t *testing.T) {
	transports := []struct {
		name      string
		transport string
		addr      func(*relay.Server) string
	}{
		{name: "yamux", transport: tunnel.TransportTCP, addr: (*relay.Server).CarrierAddr},
		{name: "quic", transport: tunnel.TransportQUIC, addr: (*relay.Server).QUICAddr},
	}

	for _, transport := range transports {
		t.Run(transport.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			home := startSilentHomeTLS(t, testHost)
			defer home.Close()
			node := startRelay(t, ctx, relay.Config{
				AdminAddr: "127.0.0.1:0",
				TokenVerifier: relay.StaticTokenVerifier{
					Token:     []byte("test-token"),
					CarrierID: "carrier-1",
					Hostnames: []string{testHost},
				},
				StreamCap:           1,
				MaxPublicConns:      1,
				MaxPublicConnsPerIP: 1,
			})
			client := startTunnelClientTransport(t, ctx, transport.transport, transport.addr(node), home.Addr(), []byte("test-token"), []string{testHost})
			defer client.Close()

			first := dialPublicTLSOverTCP(t, node.PublicAddr(), home.Roots)
			waitForRelayMetric(t, node.AdminAddr(), "beamfall_relay_streams_active 1", time.Second)

			started := time.Now()
			resetTCP(t, first)
			waitForRelayMetric(t, node.AdminAddr(), "beamfall_relay_streams_active 0", time.Until(started.Add(time.Second)))
			second := dialPublicTLSBefore(t, node.PublicAddr(), home.Roots, started.Add(time.Second))

			started = time.Now()
			resetTCP(t, second)

			shutdownDone := make(chan struct{})
			go func() {
				node.Shutdown(5 * time.Second)
				close(shutdownDone)
			}()
			select {
			case <-shutdownDone:
			case <-time.After(time.Until(started.Add(time.Second))):
				t.Fatal("abrupt public disconnect did not release streamWG within 1s")
			}
		})
	}
}

func dialPublicTLSOverTCP(t *testing.T, addr string, roots *x509.CertPool) *net.TCPConn {
	t.Helper()
	tcp, err := net.DialTCP("tcp", nil, mustResolveTCPAddr(t, addr))
	if err != nil {
		t.Fatalf("dial public TCP: %v", err)
	}
	tlsConn := tls.Client(tcp, &tls.Config{
		ServerName: testHost,
		RootCAs:    roots,
		MinVersion: tls.VersionTLS13,
	})
	if err := tlsConn.Handshake(); err != nil {
		_ = tcp.Close()
		t.Fatalf("handshake public TLS: %v", err)
	}
	return tcp
}

func dialPublicTLSBefore(t *testing.T, addr string, roots *x509.CertPool, deadline time.Time) *net.TCPConn {
	t.Helper()
	var lastErr error
	for time.Now().Before(deadline) {
		tcp, err := net.DialTCP("tcp", nil, mustResolveTCPAddr(t, addr))
		if err != nil {
			lastErr = err
			continue
		}
		_ = tcp.SetDeadline(deadline)
		tlsConn := tls.Client(tcp, &tls.Config{
			ServerName: testHost,
			RootCAs:    roots,
			MinVersion: tls.VersionTLS13,
		})
		if err := tlsConn.Handshake(); err == nil {
			_ = tcp.SetDeadline(time.Time{})
			return tcp
		} else {
			lastErr = err
		}
		_ = tcp.Close()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("all four relay slots were not released within 1s; replacement public TLS handshake failed: %v", lastErr)
	return nil
}

func mustResolveTCPAddr(t *testing.T, addr string) *net.TCPAddr {
	t.Helper()
	resolved, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		t.Fatalf("resolve TCP address: %v", err)
	}
	return resolved
}

func resetTCP(t *testing.T, conn *net.TCPConn) {
	t.Helper()
	if err := conn.SetLinger(0); err != nil {
		t.Fatalf("set TCP RST linger: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close TCP with RST: %v", err)
	}
}

func waitForRelayMetric(t *testing.T, adminAddr, metric string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(getMetrics(t, adminAddr), metric+"\n") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("metric %q did not appear within %s", metric, timeout)
}

type silentHomeTLS struct {
	listener net.Listener
	Roots    *x509.CertPool
	stop     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
}

func startSilentHomeTLS(t *testing.T, host string) *silentHomeTLS {
	t.Helper()
	cert := mustSelfSignedCert(t, host)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert.TLSCert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("start silent home TLS server: %v", err)
	}
	home := &silentHomeTLS{
		listener: listener,
		Roots:    cert.Roots,
		stop:     make(chan struct{}),
		conns:    make(map[net.Conn]struct{}),
	}
	home.wg.Add(1)
	go home.serve()
	return home
}

func (h *silentHomeTLS) Addr() string { return h.listener.Addr().String() }

func (h *silentHomeTLS) serve() {
	defer h.wg.Done()
	for {
		conn, err := h.listener.Accept()
		if err != nil {
			return
		}
		h.mu.Lock()
		h.conns[conn] = struct{}{}
		h.mu.Unlock()
		h.wg.Add(1)
		go h.silence(conn)
	}
}

func (h *silentHomeTLS) silence(conn net.Conn) {
	defer h.wg.Done()
	defer func() {
		_ = conn.Close()
		h.mu.Lock()
		delete(h.conns, conn)
		h.mu.Unlock()
	}()
	if err := conn.(*tls.Conn).Handshake(); err != nil {
		return
	}
	<-h.stop
}

func (h *silentHomeTLS) Close() {
	h.once.Do(func() {
		close(h.stop)
		_ = h.listener.Close()
		h.mu.Lock()
		for conn := range h.conns {
			_ = conn.Close()
		}
		h.mu.Unlock()
		h.wg.Wait()
	})
}
