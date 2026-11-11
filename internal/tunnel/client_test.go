package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/beamfall/relay/internal/protocol"
)

type fakeCarrier struct {
	ln   net.Listener
	cert tls.Certificate

	mu       sync.Mutex
	sessions []*yamux.Session
	tokens   [][]byte
	hellos   []protocol.Hello
	accepted int

	ackVersion  int
	rejectError string
}

type lifecycleQUICCarrier struct {
	closeOnce  sync.Once
	closeCount atomic.Int32
	handshake  func(context.Context) error
	stream     protocol.FrameReadWriter
}

func (c *lifecycleQUICCarrier) Close() error {
	c.closeOnce.Do(func() {
		c.closeCount.Add(1)
		if closer, ok := c.stream.(io.Closer); ok {
			_ = closer.Close()
		}
	})
	return nil
}

func (c *lifecycleQUICCarrier) Handshake(ctx context.Context, _ *tls.Config) error {
	if c.handshake != nil {
		return c.handshake(ctx)
	}
	return nil
}

func (c *lifecycleQUICCarrier) OpenHandshakeStream(context.Context) (protocol.FrameReadWriter, error) {
	return c.stream, nil
}

func (c *lifecycleQUICCarrier) Session() protocol.Session { return nil }

func passThroughTLS(_ context.Context, conn net.Conn, _ *tls.Config) (net.Conn, error) {
	return conn, nil
}

func TestQUICCarrierTLSConfigServerName(t *testing.T) {
	tests := []struct {
		name       string
		relayAddr  string
		serverName string
		want       string
	}{
		{"derived hostname", "relay.example:443", "", "relay.example"},
		{"explicit override", "relay.example:443", "override.example", "override.example"},
		{"IPv4", "192.0.2.10:443", "", "192.0.2.10"},
		{"IPv6", "[2001:db8::10]:443", "", "2001:db8::10"},
	}
	stopHandshake := errors.New("stop after TLS config capture")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newLifecycleClient(t, time.Second)
			client.cfg.Transport = TransportQUIC
			client.cfg.RelayAddr = tt.relayAddr
			client.cfg.TLSConfig.ServerName = tt.serverName
			originalTLSConfig := client.cfg.TLSConfig
			carrier := &lifecycleQUICCarrier{}
			client.dialQUICCarrier = func(context.Context, string) (quicCarrier, error) {
				return carrier, nil
			}
			var captured *tls.Config
			client.handshakeQUICCarrier = func(_ context.Context, _ quicCarrier, cfg *tls.Config) error {
				captured = cfg
				return stopHandshake
			}

			if _, err := client.serveOnce(context.Background()); !errors.Is(err, stopHandshake) {
				t.Fatalf("serveOnce error = %v, want capture stop", err)
			}
			if captured == nil {
				t.Fatal("QUIC handshake did not receive TLS config")
			}
			if captured.ServerName != tt.want {
				t.Fatalf("TLS ServerName = %q, want %q", captured.ServerName, tt.want)
			}
			if captured == originalTLSConfig {
				t.Fatal("QUIC handshake received caller-owned TLS config")
			}
			if originalTLSConfig.ServerName != tt.serverName {
				t.Fatalf("caller TLS ServerName mutated to %q, want %q", originalTLSConfig.ServerName, tt.serverName)
			}
			if got := carrier.closeCount.Load(); got != 1 {
				t.Fatalf("carrier closed %d times, want exactly once", got)
			}
			assertNoLiveCarrier(t, client)
		})
	}
}

func TestQUICCarrierMalformedAckCancellationAndLateSuccess(t *testing.T) {
	t.Run("malformed Ack", func(t *testing.T) {
		client := newLifecycleClient(t, time.Second)
		client.cfg.Transport = TransportQUIC
		local, peer := net.Pipe()
		defer peer.Close() //nolint:errcheck
		carrier := &lifecycleQUICCarrier{stream: local}
		client.dialQUICCarrier = func(context.Context, string) (quicCarrier, error) { return carrier, nil }
		peerDone := make(chan struct{})
		go func() {
			defer close(peerDone)
			if _, err := protocol.ReadFrame(peer); err == nil {
				_ = protocol.WriteFrame(peer, protocol.Frame{Type: protocol.FrameAck})
			}
		}()
		if _, err := client.serveOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "malformed Ack") {
			t.Fatalf("serveOnce error = %v, want malformed Ack", err)
		}
		waitSignal(t, peerDone, "malformed-Ack peer goroutine leaked")
		if carrier.closeCount.Load() != 1 {
			t.Fatalf("close count = %d, want 1", carrier.closeCount.Load())
		}
		assertNoLiveCarrier(t, client)
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		client := newLifecycleClient(t, 5*time.Second)
		client.cfg.Transport = TransportQUIC
		h := installHangingQUICPhase(t, client, "ack")
		defer h.cleanup()
		startLifecycleLoop(client, ctx)
		waitSignal(t, h.entered, "Ack wait did not begin")
		cancel()
		waitClient(t, client, "context cancellation did not terminate QUIC loop")
		h.waitExited(t)
		h.assertCloseCount(t)
	})

	for _, phase := range []string{"dial", "tls"} {
		t.Run("late "+phase+" success", func(t *testing.T) {
			client := newLifecycleClient(t, 20*time.Millisecond)
			client.cfg.Transport = TransportQUIC
			carrier := &lifecycleQUICCarrier{}
			client.dialQUICCarrier = func(ctx context.Context, _ string) (quicCarrier, error) {
				if phase == "dial" {
					<-ctx.Done()
				}
				return carrier, nil
			}
			if phase == "tls" {
				carrier.handshake = func(ctx context.Context) error { <-ctx.Done(); return nil }
			}
			if _, err := client.serveOnce(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("serveOnce error = %v, want deadline exceeded", err)
			}
			if carrier.closeCount.Load() != 1 {
				t.Fatalf("late carrier closed %d times, want 1", carrier.closeCount.Load())
			}
			assertNoLiveCarrier(t, client)
		})
	}
}

func newFakeCarrier(t *testing.T) *fakeCarrier {
	t.Helper()
	c := &fakeCarrier{cert: selfSignedCert(t), ackVersion: protocol.Version}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{c.cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listen carrier: %v", err)
	}
	c.ln = ln
	go c.serve()
	return c
}

func (c *fakeCarrier) addr() string { return c.ln.Addr().String() }

func (c *fakeCarrier) serve() {
	for {
		conn, err := c.ln.Accept()
		if err != nil {
			return
		}
		go c.handle(conn)
	}
}

func (c *fakeCarrier) handle(conn net.Conn) {
	frame, err := protocol.ReadFrame(conn)
	if err != nil || frame.Type != protocol.FrameHello || frame.Hello == nil {
		conn.Close() //nolint:errcheck // test carrier cleanup after rejected handshake.
		return
	}
	if c.rejectError != "" {
		_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.FrameError, Error: c.rejectError})
		conn.Close() //nolint:errcheck // test carrier cleanup after rejected handshake.
		return
	}
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.FrameAck, Ack: &protocol.Ack{
		Version:   c.ackVersion,
		CarrierID: "fake",
		Hostnames: frame.Hello.Hostnames,
	}}); err != nil {
		conn.Close() //nolint:errcheck // test carrier cleanup after rejected handshake.
		return
	}
	session, err := yamux.Server(conn, nil)
	if err != nil {
		conn.Close() //nolint:errcheck // test carrier cleanup after yamux setup failure.
		return
	}
	c.mu.Lock()
	c.tokens = append(c.tokens, append([]byte(nil), frame.Hello.Token...))
	c.hellos = append(c.hellos, *frame.Hello)
	c.sessions = append(c.sessions, session)
	c.accepted++
	c.mu.Unlock()
}

func (c *fakeCarrier) latestSession(t *testing.T) *yamux.Session {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		n := len(c.sessions)
		if n > 0 {
			s := c.sessions[n-1]
			c.mu.Unlock()
			return s
		}
		c.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no carrier session established")
	return nil
}

func (c *fakeCarrier) acceptedCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.accepted
}

func (c *fakeCarrier) waitAcceptedCount(t *testing.T, want int) {
	t.Helper()
	c.waitAcceptedCountWithin(t, want, 3*time.Second)
}

func (c *fakeCarrier) waitAcceptedCountWithin(t *testing.T, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c.acceptedCount() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("carrier accepted %d connections, want at least %d", c.acceptedCount(), want)
}

func (c *fakeCarrier) closeSessions() {
	c.mu.Lock()
	sessions := append([]*yamux.Session(nil), c.sessions...)
	c.mu.Unlock()
	for _, session := range sessions {
		_ = session.Close()
	}
}

func (c *fakeCarrier) latestToken(t *testing.T) []byte {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		n := len(c.tokens)
		if n > 0 {
			token := append([]byte(nil), c.tokens[n-1]...)
			c.mu.Unlock()
			return token
		}
		c.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no carrier token observed")
	return nil
}

func (c *fakeCarrier) hellosBySurface(surface string) []protocol.Hello {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []protocol.Hello
	for _, h := range c.hellos {
		got, err := protocol.HelloSurface(&h)
		if err == nil && got == surface {
			out = append(out, h)
		}
	}
	return out
}

func (c *fakeCarrier) close() { _ = c.ln.Close() }

type backendEcho struct {
	ln net.Listener
}

type backendBlocker struct {
	ln      net.Listener
	release chan struct{}

	mu       sync.Mutex
	accepted int
	first    chan struct{}
}

func TestClientUsesTokenProviderForCarrierHello(t *testing.T) {
	carrier := newFakeCarrier(t)
	defer carrier.close()
	backend := newBackendEcho(t)
	defer backend.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, err := Start(ctx, Config{
		RelayAddr:   carrier.addr(),
		BackendAddr: backend.addr(),
		Token:       []byte("static-token"),
		TokenProvider: func(context.Context) ([]byte, error) {
			return []byte("cloud-minted-token"), nil
		},
		Hostnames: []string{"home.relay.test"},
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		BackoffMin: 5 * time.Millisecond,
		BackoffMax: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("start client: %v", err)
	}
	defer client.Close()
	if err := client.WaitReady(ctx); err != nil {
		t.Fatalf("wait ready: %v", err)
	}
	if got := string(carrier.latestToken(t)); got != "cloud-minted-token" {
		t.Fatalf("hello token = %q, want cloud-minted-token", got)
	}
}

func TestTokenExpiryTakeoverRotatesCarrierAtHalfTTL(t *testing.T) {
	carrier := newFakeCarrier(t)
	defer carrier.close()
	backend := newBackendEcho(t)
	defer backend.close()

	const ttl = time.Second
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, err := Start(ctx, Config{
		RelayAddr:   carrier.addr(),
		BackendAddr: backend.addr(),
		TokenProvider: func(context.Context) ([]byte, error) {
			return []byte{byte(calls.Add(1))}, nil
		},
		TokenRotationInterval: ttl / 2,
		Hostnames:             []string{"home.relay.test"},
		TLSConfig:             &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
		BackoffMin:            5 * time.Millisecond,
		BackoffMax:            10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("start client: %v", err)
	}
	if err := client.WaitReady(ctx); err != nil {
		t.Fatalf("wait ready: %v", err)
	}
	carrier.waitAcceptedCount(t, 2)

	carrier.mu.Lock()
	first := carrier.sessions[0]
	tokens := append([][]byte(nil), carrier.tokens...)
	carrier.mu.Unlock()
	if first.IsClosed() {
		t.Fatal("first carrier was closed during proactive takeover")
	}
	if len(tokens) < 2 || bytes.Equal(tokens[0], tokens[1]) {
		t.Fatalf("carrier tokens were not refreshed: %v", tokens)
	}

	client.Close()
	client.Wait()
}

func TestClientStartsDedicatedCacheCarrier(t *testing.T) {
	carrier := newFakeCarrier(t)
	defer carrier.close()
	backend := newBackendEcho(t)
	defer backend.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, err := Start(ctx, Config{
		RelayAddr:   carrier.addr(),
		BackendAddr: backend.addr(),
		Token:       []byte("passthrough-token"),
		Hostnames:   []string{"home.relay.test"},
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		BackoffMin:           5 * time.Millisecond,
		BackoffMax:           10 * time.Millisecond,
		CacheCarrier:         true,
		CacheToken:           []byte("cache-token"),
		CacheVerificationKey: testCacheVerificationKey(1),
	})
	if err != nil {
		t.Fatalf("start client: %v", err)
	}
	defer client.Close()
	if err := client.WaitReady(ctx); err != nil {
		t.Fatalf("wait ready: %v", err)
	}
	carrier.waitAcceptedCount(t, 2)

	pass := carrier.hellosBySurface(protocol.SurfacePassthrough)
	if len(pass) != 1 {
		t.Fatalf("passthrough hellos = %d, want 1", len(pass))
	}
	if string(pass[0].Token) != "passthrough-token" {
		t.Fatalf("passthrough token = %q", pass[0].Token)
	}
	cache := carrier.hellosBySurface(protocol.SurfaceCache)
	if len(cache) != 1 {
		t.Fatalf("cache hellos = %d, want 1", len(cache))
	}
	if string(cache[0].Token) != "cache-token" {
		t.Fatalf("cache token = %q", cache[0].Token)
	}
}

func TestClientRotatesCacheVerificationKeyOnReconnect(t *testing.T) {
	carrier := newFakeCarrier(t)
	defer carrier.close()
	backend := newBackendEcho(t)
	defer backend.close()

	keys := [][]byte{testCacheVerificationKey(1), testCacheVerificationKey(2)}
	var calls int
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, err := Start(ctx, Config{
		RelayAddr:   carrier.addr(),
		BackendAddr: backend.addr(),
		Token:       []byte("passthrough-token"),
		Hostnames:   []string{"home.relay.test"},
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		BackoffMin:   5 * time.Millisecond,
		BackoffMax:   10 * time.Millisecond,
		CacheCarrier: true,
		CacheToken:   []byte("cache-token"),
		CacheVerificationKeyProvider: func(context.Context) ([]byte, error) {
			if calls >= len(keys) {
				return keys[len(keys)-1], nil
			}
			key := keys[calls]
			calls++
			return key, nil
		},
	})
	if err != nil {
		t.Fatalf("start client: %v", err)
	}
	defer client.Close()
	if err := client.WaitReady(ctx); err != nil {
		t.Fatalf("wait ready: %v", err)
	}
	carrier.waitAcceptedCount(t, 2)
	carrier.closeSessions()
	carrier.waitAcceptedCount(t, 4)

	cache := carrier.hellosBySurface(protocol.SurfaceCache)
	if len(cache) < 2 {
		t.Fatalf("cache hellos = %d, want at least 2", len(cache))
	}
	if !bytes.Equal(cache[0].CacheVerificationKey, keys[0]) {
		t.Fatal("first cache hello did not use initial verification key")
	}
	if !bytes.Equal(cache[len(cache)-1].CacheVerificationKey, keys[1]) {
		t.Fatal("reconnected cache hello did not rotate verification key")
	}
}

func testCacheVerificationKey(offset byte) []byte {
	key := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	for i := range key {
		key[i] += offset
	}
	return key
}

func TestClientTokenProviderFailureDoesNotDialCarrier(t *testing.T) {
	carrier := newFakeCarrier(t)
	defer carrier.close()
	backend := newBackendEcho(t)
	defer backend.close()

	ctx, cancel := context.WithCancel(context.Background())
	client, err := Start(ctx, Config{
		RelayAddr:   carrier.addr(),
		BackendAddr: backend.addr(),
		TokenProvider: func(context.Context) ([]byte, error) {
			return nil, errors.New("cloud token unavailable")
		},
		Hostnames: []string{"home.relay.test"},
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		BackoffMin: 5 * time.Millisecond,
		BackoffMax: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("start client: %v", err)
	}
	time.Sleep(25 * time.Millisecond)
	cancel()
	client.Wait()
	if got := carrier.acceptedCount(); got != 0 {
		t.Fatalf("carrier accepted %d connections, want 0", got)
	}
}

func TestClientAcceptsAckVersionMismatch(t *testing.T) {
	carrier := newFakeCarrier(t)
	carrier.ackVersion = protocol.Version + 999
	defer carrier.close()
	backend := newBackendEcho(t)
	defer backend.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := startTestClient(t, ctx, carrier.addr(), backend.addr())
	defer client.Close()
	if err := client.WaitReady(ctx); err != nil {
		t.Fatalf("client not ready after ack version mismatch: %v", err)
	}
}

func TestClientReportsRelayErrorFrame(t *testing.T) {
	carrier := newFakeCarrier(t)
	carrier.rejectError = "unauthorized"
	defer carrier.close()

	client := &Client{cfg: Config{
		RelayAddr:   carrier.addr(),
		BackendAddr: "127.0.0.1:1",
		Token:       []byte("test-token"),
		Hostnames:   []string{"home.relay.test"},
		TLSConfig:   &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
	}}
	_, err := client.serveOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("serveOnce err = %v, want relay error detail", err)
	}
}

func newBackendEcho(t *testing.T) *backendEcho {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	b := &backendEcho{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close() //nolint:errcheck // test backend cleanup.
				_, _ = io.Copy(conn, conn)
			}(conn)
		}
	}()
	return b
}

func (b *backendEcho) addr() string { return b.ln.Addr().String() }
func (b *backendEcho) close()       { _ = b.ln.Close() }

func newBackendBlocker(t *testing.T) *backendBlocker {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	b := &backendBlocker{ln: ln, release: make(chan struct{}), first: make(chan struct{})}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		b.mu.Lock()
		b.accepted++
		b.mu.Unlock()
		if _, err := conn.Read(make([]byte, 1)); err != nil {
			return
		}
		close(b.first)
		<-b.release
		conn.Close() //nolint:errcheck // test backend cleanup.
	}()
	return b
}

func (b *backendBlocker) addr() string { return b.ln.Addr().String() }
func (b *backendBlocker) acceptedCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.accepted
}
func (b *backendBlocker) close() {
	close(b.release)
	_ = b.ln.Close()
}

type backendHalfCloser struct {
	ln       net.Listener
	response []byte
	gap      time.Duration
	uploaded chan []byte
}

func newBackendHalfCloser(t *testing.T, response []byte, gap time.Duration) *backendHalfCloser {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	b := &backendHalfCloser{ln: ln, response: response, gap: gap, uploaded: make(chan []byte, 1)}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck // test backend cleanup.
		if _, err := conn.Write(b.response); err != nil {
			return
		}
		if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
			return
		}
		time.Sleep(b.gap)
		got, _ := io.ReadAll(conn)
		b.uploaded <- got
	}()
	return b
}

func (b *backendHalfCloser) addr() string { return b.ln.Addr().String() }
func (b *backendHalfCloser) close()       { _ = b.ln.Close() }

func startTestClient(t *testing.T, ctx context.Context, relayAddr, backendAddr string) *Client {
	t.Helper()
	client, err := Start(ctx, Config{
		RelayAddr:   relayAddr,
		BackendAddr: backendAddr,
		Token:       []byte("test-token"),
		Hostnames:   []string{"home.relay.test"},
		TLSConfig:   &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
		BackoffMin:  10 * time.Millisecond,
		BackoffMax:  50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("start tunnel client: %v", err)
	}
	return client
}

func roundTrip(t *testing.T, session *yamux.Session, msg string) {
	t.Helper()
	stream, err := session.Open()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer stream.Close() //nolint:errcheck // test stream cleanup.
	if _, err := stream.Write([]byte(msg + "\n")); err != nil {
		t.Fatalf("write stream: %v", err)
	}
	line, err := bufio.NewReader(stream).ReadString('\n')
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if line != msg+"\n" {
		t.Fatalf("echo = %q, want %q", line, msg+"\n")
	}
}

func TestClientServesStreamToBackend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	carrier := newFakeCarrier(t)
	defer carrier.close()
	backend := newBackendEcho(t)
	defer backend.close()

	client := startTestClient(t, ctx, carrier.addr(), backend.addr())
	defer client.Close()

	if err := client.WaitReady(ctx); err != nil {
		t.Fatalf("client not ready: %v", err)
	}
	roundTrip(t, carrier.latestSession(t), "hello")
}

func TestClientRejectsStreamsOverCap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	carrier := newFakeCarrier(t)
	defer carrier.close()
	backend := newBackendBlocker(t)
	defer backend.close()

	client, err := Start(ctx, Config{
		RelayAddr:   carrier.addr(),
		BackendAddr: backend.addr(),
		Token:       []byte("test-token"),
		Hostnames:   []string{"home.relay.test"},
		TLSConfig:   &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
		BackoffMin:  10 * time.Millisecond,
		BackoffMax:  50 * time.Millisecond,
		MaxStreams:  1,
	})
	if err != nil {
		t.Fatalf("start tunnel client: %v", err)
	}
	defer client.Close()
	if err := client.WaitReady(ctx); err != nil {
		t.Fatalf("client not ready: %v", err)
	}

	session := carrier.latestSession(t)
	first, err := session.Open()
	if err != nil {
		t.Fatalf("open first stream: %v", err)
	}
	defer first.Close() //nolint:errcheck // test connection cleanup.
	if _, err := first.Write([]byte("hold")); err != nil {
		t.Fatalf("write first stream: %v", err)
	}
	select {
	case <-backend.first:
	case <-time.After(2 * time.Second):
		t.Fatal("backend did not receive first stream")
	}

	second, err := session.Open()
	if err != nil {
		t.Fatalf("open second stream: %v", err)
	}
	defer second.Close() //nolint:errcheck // test connection cleanup.
	_ = second.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := second.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("second stream read err = %v, want closed stream before deadline", err)
	}
	if got := backend.acceptedCount(); got != 1 {
		t.Fatalf("backend accepted %d connections, want 1", got)
	}
}

func TestJitterStaysWithinBounds(t *testing.T) {
	d := 10 * time.Second
	for range 1000 {
		j := jitter(d)
		if j < 0 {
			t.Fatalf("jitter produced negative delay: %v", j)
		}
		// ±20% bound.
		if j < d-d/5 || j > d+d/5 {
			t.Fatalf("jitter %v out of ±20%% bounds around %v", j, d)
		}
	}
	if jitter(0) != 0 {
		t.Fatal("jitter(0) must be 0")
	}
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "carrier.local"},
		DNSNames:     []string{"carrier.local"},
		IPAddresses:  []net.IP{net.ParseIP("::1")},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}
	return cert
}
