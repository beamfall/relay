package relay_test

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/beamfall/relay/internal/protocol"
	"github.com/beamfall/relay/internal/relay"
	"github.com/beamfall/relay/internal/tunnel"
)

// dialCarrier opens a raw TLS connection to the relay's carrier listener. The
// carrier cert is the throwaway self-signed cert minted by startRelay, so the
// test skips verification (the tunnel client tests do the same).
func dialCarrier(t *testing.T, addr string) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("dial carrier TLS: %v", err)
	}
	return conn
}

// TestCarrierHandshakeRejectsBadVersion asserts the server rejects a hello whose
// protocol version does not match, responding with an "invalid hello" error
// frame and bumping the handshake-failure metric.
func TestCarrierHandshakeRejectsBadVersion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	node := startRelay(t, ctx, relay.Config{
		AdminAddr: "127.0.0.1:0",
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
	})
	defer node.Close()

	conn := dialCarrier(t, node.CarrierAddr())
	defer conn.Close() //nolint:errcheck // test connection cleanup.

	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.FrameHello, Hello: &protocol.Hello{
		Version:   protocol.Version + 999, // wrong version
		Token:     []byte("test-token"),
		Hostnames: []string{testHost},
	}}); err != nil {
		t.Fatalf("write hello: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	frame, err := protocol.ReadFrame(conn)
	if err != nil {
		t.Fatalf("read reject frame: %v", err)
	}
	if frame.Type != protocol.FrameError || frame.Error != "invalid hello" {
		t.Fatalf("reject frame = %+v, want error 'invalid hello'", frame)
	}
	assertHandshakeFailures(t, node.AdminAddr(), 1)
}

// TestCarrierHandshakeRejectsNonHello asserts a first frame that is not a hello
// (here, an ack) is rejected as an invalid hello.
func TestCarrierHandshakeRejectsNonHello(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	node := startRelay(t, ctx, relay.Config{
		AdminAddr: "127.0.0.1:0",
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
	})
	defer node.Close()

	conn := dialCarrier(t, node.CarrierAddr())
	defer conn.Close() //nolint:errcheck // test connection cleanup.

	// A well-formed frame of the wrong type: Hello is nil, so the server's
	// hello-shape check rejects it.
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.FrameAck, Ack: &protocol.Ack{
		Version:   protocol.Version,
		CarrierID: "spoof",
	}}); err != nil {
		t.Fatalf("write non-hello frame: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	frame, err := protocol.ReadFrame(conn)
	if err != nil {
		t.Fatalf("read reject frame: %v", err)
	}
	if frame.Type != protocol.FrameError || frame.Error != "invalid hello" {
		t.Fatalf("reject frame = %+v, want error 'invalid hello'", frame)
	}
	assertHandshakeFailures(t, node.AdminAddr(), 1)
}

// TestCarrierHandshakeRejectsUnauthorized asserts a hello with the wrong token is
// rejected with an "unauthorized" error frame.
func TestCarrierHandshakeRejectsUnauthorized(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	node := startRelay(t, ctx, relay.Config{
		AdminAddr: "127.0.0.1:0",
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
	})
	defer node.Close()

	conn := dialCarrier(t, node.CarrierAddr())
	defer conn.Close() //nolint:errcheck // test connection cleanup.

	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.FrameHello, Hello: &protocol.Hello{
		Version:   protocol.Version,
		Token:     []byte("WRONG-TOKEN"),
		Hostnames: []string{testHost},
	}}); err != nil {
		t.Fatalf("write hello: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	frame, err := protocol.ReadFrame(conn)
	if err != nil {
		t.Fatalf("read reject frame: %v", err)
	}
	if frame.Type != protocol.FrameError || frame.Error != "unauthorized" {
		t.Fatalf("reject frame = %+v, want error 'unauthorized'", frame)
	}
	assertHandshakeFailures(t, node.AdminAddr(), 1)
}

// TestCarrierHandshakeDeadlineReapsSilentConn asserts a carrier that connects and
// sends nothing is reaped at the handshake deadline rather than holding a
// goroutine indefinitely.
func TestCarrierHandshakeDeadlineReapsSilentConn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	node := startRelay(t, ctx, relay.Config{
		AdminAddr: "127.0.0.1:0",
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		CarrierHandshakeTimeout: 150 * time.Millisecond,
	})
	defer node.Close()

	conn := dialCarrier(t, node.CarrierAddr())
	defer conn.Close() //nolint:errcheck // test connection cleanup.

	// Send nothing. The server should hit its read deadline and close the conn.
	// A read here should return (EOF/closed) well before a generous fallback.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	start := time.Now()
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected silent carrier connection to be reaped, got data")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("silent carrier conn not reaped promptly: waited %v", elapsed)
	}
}

// TestQUICCarrierHandshakeDeadlineReapsSlowlorisStream is the QUIC counterpart
// to TestCarrierHandshakeDeadlineReapsSilentConn: a QUIC peer that opens the
// handshake stream (so AcceptStream's own hsCtx deadline is already satisfied)
// but then sends only a partial frame must still be reaped within
// carrierHandshakeT, and its carrier slot must be released afterward -- not
// just the stream's own AcceptStream wait. This pins the read-deadline fix on
// hsStream (relay.go handleQUICCarrierConn), which mirrors the TCP path's
// SetReadDeadline on the raw conn.
func TestQUICCarrierHandshakeDeadlineReapsSlowlorisStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const handshakeTimeout = 150 * time.Millisecond

	node := startRelay(t, ctx, relay.Config{
		AdminAddr: "127.0.0.1:0",
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		CarrierHandshakeTimeout: handshakeTimeout,
		MaxCarrierConns:         1,
	})
	defer node.Close()

	conn := dialQUICCarrier(t, ctx, node.QUICAddr())
	defer conn.CloseWithError(0, "") //nolint:errcheck // test connection cleanup.

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open quic handshake stream: %v", err)
	}
	defer stream.Close() //nolint:errcheck // test stream cleanup.

	// Open the stream (satisfying AcceptStream's hsCtx deadline) but send only a
	// partial frame -- fewer bytes than the frame length prefix declares -- so
	// the server blocks on the frame body read, not the stream accept.
	if _, err := stream.Write([]byte{0x00, 0x00, 0x00}); err != nil {
		t.Fatalf("write partial frame: %v", err)
	}

	// The server must reap the stalled read within a generous multiple of the
	// handshake timeout, well before any fallback default.
	_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	start := time.Now()
	if _, err := stream.Read(buf); err == nil {
		t.Fatal("expected slowloris QUIC handshake stream to be reaped, got data")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("slowloris QUIC handshake stream not reaped promptly: waited %v", elapsed)
	}

	// The carrier slot (cap=1) must be released, not held by the reaped
	// connection: a fresh carrier can now complete its handshake.
	client := startTunnelClientTransport(t, ctx, tunnel.TransportQUIC, node.QUICAddr(), "127.0.0.1:1", []byte("test-token"), []string{testHost})
	defer client.Close()
}

// dialQUICCarrier opens a raw QUIC connection to the relay's QUIC carrier
// listener, mirroring dialCarrier for the TCP path. The carrier cert is the
// throwaway self-signed cert minted by startRelay, so the test skips
// verification (the tunnel client tests do the same).
func dialQUICCarrier(t *testing.T, ctx context.Context, addr string) *quic.Conn {
	t.Helper()
	conn, err := quic.DialAddr(ctx, addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"beamfall-relay-carrier/1"},
	}, protocol.QUICConfig())
	if err != nil {
		t.Fatalf("dial quic carrier: %v", err)
	}
	return conn
}

// TestCarrierSessionSurvivesPastHandshakeDeadline pins the post-hello deadline
// clear (relay.go: SetReadDeadline(time.Time{}) after the hello frame). The
// handshake deadline must bound only the pre-hello window; once a carrier has
// completed its hello, an idle-but-healthy long-lived yamux session must NOT be
// reaped when it stays quiet past CarrierHandshakeTimeout -- this is exactly the
// paused-player / websocket / long-poll case. A regression that forgot to clear
// the deadline (or cleared it wrong) would reap the session here.
//
// With a short handshake timeout, we establish a real carrier + a relayed
// stream, idle well past the timeout with zero traffic, then assert a fresh
// round-trip still relays through the still-live session.
func TestCarrierSessionSurvivesPastHandshakeDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const handshakeTimeout = 150 * time.Millisecond

	home := startHomeTLSEcho(t, testHost)
	defer home.Close()
	node := startRelay(t, ctx, relay.Config{
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		StreamCap:               8,
		CarrierHandshakeTimeout: handshakeTimeout,
	})
	defer node.Close()

	client := startTunnelClient(t, ctx, node.CarrierAddr(), home.Addr(), []byte("test-token"), []string{testHost})
	defer client.Close()

	conn := dialPublicTLS(t, node.PublicAddr(), testHost, home.Roots)
	defer conn.Close() //nolint:errcheck // test connection cleanup.

	// Idle the carrier session far past the handshake timeout with no traffic.
	// If the post-hello deadline clear regressed, the server would reap the
	// session during this sleep and the round-trip below would fail.
	time.Sleep(4 * handshakeTimeout)

	if _, err := conn.Write([]byte("still-alive\n")); err != nil {
		t.Fatalf("write after idle: %v", err)
	}
	line, err := readLine(conn)
	if err != nil {
		t.Fatalf("read echo after idling past handshake deadline: %v", err)
	}
	if line != "echo:still-alive\n" {
		t.Fatalf("echo after idle = %q, want %q (idle session was reaped?)", line, "echo:still-alive\n")
	}
}

// TestPublicAcceptBoundClosesOverCapConnections asserts a flood of public
// connections beyond MaxPublicConns is accept-and-closed (not queued into
// unbounded goroutines), and the over-cap metric reflects the refusals. Cap=1
// with no carrier registered means the single slot is held just long enough for
// SNI peek; we drive a burst and assert at least one over-cap close is recorded.
func TestPublicAcceptBoundClosesOverCapConnections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	node := startRelay(t, ctx, relay.Config{
		AdminAddr: "127.0.0.1:0",
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		MaxPublicConns: 1,
	})
	defer node.Close()

	// Open a burst of raw TCP connections that occupy slots while their handler
	// blocks in the SNI peek (we never send a ClientHello). With cap=1, only
	// one can hold the slot; the rest must be over-cap closed.
	const burst = 40
	var conns []net.Conn
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range burst {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("tcp", node.PublicAddr())
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}()
	}
	wg.Wait()
	defer func() {
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	}()

	// The over-cap closes are recorded as the accept loop processes the backlog.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		body := getMetrics(t, node.AdminAddr())
		if v := metricValue(t, body, "beamfall_relay_public_over_cap_total"); v >= 1 {
			return // at least one connection was refused over the cap
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected over-cap refusals, metrics:\n%s", getMetrics(t, node.AdminAddr()))
}

// TestPublicPerIPCapClosesOverCapConnections (SECREV-RELAY-9) asserts a
// partial-record flood from a single source — TCP-connect then never send a
// ClientHello — is bounded by MaxPublicConnsPerIP so it cannot pin the whole
// public slot pool. With a per-IP cap of 2 and a global cap far above the
// burst, the flood from one loopback source is capped at 2 in-flight and the
// rest are recorded as per-IP over-cap refusals.
func TestPublicPerIPCapClosesOverCapConnections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	node := startRelay(t, ctx, relay.Config{
		AdminAddr: "127.0.0.1:0",
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		MaxPublicConns:      1000, // global pool far above the burst
		MaxPublicConnsPerIP: 2,    // the control under test
	})
	defer node.Close()

	const burst = 40
	var conns []net.Conn
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range burst {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("tcp", node.PublicAddr())
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}()
	}
	wg.Wait()
	defer func() {
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	}()

	// All connections share one loopback source IP, so only MaxPublicConnsPerIP
	// (2) may be in flight; the remaining ~38 are per-IP over-cap refusals.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		body := getMetrics(t, node.AdminAddr())
		if v := metricValue(t, body, "beamfall_relay_public_per_ip_over_cap_total"); v >= 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected per-IP over-cap refusals, metrics:\n%s", getMetrics(t, node.AdminAddr()))
}

// TestGracefulShutdownDrainsInFlightStream asserts that with a grace window an
// in-flight relayed stream completes after the shutdown signal, while no new
// public connection is accepted post-signal.
func TestGracefulShutdownDrainsInFlightStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	home := startHomeTLSEcho(t, testHost)
	defer home.Close()
	node := startRelay(t, ctx, relay.Config{
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		StreamCap: 8,
	})

	client := startTunnelClient(t, ctx, node.CarrierAddr(), home.Addr(), []byte("test-token"), []string{testHost})
	defer client.Close()

	// Establishing the TLS connection opens the relayed stream end-to-end (the
	// SNI peek + carrier stream open complete during the handshake), so the
	// stream is counted in the drain set before we trigger shutdown. The home
	// echo server replies once per stream, so we save that single round-trip for
	// the during-grace assertion.
	conn := dialPublicTLS(t, node.PublicAddr(), testHost, home.Roots)
	defer conn.Close() //nolint:errcheck // test connection cleanup.

	publicAddr := node.PublicAddr()

	// Shutdown with a generous grace; the in-flight stream must survive it.
	done := make(chan struct{})
	go func() {
		node.Shutdown(2 * time.Second)
		close(done)
	}()

	// Give the public listener a moment to close, then assert no new accept.
	time.Sleep(100 * time.Millisecond)
	if c, err := net.DialTimeout("tcp", publicAddr, 300*time.Millisecond); err == nil {
		_ = c.Close()
		t.Fatal("public listener still accepting after shutdown signal")
	}

	// The pre-existing stream must still relay its one round-trip within grace.
	if _, err := conn.Write([]byte("still-here\n")); err != nil {
		t.Fatalf("in-flight stream broken during grace: %v", err)
	}
	if line, err := readLine(conn); err != nil {
		t.Fatalf("read echo during grace: %v", err)
	} else if line != "echo:still-here\n" {
		t.Fatalf("echo during grace = %q", line)
	}

	_ = conn.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown did not return after stream drained")
	}
}

// TestGracefulShutdownForceClosesOverGrace asserts a stream that outlives the
// grace window is force-closed and Shutdown returns near the grace boundary
// rather than blocking on the stuck stream.
func TestGracefulShutdownForceClosesOverGrace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	home := startHomeTLSEcho(t, testHost)
	defer home.Close()
	node := startRelay(t, ctx, relay.Config{
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		StreamCap: 8,
	})

	client := startTunnelClient(t, ctx, node.CarrierAddr(), home.Addr(), []byte("test-token"), []string{testHost})
	defer client.Close()

	// Establish a stream and keep it open without closing it.
	conn := dialPublicTLS(t, node.PublicAddr(), testHost, home.Roots)
	defer conn.Close() //nolint:errcheck // test connection cleanup.
	if _, err := conn.Write([]byte("hold\n")); err != nil {
		t.Fatalf("write to establish stream: %v", err)
	}
	if _, err := readLine(conn); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	// Short grace; the held-open stream exceeds it and must be force-closed.
	const grace = 200 * time.Millisecond
	start := time.Now()
	done := make(chan struct{})
	go func() {
		node.Shutdown(grace)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown blocked past grace on a stuck stream")
	}
	if elapsed := time.Since(start); elapsed < grace {
		t.Fatalf("Shutdown returned before grace elapsed: %v < %v", elapsed, grace)
	}

	// After force-close the carrier session is gone; the held stream must break.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected held stream to be force-closed after grace")
	}
}

func assertHandshakeFailures(t *testing.T, adminAddr string, want int) {
	t.Helper()
	// The metric is incremented before the reject frame is written, but to avoid
	// a write/scrape race we poll briefly.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		body := getMetrics(t, adminAddr)
		if metricValue(t, body, "beamfall_relay_handshake_failures_total") >= int64(want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("handshake failures < %d, metrics:\n%s", want, getMetrics(t, adminAddr))
}

// metricValue extracts the integer value of a single-line gauge/counter from a
// Prometheus text body. Returns -1 if not found.
func metricValue(t *testing.T, body, name string) int64 {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, name+" ") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				continue
			}
			var v int64
			for _, r := range fields[1] {
				if r < '0' || r > '9' {
					t.Fatalf("non-numeric metric value %q for %s", fields[1], name)
				}
				v = v*10 + int64(r-'0')
			}
			return v
		}
	}
	return -1
}

// readLine reads a single newline-terminated line from conn with a deadline.
func readLine(conn net.Conn) (string, error) {
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b []byte
	buf := make([]byte, 1)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			b = append(b, buf[0])
			if buf[0] == '\n' {
				return string(b), nil
			}
		}
		if err != nil {
			return string(b), err
		}
	}
}
