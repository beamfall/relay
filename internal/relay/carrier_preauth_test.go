package relay

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beamfall/relay/internal/protocol"
)

// attackerSource is the documentation-range address the remapping listener
// reports for connections the test marks as coming from the attacker.
const attackerSource = "198.51.100.7"

// remapListener reports a fixed attacker source address for connections
// accepted while attacker mode is on, so one loopback test can present two
// distinct sources to the relay's per-source accounting. Classifying at accept
// time (rather than by client port after Dial returns) cannot race the relay's
// accept loop.
type remapListener struct {
	net.Listener
	attackerMode atomic.Bool
	accepted     atomic.Int64
}

func (l *remapListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	isAttacker := l.attackerMode.Load()
	l.accepted.Add(1)
	if !isAttacker {
		return conn, nil
	}
	port := 0
	if remote, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		port = remote.Port
	}
	return remappedConn{Conn: conn, remote: &net.TCPAddr{IP: net.ParseIP(attackerSource), Port: port}}, nil
}

type remappedConn struct {
	net.Conn
	remote net.Addr
}

func (c remappedConn) RemoteAddr() net.Addr { return c.remote }

func startPreAuthTestRelay(t *testing.T, ctx context.Context, cfg Config) (*Server, *remapListener) {
	t.Helper()
	var remap *remapListener
	cfg.PublicAddr = "127.0.0.1:0"
	cfg.CarrierAddr = "127.0.0.1:0"
	cfg.CarrierTLSConfig = &tls.Config{
		Certificates: []tls.Certificate{backoffTestCert(t)},
		MinVersion:   tls.VersionTLS13,
	}
	cfg.TokenVerifier = StaticTokenVerifier{
		Token:     []byte("the-real-token"),
		CarrierID: "carrier-1",
		Hostnames: []string{"home.relay.test"},
	}
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg.listenCarrier = func(network, address string) (net.Listener, error) {
		ln, err := net.Listen(network, address)
		if err != nil {
			return nil, err
		}
		remap = &remapListener{Listener: ln}
		return remap, nil
	}
	s, err := Start(ctx, cfg)
	if err != nil {
		t.Fatalf("start relay: %v", err)
	}
	t.Cleanup(s.Close)
	return s, remap
}

// dialIdleAttackers opens n raw TCP connections that never send a byte, each
// reported to the relay as coming from attackerSource, and waits until the
// relay's accept loop has taken all of them.
func dialIdleAttackers(t *testing.T, remap *remapListener, n int) {
	t.Helper()
	start := remap.accepted.Load()
	remap.attackerMode.Store(true)
	for i := 0; i < n; i++ {
		raw, err := net.Dial("tcp", remap.Addr().String())
		if err != nil {
			t.Fatalf("dial attacker %d: %v", i, err)
		}
		t.Cleanup(func() { _ = raw.Close() })
	}
	waitFor(t, func() bool { return remap.accepted.Load()-start >= int64(n) }, "relay to accept every attacker connection")
	remap.attackerMode.Store(false)
	// Let the per-connection goroutines reach their admission and slot
	// decisions; the valid carrier below is then judged against the settled
	// budgets rather than racing the attackers' goroutines.
	time.Sleep(200 * time.Millisecond)
}

// handshakeValidCarrier dials the carrier listener from the loopback source,
// sends a valid Hello and returns the relay's reply frame.
func handshakeValidCarrier(t *testing.T, addr string) (protocol.Frame, error) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test relay uses a throwaway self-signed cert.
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		return protocol.Frame{}, err
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.FrameHello, Hello: &protocol.Hello{
		Version:   protocol.Version,
		Token:     []byte("the-real-token"),
		Hostnames: []string{"home.relay.test"},
	}}); err != nil {
		return protocol.Frame{}, err
	}
	return protocol.ReadFrame(conn)
}

// TestIdleConnectionsFromOneSourceCannotBlockValidCarrier (CORE-1385): idle
// pre-auth connections from one source used to take every carrier slot for
// the whole handshake timeout, so a valid carrier from another source was
// closed on accept. Pre-auth admissions are now capped per source and kept
// apart from the authenticated-carrier budget, so the valid carrier connects.
func TestIdleConnectionsFromOneSourceCannotBlockValidCarrier(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const maxCarriers = 4
	s, remap := startPreAuthTestRelay(t, ctx, Config{
		MaxCarrierConns:         maxCarriers,
		CarrierHandshakeTimeout: 30 * time.Second,
	})

	dialIdleAttackers(t, remap, 4*maxCarriers)

	frame, err := handshakeValidCarrier(t, s.CarrierAddr())
	if err != nil {
		t.Fatalf("valid carrier handshake failed while one source held idle connections: %v", err)
	}
	if frame.Type != protocol.FrameAck {
		t.Fatalf("valid carrier reply = %+v, want ack", frame)
	}
}

// TestAuthenticatedCarriersDoNotSharePreAuthBudget (CORE-1385): a full pre-auth
// budget held by idle connections (from many sources) must not refuse a carrier
// that is already authenticated, and authenticated carriers must not consume
// the pre-auth budget.
func TestAuthenticatedCarriersDoNotSharePreAuthBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s, _ := startPreAuthTestRelay(t, ctx, Config{
		MaxCarrierConns:         2,
		MaxPendingCarrierConns:  2,
		CarrierHandshakeTimeout: 30 * time.Second,
	})

	frame, err := handshakeValidCarrier(t, s.CarrierAddr())
	if err != nil || frame.Type != protocol.FrameAck {
		t.Fatalf("first carrier = %+v, %v; want ack", frame, err)
	}
	waitFor(t, func() bool { return len(s.carrierSlots) == 1 && len(s.carrierAdmissions) == 0 },
		"authenticated carrier to move from the pre-auth budget to a carrier slot")
}

// TestHandshakeTimeoutFeedsThrottle (CORE-1385): a connection that idles
// through the handshake timeout, or sends a malformed hello, now counts as a
// failed handshake for its source.
func TestHandshakeTimeoutFeedsThrottle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s, remap := startPreAuthTestRelay(t, ctx, Config{
		CarrierHandshakeTimeout: 100 * time.Millisecond,
	})
	src := &net.TCPAddr{IP: net.ParseIP(attackerSource)}

	dialIdleAttackers(t, remap, 2)
	waitFor(t, func() bool { return s.handshakeThrottle.FailureCount(src) == 2 },
		"two handshake timeouts to count against the source")

	raw, err := tls.Dial("tcp", s.CarrierAddr(), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test relay uses a throwaway self-signed cert.
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close() //nolint:errcheck // test connection cleanup.
	if err := protocol.WriteFrame(raw, protocol.Frame{Type: protocol.FrameHello, Hello: &protocol.Hello{Version: protocol.Version + 99}}); err != nil {
		t.Fatalf("write bad hello: %v", err)
	}
	loopback := &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}
	waitFor(t, func() bool { return s.handshakeThrottle.FailureCount(loopback) == 1 },
		"a malformed hello to count against the source")
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
