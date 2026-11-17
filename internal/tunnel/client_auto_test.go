package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/beamfall/relay/internal/protocol"
)

// autoHarness is a client on the automatic transport whose TLS/TCP side dials
// a real fake carrier and whose QUIC side is a test hook.
type autoHarness struct {
	client    *Client
	carrier   *fakeCarrier
	quicDials atomic.Int32
	tokens    atomic.Int32
}

func newAutoHarness(t *testing.T) *autoHarness {
	t.Helper()
	h := &autoHarness{carrier: newFakeCarrier(t)}
	t.Cleanup(h.carrier.close)
	backend := newBackendEcho(t)
	t.Cleanup(backend.close)

	client := newLifecycleClient(t, time.Second)
	client.cfg.Transport = TransportAuto
	client.cfg.RelayAddr = h.carrier.addr()
	client.cfg.BackendAddr = backend.addr()
	client.cfg.Hostnames = []string{"home.relay.test"}
	client.cfg.TLSConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}
	client.cfg.TokenProvider = func(context.Context) ([]byte, error) {
		return fmt.Appendf(nil, "token-%d", h.tokens.Add(1)), nil
	}
	client.dialQUICCarrier = func(context.Context, string) (quicCarrier, error) {
		h.quicDials.Add(1)
		return nil, errors.New("udp does not reach the relay")
	}
	h.client = client
	return h
}

func (h *autoHarness) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	startLifecycleLoop(h.client, ctx)
	t.Cleanup(func() {
		cancel()
		h.client.Close()
	})
	h.waitReady(t)
}

func (h *autoHarness) waitReady(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := h.client.WaitReady(ctx); err != nil {
		t.Fatalf("client not ready: %v", err)
	}
}

func TestAutoTransportFallsBackToTCPWithFreshToken(t *testing.T) {
	h := newAutoHarness(t)
	h.start(t)

	if got := h.quicDials.Load(); got != 1 {
		t.Fatalf("quic dials = %d, want 1", got)
	}
	// The relay refuses a replayed token, so the token it may have seen over
	// QUIC must not be the one sent over TLS/TCP.
	if got := string(h.carrier.latestToken(t)); got != "token-2" {
		t.Fatalf("TLS/TCP hello token = %q, want the token obtained after the QUIC failure (token-2)", got)
	}
	roundTrip(t, h.carrier.latestSession(t), "over-tcp-after-fallback")
}

func TestAutoTransportSkipsQUICWhileHeldOff(t *testing.T) {
	h := newAutoHarness(t)
	h.start(t)

	h.carrier.closeSessions()
	h.carrier.waitAcceptedCount(t, 2)
	if got := h.quicDials.Load(); got != 1 {
		t.Fatalf("quic dials after reconnect = %d, want 1 (held off)", got)
	}
	if got := string(h.carrier.latestToken(t)); got != "token-3" {
		t.Fatalf("reconnect token = %q, want token-3 (one token per held-off attempt)", got)
	}
}

func TestAutoTransportTriesQUICAgainAfterHoldOff(t *testing.T) {
	h := newAutoHarness(t)
	h.client.quicHoldOff = time.Millisecond
	h.start(t)

	time.Sleep(5 * time.Millisecond)
	h.carrier.closeSessions()
	h.carrier.waitAcceptedCount(t, 2)
	if got := h.quicDials.Load(); got != 2 {
		t.Fatalf("quic dials after the hold-off passed = %d, want 2", got)
	}
}

func TestAutoTransportFallsBackWhenQUICGetsNoAnswer(t *testing.T) {
	h := newAutoHarness(t)
	h.client.quicProbeBudget = 30 * time.Millisecond
	h.client.dialQUICCarrier = func(ctx context.Context, _ string) (quicCarrier, error) {
		h.quicDials.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	start := time.Now()
	h.start(t)

	// The phase timeouts are one second; only the probe budget ends the wait.
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("fallback took %v, want about the 30ms probe budget", elapsed)
	}
	roundTrip(t, h.carrier.latestSession(t), "over-tcp-after-silence")
}

// rejectingQUICCarrier answers the Hello with a relay error frame.
func rejectingQUICCarrier(t *testing.T, detail string) *lifecycleQUICCarrier {
	t.Helper()
	clientSide, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	go func() {
		if _, err := protocol.ReadFrame(peer); err != nil {
			return
		}
		_ = protocol.WriteFrame(peer, protocol.Frame{Type: protocol.FrameError, Error: detail})
	}()
	return &lifecycleQUICCarrier{stream: clientSide}
}

func TestAutoTransportDoesNotFallBackWhenRelayRefusesOverQUIC(t *testing.T) {
	h := newAutoHarness(t)
	carrier := rejectingQUICCarrier(t, "unauthorized")
	h.client.dialQUICCarrier = func(context.Context, string) (quicCarrier, error) { return carrier, nil }

	_, err := h.client.serveOnce(context.Background())
	if !errors.Is(err, errCarrierRejected) || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("serveOnce err = %v, want the relay's refusal", err)
	}
	if got := h.carrier.acceptedCount(); got != 0 {
		t.Fatalf("TLS/TCP carriers after a refusal = %d, want 0", got)
	}
	if got := h.tokens.Load(); got != 1 {
		t.Fatalf("tokens obtained = %d, want 1 (no second token for a refused carrier)", got)
	}
	if h.client.quicHeldOff() {
		t.Fatal("a relay refusal must not hold QUIC off")
	}
	assertNoLiveCarrier(t, h.client)
}

// closedByRelayStream is a handshake stream on a QUIC connection the relay
// closed before the client read an answer: quic-go drops unread stream data on
// a connection close, and an admission refusal closes with no frame at all.
type closedByRelayStream struct{}

func (closedByRelayStream) Write(p []byte) (int, error)      { return len(p), nil }
func (closedByRelayStream) SetReadDeadline(time.Time) error  { return nil }
func (closedByRelayStream) SetWriteDeadline(time.Time) error { return nil }
func (closedByRelayStream) Read([]byte) (int, error) {
	return 0, &quic.ApplicationError{Remote: true, ErrorMessage: "carrier refused"}
}

// A connection the relay closed is its answer too: UDP reached it, and the
// same registration over TLS/TCP would be refused again.
func TestAutoTransportDoesNotFallBackWhenRelayClosesTheQUICConnection(t *testing.T) {
	h := newAutoHarness(t)
	carrier := &lifecycleQUICCarrier{stream: closedByRelayStream{}}
	h.client.dialQUICCarrier = func(context.Context, string) (quicCarrier, error) { return carrier, nil }

	_, err := h.client.serveOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "carrier refused") {
		t.Fatalf("serveOnce err = %v, want the relay's connection close", err)
	}
	if got := h.carrier.acceptedCount(); got != 0 {
		t.Fatalf("TLS/TCP carriers after the relay closed QUIC = %d, want 0", got)
	}
	if h.client.quicHeldOff() {
		t.Fatal("a connection the relay closed must not hold QUIC off")
	}
	assertNoLiveCarrier(t, h.client)
}

// The hold-off records that TLS/TCP works where QUIC does not. When neither
// connects, the relay is down or the network is, and the next attempt probes
// QUIC again.
func TestAutoTransportDoesNotHoldQUICOffWhenTCPAlsoFails(t *testing.T) {
	h := newAutoHarness(t)
	h.carrier.close()

	if _, err := h.client.serveOnce(context.Background()); err == nil {
		t.Fatal("serveOnce succeeded with no carrier listening")
	}
	if h.client.quicHeldOff() {
		t.Fatal("QUIC is held off although TLS/TCP did not connect either")
	}
	if got := h.quicDials.Load(); got != 1 {
		t.Fatalf("QUIC dials = %d, want 1", got)
	}
}

func TestExplicitQUICTransportDoesNotFallBack(t *testing.T) {
	h := newAutoHarness(t)
	h.client.cfg.Transport = TransportQUIC

	if _, err := h.client.serveOnce(context.Background()); err == nil {
		t.Fatal("serveOnce succeeded, want the QUIC dial error")
	}
	if got := h.carrier.acceptedCount(); got != 0 {
		t.Fatalf("TLS/TCP carriers with transport quic = %d, want 0", got)
	}
}

func TestExplicitTCPTransportDoesNotTryQUIC(t *testing.T) {
	h := newAutoHarness(t)
	h.client.cfg.Transport = TransportTCP
	h.start(t)

	if got := h.quicDials.Load(); got != 0 {
		t.Fatalf("quic dials with transport tcp = %d, want 0", got)
	}
}

func TestStartDefaultsToAutoTransport(t *testing.T) {
	carrier := newFakeCarrier(t)
	defer carrier.close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := Config{
		RelayAddr:   carrier.addr(),
		BackendAddr: "127.0.0.1:1",
		Token:       []byte("test-token"),
		Hostnames:   []string{"home.relay.test"},
		TLSConfig:   &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
	}
	client, err := Start(ctx, cfg)
	if err != nil {
		t.Fatalf("start client: %v", err)
	}
	defer client.Close()
	if client.cfg.Transport != TransportAuto {
		t.Fatalf("default transport = %q, want %q", client.cfg.Transport, TransportAuto)
	}

	cfg.Transport = "sctp"
	if _, err := Start(ctx, cfg); err == nil || !strings.Contains(err.Error(), "unknown carrier transport") {
		t.Fatalf("Start with transport sctp err = %v, want unknown carrier transport", err)
	}
}
