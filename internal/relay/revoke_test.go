package relay

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/beamfall/relay/internal/protocol"
)

// stubSession is a minimal protocol.Session for exercising awaitCarrierEnd: it
// only needs Close/IsClosed/CloseChan (the stream methods are never called by
// the teardown path and panic if hit, so a misuse is loud).
type stubSession struct {
	closeOnce sync.Once
	closed    chan struct{}
}

func newStubSession() *stubSession { return &stubSession{closed: make(chan struct{})} }

func (s *stubSession) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func (s *stubSession) IsClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func (s *stubSession) CloseChan() <-chan struct{} { return s.closed }

func (s *stubSession) Open() (net.Conn, error)   { panic("unused") }
func (s *stubSession) Accept() (net.Conn, error) { panic("unused") }

var _ protocol.Session = (*stubSession)(nil)

func testServer() *Server {
	return &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// An expired token's still-open carrier session is torn down at its token
// deadline, not merely refused on the next dial (RELAY-REVOKE-1). The token's
// ExpiresAt is a self-contained signed claim (ADR-0018 §5), so this is a local
// timer, not a fetched revocation list or a playback-time phone-home.
func TestAwaitCarrierEnd_TearsDownOnTokenExpiry(t *testing.T) {
	s := testServer()
	session := newStubSession()
	verified := VerifiedCarrier{ID: "srv-1", ExpiresAt: time.Now().Add(time.Second)}

	done := make(chan struct{})
	go func() {
		s.awaitCarrierEnd(context.Background(), session, verified, nil)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("awaitCarrierEnd did not return after the token expired")
	}
	if !session.IsClosed() {
		t.Fatal("session was not closed when the token expired")
	}
}

// A zero ExpiresAt (e.g. the StaticTokenVerifier's shared-secret carriers) means
// no token-driven deadline: the session lives until it closes naturally, and
// awaitCarrierEnd never force-closes it.
func TestAwaitCarrierEnd_NoExpiryWaitsForNaturalClose(t *testing.T) {
	s := testServer()
	session := newStubSession()
	verified := VerifiedCarrier{ID: "srv-1"} // zero ExpiresAt

	done := make(chan struct{})
	go func() {
		s.awaitCarrierEnd(context.Background(), session, verified, nil)
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("awaitCarrierEnd returned before the session closed (unexpected force-close)")
	case <-time.After(50 * time.Millisecond):
	}
	if session.IsClosed() {
		t.Fatal("session was closed despite no token expiry")
	}

	_ = session.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("awaitCarrierEnd did not return after the session closed naturally")
	}
}

// Cancelling the server context unblocks awaitCarrierEnd even before token
// expiry, so shutdown/forceClose never wedges on a not-yet-expired carrier.
func TestAwaitCarrierEnd_ContextCancelUnblocks(t *testing.T) {
	s := testServer()
	session := newStubSession()
	verified := VerifiedCarrier{ID: "srv-1", ExpiresAt: time.Now().Add(time.Hour)}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.awaitCarrierEnd(ctx, session, verified, nil)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("awaitCarrierEnd did not return after context cancel")
	}
}

func TestTakeoverDrain_AllowsInflightPastOneSecondExpiry(t *testing.T) {
	s := testServer()
	s.expiredSessionDrain = 500 * time.Millisecond
	session := newStubSession()
	carrier := &carrier{active: 1, drained: make(chan struct{})}
	carrier.beginDrain()
	verified := VerifiedCarrier{ID: "srv-1", ExpiresAt: time.Now().Add(time.Second)}

	done := make(chan struct{})
	go func() {
		s.awaitCarrierEnd(context.Background(), session, verified, carrier)
		close(done)
	}()

	time.Sleep(1100 * time.Millisecond)
	if session.IsClosed() {
		t.Fatal("superseded carrier closed at expiry while an in-flight stream remained")
	}
	carrier.release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("superseded carrier did not close after its in-flight stream drained")
	}
}

// supersededPair registers an old and a new carrier of one identity for the
// same host, so the old one is superseded (draining) with one in-flight stream.
func supersededPair(t *testing.T, s *Server) (old, cur *carrier) {
	t.Helper()
	s.registry = newRegistry()
	old = &carrier{id: "srv-1", session: newStubSession(), active: 1, drained: make(chan struct{})}
	cur = &carrier{id: "srv-1", session: newStubSession(), drained: make(chan struct{})}
	s.registry.register(old, []string{"h.example"})
	s.registry.register(cur, []string{"h.example"})
	if !old.isDraining() {
		t.Fatal("old carrier not superseded")
	}
	return old, cur
}

func waitClosed(t *testing.T, session protocol.Session, within time.Duration, what string) {
	t.Helper()
	select {
	case <-session.CloseChan():
	case <-time.After(within):
		t.Fatal(what)
	}
}

// CORE-1382: a superseded carrier keeps its streams past its own token expiry
// while a live same-identity carrier holds its host, and falls back to
// ExpiredSessionDrain once that successor is gone.
func TestSupersededHold_KeepsStreamsWhileSuccessorLive(t *testing.T) {
	s := testServer()
	s.expiredSessionDrain = 100 * time.Millisecond
	s.supersededMaxAge = time.Hour
	s.supersededPoll = 10 * time.Millisecond
	old, cur := supersededPair(t, s)
	verified := VerifiedCarrier{ID: "srv-1", ExpiresAt: time.Now().Add(50 * time.Millisecond)}

	go s.awaitCarrierEnd(context.Background(), old.session, verified, old)

	time.Sleep(400 * time.Millisecond) // past expiry plus drain
	if old.session.IsClosed() {
		t.Fatal("superseded carrier closed past expiry while a live successor held its host")
	}
	_ = cur.session.Close()
	waitClosed(t, old.session, time.Second, "superseded carrier stayed open after its successor ended")
}

func TestSupersededHold_MaxAgeClosesCarrier(t *testing.T) {
	s := testServer()
	s.expiredSessionDrain = time.Hour
	s.supersededMaxAge = 100 * time.Millisecond
	s.supersededPoll = 10 * time.Millisecond
	old, _ := supersededPair(t, s)
	verified := VerifiedCarrier{ID: "srv-1", ExpiresAt: time.Now().Add(50 * time.Millisecond)}

	go s.awaitCarrierEnd(context.Background(), old.session, verified, old)

	waitClosed(t, old.session, time.Second, "superseded carrier outlived SupersededStreamMaxAge")
}

func TestSupersededHold_ClosesWhenLastStreamEnds(t *testing.T) {
	s := testServer()
	s.expiredSessionDrain = time.Hour
	s.supersededMaxAge = time.Hour
	s.supersededPoll = 10 * time.Millisecond
	old, _ := supersededPair(t, s)
	verified := VerifiedCarrier{ID: "srv-1", ExpiresAt: time.Now().Add(50 * time.Millisecond)}

	go s.awaitCarrierEnd(context.Background(), old.session, verified, old)

	time.Sleep(150 * time.Millisecond)
	old.release()
	waitClosed(t, old.session, time.Second, "superseded carrier stayed open after its last stream ended")
}

func TestRegistryHasLiveSuccessor(t *testing.T) {
	r := newRegistry()
	old := &carrier{id: "srv-1", session: newStubSession(), drained: make(chan struct{})}
	r.register(old, []string{"a.example", "b.example"})
	if r.hasLiveSuccessor(old) {
		t.Fatal("current carrier reported a successor")
	}

	other := &carrier{id: "srv-2", session: newStubSession(), drained: make(chan struct{})}
	if accepted, _ := r.register(other, []string{"a.example"}); len(accepted) != 0 {
		t.Fatalf("different identity took a live host: %v", accepted)
	}
	if r.hasLiveSuccessor(old) {
		t.Fatal("different identity counted as a successor")
	}

	cur := &carrier{id: "srv-1", session: newStubSession(), drained: make(chan struct{})}
	r.register(cur, []string{"b.example"})
	if !r.hasLiveSuccessor(old) {
		t.Fatal("live same-identity carrier on a shared host not seen")
	}

	_ = cur.session.Close()
	if r.hasLiveSuccessor(old) {
		t.Fatal("closed successor counted as live")
	}
	r.unregister(cur)
	if r.hasLiveSuccessor(old) {
		t.Fatal("unregistered successor counted as live")
	}
}
