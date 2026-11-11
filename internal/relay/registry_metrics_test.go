package relay

import (
	"errors"
	"net"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/yamux"
)

// livePair returns a carrier whose yamux session is open, plus a cleanup func.
// The peer session is kept alive (closing it would close ours) until cleanup.
func liveCarrier(t *testing.T, id string) (*carrier, func()) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	server, err := yamux.Server(serverConn, nil)
	if err != nil {
		t.Fatalf("yamux server: %v", err)
	}
	client, err := yamux.Client(clientConn, nil)
	if err != nil {
		t.Fatalf("yamux client: %v", err)
	}
	c := &carrier{id: id, session: server}
	cleanup := func() {
		_ = server.Close()
		_ = client.Close()
		_ = serverConn.Close()
		_ = clientConn.Close()
	}
	return c, cleanup
}

// Task 2: two carriers claiming the same allowed host must not silently overwrite.
// First-writer-wins; the second carrier's claim is refused, not stolen.
func TestRegistryRefusesLiveHostTakeover(t *testing.T) {
	const host = "shared.example.com"
	r := newRegistry()

	first, cleanup1 := liveCarrier(t, "carrier-first")
	defer cleanup1()
	second, cleanup2 := liveCarrier(t, "carrier-second")
	defer cleanup2()

	if _, refused := r.register(first, []string{host}); len(refused) != 0 {
		t.Fatalf("first registration refused unexpectedly: %v", refused)
	}
	if got := r.lookup(host); got != first {
		t.Fatalf("after first register, lookup = %v, want first carrier", got)
	}

	accepted, refused := r.register(second, []string{host})
	if len(accepted) != 0 {
		t.Fatalf("second registration accepted = %v, want none", accepted)
	}
	if len(refused) != 1 || refused[0] != host {
		t.Fatalf("second registration refused = %v, want [%s]", refused, host)
	}
	if got := r.lookup(host); got != first {
		t.Fatalf("after conflicting register, lookup = %v, want first carrier (no silent takeover)", got)
	}

	// Refused host must not be in the second carrier's hostsFor, so its unregister
	// cannot delete the rightful owner's mapping.
	r.unregister(second)
	if got := r.lookup(host); got != first {
		t.Fatalf("after refused carrier unregister, lookup = %v, want first carrier", got)
	}
}

// Task 2: a same-identity reconnect must reclaim its own host even while the prior
// session is still live (e.g. a network blip before yamux detects the stale session
// as closed). Refusing this would break legitimate reconnection.
func TestRegistryAllowsSameIdentityReconnect(t *testing.T) {
	const (
		host = "carrier.example.com"
		id   = "carrier-stable-id"
	)
	r := newRegistry()

	old, cleanupOld := liveCarrier(t, id)
	defer cleanupOld() // old session deliberately stays live for this test
	if _, refused := r.register(old, []string{host}); len(refused) != 0 {
		t.Fatalf("first registration refused unexpectedly: %v", refused)
	}

	// Same identity reconnects with a brand-new (still-live) session/pointer.
	reconnect, cleanupReconnect := liveCarrier(t, id)
	defer cleanupReconnect()
	if _, refused := r.register(reconnect, []string{host}); len(refused) != 0 {
		t.Fatalf("same-identity reconnect refused = %v, want none (reconnection must work)", refused)
	}
	if got := r.lookup(host); got != reconnect {
		t.Fatalf("after reconnect, lookup = %v, want reconnecting carrier", got)
	}

	// The stale old carrier's unregister must not delete the route now owned by the
	// reconnected carrier.
	r.unregister(old)
	if got := r.lookup(host); got != reconnect {
		t.Fatalf("after stale carrier unregister, lookup = %v, want reconnecting carrier", got)
	}
}

func TestTakeoverDrainRoutesNewStreamsOnlyToFreshCarrier(t *testing.T) {
	const host = "carrier.example.com"
	r := newRegistry()
	old, cleanupOld := liveCarrier(t, "carrier-stable-id")
	defer cleanupOld()
	old.streamCap = 1
	fresh, cleanupFresh := liveCarrier(t, "carrier-stable-id")
	defer cleanupFresh()
	fresh.streamCap = 1

	r.register(old, []string{host})
	r.register(fresh, []string{host})

	if got := r.lookup(host); got != fresh {
		t.Fatalf("lookup after same-identity takeover = %p, want fresh carrier %p", got, fresh)
	}
	if _, _, err := old.open(); !errors.Is(err, errCarrierDraining) {
		t.Fatalf("old carrier open error = %v, want %v", err, errCarrierDraining)
	}
}

func TestTakeoverDrainRetriesFreshCarrierAfterStaleLookup(t *testing.T) {
	const host = "carrier.example.com"
	r := newRegistry()
	old, cleanupOld := liveCarrier(t, "carrier-stable-id")
	defer cleanupOld()
	old.streamCap = 1
	fresh, cleanupFresh := liveCarrier(t, "carrier-stable-id")
	defer cleanupFresh()
	fresh.streamCap = 1

	r.register(old, []string{host})
	selected := r.lookup(host)
	r.register(fresh, []string{host})

	s := &Server{registry: r}
	selected, stream, release, err := s.openCarrierStream(host, "test-source", selected)
	if err != nil {
		t.Fatalf("fresh carrier retry: %v", err)
	}
	release()
	if err := stream.Close(); err != nil {
		t.Fatalf("close fresh stream: %v", err)
	}
	if selected != fresh {
		t.Fatalf("retry carrier = %p, want fresh carrier %p", selected, fresh)
	}
}

// A host owned by a closed (dead) carrier may be reclaimed by a new one.
func TestRegistryReclaimsDeadCarrierHost(t *testing.T) {
	const host = "reclaim.example.com"
	r := newRegistry()

	dead, cleanupDead := liveCarrier(t, "carrier-dead")
	r.register(dead, []string{host})
	cleanupDead() // closes the session -> IsClosed() becomes true

	fresh, cleanupFresh := liveCarrier(t, "carrier-fresh")
	defer cleanupFresh()
	if _, refused := r.register(fresh, []string{host}); len(refused) != 0 {
		t.Fatalf("reclaim of dead carrier host refused: %v", refused)
	}
	if got := r.lookup(host); got != fresh {
		t.Fatalf("after reclaim, lookup = %v, want fresh carrier", got)
	}
}

// Task 1: each prometheus gauge must map to its own underlying counter. In
// particular active_tunnels must track tunnelsActive, NOT carriersConnected.
func TestMetricsGaugesMapToDistinctCounters(t *testing.T) {
	m := &metrics{}
	m.carriersConnected.Store(7)
	m.tunnelsActive.Store(3)
	m.streamsActive.Store(5)

	rec := httptest.NewRecorder()
	m.metricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()

	gauge := func(name string) string {
		t.Helper()
		for _, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(line, name+" ") {
				return strings.TrimSpace(strings.TrimPrefix(line, name))
			}
		}
		t.Fatalf("gauge %s not found in:\n%s", name, body)
		return ""
	}

	if got := gauge("beamfall_relay_carriers_connected"); got != "7" {
		t.Fatalf("carriers_connected = %s, want 7", got)
	}
	if got := gauge("beamfall_relay_active_tunnels"); got != "3" {
		t.Fatalf("active_tunnels = %s, want 3 (must track tunnelsActive, not carriersConnected)", got)
	}
	if got := gauge("beamfall_relay_streams_active"); got != "5" {
		t.Fatalf("streams_active = %s, want 5", got)
	}
}

// The drain retry and the per-source carrier cap have to compose: after a stale
// lookup retries onto a fresh carrier, exactly one reservation is held while the
// stream is open and it is freed by the caller's release. The draining carrier's
// failed open must not leak a reservation.
//
// Note this cannot distinguish "charged to the fresh carrier" from "charged to
// the drained one": takeover is same-identity, so both carriers share one
// sourceCarrierKey. It guards the leak, not the attribution.
func TestOpenCarrierStreamHoldsOneBudgetAcrossDrainRetry(t *testing.T) {
	const host = "carrier.example.com"
	const source = "203.0.113.0"
	r := newRegistry()
	old, cleanupOld := liveCarrier(t, "carrier-stable-id")
	defer cleanupOld()
	old.streamCap = 1
	fresh, cleanupFresh := liveCarrier(t, "carrier-stable-id")
	defer cleanupFresh()
	fresh.streamCap = 1

	r.register(old, []string{host})
	stale := r.lookup(host)
	r.register(fresh, []string{host})

	s := &Server{registry: r, publicPerCarrier: newSourceCarrierLimiter(1)}
	used, stream, release, err := s.openCarrierStream(host, source, stale)
	if err != nil {
		t.Fatalf("open after stale lookup: %v", err)
	}
	if used != fresh {
		t.Fatalf("stream opened on %p, want fresh carrier %p", used, fresh)
	}
	if got := s.publicPerCarrier.counts[sourceCarrierKey{source: source, carrier: fresh.id}]; got != 1 {
		t.Fatalf("held budget = %d, want exactly 1 while the stream is open (a leaked drain reservation shows as 2)", got)
	}

	release()
	if err := stream.Close(); err != nil {
		t.Fatalf("close stream: %v", err)
	}
	if got := s.publicPerCarrier.counts[sourceCarrierKey{source: source, carrier: fresh.id}]; got != 0 {
		t.Fatalf("budget after release = %d, want 0", got)
	}
}
