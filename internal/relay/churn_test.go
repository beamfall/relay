package relay_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"runtime"
	"testing"
	"time"

	"github.com/beamfall/relay/internal/relay"
)

// TestRelayChurnDoesNotLeakGoroutines drives an open/close storm of tunneled
// public connections — including abrupt mid-stream disconnects — through a live
// relay, then asserts the relay returns to a baseline goroutine count after the
// storm drains. It covers the bounded-carrier-accept and head-of-line teardown
// paths flagged in the 2026-06-15 review (relay#7 churn/leak soak gap): a leaked
// goroutine per accepted public connection or per half-open stream would surface
// here as growth proportional to the cycle count, not as steady-state noise.
//
// It is fast (sequential cycles, no throughput target) so it runs in the normal
// gate; the throughput-confirmation half of relay#7 (`make soak` against the
// 40 Mbps / 50 ms-RTT profile) is a separate, network-profile-bound concern.
func TestRelayChurnDoesNotLeakGoroutines(t *testing.T) {
	if testing.Short() {
		t.Skip("churn/leak soak skipped in -short")
	}

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
		// Generous caps: this test probes per-connection *teardown* (goroutine
		// leaks), not the caps. A small StreamCap/MaxPublicConns would spuriously
		// refuse a rapid next dial while a just-closed connection's yamux stream is
		// still draining — not the leak we are after. We pace cycles below so
		// streams drain between dials regardless.
		StreamCap:      512,
		MaxPublicConns: 256,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	defer node.Close()

	client := startTunnelClient(t, ctx, node.CarrierAddr(), home.Addr(), []byte("test-token"), []string{testHost})
	defer client.Close()

	// fullCycle opens a tunneled connection, exchanges one echo, and closes it
	// cleanly. abruptCycle opens one and closes it immediately without reading —
	// the relay must tear down the half-open stream rather than strand a
	// goroutine. Both are sequential, so at most one stream is live and StreamCap
	// is never the limiter (we are probing teardown, not the cap).
	// dial is resilient to the occasional transient accept-close under churn
	// (brief teardown-accounting lag): a teardown leak shows up in the goroutine
	// assertion, not as a permanent dial failure, so a few retries keep the test
	// about leaks rather than reconnect timing.
	dial := func() *tls.Conn {
		t.Helper()
		var lastErr error
		for attempt := 0; attempt < 8; attempt++ {
			conn, err := tls.Dial("tcp", node.PublicAddr(), &tls.Config{
				ServerName: testHost,
				RootCAs:    home.Roots,
				MinVersion: tls.VersionTLS13,
			})
			if err == nil {
				return conn
			}
			lastErr = err
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("dial public TLS after retries: %v", lastErr)
		return nil
	}

	fullCycle := func() {
		conn := dial()
		defer conn.Close() //nolint:errcheck // test connection cleanup.
		if _, err := conn.Write([]byte("churn\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
			t.Fatalf("read echo: %v", err)
		}
	}
	abruptCycle := func() {
		conn := dial()
		// Write a partial line and drop the connection mid-stream (no read).
		_, _ = conn.Write([]byte("partial"))
		_ = conn.Close()
	}

	// pace lets each cycle's yamux stream drain before the next dial, so the
	// storm stays well under StreamCap and exercises teardown rather than the cap.
	const pace = 15 * time.Millisecond

	// Warm up so connection/session goroutines reach steady state before we
	// snapshot the baseline.
	for i := 0; i < 10; i++ {
		fullCycle()
		time.Sleep(pace)
	}
	baseline := settleGoroutines(120 * time.Millisecond)

	const cycles = 90
	for i := 0; i < cycles; i++ {
		if i%3 == 0 {
			abruptCycle()
		} else {
			fullCycle()
		}
		time.Sleep(pace)
	}

	// Allow async teardown to drain, then assert no growth proportional to the
	// storm. The tolerance absorbs scheduler/GC noise; a real per-conn leak would
	// add ~cycles goroutines, far exceeding it.
	const tolerance = 8
	deadline := time.Now().Add(5 * time.Second)
	var got int
	for {
		got = settleGoroutines(100 * time.Millisecond)
		if got <= baseline+tolerance || time.Now().After(deadline) {
			break
		}
	}
	if got > baseline+tolerance {
		t.Fatalf("goroutine leak after %d churn cycles: baseline=%d, after-drain=%d (tolerance %d)", cycles, baseline, got, tolerance)
	}
}

// settleGoroutines runs a short GC-and-settle window and returns the lowest
// goroutine count observed in it, damping transient spikes from in-flight
// teardown so the reading reflects resident (not in-flight) goroutines.
func settleGoroutines(window time.Duration) int {
	min := int(^uint(0) >> 1)
	deadline := time.Now().Add(window)
	for {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
		if n := runtime.NumGoroutine(); n < min {
			min = n
		}
		if time.Now().After(deadline) {
			return min
		}
	}
}
