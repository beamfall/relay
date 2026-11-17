package loadtest

import (
	"context"
	"testing"
	"time"

	"github.com/beamfall/relay/internal/tunnel"
)

// TestControlStreamLatencyBudget enforces docs/relay-latency-budget.md: on the
// QUIC carrier a small control stream keeps its round-trip p99 inside
// ControlP99Budget while a media stream saturates the same carrier, with and
// without 1% packet loss. The v1 TCP carrier is not held to the budget: it
// misses it several times over (see the doc), which is why the doc recommends
// QUIC for this traffic.
func TestControlStreamLatencyBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a saturated carrier for several seconds")
	}
	for name, loss := range map[string]float64{"no loss": 0, "1% loss": 0.01} {
		t.Run(name, func(t *testing.T) {
			link := ReferenceLink()
			link.Loss = loss
			opts := LatencyOptions{
				Transport:    tunnel.TransportQUIC,
				Link:         link,
				Duration:     4 * time.Second,
				Warmup:       time.Second,
				MediaStreams: 1,
			}
			result, err := RunLatency(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("samples=%d unanswered=%d p50=%s p99=%s p99.9=%s max=%s media=%.1f Mbit/s",
				result.Samples, result.Unanswered, result.P50, result.P99, result.P999, result.Max, result.MediaMbps)
			// Half the offered messages is far below any healthy run and still
			// enough for a p99.
			if offered := int(opts.Duration / (5 * time.Millisecond)); result.Samples < offered/2 {
				t.Fatalf("only %d of ~%d control messages were echoed", result.Samples, offered)
			}
			if result.Unanswered > 0 {
				t.Fatalf("%d control messages were not echoed within %s", result.Unanswered, echoGrace)
			}
			if result.MediaMbps < 1 {
				t.Fatalf("media moved %.2f Mbit/s: the carrier was not loaded", result.MediaMbps)
			}
			if result.P99 > ControlP99Budget {
				t.Fatalf("control-stream p99 %s exceeds the %s budget", result.P99, ControlP99Budget)
			}
		})
	}
}

// TestLinkDelaysBothCarriers checks the emulated link is in the path for each
// carrier: an idle control stream cannot beat the link's round trip.
func TestLinkDelaysBothCarriers(t *testing.T) {
	link := Link{Delay: 15 * time.Millisecond}
	for _, transport := range []string{tunnel.TransportTCP, tunnel.TransportQUIC} {
		t.Run(transport, func(t *testing.T) {
			result, err := RunLatency(context.Background(), LatencyOptions{
				Transport: transport,
				Link:      link,
				Duration:  500 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.Samples == 0 || result.Unanswered > 0 {
				t.Fatalf("samples=%d unanswered=%d", result.Samples, result.Unanswered)
			}
			if result.P50 < 2*link.Delay {
				t.Fatalf("p50 %s is below the link round trip %s", result.P50, 2*link.Delay)
			}
		})
	}
}

// TestTCPLossHoldsLaterSegments pins the TCP loss model: a lost segment is
// delivered one round trip late, and the segments behind it wait for it.
func TestTCPLossHoldsLaterSegments(t *testing.T) {
	const delay = 10 * time.Millisecond
	s := newShaper(Link{Delay: delay, Loss: 1}, 0)
	now := time.Now()
	lost := s.scheduleSegment(now, tcpSegmentBytes)
	if want := now.Add(3 * delay); !lost.Equal(want) {
		t.Fatalf("lost segment delivered after %s, want %s", lost.Sub(now), want.Sub(now))
	}
	s.link.Loss = 0
	next := s.scheduleSegment(now.Add(time.Millisecond), tcpSegmentBytes)
	if next.Before(lost) {
		t.Fatalf("segment behind the loss delivered after %s, ahead of the loss at %s", next.Sub(now), lost.Sub(now))
	}
	later := s.scheduleSegment(now.Add(4*delay), tcpSegmentBytes)
	if want := now.Add(5 * delay); !later.Equal(want) {
		t.Fatalf("segment after recovery delivered after %s, want %s", later.Sub(now), want.Sub(now))
	}
}

// TestLinkRateAndQueue pins the bottleneck: bytes leave at the link rate, and
// the backlog is what a tail-drop queue compares against Link.Queue.
func TestLinkRateAndQueue(t *testing.T) {
	s := newShaper(Link{BitsPerSecond: 8e6}, 0) // 1 MB/s
	now := time.Now()
	for i := 1; i <= 3; i++ {
		if got, want := s.schedule(now, 10_000), now.Add(time.Duration(i)*10*time.Millisecond); !got.Equal(want) {
			t.Fatalf("chunk %d delivered after %s, want %s", i, got.Sub(now), want.Sub(now))
		}
	}
	if got := s.backlog(now); got != 30*time.Millisecond {
		t.Fatalf("backlog = %s, want 30ms", got)
	}
	if got := s.backlog(now.Add(time.Second)); got != 0 {
		t.Fatalf("drained backlog = %s, want 0", got)
	}
}

func TestPercentile(t *testing.T) {
	sorted := make([]time.Duration, 1000)
	for i := range sorted {
		sorted[i] = time.Duration(i + 1)
	}
	for p, want := range map[float64]time.Duration{0.5: 500, 0.99: 990, 0.999: 999, 1: 1000} {
		if got := Percentile(sorted, p); got != want {
			t.Errorf("Percentile(%v) = %d, want %d", p, got, want)
		}
	}
	if got := Percentile(nil, 0.99); got != 0 {
		t.Errorf("Percentile(nil) = %d, want 0", got)
	}
}
