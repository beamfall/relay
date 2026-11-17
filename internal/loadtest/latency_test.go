package loadtest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/beamfall/relay/internal/relay"
	"github.com/beamfall/relay/internal/tunnel"
)

// TestControlStreamLatencyBudget enforces docs/relay-latency-budget.md: a small
// control stream keeps its round-trip p99 inside ControlP99Budget while a media
// stream saturates the same carrier, with and without 1% loss, on both
// carriers.
//
// The TLS/TCP carrier is held on Linux only. Its figure depends on the carrier
// bounding its unsent backlog (CORE-2262) and on the emulated link adding no
// buffer of its own. On macOS loopback ignores the small receive buffer the
// link's proxy sockets ask for, which adds a queue of several hundred
// kilobytes that the reference link does not have.
func TestControlStreamLatencyBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a saturated carrier for several seconds")
	}
	for _, transport := range []string{tunnel.TransportTCP, tunnel.TransportQUIC} {
		for _, loss := range []float64{0, 0.01} {
			t.Run(fmt.Sprintf("%s/%g%% loss", transport, loss*100), func(t *testing.T) {
				if transport == tunnel.TransportTCP && runtime.GOOS != "linux" {
					t.Skipf("the emulated TCP link is only faithful on Linux, not %s", runtime.GOOS)
				}
				link := ReferenceLink()
				link.Loss = loss
				opts := LatencyOptions{
					Transport:    transport,
					Link:         link,
					Duration:     4 * time.Second,
					Warmup:       time.Second,
					MediaStreams: 1,
				}
				// The emulated link is timed by goroutines, so a loaded host adds
				// to the figure. One retry separates that from a carrier that is
				// over the budget on every run.
				var result LatencyResult
				for attempt := 1; attempt <= 2; attempt++ {
					var err error
					result, err = RunLatency(context.Background(), opts)
					if err != nil {
						t.Fatal(err)
					}
					t.Logf("attempt %d: samples=%d unanswered=%d p50=%s p99=%s p99.9=%s max=%s media=%.1f Mbit/s",
						attempt, result.Samples, result.Unanswered, result.P50, result.P99, result.P999, result.Max, result.MediaMbps)
					if result.P99 <= ControlP99Budget {
						break
					}
				}
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
}

// TestExternalLinkDialsTheCarrierDirectly covers the mode the netem script
// uses: no emulated link, so an idle control stream is not delayed.
func TestExternalLinkDialsTheCarrierDirectly(t *testing.T) {
	for _, transport := range []string{tunnel.TransportTCP, tunnel.TransportQUIC} {
		t.Run(transport, func(t *testing.T) {
			result, err := RunLatency(context.Background(), LatencyOptions{
				Transport:    transport,
				Link:         Link{Delay: time.Second},
				Duration:     300 * time.Millisecond,
				ExternalLink: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.Samples == 0 || result.Unanswered > 0 {
				t.Fatalf("samples=%d unanswered=%d", result.Samples, result.Unanswered)
			}
			if result.P50 >= time.Second {
				t.Fatalf("p50 %s: the emulated link was still in the path", result.P50)
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

// TestExternalCarrierRegistersFromTheWrittenFiles covers the mode that measures
// another tunnel client (core's): the run starts no carrier of its own, and a
// client that knows only the files in the directory registers and carries.
func TestExternalCarrierRegistersFromTheWrittenFiles(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	carrierErr := make(chan error, 1)
	go func() { carrierErr <- runFileCarrier(ctx, dir) }()

	result, err := RunLatency(ctx, LatencyOptions{
		Transport:          tunnel.TransportTCP,
		Duration:           300 * time.Millisecond,
		ExternalLink:       true,
		ExternalCarrierDir: dir,
	})
	if err != nil {
		select {
		case cerr := <-carrierErr:
			t.Fatalf("%v (carrier: %v)", err, cerr)
		default:
			t.Fatal(err)
		}
	}
	if result.Samples == 0 || result.Unanswered > 0 {
		t.Fatalf("samples=%d unanswered=%d", result.Samples, result.Unanswered)
	}
}

// runFileCarrier stands in for the outside client: it waits for carrier.env,
// then registers with a token minted from the secret file, verifying the relay
// against the written certificate.
func runFileCarrier(ctx context.Context, dir string) error {
	var env []byte
	for {
		var err error
		if env, err = os.ReadFile(filepath.Join(dir, ExternalCarrierEnvFile)); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(env)), "\n") {
		key, value, _ := strings.Cut(line, "=")
		values[key] = value
	}
	secret, err := os.ReadFile(filepath.Join(dir, ExternalCarrierSecretFile))
	if err != nil {
		return err
	}
	ca, err := os.ReadFile(filepath.Join(dir, ExternalCarrierCAFile))
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return errors.New("relay-ca.pem holds no certificate")
	}
	hostnames := []string{values["PUBLIC_HOST"]}
	token, err := relay.MintHMACTunnelToken(secret, hostnames, time.Minute)
	if err != nil {
		return err
	}
	client, err := tunnel.Start(ctx, tunnel.Config{
		RelayAddr:   values["RELAY_ENDPOINT"],
		BackendAddr: values["BACKEND_ADDR"],
		Token:       token,
		Hostnames:   hostnames,
		Transport:   tunnel.TransportTCP,
		TLSConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
	})
	if err != nil {
		return err
	}
	<-ctx.Done()
	client.Close()
	return nil
}

// TestAutoTransportReachesQUICAtTheCarrierAddress runs the tunnel client's
// default configuration against a relay with both carriers on one port, as
// relayd listens by default (CORE-2283).
func TestAutoTransportReachesQUICAtTheCarrierAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	result, err := RunLatency(context.Background(), LatencyOptions{
		Transport:    tunnel.TransportAuto,
		Duration:     300 * time.Millisecond,
		ExternalLink: true,
		CarrierPort:  port,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.CarrierTransport != tunnel.TransportQUIC {
		t.Fatalf("carrier transport = %q, want %q", result.CarrierTransport, tunnel.TransportQUIC)
	}
	if result.Samples == 0 || result.Unanswered > 0 {
		t.Fatalf("samples=%d unanswered=%d", result.Samples, result.Unanswered)
	}

	// The netem script measures every transport in one process on one port, so
	// the next run must get the UDP port the last one is still giving back.
	if _, err := RunLatency(context.Background(), LatencyOptions{
		Transport:    tunnel.TransportAuto,
		Duration:     50 * time.Millisecond,
		ExternalLink: true,
		CarrierPort:  port,
	}); err != nil {
		t.Fatalf("second run on the same carrier port: %v", err)
	}

	if _, err := RunLatency(context.Background(), LatencyOptions{Transport: tunnel.TransportAuto, Duration: time.Millisecond}); err == nil {
		t.Fatal("auto transport accepted an emulated link")
	}
}
