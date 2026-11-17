package relay_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/beamfall/relay/internal/relay"
)

// startHomeTLSBlaster serves a home backend that writes zeros to every
// connection for as long as the peer takes them. With stopOnPeerClose it
// closes a connection once its peer has closed, as a real server does;
// without it the backend keeps writing whatever the peer does.
func startHomeTLSBlaster(t *testing.T, host string, stopOnPeerClose bool) *homeServer {
	t.Helper()
	cert := mustSelfSignedCert(t, host)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert.TLSCert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("start home tls server: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		block := make([]byte, 64*1024)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close() //nolint:errcheck // test home server cleanup.
				if stopOnPeerClose {
					go func() {
						_, _ = io.Copy(io.Discard, conn)
						_ = conn.Close()
					}()
				}
				for {
					if _, err := conn.Write(block); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return &homeServer{listener: ln, Roots: cert.Roots}
}

// dialPublicTLSNoRead completes a TLS handshake through the relay and returns
// the raw TCP connection, which the caller may leave unread.
func dialPublicTLSNoRead(addr string, roots *x509.CertPool) (*net.TCPConn, *tls.Conn, error) {
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, nil, err
	}
	tcp := raw.(*net.TCPConn)
	conn := tls.Client(tcp, &tls.Config{ServerName: testHost, RootCAs: roots, MinVersion: tls.VersionTLS13})
	_ = tcp.SetDeadline(time.Now().Add(5 * time.Second))
	if err := conn.Handshake(); err != nil {
		_ = tcp.Close()
		return nil, nil, err
	}
	_ = tcp.SetDeadline(time.Time{})
	return tcp, conn, nil
}

func stalledReaderRelay(t *testing.T, ctx context.Context, cfg relay.Config) (*relay.Server, *homeServer) {
	t.Helper()
	return stalledReaderRelayWithHome(t, ctx, cfg, false)
}

func stalledReaderRelayWithHome(t *testing.T, ctx context.Context, cfg relay.Config, stopOnPeerClose bool) (*relay.Server, *homeServer) {
	t.Helper()
	token := []byte("stalled-reader-token")
	cfg.TokenVerifier = relay.StaticTokenVerifier{Token: token, CarrierID: "home-a", Hostnames: []string{testHost}}
	cfg.AdminAddr = "127.0.0.1:0"
	node := startRelay(t, ctx, cfg)
	home := startHomeTLSBlaster(t, testHost, stopOnPeerClose)
	client := startTunnelClient(t, ctx, node.CarrierAddr(), home.Addr(), token, []string{testHost})
	t.Cleanup(client.Close)
	return node, home
}

// CORE-2252: a public client that accepts no bytes while the home keeps
// sending is closed after the client write stall timeout.
func TestStalledPublicReaderIsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	node, home := stalledReaderRelay(t, ctx, relay.Config{ClientWriteStallTimeout: 400 * time.Millisecond})

	tcp, _, err := dialPublicTLSNoRead(node.PublicAddr(), home.Roots)
	if err != nil {
		t.Fatalf("dial public: %v", err)
	}
	defer tcp.Close() //nolint:errcheck // test cleanup.

	waitForRelayMetric(t, node.AdminAddr(), "beamfall_relay_streams_stalled_closed_total 1", 20*time.Second)
	waitForRelayMetric(t, node.AdminAddr(), "beamfall_relay_streams_active 0", 5*time.Second)
}

// CORE-2252: a client that pauses for less than the timeout and then reads
// again keeps its stream, however long the stream lives in total.
func TestPausedReaderThatResumesKeepsItsStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const stall = 3 * time.Second
	node, home := stalledReaderRelay(t, ctx, relay.Config{ClientWriteStallTimeout: stall})

	_, conn, err := dialPublicTLSNoRead(node.PublicAddr(), home.Roots)
	if err != nil {
		t.Fatalf("dial public: %v", err)
	}
	defer conn.Close() //nolint:errcheck // test cleanup.

	// Each round leaves the socket unread for a third of the timeout, long
	// enough for the relay's write to block, then takes more than every
	// buffer between the home and this client can hold.
	buf := make([]byte, 1<<20)
	start := time.Now()
	for time.Since(start) < 2*stall+stall/2 {
		time.Sleep(stall / 3)
		for read := 0; read < 24<<20; {
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("read after a pause shorter than the stall timeout: %v", err)
			}
			read += n
		}
	}
	metrics := getMetrics(t, node.AdminAddr())
	for _, want := range []string{"beamfall_relay_streams_stalled_closed_total 0\n", "beamfall_relay_streams_active 1\n"} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("metrics missing %q after a reader that kept resuming", strings.TrimSpace(want))
		}
	}
}

// CORE-2252: a home that rotates its carrier keeps one stream cap. Streams
// still running on the superseded carrier count against the new one.
func TestSupersededCarrierStreamsCountAgainstIdentityCap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	identity := relay.VerifiedCarrier{ID: "home-a"}
	node := startRelay(t, ctx, relay.Config{
		TokenVerifier:             mapTokenVerifier{"old-token": identity, "new-token": identity},
		StreamCap:                 2,
		MaxStreamsPerIPPerCarrier: 8,
		AdminAddr:                 "127.0.0.1:0",
	})
	home := startHomeTLSEcho(t, testHost)
	defer home.Close()

	old := startTunnelClient(t, ctx, node.CarrierAddr(), home.Addr(), []byte("old-token"), []string{testHost})
	defer old.Close()
	first := dialPublicTLS(t, node.PublicAddr(), testHost, home.Roots)
	defer first.Close() //nolint:errcheck // test cleanup.
	second := dialPublicTLS(t, node.PublicAddr(), testHost, home.Roots)
	defer second.Close() //nolint:errcheck // test cleanup.
	waitForRelayMetric(t, node.AdminAddr(), "beamfall_relay_streams_active 2", 5*time.Second)

	rotated := startTunnelClient(t, ctx, node.CarrierAddr(), home.Addr(), []byte("new-token"), []string{testHost})
	defer rotated.Close()
	waitForRelayMetric(t, node.AdminAddr(), "beamfall_relay_carriers_connected 2", 5*time.Second)

	if _, conn, err := dialPublicTLSNoRead(node.PublicAddr(), home.Roots); err == nil {
		_ = conn.Close()
		t.Fatal("a third stream opened on the new carrier while the superseded carrier held the identity's whole cap")
	}

	_ = first.Close()
	waitForRelayMetric(t, node.AdminAddr(), "beamfall_relay_streams_active 1", 5*time.Second)
	_, conn, err := dialPublicTLSNoRead(node.PublicAddr(), home.Roots)
	if err != nil {
		t.Fatalf("stream refused after the superseded carrier freed a slot: %v", err)
	}
	_ = conn.Close()
}

// waitForRelayedBytesToSettle waits until the relay forwards nothing more:
// the home has filled every stalled stream's window.
func waitForRelayedBytesToSettle(t *testing.T, node *relay.Server) {
	t.Helper()
	relayed := func() string {
		for _, line := range strings.Split(getMetrics(t, node.AdminAddr()), "\n") {
			if strings.HasPrefix(line, "beamfall_relay_bytes_relayed_total ") {
				return line
			}
		}
		return ""
	}
	deadline := time.Now().Add(60 * time.Second)
	for last := ""; ; {
		time.Sleep(time.Second)
		now := relayed()
		if now == last {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("relayed bytes still moving after 60s of stalled readers")
		}
		last = now
	}
}

// abortStalledStream fills the relay's only stream slot with a stalled
// reader, lets the home fill its window, then resets the client connection.
func abortStalledStream(t *testing.T, node *relay.Server, home *homeServer) {
	t.Helper()
	tcp, _, err := dialPublicTLSNoRead(node.PublicAddr(), home.Roots)
	if err != nil {
		t.Fatalf("dial public: %v", err)
	}
	waitForRelayedBytesToSettle(t, node)
	_ = tcp.SetLinger(0)
	_ = tcp.Close()
	waitForRelayMetric(t, node.AdminAddr(), "beamfall_relay_streams_active 0", 5*time.Second)
}

// oneStreamBudget is a stream memory budget that admits a single stream.
const oneStreamBudget = 8 << 20

// CORE-2252: a stalled stream whose client goes away still holds its window
// in the relay until the home closes the carrier stream. Its memory slot is
// held for as long, so a churn of such clients cannot stack buffers past the
// budget.
func TestAbortedStalledStreamKeepsItsMemorySlot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	node, home := stalledReaderRelay(t, ctx, relay.Config{
		StreamMemoryBudgetBytes: oneStreamBudget,
		ClientWriteStallTimeout: time.Minute,
	})
	abortStalledStream(t, node, home)

	// This home never closes its side, so the carrier stream lives until its
	// close timeout, far longer than this test.
	if _, conn, err := dialPublicTLSNoRead(node.PublicAddr(), home.Roots); err == nil {
		_ = conn.Close()
		t.Fatal("a new stream was admitted while the aborted stream still held its carrier buffer")
	}
	waitForRelayMetric(t, node.AdminAddr(), "beamfall_relay_stream_memory_budget_refusals_total 1", 5*time.Second)
}

// CORE-2252: when the home closes its side, as a real server does once its
// client is gone, the aborted stream's slot comes back well before the
// carrier's 30s close timeout.
func TestAbortedStreamFreesItsSlotOnceTheHomeCloses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	node, home := stalledReaderRelayWithHome(t, ctx, relay.Config{
		StreamMemoryBudgetBytes: oneStreamBudget,
		ClientWriteStallTimeout: time.Minute,
	}, true)
	abortStalledStream(t, node, home)

	deadline := time.Now().Add(10 * time.Second)
	for {
		_, conn, err := dialPublicTLSNoRead(node.PublicAddr(), home.Roots)
		if err == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no stream admitted 10s after the home closed the aborted stream: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// CORE-2252: with every other cap out of the way, stalled readers cannot
// push the relay's heap past its stream memory budget. Streams beyond the
// budget are refused.
func TestStalledReadersStayInsideStreamMemoryBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const budget = 64 << 20
	node, home := stalledReaderRelay(t, ctx, relay.Config{
		StreamMemoryBudgetBytes:   budget,
		ClientWriteStallTimeout:   time.Minute,
		StreamCap:                 1024,
		MaxPublicConnsPerIP:       1024,
		MaxStreamsPerIPPerCarrier: 1024,
	})
	// startRelay turns the QUIC carrier on, so the limit counts its window.
	limit := relay.StreamMemoryStreamLimit(budget, 0, true)
	const refused = 4

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	admitted := 0
	for i := 0; i < limit+refused; i++ {
		tcp, _, err := dialPublicTLSNoRead(node.PublicAddr(), home.Roots)
		if err != nil {
			continue
		}
		admitted++
		defer tcp.Close() //nolint:errcheck // test cleanup.
	}
	if admitted != limit {
		t.Fatalf("admitted %d stalled streams, want the stream limit %d", admitted, limit)
	}
	waitForRelayMetric(t, node.AdminAddr(), fmt.Sprintf("beamfall_relay_stream_memory_budget_refusals_total %d", refused), 5*time.Second)

	waitForRelayedBytesToSettle(t, node)

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	held := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("%d stalled streams hold %.1f MiB of heap (%.2f MiB each), budget %d MiB", admitted, float64(held)/(1<<20), float64(held)/float64(admitted)/(1<<20), budget>>20)
	if held < int64(admitted)<<20 {
		t.Fatalf("stalled streams hold only %d bytes: the readers did not stall the relay", held)
	}
	if held > budget {
		t.Fatalf("stalled streams hold %d bytes of heap, over the %d byte stream memory budget", held, budget)
	}
}

// CORE-2252: the default budget and its headroom fit the shipped 512 MiB
// memory limit, and the default budget leaves room for real use.
func TestDefaultStreamMemoryBudgetFitsShippedLimit(t *testing.T) {
	const shippedLimit = 512 << 20
	if total := int64(relay.DefaultStreamMemoryBudgetBytes + relay.StreamMemoryHeadroomBytes); total > shippedLimit {
		t.Fatalf("default budget plus headroom is %d bytes, over the shipped %d byte limit", total, shippedLimit)
	}
	if got := relay.StreamMemoryStreamLimit(0, 0, false); got != 40 {
		t.Fatalf("default stream limit = %d, want 40 (320 MiB / twice the 4 MiB window)", got)
	}
	if got := relay.StreamMemoryStreamLimit(1, 0, false); got != 1 {
		t.Fatalf("stream limit for a tiny budget = %d, want 1", got)
	}
	if got := relay.StreamMemoryStreamLimit(64<<20, 1<<20, true); got != 8 {
		t.Fatalf("stream limit with QUIC on = %d, want 8 (64 MiB / the 8 MiB QUIC window)", got)
	}
}
