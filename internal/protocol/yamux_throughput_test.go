package protocol

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

// minSingleStreamBytesPerSec and throughputRTT are the CORE-1386 target: one
// relayed stream must sustain 40 MB/s over a 50 ms carrier round trip.
const (
	minSingleStreamBytesPerSec = 40_000_000
	throughputRTT              = 50 * time.Millisecond
)

// TestDefaultYamuxStreamWindowSustainsTarget (CORE-1386) checks the default
// window against yamux's flow control: the receiver refills the window only
// after half of it is drained (hashicorp/yamux stream.go sendWindowUpdate), so
// the conservative bound for one stream is window/2 per round trip. The old
// 1 MiB default gives ~10 MB/s at 50 ms. BenchmarkYamuxStreamThroughputRTT
// measures real throughput over a delayed link.
func TestDefaultYamuxStreamWindowSustainsTarget(t *testing.T) {
	cfg := YamuxConfig(0)
	if got := int(cfg.MaxStreamWindowSize); got != DefaultYamuxStreamWindowBytes {
		t.Fatalf("YamuxConfig(0).MaxStreamWindowSize = %d, want DefaultYamuxStreamWindowBytes %d", got, DefaultYamuxStreamWindowBytes)
	}
	perRoundTrip := float64(cfg.MaxStreamWindowSize) / 2
	bound := perRoundTrip / throughputRTT.Seconds()
	if bound < minSingleStreamBytesPerSec {
		t.Fatalf("default window %d B bounds one stream to %.1f MB/s at %v, want >= %.1f MB/s",
			cfg.MaxStreamWindowSize, bound/1e6, throughputRTT, float64(minSingleStreamBytesPerSec)/1e6)
	}
	if got := YamuxConfig(2 << 20).MaxStreamWindowSize; got != 2<<20 {
		t.Fatalf("YamuxConfig override = %d, want %d", got, 2<<20)
	}
}

// BenchmarkYamuxStreamThroughputRTT measures one yamux stream's throughput over
// a loopback link with injected round-trip delay, for the old 1 MiB window and
// the current default. Run with:
//
//	go test -run '^$' -bench YamuxStreamThroughputRTT -benchtime 1x ./internal/protocol/
func BenchmarkYamuxStreamThroughputRTT(b *testing.B) {
	for _, rtt := range []time.Duration{50 * time.Millisecond, 150 * time.Millisecond} {
		for _, window := range []int{1 << 20, DefaultYamuxStreamWindowBytes} {
			b.Run(fmt.Sprintf("rtt=%v/window=%dMiB", rtt, window>>20), func(b *testing.B) {
				const payload = 64 << 20
				b.SetBytes(payload)
				var total time.Duration
				for i := 0; i < b.N; i++ {
					total += timeYamuxTransfer(b, window, rtt, payload)
				}
				b.ReportMetric(float64(payload)*float64(b.N)/total.Seconds()/1e6, "MB/s")
			})
		}
	}
}

// timeYamuxTransfer sends payload bytes from a yamux server stream to a client
// over a link that delays each direction by rtt/2, and returns the time from
// the first byte read to the last.
func timeYamuxTransfer(tb testing.TB, window int, rtt time.Duration, payload int) time.Duration {
	tb.Helper()
	clientRaw, serverRaw := delayedPipe(tb, rtt/2)
	cfg := YamuxConfig(window)
	server, err := yamux.Server(serverRaw, cfg)
	if err != nil {
		tb.Fatalf("yamux server: %v", err)
	}
	defer server.Close() //nolint:errcheck // benchmark cleanup.
	client, err := yamux.Client(clientRaw, cfg)
	if err != nil {
		tb.Fatalf("yamux client: %v", err)
	}
	defer client.Close() //nolint:errcheck // benchmark cleanup.

	sendErr := make(chan error, 1)
	go func() {
		stream, err := server.AcceptStream()
		if err != nil {
			sendErr <- err
			return
		}
		defer stream.Close() //nolint:errcheck // benchmark cleanup.
		_, err = io.CopyN(stream, zeroReader{}, int64(payload))
		sendErr <- err
	}()

	stream, err := client.OpenStream()
	if err != nil {
		tb.Fatalf("open stream: %v", err)
	}
	defer stream.Close() //nolint:errcheck // benchmark cleanup.
	// yamux opens the stream lazily; a one-byte write makes the server accept it.
	if _, err := stream.Write([]byte{0}); err != nil {
		tb.Fatalf("open stream write: %v", err)
	}
	first := make([]byte, 1)
	if _, err := io.ReadFull(stream, first); err != nil {
		tb.Fatalf("read first byte: %v", err)
	}
	start := time.Now()
	if n, err := io.Copy(io.Discard, stream); err != nil || n != int64(payload-1) {
		tb.Fatalf("read payload = %d, %v; want %d", n, err, payload-1)
	}
	elapsed := time.Since(start)
	if err := <-sendErr; err != nil {
		tb.Fatalf("send payload: %v", err)
	}
	return elapsed
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// delayedPipe returns two ends of a loopback TCP connection whose bytes are
// delivered oneWay later in each direction, with no bandwidth limit.
func delayedPipe(tb testing.TB, oneWay time.Duration) (net.Conn, net.Conn) {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck // listener is only needed for one accept.
	// Two loopback pairs joined by delaying relays: a <-> b and c <-> d,
	// with b -> c and c -> b delayed.
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		tb.Fatalf("dial: %v", err)
	}
	b, err := ln.Accept()
	if err != nil {
		tb.Fatalf("accept: %v", err)
	}
	d, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		tb.Fatalf("dial: %v", err)
	}
	c, err := ln.Accept()
	if err != nil {
		tb.Fatalf("accept: %v", err)
	}
	go delayCopy(c, b, oneWay)
	go delayCopy(b, c, oneWay)
	tb.Cleanup(func() {
		for _, conn := range []net.Conn{a, b, c, d} {
			_ = conn.Close()
		}
	})
	return a, d
}

type delayedChunk struct {
	data []byte
	due  time.Time
}

// delayCopy copies src to dst, holding each chunk until oneWay after it was
// read. Chunks queue without bound, so the link adds latency but not a
// bandwidth cap.
func delayCopy(dst, src net.Conn, oneWay time.Duration) {
	queue := make(chan delayedChunk, 1<<16)
	go func() {
		defer close(queue)
		for {
			buf := make([]byte, 64<<10)
			n, err := src.Read(buf)
			if n > 0 {
				queue <- delayedChunk{data: buf[:n], due: time.Now().Add(oneWay)}
			}
			if err != nil {
				return
			}
		}
	}()
	for chunk := range queue {
		time.Sleep(time.Until(chunk.due))
		if _, err := dst.Write(chunk.data); err != nil {
			_ = src.Close()
			return
		}
	}
	_ = dst.Close()
}
