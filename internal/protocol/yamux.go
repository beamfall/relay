package protocol

import (
	"fmt"
	"io"
	"math"
	"time"

	"github.com/hashicorp/yamux"
)

// DefaultYamuxStreamWindowBytes is the v1 carrier's per-stream window absent an
// operator override: 4 MiB. yamux sends a window update only after the reader
// has drained half the window, so a stream is guaranteed about window/2 per
// round trip: 4 MiB keeps one stream above 40 MB/s (320 Mbps) at 50 ms. Measured
// over a delayed loopback link it reaches ~80 MB/s at 50 ms and ~28 MB/s at
// 150 ms, against ~10 MB/s and ~3.4 MB/s for the previous 1 MiB (CORE-1386). A stream whose reader stalls can buffer up to one window on the
// receiving side, so the worst case is the stream count times this value.
const DefaultYamuxStreamWindowBytes = 4 * 1024 * 1024

// MinYamuxStreamWindowBytes is the smallest per-stream window yamux accepts:
// its initial stream window, 256 KiB. yamux.VerifyConfig rejects anything
// smaller, but only when a carrier session starts.
const MinYamuxStreamWindowBytes = 256 * 1024

// ValidateYamuxStreamWindowBytes checks an operator-supplied
// --yamux-stream-window-bytes value before any yamux config is built. 0 selects
// DefaultYamuxStreamWindowBytes. Any other value must lie in
// [MinYamuxStreamWindowBytes, math.MaxUint32]: yamux stores the window as a
// uint32, so a larger value would silently wrap (exactly 2^32 becomes a zero
// window), and a smaller one would pass startup only to fail when the first
// carrier session is created.
func ValidateYamuxStreamWindowBytes(streamWindowBytes int64) error {
	switch {
	case streamWindowBytes == 0:
		return nil
	case streamWindowBytes < 0:
		return fmt.Errorf("--yamux-stream-window-bytes %d is negative; use 0 for the %d-byte default or a value in [%d, %d]",
			streamWindowBytes, DefaultYamuxStreamWindowBytes, MinYamuxStreamWindowBytes, uint64(math.MaxUint32))
	case streamWindowBytes < MinYamuxStreamWindowBytes:
		return fmt.Errorf("--yamux-stream-window-bytes %d is below the yamux minimum of %d bytes",
			streamWindowBytes, MinYamuxStreamWindowBytes)
	case streamWindowBytes > math.MaxUint32:
		return fmt.Errorf("--yamux-stream-window-bytes %d exceeds the yamux maximum of %d bytes",
			streamWindowBytes, uint64(math.MaxUint32))
	}
	return nil
}

// YamuxConfig returns the carrier-session multiplexer config shared by the relay
// (server side) and the tunnel client (client side). Both ends MUST use the same
// config (including streamWindowBytes) so window-size and keep-alive expectations
// match.
//
// The defaults are tuned for a long-lived media-relay carrier carrying many
// concurrent byte-blind streams, where yamux DefaultConfig() is actively harmful:
//
//   - ConnectionWriteTimeout (default 10s) is a *session-wide* safety valve: when a
//     single frame write blocks past it, yamux tears down the ENTIRE carrier session
//     and every multiplexed stream with it. For media we expect individual streams to
//     stall (a paused player, a slow client) without that being a carrier fault, so we
//     raise it to 30s — long enough to ride out a transient stall, still bounded so a
//     truly wedged socket is eventually reaped. Per-stream liveness is handled by the
//     splice layer and StreamCap, not by this session-wide valve.
//   - MaxStreamWindowSize (default 256 KiB) caps in-flight unacked bytes per stream.
//     Because yamux refills the window only after half of it is consumed, a stream
//     needs about twice its bandwidth-delay product: 4K remux at 100 Mbps over a
//     150 ms path needs ~3.75 MiB. streamWindowBytes lets an operator tune this per
//     deployment (a longer-RTT link needs more headroom, a memory-constrained host
//     less); <=0 falls back to DefaultYamuxStreamWindowBytes. Callers validate
//     operator input with ValidateYamuxStreamWindowBytes first. Each receiver's own
//     setting bounds the direction it receives, so core's window bounds uploads and
//     the relay's bounds downloads.
//   - KeepAlive stays enabled (default 30s interval) so a dead carrier is detected and
//     reaped rather than parking streams on a silently-gone peer.
//   - StreamCloseTimeout is reduced from 5m to 30s so a half-closed stream whose
//     peer never answers is eventually reset without retaining session resources
//     for five minutes. Splice deadlines provide the tighter per-request bound.
//   - LogOutput is routed to io.Discard: yamux otherwise logs to os.Stderr directly,
//     bypassing the relay's configured logger.
func YamuxConfig(streamWindowBytes int) *yamux.Config {
	if streamWindowBytes <= 0 {
		streamWindowBytes = DefaultYamuxStreamWindowBytes
	}
	cfg := yamux.DefaultConfig()
	cfg.ConnectionWriteTimeout = 30 * time.Second
	cfg.MaxStreamWindowSize = uint32(streamWindowBytes)
	cfg.StreamCloseTimeout = 30 * time.Second
	cfg.EnableKeepAlive = true
	cfg.LogOutput = io.Discard
	return cfg
}
