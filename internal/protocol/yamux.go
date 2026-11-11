package protocol

import (
	"io"
	"time"

	"github.com/hashicorp/yamux"
)

// DefaultYamuxStreamWindowBytes is the v1 carrier's per-stream window absent an
// operator override: 1 MiB (BDP headroom for 40 Mbps / 50 ms RTT).
const DefaultYamuxStreamWindowBytes = 1024 * 1024

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
//   - MaxStreamWindowSize (default 256 KiB) caps in-flight unacked bytes per stream:
//     a 40 Mbps stream over a 50 ms RTT needs ~250 KiB of bandwidth-delay product, so
//     256 KiB sits right at the edge and throttles throughput as soon as ACKs lag.
//     streamWindowBytes lets an operator tune this per deployment (e.g. a longer-RTT
//     link needs more BDP headroom); <=0 falls back to DefaultYamuxStreamWindowBytes,
//     the same 1 MiB this carrier previously hardcoded.
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
