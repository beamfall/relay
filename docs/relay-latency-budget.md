# Relay latency budget for established streams

Ticket: CORE-2246. Scope: the latency the relay and its carrier add to a stream that is already
open, as opposed to tunnel setup (`beamfall_relay_tunnel_setup_seconds`). The case that matters is
a small control stream (playback sync signals, clock exchanges) sharing a carrier with media.

## The budget

**A control stream's round-trip p99 stays at or below 250 ms while a media stream saturates the
same carrier in both directions**, on the reference link, with and without 1% packet loss.

- Reference link: 20 Mbit/s each way, 10 ms one-way delay (20 ms round trip), 50 ms bottleneck
  queue. It sits between the tunnel client and the relay's carrier listener.
- Control stream: one 64-byte message every 5 ms carrying its send time, echoed by the home
  server. The latency is client to home server and back, through the relay twice.
- Media: one stream writing as fast as the carrier accepts, in both directions.

Why 250 ms: the QUIC carrier measures 80 to 108 ms at p99 across runs, including under the race
detector, so the budget keeps a little over twice the worst measured value as headroom for slower
hosts. It is a regression ceiling taken from measurement, not a product requirement: if playback
sync needs a tighter figure, lower it here and in `loadtest.ControlP99Budget`.

`TestControlStreamLatencyBudget` (`internal/loadtest`) fails when the QUIC carrier exceeds the
budget. It runs in `make gate` and is skipped under `-short`. The constants are
`loadtest.ControlP99Budget` and `loadtest.ReferenceLink`.

**The default TLS/TCP carrier does not meet the budget** and the test does not hold it to one. See
the numbers and the recommendation below.

## Measurements

`go run ./cmd/relay-loadgen -mode latency -duration 20s`, Apple M2 Max, macOS, Go 1.27.4,
2026-11-17. Round-trip latency of the control stream, milliseconds.

| Carrier | Loss | Media | p50 | p99 | p99.9 | max | Media moved (both ways) |
|---|---|---|---|---|---|---|---|
| TCP + yamux | 0% | saturating | 743.5 | 810.5 | 878.7 | 886.6 | 40.6 Mbit/s |
| TCP + yamux | 1% | saturating | 743.7 | 881.2 | 896.0 | 905.7 | 40.6 Mbit/s |
| QUIC | 0% | saturating | 67.7 | 93.3 | 140.5 | 148.2 | 36.6 Mbit/s |
| QUIC | 1% | saturating | 30.8 | 64.3 | 77.0 | 81.9 | 17.6 Mbit/s |
| TCP + yamux | 0% | none | 20.8 | 36.7 | 53.5 | 57.9 | |
| TCP + yamux | 1% | none | 20.5 | 40.5 | 41.0 | 41.9 | |
| QUIC | 0% | none | 20.6 | 21.7 | 22.7 | 22.9 | |
| QUIC | 1% | none | 20.6 | 46.1 | 61.2 | 70.9 | |

The idle rows (`-media-streams 0 -duration 10s`) are the floor: the link's 20 ms round trip.

What the numbers say:

- On the TCP carrier a control message waits about 370 ms in each direction behind media. yamux
  frames every stream onto one TCP connection in arrival order, and the kernel's send buffer for
  that connection already holds media bytes, so a control frame cannot overtake them. The delay is
  the buffered media divided by the link rate: it grows as the uplink gets slower and with the
  host's send-buffer autotuning (4 MiB ceiling on this host). One earlier run on the same host,
  with larger proxy socket buffers, measured a 1.59 s p99.
- On the QUIC carrier each stream is scheduled separately, so the control stream waits only for
  the link queue (50 ms here) and never behind buffered media.
- 1% loss barely moves TCP in this harness because the queueing delay dominates and the loss model
  is kind to TCP (below). On QUIC, loss lowers control latency because the congestion controller
  backs off and the link queue stays short, at the cost of media throughput (17.6 against
  36.6 Mbit/s).

## How loss is injected

Real packet loss cannot be injected portably: Linux needs `tc`/netem and root
(`script/netem-soak.sh`), and macOS has no netem. The harness instead puts an in-process proxy,
`loadtest.Link`, between the tunnel client and the relay. Neither end is modified.

- **QUIC: real loss.** The UDP proxy drops each datagram with the configured probability and
  tail-drops when the queue is full. quic-go's own loss recovery does the rest.
- **TCP: modelled loss.** A TCP stream cannot lose bytes, so the proxy models what loss does to
  it: a lost segment and everything behind it on the connection is held for one round trip, the
  time a fast retransmit takes. There is no congestion-window cut and no retransmission timeout,
  so the TCP rows under loss are a best case. Real 1% loss would be worse for TCP, not better.

The proxy's own sockets are kept at 16 KiB so the bottleneck buffer is the configured queue. The
relay's and tunnel client's send buffers are left at the system defaults, because that is what
ships.

## Relay metrics

The relay now exports what it adds itself, per forwarded chunk, timed from the read on one side
to the completed write on the other:

- `beamfall_relay_stream_forward_seconds{direction}`
- `beamfall_relay_stream_forward_jitter_seconds{direction}`: absolute change between consecutive
  chunks of one stream direction.

`direction` is `to_carrier` or `to_client`, the only label. The relay reads the clock and never
the payload. These histograms see time spent blocked on a write, which is where a full carrier
shows up. They cannot see time a chunk spent in a kernel or carrier buffer before the relay read
it, so the end-to-end figure comes from the loadgen run above, not from these series alone.

## Recommendation on the default carrier

Make QUIC the default carrier for servers that carry control traffic next to media, with TLS/TCP
as the fallback when UDP is blocked. On the same link the QUIC carrier's control p99 is about a
ninth of the TCP carrier's (93 against 811 ms), and it is the only one inside the budget.

The default is not changed here. Switching it needs the QUIC listener exposed on hosted relays, a
client fallback to TCP when UDP does not get through, and core's tunnel client changed in step,
none of which is a one-line switch. Two smaller options would narrow the gap on the TCP carrier
and are worth a ticket each: cap the carrier socket's unsent backlog (`TCP_NOTSENT_LOWAT` or a
smaller send buffer), or carry control streams on a second carrier connection.
