# Relay latency budget for established streams

Tickets: CORE-2246 (budget), CORE-2262 (TCP carrier). Scope: the latency the relay and its carrier add to a stream that is already
open, as opposed to tunnel setup (`beamfall_relay_tunnel_setup_seconds`). The case that matters is
a small control stream (playback sync signals, clock exchanges) sharing a carrier with media.

## The budget

**A control stream's round-trip p99 stays at or below 250 ms while a media stream saturates the
same carrier in both directions**, on the reference link, with and without 1% packet loss. QUIC
meets it. The default TLS/TCP carrier meets it without loss and misses it with real 1% loss (see
the decision below).

- Reference link: 20 Mbit/s each way, 10 ms one-way delay (20 ms round trip), 50 ms bottleneck
  queue. It sits between the tunnel client and the relay's carrier listener.
- Control stream: one 64-byte message every 5 ms carrying its send time, echoed by the home
  server. The latency is client to home server and back, through the relay twice.
- Media: one stream writing as fast as the carrier accepts, in both directions.

Why 250 ms: the QUIC carrier measures 80 to 108 ms at p99 across runs, including under the race
detector, so the budget keeps a little over twice the worst measured value as headroom for slower
hosts. It is a regression ceiling taken from measurement, not a product requirement: if playback
sync needs a tighter figure, lower it here and in `loadtest.ControlP99Budget`.

`TestControlStreamLatencyBudget` (`internal/loadtest`) fails when a carrier exceeds the budget. It
holds the QUIC carrier on every host and the TLS/TCP carrier on Linux (why not macOS: see
[the macOS harness](#the-macos-harness-and-the-tcp-carrier)). It runs in `make gate` and is skipped
under `-short`. The constants are `loadtest.ControlP99Budget` and `loadtest.ReferenceLink`.

## Decision for 1.0 (CORE-2262)

**TLS/TCP stays the default carrier, and each end bounds the carrier socket's unsent send backlog
to 16 KiB** (`protocol.CarrierUnsentLowat`). Before this the TCP carrier measured 0.5 to 1.0 s at
p99; with it the carrier is inside the budget on the reference link without loss, and with the
harness's modelled loss. **With real 1% packet loss it is not**: 353 ms at p99 through `tc`/netem,
down from 1.57 s. What remains there is TCP's own loss recovery holding every stream behind a lost
segment, which no send-side setting removes. QUIC stays inside the budget in every case measured.

The options not taken for 1.0:

- **QUIC as the default, TCP as the fallback.** Still the better carrier for this traffic, and the
  only one that meets the budget under real loss. It needs the QUIC listener exposed on hosted
  relays, a client fallback when UDP is blocked, and core's tunnel client changed in step.
- **Control streams on a second carrier connection.** The relay forwards opaque TLS and cannot tell
  a control stream from media, so this needs a protocol change at both ends.
- **A smaller send buffer** (`SO_SNDBUF`). It caps bytes in flight as well as unsent bytes, so it
  limits throughput to one buffer per round trip.

How the bound works: on Linux `TCP_NOTSENT_LOWAT` makes the kernel refuse a write while 16 KiB is
unsent, so the writer waits. macOS applies that option only to writability events, so there each
write first waits until the send buffer holds no more than 16 KiB beyond what the congestion and
peer windows allow in flight (`TCP_CONNECTION_INFO`, polled every 0.1 ms at first, then every
millisecond). Neither limits bytes in flight, so throughput is about the same (see the "Media moved" column). Under real loss a
4 KiB bound measured the same as 16 KiB.

Limits of what ships:

- The relay bounds its own carrier sockets, and so does this repository's tunnel client. **Core's
  home server uses its own tunnel client**, which sends the media. It has the same bound on Linux
  and macOS from CORE-2282 (measured below); a home server older than that is bounded only in the
  relay-to-home direction.
- **Windows has no bound**, in the relay or in core's tunnel client: Windows has no
  `TCP_NOTSENT_LOWAT`. A home server on Windows using the TLS/TCP carrier still queues accepted
  media ahead of control streams. It has not been measured there; the Linux "before" rows are the
  nearest indication. CORE-2291 tracks it.

## Measurements

Round-trip latency of the control stream in milliseconds, one saturating media stream, 20 s runs,
Go 1.27.4, 2026-11-17. "Before" is the carrier without the bound.

### Linux, real `tc`/netem link

`script/netem-latency.sh` on WSL2 (kernel 6.18.33.2-microsoft-standard-WSL2, 32 cores). The
loadgen dials the relay's carrier port directly; netem shapes that port in a private network
namespace, each direction separately: 20 Mbit/s, 10 ms delay, an 83-packet netem limit (50 ms at
the link rate; it also counts the packets in the delay line, so the waiting queue is nearer 40 ms),
loopback MTU 1500 with segmentation offload off. Loss here is real packet loss for both carriers.

| Carrier | Loss | | p50 | p99 | p99.9 | max | Media moved (both ways) |
|---|---|---|---|---|---|---|---|
| TCP + yamux | 0% | before | 726.5 | 983.2 | 1149.3 | 1169.5 | 36.6 Mbit/s |
| TCP + yamux | 0% | bounded | 119.5 | 158.8 | 168.6 | 172.6 | 35.9 Mbit/s |
| TCP + yamux | 1% | before | 1001.8 | 1570.8 | 1717.1 | 1732.7 | 14.8 Mbit/s |
| TCP + yamux | 1% | bounded | 169.7 | **352.8** | 452.5 | 472.6 | 13.7 Mbit/s |
| QUIC | 0% | | 102.1 | 161.7 | 226.4 | 236.4 | 36.0 Mbit/s |
| QUIC | 1% | | 33.1 | 65.7 | 75.3 | 78.6 | 21.1 Mbit/s |

Two runs with a 4 KiB bound and 1% loss gave a TCP p99 of 349.9 and 327.8 ms, no better than
16 KiB. This is one host and a virtualised kernel; treat the figures as indicative.

### Linux, real `tc`/netem link, core's tunnel client as the carrier

The same link and host, with core's home server tunnel client (`internal/remoteaccess` at core
`ed8d56e5`, CORE-2282) registering as the carrier and sending the media, in place of this
repository's client. "Before" is core's client dialled without the bound. 4000 control messages
per run, all echoed.

| Carrier client | Loss | | p50 | p99 | p99.9 | max | Media moved (both ways) |
|---|---|---|---|---|---|---|---|
| core | 0% | before | 392.1 | 547.8 | 573.0 | 583.3 | 35.2 Mbit/s |
| core | 0% | bounded | 116.4 | 156.1 | 164.5 | 169.2 | 35.7 Mbit/s |
| core | 0% | bounded | 117.5 | 154.7 | 163.8 | 166.2 | 35.6 Mbit/s |
| core | 0% | bounded | 118.9 | 157.0 | 164.5 | 177.5 | 36.0 Mbit/s |
| core | 1% | before | 515.8 | 1051.7 | 1120.9 | 1126.2 | 13.6 Mbit/s |
| core | 1% | bounded | 164.2 | **329.5** | 373.3 | 387.6 | 14.5 Mbit/s |
| this repository | 0% | bounded | 116.0 | 153.3 | 160.8 | 164.7 | 34.9 Mbit/s |

Core's client is inside the budget without loss and matches this repository's client run in the
same session. With real 1% loss it is over the budget by the same margin as above, for the same
reason. The 1% rows are single runs.

To repeat it, build core's test binary and pass it as the carrier:

```sh
# in a core checkout
CGO_ENABLED=0 go test -c -o /tmp/remoteaccess.test ./internal/remoteaccess/
# in this repository
go build -o /tmp/relay-loadgen ./cmd/relay-loadgen
sudo BIN=/tmp/relay-loadgen DURATION=20s \
  CARRIER_CMD='/tmp/remoteaccess.test -test.run TestCarryForRelayLatencyHarness' \
  script/netem-latency.sh
```

With `CARRIER_CMD` set, the loadgen runs with `-external-carrier-dir`: it starts the relay with a
one-run HMAC secret, writes that secret (`relay-token`), the carrier CA (`relay-ca.pem`) and the
addresses (`carrier.env`) into a scratch directory, and waits up to 60 s for the outside carrier
to register before measuring. `CARRIER_UNBOUNDED=1` in the environment gives the "before" rows.

### Linux, in-process link

`relay-loadgen -mode latency -duration 20s` on the same host. This is the configuration the test
holds.

| Carrier | Loss | | p50 | p99 | p99.9 | max | Media moved (both ways) |
|---|---|---|---|---|---|---|---|
| TCP + yamux | 0% | before | 492.9 | 580.6 | 628.6 | 639.1 | 41.4 Mbit/s |
| TCP + yamux | 0% | bounded | 160.8 | 178.8 | 184.2 | 189.2 | 40.4 Mbit/s |
| TCP + yamux | 1% (modelled) | before | 399.2 | 474.3 | 506.8 | 516.6 | 41.6 Mbit/s |
| TCP + yamux | 1% (modelled) | bounded | 165.6 | 197.3 | 208.6 | 219.5 | 40.7 Mbit/s |
| QUIC | 0% | | 66.8 | 117.4 | 148.9 | 154.1 | 37.7 Mbit/s |
| QUIC | 1% | | 30.7 | 62.2 | 69.1 | 73.2 | 17.4 Mbit/s |

### macOS, in-process link

Apple M2 Max. The "before" and idle rows are the CORE-2246 runs.

| Carrier | Loss | Media | p50 | p99 | p99.9 | max | Media moved (both ways) |
|---|---|---|---|---|---|---|---|
| TCP + yamux | 0% | saturating, before | 743.5 | 810.5 | 878.7 | 886.6 | 40.6 Mbit/s |
| TCP + yamux | 0% | saturating, bounded | 475.9 | 530.2 | 538.0 | 545.1 | 40.4 Mbit/s |
| TCP + yamux | 1% (modelled) | saturating, before | 743.7 | 881.2 | 896.0 | 905.7 | 40.6 Mbit/s |
| TCP + yamux | 1% (modelled) | saturating, bounded | 504.0 | 614.6 | 647.7 | 657.7 | 40.4 Mbit/s |
| QUIC | 0% | saturating | 68.4 | 79.4 | 139.5 | 149.5 | 36.3 Mbit/s |
| QUIC | 1% | saturating | 28.9 | 58.9 | 74.9 | 85.5 | 18.8 Mbit/s |
| TCP + yamux | 0% | none | 20.8 | 36.7 | 53.5 | 57.9 | |
| TCP + yamux | 1% (modelled) | none | 20.5 | 40.5 | 41.0 | 41.9 | |
| QUIC | 0% | none | 20.6 | 21.7 | 22.7 | 22.9 | |
| QUIC | 1% | none | 20.6 | 46.1 | 61.2 | 70.9 | |

The idle rows (`-media-streams 0 -duration 10s`) are the floor: the link's 20 ms round trip.

### The macOS harness and the TCP carrier

The macOS TCP rows stay over the budget because of the harness, not the carrier. The emulated
link's proxy asks for 16 KiB socket buffers so that its only queue is the configured 50 ms. macOS
loopback does not honour that for the receive side: with the bound in place the carrier's own send
buffer held 16 to 100 KB, while the proxy's receive socket held 300 to 530 KB of unread carrier
bytes, about 200 ms at the link rate in each direction. Setting the buffer on the listener, on the
accepted socket, or again before each read did not change it. That queue does not exist on a real
link, so the macOS TCP rows overstate the carrier's latency and the test holds the TCP carrier on
Linux only. The macOS write path has its own test
(`TestBoundUnsentBacklogHoldsWriter`), which shows the writer is held; it has not been measured
end to end on a real link from a Mac, and its polling has not been measured above the 20 Mbit/s
reference link: on a much faster link the poll interval, not the congestion window, could pace a
saturated writer.

### What the numbers say

- Unbounded, a control message on the TCP carrier waits behind media the kernel has accepted but
  not sent. yamux frames every stream onto one TCP connection in arrival order, so a control frame
  cannot overtake those bytes. The wait is the buffered media divided by the link rate, so it grows
  as the uplink gets slower and with send-buffer autotuning.
- Bounded, what is left ahead of a control frame is the 16 KiB, the rest of the media frame being
  written (up to 32 KiB) and the link queue.
- Under real loss TCP delivers nothing behind a lost segment until it is retransmitted, and a lost
  retransmission waits for a timeout. That is the 353 ms p99, and it applies to every stream on the
  carrier. The in-process loss model leaves out the timeout and the congestion-window cut (below),
  which is why its 1% row is inside the budget and the netem row is not.
- On the QUIC carrier each stream is scheduled and recovered separately, so the control stream
  waits only for the link queue. Loss lowers its latency because the congestion controller backs
  off and the queue stays short, at the cost of media throughput.

## How loss is injected

Real packet loss cannot be injected portably: Linux needs `tc`/netem and root
(`script/netem-latency.sh`, above), and macOS has no netem. The in-process harness instead puts a proxy,
`loadtest.Link`, between the tunnel client and the relay. Neither end is modified.

- **QUIC: real loss.** The UDP proxy drops each datagram with the configured probability and
  tail-drops when the queue is full. quic-go's own loss recovery does the rest.
- **TCP: modelled loss.** A TCP stream cannot lose bytes, so the proxy models what loss does to
  it: a lost segment and everything behind it on the connection is held for one round trip, the
  time a fast retransmit takes. There is no congestion-window cut and no retransmission timeout,
  so the TCP rows under loss are a best case. The netem table shows the real figure.

The proxy's own sockets ask for 16 KiB buffers so the bottleneck buffer is the configured queue
(macOS does not honour this, above). The relay's and tunnel client's send buffers are left at the
system defaults, because that is what ships.

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

## After 1.0

Making QUIC the default carrier, with TLS/TCP as the fallback when UDP is blocked, is still the
way to meet the budget on a lossy link. It is not scheduled for 1.0 (see the decision above).
