# Keep control streams inside the latency budget on the default TLS/TCP carrier

Ticket: CORE-2262 (`queue:core:main`).

## Why

On the default TLS/TCP carrier a small control stream (playback sync, clock exchange) waited about
0.8 s round trip while media saturated the same carrier, against 93 ms on the QUIC carrier and a
250 ms budget (`docs/relay-latency-budget.md`, CORE-2246). yamux puts every stream on one TCP
connection in arrival order, and the kernel's send buffer for that connection held media bytes it
had accepted but not yet sent. Send-buffer autotuning lets that backlog reach megabytes, and a
control frame written behind it cannot overtake it.

## Decision

For 1.0 the TLS/TCP carrier stays the default and each end bounds the carrier socket's unsent
backlog to 16 KiB. The two other options on the ticket are not taken for 1.0:

- **QUIC as the default with TCP fallback.** It needs the QUIC listener exposed on hosted relays, a
  client fallback when UDP is blocked, and core's tunnel client changed in step. It stays the better
  carrier for this traffic and is not ruled out after 1.0.
- **Control streams on a second carrier.** The relay forwards opaque TLS and cannot tell a control
  stream from media, so the split would need a protocol change on both ends.

A smaller send buffer (`SO_SNDBUF`) was also rejected: it caps bytes in flight as well as unsent
bytes, so it limits throughput to the buffer size per round trip.

## What Changes

- The relay's TLS/TCP carrier listener and the tunnel client's carrier dial bound the socket's
  unsent backlog to `protocol.CarrierUnsentLowat` (16 KiB). On Linux this is `TCP_NOTSENT_LOWAT`,
  which makes the kernel refuse a write while that much is unsent. macOS applies the option only to
  writability events, so there the connection is wrapped and each write first waits for the
  estimated unsent bytes to fall to the mark. Other platforms are unchanged.
- `TestControlStreamLatencyBudget` holds the TLS/TCP carrier to the 250 ms budget, with and without
  1% loss, on Linux. On macOS the TCP case is skipped: loopback there ignores the small receive
  buffer the link emulation sets on its proxy sockets, which adds a queue of about 400 KB (about
  200 ms at the reference rate) that is not part of the reference link. The macOS wrapper has its
  own test.
- `script/netem-latency.sh` repeats the measurement on Linux through a real `tc`/netem link in a
  private network namespace; `relay-loadgen -mode latency` gains the flags it needs.
- `docs/relay-latency-budget.md` records the decision and the new numbers.

## Not in this change

- Core's own tunnel client (`internal/remoteaccess` in beamfall/core) is the sending end for media
  in production. It needs the same bound; that is a core ticket. Until it lands, only the
  relay-to-home direction is bounded for real home servers.
- Windows home servers have no equivalent control here.
- The QUIC carrier is unchanged.
