# Bound the memory stalled public readers can hold in relayd

Ticket: CORE-2252 (`queue:core:main`).

## Why

A public client that stops reading lets the home fill one carrier stream window in relayd before
flow control stops it: 4 MiB on the yamux carrier, held in a buffer that grows by doubling and can
reach 8 MiB, or 8 MiB on the QUIC carrier. Nothing closed such a client and nothing counted that
memory. At the shipped caps (1024 public connections, 64 streams per carrier, any number of
carriers) stalled readers could push relayd past its shipped 512 MiB memory limit. The kernel then
kills the process and every home on the relay drops. A home that rotated its carrier also got a
fresh stream cap while its superseded carrier kept its old streams, so one identity could hold
twice its cap. The packaging comments sized the memory limit from splice buffers alone.

## What Changes

- relayd takes a stream memory budget (`--stream-memory-budget-bytes`,
  `RELAYD_STREAM_MEMORY_BUDGET_BYTES`, default 320 MiB). It carries at most the budget divided by
  one stream's worst-case buffer and refuses public connections beyond that, counted in
  `beamfall_relay_stream_memory_budget_refusals_total`. At the defaults that is 40 streams.
- relayd closes a stream whose public client accepts no bytes for
  `--client-write-stall-timeout` (`RELAYD_CLIENT_WRITE_STALL_TIMEOUT`, default 5m) while the relay
  holds data for it, counted in `beamfall_relay_streams_stalled_closed_total`. Any bytes accepted
  restart the period.
- Streams on a superseded carrier count against the same per-identity stream cap as the live
  carrier of that identity.
- relayd sets the Go runtime's soft memory limit to the budget plus 128 MiB of headroom unless
  `GOMEMLIMIT` is set.
- The systemd and compose memory comments, the env example and the operator guide state the
  sizing rule: memory limit at least the stream memory budget plus 128 MiB.

## Non-goals

- Changing the shipped memory limit, the default stream window or any default connection cap.
- A per-home share of the stream memory budget. One home, or one source inside its own caps, can
  still take every slot of a small budget; the result is refused connections, not a dead relay.
- Bounding connections that idle before sending a ClientHello beyond the existing peek timeout.
- Closing clients that read slowly. Only a client that accepts nothing for the whole period is
  closed.
