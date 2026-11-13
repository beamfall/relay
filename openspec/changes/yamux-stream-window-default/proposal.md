# Raise the default yamux stream window to 4 MiB

Ticket: CORE-1386 (`queue:core:main`).

## Why

The v1 carrier's per-stream yamux window defaulted to 1 MiB. hashicorp/yamux v0.1.2 refills a
stream's window only after the reader drains half of it, so a single relayed stream was held to
about 10 MB/s at 50 ms and 3.4 MB/s at 150 ms on a delayed loopback link. A 4K remux at 60-100
Mbps stalled for any viewer more than ~50 ms from the relay. The comment that 1 MiB left headroom
for 40 Mbps at 50 ms ignored the half-window refill.

## What Changes

- `protocol.DefaultYamuxStreamWindowBytes` rises from 1 MiB to 4 MiB, the low end of the ticket's
  4-8 MiB range, which keeps one stream above 40 MB/s at 50 ms.
- The doc comments, the `relayd` and `tunnel-client` flag help and the operator guide state the new
  default, the half-window effect, and the worst-case buffering cost.
- A benchmark measures single-stream throughput over a loopback link with injected round-trip
  delay; a unit test checks the default against the 40 MB/s at 50 ms target.
- Core's matching default, override and `StreamCloseTimeout` land in core under the same ticket.

## Non-goals

- Changing the QUIC carrier's windows, which are already 8 MiB per stream.
- A session-wide receive budget across streams.

## Failure modes

- A stream whose reader stalls can buffer up to one window on the receiving side, so worst-case
  relay memory for stalled streams rises from `--max-public-conns` × 1 MiB to × 4 MiB (4 GiB at the
  default 1024 connections). Reaching it needs every stream's consumer to stall while its home
  server keeps sending. Operators on small hosts can lower `--yamux-stream-window-bytes`.
- Windows that differ between peers still interoperate: each receiver's setting bounds the
  direction it receives.

## Acceptance evidence

- `internal/protocol/yamux_throughput_test.go`:
  - `TestDefaultYamuxStreamWindowSustainsTarget` fails at 1 MiB (10.5 MB/s bound) and passes at
    4 MiB.
  - `BenchmarkYamuxStreamThroughputRTT` measured on an M2 Max: 9.95 → 81 MB/s at 50 ms, and
    3.4 → 28.5 MB/s at 150 ms.
- `make gate`.

## Rollback

Set `--yamux-stream-window-bytes 1048576` on relayd, or revert the change.
