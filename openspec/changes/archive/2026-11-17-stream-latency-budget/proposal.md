# Measure and budget the latency the relay adds to established streams

Ticket: CORE-2246 (`queue:core:main`).

## Why

The relay's only latency metric covered tunnel setup. Nothing measured the delay added to a stream
that is already open, so there was no way to say whether small control messages (playback sync
signals, clock exchanges) are held up when media saturates the same carrier. The default carrier
puts every stream on one TLS/TCP connection, where that is a known risk.

## What Changes

- The relay exports `beamfall_relay_stream_forward_seconds` and
  `beamfall_relay_stream_forward_jitter_seconds`, labelled only by direction, timed from a chunk
  being read on one side to written on the other.
- `relay-loadgen -mode latency` reports p50/p99/p99.9 round-trip latency of a small control stream
  while a media stream saturates the same carrier, for the TCP and QUIC carriers, with and without
  loss, over an in-process emulated link (`internal/loadtest`).
- `docs/relay-latency-budget.md` states the budget (control-stream p99 at or below 250 ms on the
  reference link), the measurements, and the recommendation on the default carrier. A test
  enforces the budget on the QUIC carrier.

## Non-goals

- Changing the default carrier. The doc recommends QUIC; the switch needs listener exposure, a
  client fallback and a matching core change.
- Reducing the TCP carrier's latency. The doc names two options for follow-up tickets.
- Per-carrier, per-hostname or per-stream latency series.

## Failure modes

- The histograms add two clock reads and two observations per forwarded chunk (up to 32 KiB).
- The budget test runs a saturated carrier for about ten seconds and depends on wall-clock time.
  It has a little over twice the worst measured p99 as headroom and is skipped under `-short`.
- TCP loss in the harness is modelled, not real, and understates what loss costs TCP. The doc says
  so next to the numbers.

## Acceptance evidence

- `internal/relay/metrics_test.go`: `TestForwardTimerRecordsLatencyAndJitter` and the exposition
  check for both directions.
- `internal/loadtest/latency_test.go`: `TestControlStreamLatencyBudget` (QUIC p99 80 to 108 ms
  against 250 ms across runs under `-race`), `TestLinkDelaysBothCarriers` and the link model tests.
- `go run ./cmd/relay-loadgen -mode latency -duration 20s`: TCP p99 810.5 ms and 881.2 ms at 1%
  loss; QUIC p99 93.3 ms and 64.3 ms at 1% loss.

## Rollback

Revert the change. The metrics are additive and nothing reads them.
