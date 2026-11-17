# Keep carrier registration and the relay alive under pre-auth pressure and handler panics

Tickets: CORE-2253, CORE-2254 (`queue:core:main`). Found by the 2026-11-17 relay audit.

## Why

At the default caps, 64 idle connections spread over 8 source addresses held every pending
(unauthenticated) carrier admission for the 10 s handshake timeout, and a valid carrier was closed
on accept for as long as the connections were renewed. Carriers re-register at least every five
minutes, so a small sustained trickle took every home offline. Separately, no connection goroutine
recovered from a panic, so one panic in one connection's handler stopped relayd for every home.

## What Changes

- When the pending budget is full, a new carrier connection is admitted and the oldest pending
  connection of the source holding the most pending connections is closed. A source at its own cap
  is still refused.
- The default carrier handshake timeout drops from 10 s to 5 s.
- New counters: `beamfall_relay_carrier_pending_evicted_total` and
  `beamfall_relay_connection_panics_total`.
- A panic in a public or carrier connection handler is recovered, counted and logged; the
  connection is closed and the relay keeps serving.
- Doc drift fixed: `PROTOCOL.md` handshake and SNI-peek deadlines, the systemd unit's carrier cap
  comment.

## Impact

- `internal/relay` accept loops and pre-auth admission; metrics; operator docs.
- Not covered: a flood fast enough to evict a valid carrier within its own handshake, from as many
  distinct sources as the pending budget has entries. That needs rate limiting upstream of the relay.
