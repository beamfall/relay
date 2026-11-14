# Separate pre-auth and authenticated carrier budgets

Ticket: CORE-1385 (`queue:core:main`).

## Why

The relay held one carrier slot per connection from accept until the yamux session closed, and the
same `MaxCarrierConns` budget (64) bounded both connections still in the handshake and
authenticated carriers. A single source that opened 64 TCP connections and sent nothing held every
slot for the whole handshake timeout, so a valid home-server carrier from anywhere else was closed
on accept. The handshake throttle counted only bad tokens, so idling through the timeout or sending
a malformed hello cost the source nothing and could be repeated indefinitely. The default of 64 also
ignored carrier rotation: core opens a replacement every two minutes and the superseded carrier
stays until its streams drain, so each home server briefly holds two carriers.

## What Changes

- Connections that have not authenticated take a **pending** admission, capped in total
  (`MaxPendingCarrierConns`, default 64) and per source (`MaxPendingCarrierConnsPerSource`,
  default 8, IPv4 /32 and IPv6 /64). Over either cap the relay closes the connection on accept. The
  admission is released as soon as the handshake is decided.
- An **authenticated** carrier slot (`MaxCarrierConns`) is reserved only after the token verifies
  and before the Ack, so unauthenticated connections can never refuse a valid carrier. Over the cap
  the relay writes the error frame `"over capacity"`, which core and the tunnel client treat as a
  retryable rejection.
- The `MaxCarrierConns` default rises from 64 to 256 (about 128 home servers with the rotation
  overlap), and its docs say to size it for twice the number of home servers.
- A handshake that times out or ends before a full hello frame, an invalid hello, and a QUIC
  connection that never opens its handshake stream now count toward the per-source handshake
  back-off, like a bad token.
- `relayd` gains `--max-pending-carrier-conns` and `--max-pending-carrier-conns-per-ip`; a new
  counter `beamfall_relay_carrier_pending_per_source_over_cap_total` reports per-source refusals.
- `PROTOCOL.md` and the operator guide describe the budgets and the new error reason.

## Non-goals

- Changing token verification, the back-off schedule or the public-listener caps.
- Per-identity caps on authenticated carriers.

## Failure modes

- A source behind a large NAT running more than eight home servers that reconnect at the same moment:
  connections over the per-source cap are closed and retried by core's reconnect back-off. The cap
  applies only during the handshake, so established carriers are unaffected.
- A distributed flood from many sources can still fill the pending budget; it then delays, but no
  longer blocks, carriers that are already connected, and each source's repeated timeouts now feed
  its back-off.
- An older client receiving `"over capacity"` logs `relay rejected carrier` and reconnects, the
  same path as any non-`"invalid hello"` rejection.

## Acceptance evidence

- `internal/relay/carrier_preauth_test.go`:
  - Sixteen idle connections from one source against `MaxCarrierConns=4` cannot block a valid
    carrier from another source.
  - An authenticated carrier moves from the pending budget to a carrier slot.
  - Handshake timeouts and a malformed hello count against their source.
  - All three fail on the previous code.
- `internal/relay/backoff_slot_test.go` keeps the SECREV-RELAY-8 guarantee that back-off holds no
  carrier slot.
- `cmd/relayd/main_test.go` maps the new flags into the relay config.
- `make gate`.

## Rollback

Raise `--max-pending-carrier-conns-per-ip` to the pending total to drop the per-source cap without
a redeploy, or revert the change.
