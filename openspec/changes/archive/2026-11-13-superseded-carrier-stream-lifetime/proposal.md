# Keep superseded-carrier streams alive while the identity holds a live carrier

Ticket: CORE-1382 (`queue:core:main`).

## Why

Core mints five-minute carrier tokens and opens a replacement carrier every two minutes. New
streams route to the replacement at once; the superseded carrier keeps the streams already on it.
When the superseded carrier's own token expires, the relay gives it `ExpiredSessionDrain` (30 s by
default) and then closes the yamux session, which kills every stream still on it. A relayed
connection that stays open longer than about five minutes (a long download, an HTTP keep-alive
connection, a playback stream) is therefore cut mid-transfer even though the same identity holds a
valid, freshly rotated carrier the whole time. Core cannot move an open stream to the new carrier,
so the relay is the only place this can be fixed.

## What Changes

- A superseded carrier whose token has expired keeps its existing streams while a live carrier of
  the same identity still holds at least one of its hostnames. That live carrier is the identity's
  current registration, which the relay itself closes at its own token expiry, so the identity's
  authority stays bounded by a valid token.
- A new `SupersededStreamMaxAge` setting (`--superseded-stream-max-age`, default `4h` in `relayd`)
  caps how long past its own token expiry a superseded carrier may keep streams. Zero disables the
  extension and restores the previous behaviour.
- When no live same-identity carrier remains (core stopped rotating, the identity was revoked, or
  the replacement disconnected), the existing rule applies from that moment: the superseded carrier
  gets `ExpiredSessionDrain` for its streams to finish, then closes.
- Unsuperseded carriers still close at token expiry. New streams never route to a superseded
  carrier. A superseded carrier still closes as soon as its last stream ends.
- `PROTOCOL.md`, the operator guide and the scaling guide describe the new lifetime.

## Non-goals

- Migrating open streams between carriers, or refreshing a token in-band on an open carrier.
- Changing token TTLs or core's rotation interval.
- Cache-surface carriers, which have their own registry and lifetime.

## Failure modes

- Identity revoked: the current carrier closes at its own token expiry (at most one TTL); within
  about a second the superseded carriers see no live successor and close after
  `ExpiredSessionDrain`. The revocation bound grows from expiry plus drain to the current carrier's
  expiry plus drain, at most one more token TTL.
- A stream that never ends: closed when `SupersededStreamMaxAge` elapses after the carrier's token
  expiry.
- Resource retention: a superseded carrier with no streams closes at once, so held sessions are
  bounded by streams actually in use and by the per-carrier stream cap.

## Acceptance evidence

- `internal/relay/relay_test.go`: a stream on a superseded carrier keeps reading bytes well past
  its token expiry plus `ExpiredSessionDrain` while a replacement is live; with a short
  `SupersededStreamMaxAge` the same stream is cut.
- An internal registry test covers the live-successor check: same identity live, successor closed,
  different identity, and no successor.
- `cmd/relayd/main_test.go` maps `--superseded-stream-max-age` into the relay config.
- `make gate`.

## Rollback

Set `--superseded-stream-max-age=0` to restore the previous lifetime without a deploy of new code,
or revert the change.
