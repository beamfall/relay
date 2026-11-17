# Make QUIC the default carrier, with TLS/TCP as the fallback

Ticket: CORE-2283 (`queue:core:main`).

## Why

With the unsent-backlog bound of CORE-2262 the TLS/TCP carrier keeps a small control stream inside
the 250 ms budget on the reference link without loss, but through real 1% packet loss it measures
330 to 353 ms. What remains is TCP loss recovery: one lost segment holds every yamux stream on the
connection until it is retransmitted, and no send-side setting removes that. The QUIC carrier
recovers loss per stream and measured 66 ms in the same run. A lossy uplink (bar Wi-Fi) is the case
that matters for synchronised screens.

## Decision

QUIC becomes the default carrier and TLS/TCP the fallback. The other option on the ticket, carrying
control streams on a second carrier connection, is not taken: the relay forwards opaque TLS and
cannot tell a control stream from media, so the split needs a protocol change at both ends and a
second authenticated connection per home, and the media carrier would still stall under loss.

- **Client.** A new carrier transport `auto` is the default. It tries QUIC at the relay address
  (same host and port, UDP) for at most 3 seconds, covering the dial, the handshake and the
  registration. If that fails without the relay answering, it connects over TLS/TCP with a fresh
  token and does not try QUIC again for 10 minutes. A refusal the relay sends over QUIC (bad token,
  hostname not allowed) is returned as it is: TCP would be refused the same way. `tcp` and `quic`
  remain as explicit choices and never fall back.
- **Relay.** `relayd` listens for QUIC carriers on the carrier address by default (same port
  number, UDP). `--quic-addr off` disables it. The stream budget is unchanged: the per-stream
  memory cost was already the larger of the two carriers' costs.
- **Hosted relays** must allow UDP on the carrier port next to TCP. A relay that does not, or an
  older relay without the listener, costs each connection attempt at most 3 seconds once per 10
  minutes, and the carrier then runs over TLS/TCP with the CORE-2262 behaviour.

## What Changes

- `internal/tunnel`: `TransportAuto`, the default; QUIC first, TLS/TCP fallback, hold-off; the
  transport in use is logged on connect.
- `cmd/tunnel-client`: `-transport` defaults to `auto`.
- `cmd/relayd`: `--quic-addr` defaults to the carrier address; `off` disables.
- `internal/loadtest`, `cmd/relay-loadgen`, `script/netem-latency.sh`: the harness can measure the
  default configuration, an external carrier on any transport, and a link that drops UDP.
- `docs/relay-latency-budget.md`, `docs/operator-self-hosted-relay.md`, packaging examples.

## Not in this change

- Core's tunnel client (`internal/remoteaccess` in beamfall/core) gets the same default in a core
  change under the same ticket.
- No protocol change: the QUIC carrier and its ALPN are those of ADR-0018 v2.
