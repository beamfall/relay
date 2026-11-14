# Beamfall Relay Protocol

Milestone 1 implements the ADR-0018 SniTun-style contract in Go. The relay has these
surfaces:

- public listener: accepts client TLS connections, peeks only the ClientHello SNI hostname,
  then forwards the original bytes into a tunnel stream.
- carrier listener: accepts authenticated outbound home-server carriers over TLS 1.3, then
  upgrades the connection to yamux.
- cache carrier: a second authenticated home-server carrier connection for the Media Cache
  surface. It is opt-in and separately versioned; passthrough deployments do not need it.

## Error frames

The relay sends an error frame and immediately closes the connection when:

- The first frame is not a valid hello, the `hello` field is nil, or `hello.version` does not
  match the relay's protocol version — reason `"invalid hello"`. This covers wrong frame type,
  malformed JSON, and version mismatches.
- Token verification fails — the `TokenVerifier` seam returned `ErrUnauthorized` or any error —
  reason `"unauthorized"`. Repeated unauthorized attempts from the same source IP are subject to
  exponential back-off **before** the token check runs (brute-force throttle on the carrier port).
  Invalid hellos and handshakes that time out or end before a full hello frame count toward the
  same per-source back-off. Unauthenticated connections are also capped in total and per source
  (IPv4 /32, IPv6 /64); over those caps the relay closes the connection without a frame.
- The token verified but the relay already holds its maximum number of authenticated carrier
  sessions — reason `"over capacity"`. Unauthenticated connections never hold these slots.

Error frame schema:

```json
{ "type": "error", "error": "<reason string>" }
```

No further frames follow an error frame. On receipt the carrier must close the connection. After
`"unauthorized"` or `"over capacity"` it may reconnect using the same exponential back-off
schedule as connection-loss reconnect (`backoffMin`–`backoffMax`); after `"invalid hello"` it should not retry until the
carrier software is updated (version mismatch).

## Reconnect and carrier lifecycle

The relay has no reconnect responsibility. The home-server carrier owns reconnection: on any
connection loss it re-dials with exponential back-off + jitter (`backoffMin`–`backoffMax`;
defaults 1 s–60 s, both configurable via `Config.BackoffMin`/`Config.BackoffMax`) and re-runs
the full handshake. The relay accepts the new connection as a fresh carrier registration.

**Same-identity reconnect** is explicitly allowed. If a reconnecting carrier's `verified.ID`
matches an existing registration whose yamux session is still open (relay has not yet received the
TCP FIN), the new registration silently overwrites the stale host mapping to avoid a split-brain
window during network blips. The old session receives no explicit relay-sent signal — it stops
receiving new public streams for the claimed hostnames; in-flight yamux streams on the old session
complete their own teardown independently and see EOF when the underlying TCP connection closes.

When a carrier's yamux session closes — cleanly or due to error — the relay unblocks from
`session.CloseChan()`, calls `registry.unregister`, and decrements `carriers_connected`. In-flight
public streams that already opened a yamux sub-stream complete their own teardown independently.

## Connection lifecycle timing

| Phase | Mechanism | Default |
|---|---|---|
| **Carrier handshake deadline** | `conn.SetReadDeadline(now + CarrierHandshakeTimeout)` set before reading the first frame; cleared immediately after the frame is read. The long-lived yamux session is not subject to this deadline. | 10 s |
| **Public SNI-peek deadline** | 5 s deadline passed as a call-site constant in `relay.go` to `sni.PeekClientHello` (the sni package itself accepts it as a parameter). | 5 s |
| **yamux session lifetime** | No idle timeout. Lives until `CloseChan()` fires (TCP close, read/write error, or `session.Close()` on server shutdown). | unbounded |
| **Shutdown grace** | On `Server.Shutdown`, the relay stops accepting new public connections and waits up to `ShutdownGrace` for in-flight relayed streams to drain before force-closing. Zero = immediate force-close. | configurable |
| **Expired-session drain** | A same-identity replacement receives new streams immediately. Its superseded predecessor retains only its existing streams and closes when the last one ends. Past its own token expiry it keeps them while a live same-identity carrier holds one of its hostnames, for at most `SupersededStreamMaxAge`; once no such carrier remains, for at most `ExpiredSessionDrain`. An unsuperseded carrier closes at expiry. | configurable |

## Version negotiation

The protocol has a single version (`version: 1`). The relay rejects any hello with a different
version with an `"invalid hello"` error frame and closes the connection. There is no downgrade
negotiation. Carriers must match the relay's protocol version.

The cache carrier is an additive extension on that same `version: 1` hello. `surface` is optional;
absent means `"passthrough"` for backward compatibility. A cache carrier sends
`"surface":"cache"` plus `cache_protocol_version`. The relay rejects unknown surfaces, cache fields
on a passthrough hello, missing cache verification keys, and cache protocol-version skew with the
same clean `"invalid hello"` error frame.

## Carrier Handshake

The carrier connection is TLS 1.3. Before yamux starts, the tunnel client writes one
length-prefixed JSON frame. Frame encoding: 4-byte big-endian `uint32` body length
(body only, header not included), followed by UTF-8 JSON. Maximum body size 64 KiB.

```json
{
  "type": "hello",
  "hello": {
    "version": 1,
    "token": "<opaque bytes, standard-base64-encoded in JSON>",
    "hostnames": ["home.relay.example"],
    "surface": "passthrough"
  }
}
```

- **`token`**: opaque bytes the relay passes verbatim to its `TokenVerifier` seam. The
  carrier obtains the token from its provisioning system; the relay does not interpret the
  token's internal structure. The relay never logs the token. relayd's default verifier
  (`--token-mode hmac`) expects a v2 carrier token; see "Carrier token v2" below. The hosted
  verifier (`internal/relay.HostedTokenVerifier`) applies the same 60-second `issued_at` leeway
  and rejects a token whose signed lifetime (`expires_at - issued_at`) exceeds 24 hours
  (`MaxHostedTokenTTL`).
- **`hostnames`**: one or more FQDNs to register. No port, no scheme, no wildcards. Each
  must match a hostname the relay is configured to accept.
- **`surface`**: optional discriminator. Empty/absent and `"passthrough"` are the legacy
  passthrough carrier. `"cache"` opens the Media Cache surface. Passthrough credentials must
  not register `"cache"` and cache credentials must not register passthrough.

Cache-surface hello:

```json
{
  "type": "hello",
  "hello": {
    "version": 1,
    "token": "<cache-carrier credential>",
    "hostnames": ["home.relay.example"],
    "surface": "cache",
    "cache_protocol_version": 1,
    "cache_verification_key": "<32+ random bytes, standard-base64-encoded in JSON>"
  }
}
```

- **`cache_protocol_version`**: Media Cache protocol version. Current value: `1`. It is separate
  from the passthrough carrier version so cache messages can evolve without changing byte-blind
  passthrough.
- **`cache_verification_key`**: per-carrier-session HMAC verification key for CacheAccessTokens.
  The relay accepts tokens signed by the current key and the immediately previous key after a
  reconnect, so rotation overlaps until the new connection is confirmed.

The relay calls its `TokenVerifier` seam with the opaque token bytes and requested
hostnames. On success it returns:

```json
{
  "type": "ack",
  "ack": {
    "version": 1,
    "carrier_id": "carrier-1",
    "hostnames": ["home.relay.example"],
    "surface": "passthrough"
  }
}
```

- **`carrier_id`**: opaque, informational. Stable for the lifetime of this connection;
  may change on reconnect. Intended for operator logs only — the carrier need not store
  or forward it.
- **`version`**: informational echo of the negotiated version. Carriers do not enforce
  this field and proceed regardless of its value — version enforcement
  happens at the hello stage (relay rejects mismatched hellos), not the ack. If a future
  relay sends a higher version in the ack, the carrier proceeds on the already-negotiated
  protocol.
- **`hostnames`**: the subset of requested hostnames the relay accepted.
- **`surface`**: informational echo of the registered surface. Absent means passthrough for
  legacy acks.

After the ack, both sides start yamux over the same TLS connection. **The relay takes the
`yamux.Server` role; the carrier takes the `yamux.Client` role.** The relay accepts streams
opened by inbound public connections; the carrier does not open streams toward the relay.
Each inbound public client connection opens one yamux stream on the carrier's session.

The cache carrier starts the same transport session after ack but does not carry public
passthrough streams. Cache prewarm, inventory, and miss/pull-through messages are scoped to this
dedicated session.

### Cache push and reconciliation frames

Every cache message is a length-prefixed JSON frame on a peer-opened cache-carrier stream. A cache
push frame is followed immediately by exactly `bytes` ciphertext bytes on the same stream; the
relay stores the payload and replies with one cache ack frame.

```json
{
  "type": "cache_push",
  "cache_push": {
    "segment_set_id": "segset_abc",
    "segment": "0001.m4s",
    "content_type": "video/mp4",
    "expires_at": "2026-07-07T12:00:00Z",
    "bytes": 1048576
  }
}
```

Ack schema:

```json
{
  "type": "cache_ack",
  "cache_ack": {
    "status": "stored",
    "quota": { "used_bytes": 1048576, "cap_bytes": 26843545600 }
  }
}
```

At quota, the relay rejects the pushed segment and does not evict existing entries:

```json
{
  "type": "cache_ack",
  "cache_ack": {
    "status": "rejected",
    "error": "quota_exceeded",
    "quota": { "used_bytes": 26843545600, "cap_bytes": 26843545600 }
  }
}
```

The home server reconciles warm-set state by opening a cache stream and sending:

```json
{
  "type": "cache_inventory_request",
  "cache_inventory_request": { "segment_set_id": "segset_abc" }
}
```

The relay replies with the currently held, unexpired segments for that segment set. TTL-expired
segments are removed before the inventory response, so expiry is server-visible on the next
reconciliation.

```json
{
  "type": "cache_inventory",
  "cache_inventory": {
    "entries": [
      {
        "segment": "0001.m4s",
        "bytes": 1048576,
        "content_type": "video/mp4",
        "expires_at": "2026-07-07T12:00:00Z"
      }
    ],
    "quota": { "used_bytes": 1048576, "cap_bytes": 26843545600 }
  }
}
```

### Cache pull-through frames

On a cache miss, the relay may hold the authenticated client request briefly and open one cache
carrier stream back to the home server. The relay sends a pull request for the same opaque segment
set and segment name; N concurrent client waiters for the same pair share that one pull. This is
additive to cache protocol version 1: clients still use the same CacheAccessToken and the same
`/cache/v1/segments/{segment}` URL.

```json
{
  "type": "cache_pull_request",
  "cache_pull_request": {
    "segment_set_id": "segset_abc",
    "segment": "0001.m4s"
  }
}
```

If the home server can serve it, the response frame is followed immediately by exactly `bytes`
ciphertext bytes on the same stream. The relay stores the payload under the existing quota/TTL
rules and serves the waiting client response.

```json
{
  "type": "cache_pull_response",
  "cache_pull_response": {
    "status": "found",
    "content_type": "video/mp4",
    "expires_at": "2026-07-07T12:00:00Z",
    "bytes": 1048576
  }
}
```

`"status":"not_found"` carries no body. Any rejected/error status is non-cacheable. Each client
waiter has its own bounded wait; timeout returns the same miss/fallback signal as v1 so an offline
home does not hold playback indefinitely. After a successful pull, the relay may sequentially pull
the next segment names, capped by measured upstream headroom.

## Carrier token v2

This section is normative for relayd's default carrier verifier, `--token-mode hmac`
(`internal/relay.HMACTokenVerifier`). It is written so a home server can mint conforming tokens
from this text alone. MUST, SHOULD and MAY are used as in RFC 2119.

The golden vectors in `contracts/protocol/v1/hmac-token-v2-vectors.json` are part of this
contract. `cmd/gen-vectors` mints them from fixed inputs by following this section (`make
gen-vectors`; `make verify-vectors` fails on any drift), and `internal/relay`
`TestHMACTokenV2VectorsMatchVerifier` replays every vector against the live verifier. A
conforming minter reproduces each vector's `mac_input_hex`, `mac_hex` and `token_text` from its
mint inputs; a conforming verifier reproduces each `verdict`.

### Shared key

The HMAC key is the operator's shared carrier secret: the contents of relayd's `--token-file` (or
the `RELAYD_TOKEN` environment value) with leading and trailing white space removed, used as raw
bytes. It is not base64-decoded. relayd refuses to start when the key is shorter than 32 bytes or
has fewer than 16 distinct byte values. The home server MUST mint with the same bytes. The key
never crosses the wire.

### Token format

The hello `token` is the ASCII text of five fields joined by `.` (0x2E). Like any hello token it
travels as standard base64 inside the JSON frame.

```text
v2.<issued_at>.<expires_at>.<nonce>.<mac>
```

| Field | Encoding |
|---|---|
| `v2` | The literal version tag. A token without the `v2.` prefix is not v2; relayd rejects it. |
| `issued_at` | Unix time in seconds, base-10 ASCII, no sign, no leading zeros. |
| `expires_at` | Same encoding. MUST be greater than `issued_at`. |
| `nonce` | 16 bytes from a cryptographically secure random source, as 32 lowercase hex characters. MUST be fresh for every token. |
| `mac` | HMAC-SHA256 over the MAC input below, as 64 lowercase hex characters. The relay compares this field as text, so uppercase hex is rejected. |

### Hostname normalization

Minter and relay normalize every hostname identically:

1. remove leading and trailing white space;
2. lowercase (hostnames are ASCII; internationalized names travel as A-labels);
3. remove one trailing `.`.

The MAC covers the normalized hostnames sorted in ascending byte order and joined with LF (0x0A).
Duplicates are kept. The hostnames are the hello's `hostnames`, so a token binds exactly the
hostnames its carrier requests: the minter MUST mint over the same list it sends in the hello. The
hello may list them in any order, in any letter case, and with or without the trailing dot.

### MAC input

```text
mac   = HMAC-SHA256(key, input)
input = "v2" 0x00 hosts 0x00 issued_at 0x00 expires_at 0x00 nonce
```

`hosts` is the sorted, LF-joined normalized hostname list; `issued_at` and `expires_at` are the
same canonical base-10 text as the token fields; `nonce` is the 32 hex characters exactly as they
appear in the token. There is no trailing separator. For example, vector `accept_multi_host`
(hostnames `home.relay.example` and `media.relay.example`) authenticates, with `<NUL>` for 0x00
and `<LF>` for 0x0A:

```text
v2<NUL>home.relay.example<LF>media.relay.example<NUL>1789999970<NUL>1790000090<NUL>d1c96997fcf920bdd4ac83a483a4bbb3
```

### Relay verification

The relay applies these checks in order and answers the first failure with the `"unauthorized"`
error frame (the reason stays inside the relay; the vectors name it in `reason`):

1. At least one hostname is requested, and every requested hostname, normalized, is in the
   relay's configured `--hostnames` set, normalized (`host_not_allowed`).
2. The token has the `v2.` prefix and exactly five fields.
3. `issued_at` and `expires_at` parse as base-10 64-bit integers and `expires_at > issued_at`.
4. `nonce` is 32 hex characters.
5. `mac` equals the MAC recomputed over the requested hostnames, compared in constant time
   (`bad_mac`).
6. `now + 60 >= issued_at`. The relay accepts an `issued_at` up to 60 seconds ahead of its own
   clock (`MaxIssuedAtSkew`) to absorb clock skew; a token issued further ahead is rejected
   (`issued_in_future`). The leeway applies to `issued_at` only, never to `expires_at`.
7. `expires_at - issued_at <= 300` seconds (`MaxHMACTokenTTL`). The cap bounds the signed
   lifetime, not the time remaining (`ttl_exceeds_cap`).
8. `now < expires_at`. A token is valid while the relay clock is on the half-open interval
   `[issued_at - 60, expires_at)` (`expired`).
9. The relay's persistent nonce store (`--hmac-nonce-store`) admits the nonce. Each nonce is
   admitted once; the store keeps it until its `expires_at`, keeps it across relayd restarts, and
   must be shared by every relay instance that serves the same hostnames. A nonce already
   admitted is rejected (`replayed_nonce`), and so is every token while the store is failing.

On success the relay registers the normalized requested hostnames in hello order and acks them.
relayd configures no fixed carrier ID, so `carrier_id` is the first of those hostnames. The
carrier session is bound to the token's `expires_at`: the relay closes a carrier that is still
open at that instant unless a same-identity replacement has superseded it (see "Expired-session
drain" under Connection lifecycle timing).

### Home-server minting and rotation

- Mint a new token, with a new nonce, for every dial: the first connection, every reconnect after
  a connection loss or an `"unauthorized"` error frame, and every rotation. Never store or re-send
  a token. A re-sent token is a replay and is rejected even inside its lifetime and even after the
  relay restarts.
- Set `issued_at` from the current clock truncated to whole seconds, never rounded up. Keep the
  home server's clock synchronized (NTP): the relay tolerates a home-server clock up to 60 seconds
  ahead of its own, and rejects a token from a clock further ahead until the relay's clock catches
  up. Because the cap applies to `expires_at - issued_at`, backdating `issued_at` to absorb skew
  shortens the usable lifetime by the same amount.
- Choose a lifetime of at most 300 seconds.
- Rotate before expiry. A carrier held longer than one token lifetime MUST establish a replacement
  carrier with a freshly minted token before the current token expires; otherwise the relay
  closes it at `expires_at` and public connections fail until the reconnect completes. The
  RECOMMENDED cadence is half the lifetime: the reference client (`cmd/tunnel-client`) mints with
  `--token-ttl` (default 5m) and dials its replacement at `ttl/2`. The replacement completes its
  handshake before the relay routes new public streams to it; the displaced carrier keeps the
  streams it already carries until they finish or the expired-session drain elapses.

### Vector file

`hmac-token-v2-vectors.json` holds a published fixture key (`shared_key_utf8`, never a deployable
secret), the relay's `allowed_hostnames`, `max_ttl_seconds`, and one entry per case:

- mint inputs: `mint_hostnames`, `issued_at_unix`, `expires_at_unix`, `nonce_hex`;
- mint outputs: `mac_input_hex` (the MAC input bytes), `mac_hex`, and `token_text`, the token the
  carrier presents (for `reject_bad_mac` its MAC field has one altered hex digit);
- verification inputs: `requested_hostnames`, `now_unix`, and optional `replay_of`;
- expectation: `verdict` (`accept` or `reject`), `reason` for rejects, and `accepted_hostnames`
  for accepts.

To replay a vector, configure a verifier with the fixture key, `allowed_hostnames`, a clock fixed
at `now_unix` and an empty nonce store; when `replay_of` is set, first present that vector's
`token_text` (it is accepted), then present this vector's `token_text` for `requested_hostnames`.

## Public Routing

The relay reads only enough bytes to parse one TLS ClientHello record and extract SNI. It
does not terminate TLS, hold public certificates, validate Stream Tokens, inspect HTTP, or
modify payload bytes. The bytes read for SNI are replayed into the yamux stream before the
remaining client connection bytes, so the home server receives a pristine ClientHello.

Connections are closed without an application response when:

- no ClientHello arrives before the SNI read deadline,
- the ClientHello has no SNI,
- the ClientHello exceeds the configured bound,
- no carrier is registered for the exact hostname,
- the carrier's concurrent-stream cap is exhausted (default: `MaxStreamsPerCarrier`, configurable
  per deployment; not communicated to the carrier in the ack — the carrier observes cap exhaustion
  only by the public client seeing a connection close).

## Observability

The admin listener exposes aggregate-only, label-free metrics:

- `/healthz`: plain `ok`. Liveness only — reports the admin listener is up, not that the
  relay is ready to carry traffic. A relay with zero connected carriers still returns `ok`
  here.
- `/readyz`: plain `ok` (200) when at least one carrier is connected, `not ready` (503)
  otherwise. Use this, not `/healthz`, for readiness checks.
- `/metrics`: Prometheus text format counters/gauges for connected carriers, active streams,
  bytes relayed, carrier handshake failures, public/carrier over-cap refusals, fair-use
  counters, and the published operational-log retention window. Metrics must not include
  per-tunnel, per-hostname, per-account, token, payload, or per-stream labels/records.

Logs may include hostnames, remote addresses, carrier ids, byte counts, errors, and
durations. Logs must not include token bytes or relayed payload bytes.

### Privacy posture (ADR-0103) — deliberate, not incidental

The relay's metadata surface is shaped to satisfy ADR-0103's data-minimization verification
implications *by design*, not by accident. Three properties are load-bearing and must be
preserved:

- **Aggregate-only metrics.** `/metrics` exposes label-free counters/gauges (see
  `internal/relay/metrics.go`). Do **not** add per-tunnel, per-hostname, or per-account labels;
  that would create a durable per-connection record joinable to a subject.
- **No durable per-connection record.** Memory-mode fair-use accounting resets on restart.
  Redis mode has a bounded, versioned local write-ahead outbox containing only an opaque tunnel
  digest, aggregate byte count, random idempotency key, and creation/expiry times. It contains no
  raw tunnel/account/hostname, stream, media, request, or payload data and is deleted after Redis
  confirms the batch or its fair-use window expires.
- **Transient logs only.** The hostname/remote-addr/byte-count fields above live in
  stdout/journal output, retained and rotated by the operator's infrastructure, not persisted
  in-repo.

ADR-0103 scopes the Self-hosted Relay OUT (the operator runs the infra), so this repo is not the
enforcement point today. When the Hosted Relay (ADR-0025) is built on this code, expand
RV-RELAY-010 in `docs/agent-memory/tests.md` to cover all four ADR-0103 obligations:
(a) no per-stream/per-hostname/per-account labels on `/metrics`;
(b) no durable per-connection record;
(c) transient log retention is bounded (days, not months) per ADR-0103 §2 — the operator's
    infrastructure must enforce this, and the Hosted Relay deployment config must document the bound;
(d) no per-stream metadata is written back to the account/entitlement record (account ↔ relay
    no-join requirement, ADR-0103 §3).
Byte-blindness itself is cryptographic via ADR-0046 client SPKI pinning; see AGENTS.md.
