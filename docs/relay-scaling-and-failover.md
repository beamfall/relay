# Relay horizontal scaling and failover

Status: scoping doc (RELAY-REVOKE-1). The hosted, multi-instance relay is future-roadmap per
ADR-0025; this document scopes the approach so the single-instance code shipping today does not
foreclose it. It does not describe a built multi-instance deployment.

## What one `relayd` instance is

A relay instance is stateless with respect to *routing*: it maps an incoming public TLS connection
to a live carrier purely by SNI hostname against its in-memory carrier registry (`internal/relay`
`registry`), then splices bytes without terminating client TLS (ADR-0018 §6, DMCA §512(a) blind
relay). Nothing about a spliced stream is persisted. That makes the byte path trivially replicable:
any instance that holds a carrier's live session can serve that carrier's public traffic.

The instance-local state that is **not** shared today, and therefore bounds horizontal scaling:

1. **Carrier registry** — which carriers are connected, and which hostnames each claims. A carrier
   dials exactly one relay instance and its session lives on that instance only. A public
   connection can only be served by the instance holding that carrier's session.
2. **Fair-use accounting** — per-tunnel rolling byte counters live in one process's memory and
   reset on restart (`docs/operator-self-hosted-relay.md`, "Single-instance ceiling"). Fanning one
   carrier across instances behind a load balancer multiplies the effective limit by the instance
   count, so it must not be done until accounting is shared.
3. **Replay-protection nonce cache** — `HostedTokenVerifier`'s accepted-nonce set is per-process and
   does not survive restart (`internal/relay/hosted_token.go`). Its safety rests on the short token
   TTL (currently ~5 min, ADR-0018 §5): the replay window a restart or a second instance opens is
   bounded to that TTL. Multiple instances each keep an independent nonce cache, so a stolen token
   could be replayed once per instance within its TTL until the cache is shared or made persistent
   (already flagged in that file as RV-RELAY-007).

## Token expiry and session lifetime (RELAY-REVOKE-1)

Carrier sessions are now torn down when their tunnel token's `expires-at` claim passes, not merely
refused on the next dial (`awaitCarrierEnd` in `internal/relay/relay.go`). This is a local timer over
the token's own already-verified, self-contained signed claim — **not** a fetched revocation list and
**not** a playback-time phone-home (those are prohibited for Entitlement Tokens by ADR-0024/0031;
carrier tunnel tokens are a distinct, revocable token class under ADR-0018 §5). Because tokens carry
a short TTL, the tunnel client proactively establishes a freshly authenticated carrier halfway
through the validity window. The same-identity registration immediately receives all new public
streams. The superseded session keeps only its existing streams until they finish, or until
`expires-at` plus `--expired-session-drain` (30 seconds by default); a carrier that never establishes
a replacement is still closed exactly at expiry. This bounds stale routing while avoiding a forced
rebuffer for streams already in flight.

## Horizontal-scaling approach (scoped, not built)

Two layers, taken in order of blast radius:

- **Stateless byte-path replication is already the easy part.** Multiple `relayd` instances can run;
  the constraint is that a public connection must land on the instance holding the target carrier's
  session. That is a routing problem, not a byte-path problem.

- **Carrier-to-instance routing** is the first thing a hosted deployment must add. Options, cheapest
  first:
  - *Sticky ingress by SNI hostname.* The public load balancer routes each customer subdomain to a
    fixed relay instance (one stable subdomain per customer already holds, ADR-0018 §6). Carriers
    dial the same instance. No shared routing state; the load balancer's host map is the source of
    truth. This is the recommended first step and scales to "many customers, each pinned to one of N
    instances."
  - *Shared carrier registry* (e.g. a small membership store keyed by hostname → instance) only if
    carriers must be able to dial any instance and have public traffic follow. Higher blast radius;
    defer until sticky ingress is proven insufficient.

- **Shared fair-use accounting and nonce store** must land *before* one carrier is ever fanned across
  instances. Until then, keep one carrier pinned to one instance (sticky ingress does this for free).
  A durable, TTL-indexed shared store (per the notes in `hosted_token.go` and
  `docs/operator-self-hosted-relay.md`) covers both the nonce cache and fair-use counters.

## Failover approach (scoped, not built)

- **Carrier reconnect is the failover primitive.** If an instance dies, its carriers' sessions drop;
  the tunnel client redials (initial connect or after any carrier drop, ADR-0018 §5) and re-reads a
  fresh token. Sticky ingress must fail the dead instance over to a healthy one (standard health-check
  + drain), after which carriers re-establish and public routing follows. No relay-side session state
  needs to migrate because none is durable.
- **In-flight streams are not migrated.** A blind splice cannot be handed off mid-stream without
  terminating TLS, which the relay must never do. Failover therefore drops live streams on the dead
  instance; clients re-request. This is acceptable given the connection-path fallback ordering already
  specified (LAN → direct HTTPS → overlay → self-hosted relay → hosted relay, ADR-0018 verification
  implications).
- **A shared Redis outage is not an instance failure.** With `RELAYD_FAIR_USE_STORE=redis`, every
  relay refuses new stream opens during the outage, and live streams continue for up to the lease
  budget (70s at the defaults) before the fence closes them. The per-duration table and its
  tuning flags are in `docs/hosted-relay-launch-runbook.md` (Redis Fair-Use Outage Policy).
- **Token TTL bounds stale-session risk during failover.** Because a session cannot outlive its token
  (RELAY-REVOKE-1), a partition that briefly leaves a carrier attached to a soon-to-be-drained
  instance self-heals at the token deadline even if health-checking is slow.

## Open items (tracked elsewhere)

- Durable shared fair-use accounting for multi-instance (ADR-0025; `docs/agent-memory/ideas.md`).
- Shared/persistent nonce store for the hosted verifier (RV-RELAY-007; `internal/relay/hosted_token.go`).
- These are prerequisites for fanning a single carrier across instances; single-carrier-per-instance
  (sticky ingress) needs neither and is the recommended launch posture.
