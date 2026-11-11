# Relay — Context glossary

Domain language for the Beamfall relay. Terms only — no implementation detail.

| Term | Meaning |
| --- | --- |
| **Passthrough** | The original byte-blind surface (ADR-0018/0046): SNI-peek TLS forwarding; the relay never reads or terminates client traffic. |
| **Media Cache surface** | The separate, opt-in relay surface (ADR-0188) that stores and fans out encrypted media segments. Distinct from the Passthrough; its absence means the feature is simply not offered. |
| **Segment** | A chunk of a media stream, encrypted by the home server before it reaches the relay. The unit of caching, fan-out, and prewarm. |
| **Content key** | The key a segment is encrypted with. Shared only between home server and clients; the relay never holds one. |
| **Fan-out** | Delivering one cached segment to many clients, so the stream crosses the home upstream once. |
| **Prewarm** | The home server pushing segments to the Media Cache before they are needed: predictive idle push (on-deck/pinned titles) or ahead-of-playhead buffering. Always server-initiated, always yields to live playback. |
| **Prewarm-hit-rate** | Fraction of prewarmed segments later watched (vs expired). The tuning and honesty signal for prewarm policy. |
| **Deterministic identity** | The invariant that a cache key is a pure function of content (Media, fingerprint, rendition/segment), never of session state. Same key ⇒ same bytes. |
| **Relay rendition** | The encrypted fMP4-HLS form of a title as cached at the relay: either a precomputed HLS rendition or a transient stream-copy remux of a direct-play file. The only format the Media Cache stores. |
| **CacheAccessToken** | A relay-verifiable, server-minted token authorizing fetches from the Media Cache. Distinct family from Stream Tokens; scopes an opaque Segment-set ID + expiry. |
| **Segment-set ID** | A random, tenant-namespaced opaque identifier for one title's cacheable segments (per Media + fingerprint + rendition). The relay's only view of content identity. |
| **Carrier** | The authenticated home-server tunnel connection (TLS 1.3 + hello + yamux) of the Passthrough. |
| **Issuer** | The control plane that mints tunnel/cache tokens for carriers. The relay trusts whichever issuer it is configured with (name + public key set); Beamfall Cloud is one issuer among many, not a privileged one. |
| **Operator** | The party running a relay deployment (one box or a fleet), possibly commercially. Owns customer relationships, entitlement, and billing — all of which live in the operator's issuer control plane, never in the relay. |
| **Metering surface** | The opt-in (default-off) admin surface exposing monotonic, cumulative per-carrier byte counters for operator billing. In-memory only, no timestamps or buckets, opaque carrier IDs, enforced minimum scrape interval. The issuer-side collector — not the relay — derives billable totals. |
