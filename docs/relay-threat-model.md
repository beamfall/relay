# Relay Threat Model

Beamfall Relay forwards encrypted client traffic between a public client and a home-server tunnel.
It is not a playback service and does not terminate the client's media TLS session.

## Relay Can Observe

- Carrier authentication success or failure.
- Tunnel connection times, disconnects, and accepted hostnames.
- Public client source address, TLS SNI, connection timing, duration, and byte counts.
- Aggregate relay metrics: active tunnels, active streams, total relayed bytes, handshake failures,
  capacity refusals, and fair-use counters.
- Short-lived operational logs needed to debug abuse, capacity, and reliability incidents.

## Relay Cannot Observe

- Relayed HTTP paths, headers, Stream Tokens, Profile ids, media ids, search terms, or playback state.
- Media payload bytes, subtitles, images, or library metadata inside the end-to-end TLS session.
- Watch history unless a client or server deliberately exposes it outside the relay protocol.

## Retention Bounds

Memory-mode fair-use buckets reset on `relayd` restart. Redis mode durably stages only bounded
aggregate records shaped as `{opaque tunnel digest, bytes, random batch id, created, expires}` in
a private local outbox. It never persists raw tunnel, server, account, hostname, stream, media,
request, or payload identifiers. Confirmed and expired records are durably removed; corrupt,
oversized, symlinked, non-private, locked, or unwritable state fails startup/admission closed.
Fair-use log lines use process-local tunnel pseudonyms rather than raw server or client identifiers.

Metrics are aggregate-only and label-free. Operational logs are transient operator logs; they are
not a durable viewing ledger and must stay within the published retention window for the deployment.

## Hosted Relay Custody

Beamfall Cloud owns the account-to-carrier mapping and checks hosted-relay entitlement before
minting a short-lived tunnel token. The relay receives only the opaque carrier id, hostnames, token
timing, nonce, and issuer/audience metadata; hosted token claims do not carry a Beamfall account id.
Relay-side fair-use/quota counters stay process-local and are not reported back to account systems.

## Byte-Blindness

The relay copies encrypted bytes and counts byte volume at the copy loop. It does not decrypt,
parse, sample, or classify relayed payloads. SNI is used only to route a public connection to the
matching carrier tunnel.

## Apple-Pinning Dependency

The byte-blind claim depends on Beamfall clients pinning and validating the home-server TLS identity
before sending playback requests through a relay. If a platform weakens that pinning, the relay can
still forward bytes, but Beamfall can no longer claim end-to-end byte-blindness for that client path.

## Residuals

- NGAUDIT-X-P18RELAY: Public connection logs redact remote addresses, SNI hostnames, and carrier ids
  by default, but the relay still observes the routable public SNI in memory to choose a carrier.
- NGAUDIT-X-P18RELAY: ECH does not remove that relay-routing dependency until clients and home
  servers support ECH with issuer-minted per-server relay public names. Hostname rotation belongs in
  the hosted hostname/token issuer, not in the relay router.
