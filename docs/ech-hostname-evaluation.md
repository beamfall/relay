> **Historical — evaluation complete (2026-07-03).** Result recorded below; kept as decision evidence (referenced by docs/operator-self-hosted-relay.md and core roadmap shard 21).

# ECH and Relay Hostname Evaluation

Date: 2026-07-03

## Result

Do not implement relay-hostname randomization or rotation inside `beamfall-relay`.

The relay does not issue public hostnames. It accepts hostnames from self-hosted flags or from
verified token claims, then routes public connections by the ClientHello SNI. Hosted hostname
randomization and rotation must be done by the hostname/token issuer so DNS, certificates, client
configuration, token claims, and carrier registration rotate together. Adding local randomization in
the relay would only break routing or produce names no client can resolve.

## ECH Evaluation

Go 1.26 `crypto/tls.Config` has client and server ECH fields:
`EncryptedClientHelloConfigList`, `EncryptedClientHelloKeys`, and
`GetEncryptedClientHelloKeys`.

That support does not directly harden the relay public listener because the relay does not terminate
public client TLS. The public listener peeks at the ClientHello, routes by visible SNI, and splices
the original bytes to the home server. Enabling server-side ECH on the carrier TLS listener would
only affect tunnel-client-to-relay authentication, not the public client SNI that drives routing.

Public-client ECH can help only when the client and home server support ECH and the outer
`public_name` is a relay-routable hostname. With the current relay router, that hostname must still
uniquely identify the carrier. Shared public relay names are not enough because the relay cannot
decrypt ECH to recover the inner home-server name.

## Required Issuer Work

- Mint random, per-server public relay hostnames in the hosted issuer.
- Keep token claims aligned with the currently active hostname set.
- Publish DNS and certificates for the rotated names before issuing claims.
- Keep overlap windows long enough for carrier reconnects and client caches.
- Retire old names only after active carrier sessions and DNS TTLs drain.

## Residual

Until issuer-backed rotation and client/home-server ECH support exist, the relay can redact logs but
still observes the routable public SNI needed to choose a carrier.
