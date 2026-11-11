# Relay CGNAT Bootstrap Audit

Status: NGAUDIT-B13 moot by NGAUDIT-B12 evidence.

## Decision

Do not make ACME-through-relay the required CGNAT bootstrap. For native clients, NGAUDIT-B12 removed
the ACME dependency: every Core server now has a persistent self-signed TLS identity, the LAN
enrollment response pins that identity's SPKI, and overlay/relay traffic presents that same identity
even when direct HTTPS/ACME is also configured.

The canonical CGNAT path is therefore:

1. Pair once on LAN and record Core's self-signed SPKI pin.
2. Point the relay hostname DNS at the public relay.
3. Let the home server open the outbound carrier to the relay.
4. Have native clients connect through the relay and validate the pinned Core identity.

## Evidence

- `beamfall/internal/app/app_test.go`:
  `TestRunSelfSignedServesBothSchemesAndPinMatches` proves a LAN-only server serves HTTPS with the
  persistent self-signed identity and that the served SPKI matches the enrollment pin.
- `beamfall/internal/app/app_test.go`:
  `TestAdvertisedEndpointsAreConnectableWithAdvertisedScheme` proves the advertised direct,
  overlay, and self-hosted-relay endpoints all handshake with the advertised scheme; direct FQDN SNI
  serves the ACME cert, while overlay and self-hosted relay serve the LAN-enrolled self-signed SPKI.
- `beamfall/docs/adr/0046-client-cert-pinning.md` section 7 records the accepted amendment:
  self-signed baseline identity for every server, pinned by native clients.
- `beamfall/docs/adr/0118-guarded-static-carrier-cert-for-relay-e2e.md` records that the old
  "no cert => carrier off" premise is superseded; the carrier terminates against the server's own
  pinned identity.

## Residual

Browser-trusted direct public-domain access still needs ACME or another browser-trusted certificate.
That is a browser compatibility residual, not a blocker for the native-client CGNAT relay bootstrap.
