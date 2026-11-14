# carrier-admission Specification

## Purpose
How the relay admits carrier connections before and after authentication: unauthenticated
connections draw on a small pre-auth budget capped per source, only authenticated carriers hold
carrier slots, and failed or idle handshakes feed the source throttle, so one source cannot
exhaust carrier capacity.

## Requirements

### Requirement: Unauthenticated carrier connections use a separate, per-source-capped budget

The relay SHALL admit a carrier connection that has not yet authenticated only within a pending
budget capped in total by `MaxPendingCarrierConns` and per source (IPv4 /32, IPv6 /64) by
`MaxPendingCarrierConnsPerSource`, and SHALL close the connection on accept when either cap is
reached. The relay SHALL release the pending admission once the handshake succeeds or fails.

#### Scenario: One source floods idle connections

- **WHEN** one source holds more idle, unauthenticated carrier connections than `MaxCarrierConns`
- **THEN** a valid carrier from another source completes its handshake and receives an Ack

#### Scenario: Per-source cap reached

- **WHEN** a source already holds `MaxPendingCarrierConnsPerSource` unauthenticated carrier
  connections and opens another
- **THEN** the relay closes the new connection without reading a frame

### Requirement: Authenticated carrier slots are reserved only after token verification

The relay SHALL reserve a `MaxCarrierConns` slot only after a carrier's token verifies and before
it sends the Ack, and SHALL hold the slot for the carrier's lifetime. When no slot is free the relay
SHALL reply with the error frame reason `"over capacity"` and close the connection.

#### Scenario: Authenticated carrier leaves the pending budget

- **WHEN** a carrier's handshake succeeds
- **THEN** it holds one carrier slot and no pending admission

#### Scenario: Authenticated cap reached

- **WHEN** a carrier authenticates while every carrier slot is held by authenticated carriers
- **THEN** the relay replies `"over capacity"` and closes the connection

### Requirement: Failed handshakes of every kind feed the per-source back-off

The relay SHALL record a handshake failure for the source when a carrier handshake times out or
ends before a complete hello frame, when the hello is invalid, when a QUIC carrier never opens its
handshake stream, and when the token is unauthorized.

#### Scenario: Handshake timeout

- **WHEN** a connection sends nothing until the carrier handshake timeout
- **THEN** the relay counts one failed handshake against its source

#### Scenario: Malformed hello

- **WHEN** a connection sends a hello with an unsupported protocol version
- **THEN** the relay replies `"invalid hello"` and counts one failed handshake against its source
