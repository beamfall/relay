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
`MaxPendingCarrierConnsPerSource`. A new connection from a source at its cap SHALL be closed on
accept. When the total is full the relay SHALL admit the new connection and close the oldest pending
connection of the source holding the most. The admission SHALL be released when the handshake ends.

#### Scenario: One source floods idle connections

- **WHEN** one source holds more idle, unauthenticated carrier connections than `MaxCarrierConns`
- **THEN** a valid carrier from another source completes its handshake and receives an Ack

#### Scenario: Per-source cap reached

- **WHEN** a source already holds `MaxPendingCarrierConnsPerSource` unauthenticated carrier
  connections and opens another
- **THEN** the relay closes the new connection without reading a frame

#### Scenario: Idle connections from many sources fill the pending budget

- **WHEN** idle connections from several sources hold every pending admission at the default caps
- **THEN** a valid carrier from another source completes its handshake and receives an Ack, and one
  idle connection is closed

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

### Requirement: A panic in one connection's handler does not stop the relay

The relay SHALL recover a panic raised while handling a public or carrier connection, close that
connection, release what it held, count the panic in `beamfall_relay_connection_panics_total` and
log it without connection payload, and SHALL keep serving other connections.

#### Scenario: Handler panics during a carrier handshake

- **WHEN** a carrier connection's handler panics
- **THEN** the panic is counted, the connection's pending admission is released, and the next valid
  carrier completes its handshake
