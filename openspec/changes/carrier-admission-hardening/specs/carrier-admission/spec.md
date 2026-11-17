## MODIFIED Requirements

### Requirement: Unauthenticated carrier connections use a separate, per-source-capped budget

The relay SHALL admit a carrier connection that has not yet authenticated only within a pending
budget capped in total by `MaxPendingCarrierConns` and per source (IPv4 /32, IPv6 /64) by
`MaxPendingCarrierConnsPerSource`. The relay SHALL close a new connection on accept when its source
is at the per-source cap. When the total budget is full the relay SHALL admit the new connection
and close the oldest pending connection of the source that holds the most pending connections, so
the number of pending connections never exceeds the total cap. The relay SHALL release the pending
admission once the handshake succeeds or fails.

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

## ADDED Requirements

### Requirement: A panic in one connection's handler does not stop the relay

The relay SHALL recover a panic raised while handling a public or carrier connection, close that
connection, release what it held, count the panic in `beamfall_relay_connection_panics_total` and
log it without connection payload, and SHALL keep serving other connections.

#### Scenario: Handler panics during a carrier handshake

- **WHEN** a carrier connection's handler panics
- **THEN** the panic is counted, the connection's pending admission is released, and the next valid
  carrier completes its handshake
