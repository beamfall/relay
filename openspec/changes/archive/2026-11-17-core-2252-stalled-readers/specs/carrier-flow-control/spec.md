## ADDED Requirements

### Requirement: Relayed streams stay inside a stream memory budget

The relay SHALL carry at most as many streams at once as its stream memory budget divided by one
stream's worst-case buffer, across all carriers, and SHALL refuse a public connection that would
exceed that number. The worst-case buffer of a stream SHALL be twice the yamux stream window, or
the QUIC stream receive window when the QUIC carrier is enabled and that window is larger. The
default budget plus the relay's documented headroom SHALL fit the shipped memory limit.

#### Scenario: Stalled readers at the stream limit

- **WHEN** as many public clients as the stream limit allows each stop reading while their home keeps sending
- **THEN** the heap those streams hold in the relay stays at or under the stream memory budget

#### Scenario: Connection beyond the budget

- **WHEN** a public connection arrives while the relay already carries its stream limit
- **THEN** the relay closes that connection and counts a stream memory budget refusal

#### Scenario: Stream cut short while the home keeps sending

- **WHEN** the relay closes a stream before its home has closed its end
- **THEN** the stream still counts against the stream limit until the carrier has released it

#### Scenario: Default budget fits the shipped limit

- **WHEN** the relay runs with its default stream memory budget
- **THEN** the budget plus the documented headroom is at most 512 MiB

### Requirement: A public client that accepts no bytes is closed

The relay SHALL close a stream when its public client accepts no bytes for the client write stall
timeout while the relay holds data for it. A client that accepts any bytes within the timeout
SHALL keep its stream, and a stream with nothing to send to the client SHALL NOT be closed for
that reason.

#### Scenario: Reader that never reads

- **WHEN** a public client accepts no bytes for the client write stall timeout while its home keeps sending
- **THEN** the relay closes the stream and counts a stalled close

#### Scenario: Paused reader that resumes

- **WHEN** a public client stops reading for less than the client write stall timeout and then reads again, repeatedly, for longer than the timeout in total
- **THEN** the stream stays open and no stalled close is counted

### Requirement: Superseded carriers share their identity's stream cap

Streams on a superseded carrier SHALL count against the same per-identity stream cap as streams on
the live carrier of that identity.

#### Scenario: Rotation while the cap is full

- **WHEN** an identity's superseded carrier holds as many streams as the stream cap and a public connection arrives for its live carrier
- **THEN** the relay refuses that connection

#### Scenario: Superseded stream ends

- **WHEN** a stream on the superseded carrier closes
- **THEN** the identity's live carrier can open one more stream
