## ADDED Requirements

### Requirement: The tunnel client prefers the QUIC carrier and falls back to TLS/TCP

With the default carrier transport the tunnel client SHALL first try the QUIC carrier at the relay
address and, when that attempt fails without an answer from the relay within 3 seconds, SHALL
connect over TLS/TCP in the same attempt using a newly obtained token. After a fallback that
connected it SHALL NOT try QUIC again for 10 minutes. An explicitly configured `tcp` or `quic`
transport SHALL use only that transport.

#### Scenario: Relay reachable over UDP

- **WHEN** a tunnel client with the default transport connects to a relay whose QUIC carrier listener is reachable
- **THEN** the carrier runs over QUIC

#### Scenario: UDP does not reach the relay

- **WHEN** a tunnel client with the default transport connects to a relay that it can reach over TCP only
- **THEN** the carrier goes live over TLS/TCP, and the token presented over TLS/TCP was obtained after the QUIC attempt failed

#### Scenario: Reconnect after a fallback

- **WHEN** the carrier reconnects within 10 minutes of a fallback
- **THEN** it dials TLS/TCP without trying QUIC first

#### Scenario: Relay refuses the carrier over QUIC

- **WHEN** the relay answers the QUIC registration with a refusal frame or by closing the connection
- **THEN** the attempt fails with that answer, TLS/TCP is not tried and QUIC is not held off

#### Scenario: Neither transport connects

- **WHEN** the QUIC attempt gets no answer and the TLS/TCP attempt fails too
- **THEN** the next attempt tries QUIC first

### Requirement: The relay accepts QUIC carriers by default

`relayd` SHALL listen for QUIC carriers on the carrier address (the same port number, UDP) unless
the QUIC carrier address is configured otherwise, and SHALL NOT listen for QUIC carriers when that
setting is `off`.

#### Scenario: Default configuration

- **WHEN** `relayd` starts with no QUIC carrier address configured
- **THEN** its QUIC carrier address is its carrier address

#### Scenario: Unverified source address

- **WHEN** a QUIC packet opens a new connection to the carrier listener
- **THEN** the relay answers with a Retry and starts the TLS handshake only after the source address returns its token

#### Scenario: Disabled

- **WHEN** `relayd` starts with the QUIC carrier address set to `off`
- **THEN** it has no QUIC carrier listener

## RENAMED Requirements

- FROM: `### Requirement: Control traffic on the default TLS/TCP carrier stays inside the latency budget under media load`
- TO: `### Requirement: Control traffic on the TLS/TCP carrier stays inside the latency budget under media load`
