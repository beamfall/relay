# stream-latency Specification

## Purpose

The latency the relay and its carrier add to an established stream is measured per direction and
held to a budget, so small control streams stay responsive while media shares the carrier.

## Requirements

### Requirement: The relay reports the latency it adds to established streams

The relay SHALL export a histogram of the time each forwarded chunk of an established stream spends
in the relay, from being read on one side to written on the other, and a histogram of the absolute
change in that time between consecutive chunks of one stream direction. Both SHALL be labelled only
by forwarding direction, and the relay SHALL NOT inspect the payload to produce them.

#### Scenario: A chunk is forwarded

- **WHEN** the relay forwards a chunk of an established stream
- **THEN** `beamfall_relay_stream_forward_seconds` records one observation under that chunk's direction

#### Scenario: Consecutive chunks

- **WHEN** the relay forwards a second or later chunk in one direction of a stream
- **THEN** `beamfall_relay_stream_forward_jitter_seconds` records the absolute difference from the previous chunk's forwarding time

#### Scenario: Bounded labels

- **WHEN** the metrics are scraped
- **THEN** the two histograms carry no label other than `direction`, whose values are `to_carrier` and `to_client`

### Requirement: Control traffic on the QUIC carrier stays inside the latency budget under media load

On the reference link of `docs/relay-latency-budget.md`, the round-trip p99 of a small control
stream SHALL be at most 250 ms on the QUIC carrier while a media stream saturates the same carrier
in both directions, with and without 1% packet loss.

#### Scenario: Saturated carrier

- **WHEN** a control stream sends a small message every 5 ms over the QUIC carrier while a media stream saturates it
- **THEN** the control stream's round-trip p99 is at most 250 ms and every message is echoed

#### Scenario: Saturated carrier with loss

- **WHEN** the same run drops 1% of carrier packets
- **THEN** the control stream's round-trip p99 is at most 250 ms and every message is echoed

### Requirement: The TLS/TCP carrier bounds its unsent send backlog

On Linux and macOS, the relay's TLS/TCP carrier listener and the tunnel client's TLS/TCP carrier
connection SHALL hold a writer back while more than 16 KiB written to the carrier socket has not yet
been sent, so a frame written later waits behind at most that much. The bound SHALL NOT limit the
bytes in flight.

#### Scenario: Carrier socket on Linux

- **WHEN** the relay accepts, or the tunnel client dials, a TLS/TCP carrier connection on Linux
- **THEN** the socket's `TCP_NOTSENT_LOWAT` is 16 KiB

#### Scenario: Peer stops reading on macOS

- **WHEN** a writer keeps writing to a bounded carrier connection on macOS whose peer has stopped reading
- **THEN** the bytes held in the socket's send buffer stay near the peer's window plus 16 KiB instead of growing to the autotuned send buffer

#### Scenario: Connection that is not TCP

- **WHEN** the carrier connection is not a TCP connection
- **THEN** it is used unchanged

### Requirement: Control traffic on the TLS/TCP carrier stays inside the latency budget under media load

On the reference link of `docs/relay-latency-budget.md`, the round-trip p99 of a small control
stream SHALL be at most 250 ms on the TLS/TCP carrier while a media stream saturates the same
carrier in both directions, without loss and with the in-process link's modelled 1% loss, when both
carrier ends bound their unsent send backlog. Real packet loss is outside this requirement.

#### Scenario: Saturated carrier

- **WHEN** a control stream sends a small message every 5 ms over the TLS/TCP carrier while a media stream saturates it
- **THEN** the control stream's round-trip p99 is at most 250 ms and every message is echoed

#### Scenario: Saturated carrier with loss

- **WHEN** the same run delays 1% of carrier segments and everything behind them by one round trip
- **THEN** the control stream's round-trip p99 is at most 250 ms and every message is echoed

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
