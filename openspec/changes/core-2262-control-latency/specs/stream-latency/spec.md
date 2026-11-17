## ADDED Requirements

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

### Requirement: Control traffic on the default TLS/TCP carrier stays inside the latency budget under media load

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
