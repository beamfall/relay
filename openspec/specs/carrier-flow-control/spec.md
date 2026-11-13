# carrier-flow-control Specification

## Purpose
The flow-control settings of v1 (TLS/TCP) carrier yamux sessions: the default per-stream window
and how it bounds single-stream throughput at a given round-trip time, and the requirement that
the relay and the tunnel client agree on it.

## Requirements

### Requirement: The default v1 carrier stream window sustains 40 MB/s at 50 ms

The v1 carrier's default per-stream yamux window SHALL be large enough that one stream sustains at
least 40 MB/s over a 50 ms round trip, counting the yamux refill at half the window. An operator
override of `YamuxStreamWindowBytes` above zero SHALL replace the default.

#### Scenario: Default window

- **WHEN** the relay or tunnel client builds its yamux config with no window override
- **THEN** the stream window is at least twice the bandwidth-delay product of 40 MB/s at 50 ms

#### Scenario: Operator override

- **WHEN** `--yamux-stream-window-bytes` is set to a positive value
- **THEN** the carrier uses that value as its stream window
