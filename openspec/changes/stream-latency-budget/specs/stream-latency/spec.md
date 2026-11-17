## ADDED Requirements

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
