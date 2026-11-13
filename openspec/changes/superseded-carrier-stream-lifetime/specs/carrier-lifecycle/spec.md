## ADDED Requirements

### Requirement: Superseded carriers keep streams while the identity holds a live carrier

When a carrier is superseded by a same-identity replacement and its token expires, the relay SHALL
keep the superseded carrier's existing streams open while a live carrier of the same identity holds
at least one of the superseded carrier's hostnames, for at most `SupersededStreamMaxAge` after the
superseded carrier's token expiry. A `SupersededStreamMaxAge` of zero SHALL disable this
extension.

#### Scenario: Long stream outlives its carrier's token

- **WHEN** a stream on a superseded carrier is still open after that carrier's token expiry plus
  `ExpiredSessionDrain`, and a live same-identity replacement holds its hostname
- **THEN** the stream stays open and keeps relaying bytes

#### Scenario: Maximum age reached

- **WHEN** a superseded carrier's streams are still open `SupersededStreamMaxAge` after its token
  expiry
- **THEN** the relay closes the carrier and its streams

#### Scenario: Extension disabled

- **WHEN** `SupersededStreamMaxAge` is zero
- **THEN** a superseded carrier closes `ExpiredSessionDrain` after its token expiry, or sooner when
  its last stream ends

### Requirement: Superseded carriers take no new streams

The relay SHALL NOT route new streams to a superseded carrier, and SHALL close a superseded carrier
once its last stream ends.

#### Scenario: Last stream ends

- **WHEN** the last stream on a superseded carrier ends
- **THEN** the relay closes that carrier

### Requirement: Superseded carriers close when the identity loses its live carrier

When no live same-identity carrier holds any of an expired superseded carrier's hostnames, the
relay SHALL allow that carrier's streams at most `ExpiredSessionDrain` more and SHALL then close
it. A carrier that is not superseded SHALL still close at its token expiry.

#### Scenario: Identity stops rotating

- **WHEN** the identity's current carrier closes at its own token expiry and no replacement
  connects
- **THEN** each expired superseded carrier of that identity closes within `ExpiredSessionDrain`
  plus the relay's successor check interval
