## ADDED Requirements

### Requirement: Cache segment reads are streamed or bounded within the memory limit

`cache-serve` SHALL stream segment reads from disk without buffering full segments in memory, and `Store.Open` / `Store.Get` SHALL reject blobs larger than `MaxSegmentBytes` before reading them.

#### Scenario: Oversized segment rejected before allocation

- **WHEN** a blob on disk exceeds `MaxSegmentBytes`
- **THEN** `Store.Open` and `Store.Get` return a size-limit error without reading the blob into memory

#### Scenario: HTTP segment hit streams without full-segment buffering

- **WHEN** `cache-serve` serves a cached segment over HTTPS
- **THEN** it streams the verified file with a bounded copy buffer instead of buffering the full segment in RAM

### Requirement: The cache-serve listener enforces a connection cap

`cache-serve` SHALL cap concurrent connections on its HTTPS segment listener at `MaxConns` (default `1024`), closing over-cap connections immediately and counting `beamfall_cache_connections_over_cap_total`.

#### Scenario: Over-cap connection is closed immediately

- **WHEN** `MaxConns` connections are open on the `cache-serve` listener and another connection arrives
- **THEN** the new connection is closed immediately, `beamfall_cache_connections_over_cap_total` increments, and once an existing connection closes a new connection succeeds

### Requirement: Clean cache reads use a shared root lock

`Store.Get` and `Store.Open` SHALL acquire a shared root lock (`LOCK_SH`) and shared tenant lock (`RLock`) on clean reads so concurrent reads across homes do not serialize, falling back to an exclusive lock (`LOCK_EX`) only when transaction recovery or eviction is required.

#### Scenario: Concurrent reads across different homes run in parallel

- **WHEN** two concurrent `Store.Get` or `Store.Open` calls read segments from different homes
- **THEN** neither blocks waiting for the other's root lock
