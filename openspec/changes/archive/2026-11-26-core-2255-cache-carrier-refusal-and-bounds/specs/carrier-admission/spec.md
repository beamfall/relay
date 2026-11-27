## ADDED Requirements

### Requirement: Cache-surface carriers are refused unless explicitly enabled

The relay SHALL refuse a carrier registering `surface: "cache"` with an `"invalid hello"` error frame and close the connection before token verification or carrier slot reservation unless `CacheCarrierEnabled` is explicitly enabled. When enabled, a same-identity cache carrier registration SHALL supersede any prior open session for that identity, and `cacheKeyRegistry` SHALL prune inactive key rings after `cache.MaxTokenTTL`.

#### Scenario: Cache carrier refused by default

- **WHEN** a carrier sends a valid hello with `surface: "cache"` to a relay started with default configuration
- **THEN** the relay replies with `"invalid hello"`, increments `beamfall_relay_handshake_failures_total`, does not reserve a carrier slot, and closes the connection

#### Scenario: Same-identity cache carrier supersedes predecessor when enabled

- **WHEN** `CacheCarrierEnabled` is true and a second cache carrier connects with the same carrier ID
- **THEN** the relay closes the superseded session and retains key overlap for `cache.MaxTokenTTL`
