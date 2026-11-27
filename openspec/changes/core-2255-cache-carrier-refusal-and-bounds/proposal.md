# Refuse unshipped cache carrier surface and bound cache reads

Ticket: CORE-2255 (`queue:core:main`).

## Why

An audit of `beamfall-relay` found four gaps on the Media Cache surface:

1. `relayd` acknowledges carriers registering `surface: "cache"` (`serveCacheCarrierSession`), but `VerifyCacheAccessToken`, `PullCacheSegment`, `CarrierHandler.Serve`, and `CarrierClient.Pull` have no non-test callers. Unwired cache carriers also lacked same-identity supersede and `cacheKeys.rings` pruning, allowing a cache carrier to hold a `carrierSlots` slot until token expiry and retain key rings indefinitely.
2. `Store.Get` and internal `Store` metadata/recovery/sweep helpers called `readNode(..., s.TenantCapBytes)` (`io.ReadAll` up to 25 GiB), and `Server.handleSegment` buffered the entire `Entry.Bytes` in RAM instead of streaming.
3. The `cache-serve` HTTPS listener (`internal/cache/server.go`) had no concurrent connection cap.
4. `Store.Get` called `lockRoot()` (`internal/cache/meta.go`), which acquired `syscall.Flock(..., syscall.LOCK_EX)` on `.cache.lock` for every read, serializing cache reads across all homes.

## What Changes

- **Cache carrier refusal & hygiene (`internal/relay/relay.go`, `PROTOCOL.md`):**
  - `relay.Config.CacheCarrierEnabled` defaults to `false`. `carrierHandshake` and `serveCarrierSession` refuse `surface: "cache"` with `"invalid hello"` before token verification, replay-nonce admission, or carrier slot reservation unless explicitly enabled.
  - When enabled, `cacheCarrierRegistry.register` supersedes any prior session for the same `carrierID`, and `cacheKeyRegistry` tracks active sessions and prunes inactive entries after `cache.MaxTokenTTL`.
- **Streamed/capped cache reads & shared read lock (`internal/cache/meta.go`, `store.go`, `transaction.go`, `push.go`):**
  - `Store.Open` streams verified segments via a 32 KiB pooled buffer without allocating segment-sized `[]byte` slices; `Store.Get` delegates to `Store.Open` and enforces `MaxSegmentBytes` (64 MiB).
  - `Store.PutStream` and `CarrierHandler.handlePush` stream pushed segments directly to staging; `Inventory`, `reapTenantDir`, `inspectPublication`, `removePairPaths`, and transaction recovery use `statAndHashNode` without `io.ReadAll` on blobs.
  - `Store.Get` and `Store.Open` use `LOCK_SH` (`lockRootShared`) and `tenantLock.RLock()` on the clean read path, falling back to `LOCK_EX` and `tenantLock.Lock()` only when `.txn-*` recovery or expired/corrupt eviction is needed.
- **`cache-serve` connection cap (`internal/cache/server.go`, `cmd/relayd/main.go`, `docs/operator-self-hosted-relay.md`):**
  - `cache.Config.MaxConns` (default `DefaultMaxConns = 1024`, `--cache-max-conns` / `RELAYD_CACHE_MAX_CONNS`) wraps the `cache-serve` TCP listener before TLS, closing over-cap accepts immediately and incrementing `beamfall_cache_connections_over_cap_total`.
  - `Server.handleSegment` streams cache hits via `Store.Open`.

## Non-goals

- Wiring `VerifyCacheAccessToken` / `PullCacheSegment` into `relayd` or shipping the Media Cache carrier feature.
- Changing `MaxSegmentBytes` (64 MiB) or the passthrough stream memory budget.

## Failure Modes & Rollback

- If a carrier presents `surface: "cache"` while disabled, `relayd` returns `"invalid hello"` and closes the connection without consuming a carrier slot or nonce.
- If a segment on disk exceeds `MaxSegmentBytes`, `Store.Open` and `Store.Get` fail closed before reading.
- Rollback: revert the commit on `main`.

## Acceptance Evidence

- Unit and `-race` regression tests in `internal/relay`, `internal/cache`, and `cmd/relayd`.
- `gofmt`, `go vet`, `golangci-lint`, `private-pointer-scan.py`, `verify-vectors`, and `openspec validate --all --strict`.
