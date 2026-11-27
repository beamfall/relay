## 1. Cache Carrier Refusal & Hygiene

- [x] 1.1 Default `CacheCarrierEnabled` to `false` in `relay.Config` and refuse `surface: "cache"` with `"invalid hello"` in `carrierHandshake` and `serveCarrierSession`
- [x] 1.2 Supersede prior session in `cacheCarrierRegistry.register` and prune expired inactive entries in `cacheKeyRegistry`
- [x] 1.3 Document default refusal in `PROTOCOL.md`

## 2. Cache Store & Server Bounds

- [x] 2.1 Check `Store.Get` lock mode (`meta.go:lockRoot` used `LOCK_EX`), record result, and switch clean read path to `LOCK_SH` + `RLock()` with `LOCK_EX` fallback
- [x] 2.2 Add `Store.Open` streaming read, cap `Store.Get` / `Store.Put` at `MaxSegmentBytes`, add `Store.PutStream` for `handlePush`, and replace `io.ReadAll` in metadata/recovery/sweep paths with `statAndHashNode`
- [x] 2.3 Add `MaxConns` connection cap (`DefaultMaxConns = 1024`) and streamed HTTP serving to `cache.Server`, plus `--cache-max-conns` flag and docs

## 3. Tests & Verification

- [x] 3.1 Regression tests for cache carrier refusal, supersede, key pruning, oversized read rejection, streamed HTTP serving, connection cap, and concurrent cross-tenant reads
- [x] 3.2 Run `gofmt`, `go vet`, `golangci-lint`, `private-pointer-scan`, `verify-vectors`, `openspec validate --all --strict`, and `go test -race ./...`
- [ ] 3.3 Archive OpenSpec change after landing
