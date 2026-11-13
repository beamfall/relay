## 1. Relay

- [x] 1.1 Add `SupersededStreamMaxAge` to `relay.Config` and the live-successor check to the registry
- [x] 1.2 Hold an expired superseded carrier open while a live same-identity carrier exists, capped by `SupersededStreamMaxAge`; fall back to `ExpiredSessionDrain` when it lapses
- [x] 1.3 Add `--superseded-stream-max-age` to `relayd`
- [x] 1.4 Tests in `internal/relay` and `cmd/relayd`

## 2. Docs

- [x] 2.1 Update `PROTOCOL.md`, `docs/operator-self-hosted-relay.md` and `docs/relay-scaling-and-failover.md`

## 3. Verify and close

- [x] 3.1 Run `openspec validate --all --strict`
- [ ] 3.2 Run `make gate`
- [ ] 3.3 Run `openspec archive superseded-carrier-stream-lifetime` after landing, before completing CORE-1382
