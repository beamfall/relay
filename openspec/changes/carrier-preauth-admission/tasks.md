## 1. Relay

- [x] 1.1 Add the pending carrier budget (total and per source) and release it when the handshake is decided
- [x] 1.2 Reserve `MaxCarrierConns` slots after token verification; reply `"over capacity"` when full
- [x] 1.3 Raise the `MaxCarrierConns` default to 256 and document the rotation overlap
- [x] 1.4 Record handshake failures for timeouts, truncated frames, invalid hellos and missing QUIC handshake streams
- [x] 1.5 Add `--max-pending-carrier-conns`, `--max-pending-carrier-conns-per-ip` and the per-source refusal counter
- [x] 1.6 Tests in `internal/relay` and `cmd/relayd`

## 2. Docs

- [x] 2.1 Update `PROTOCOL.md` and `docs/operator-self-hosted-relay.md`

## 3. Verify and close

- [ ] 3.1 Run `openspec validate --all --strict`
- [ ] 3.2 Run `make gate`
- [ ] 3.3 Run `openspec archive carrier-preauth-admission` after landing, before completing CORE-1385
