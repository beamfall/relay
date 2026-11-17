## 1. Relay

- [x] 1.1 Export the established-stream latency and jitter histograms, labelled by direction only
- [x] 1.2 Add the emulated link and the control-stream latency harness (`internal/loadtest`)
- [x] 1.3 Add `relay-loadgen -mode latency`
- [x] 1.4 Write `docs/relay-latency-budget.md` and add the budget test

## 2. Verify and close

- [x] 2.1 Run `openspec validate --all --strict`
- [ ] 2.2 Run `make gate`
- [ ] 2.3 Run `openspec archive stream-latency-budget` after landing, before completing CORE-2246
