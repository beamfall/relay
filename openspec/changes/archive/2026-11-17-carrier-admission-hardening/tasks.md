## 1. Relay

- [x] 1.1 Evict the oldest pending connection of the heaviest source when the pending budget is full
- [x] 1.2 Lower the default carrier handshake timeout to 5 s
- [x] 1.3 Recover, count and log panics in connection handlers
- [x] 1.4 Tests: idle connections from eight sources at default caps, eviction choice, injected panic
- [x] 1.5 Operator and protocol docs

## 2. Verify and close

- [ ] 2.1 `openspec validate --all --strict`, scoped checks, review
- [ ] 2.2 Land, archive this change, complete CORE-2253 and CORE-2254
