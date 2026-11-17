## 1. Carrier

- [ ] 1.1 `protocol.BoundUnsentBacklog` and `protocol.UnsentBacklogListener`: Linux, macOS, no-op elsewhere
- [ ] 1.2 Relay carrier listener and tunnel client carrier dial use them

## 2. Tests

- [ ] 2.1 Linux: the option is set on accepted and dialled carrier sockets
- [ ] 2.2 macOS: a writer to a stalled peer is held near the mark
- [ ] 2.3 `TestControlStreamLatencyBudget` holds the TLS/TCP carrier, with and without 1% loss (Linux)

## 3. Measurement and docs

- [ ] 3.1 `relay-loadgen -mode latency` can run without the emulated link on fixed carrier ports
- [ ] 3.2 `script/netem-latency.sh`: tc/netem in a private network namespace
- [ ] 3.3 `docs/relay-latency-budget.md`: decision, macOS and Linux numbers, netem numbers
