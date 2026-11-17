## 1. Relay

- [x] 1.1 Stream memory budget: slot limit from budget and per-stream cost, refusal metric
- [x] 1.2 Client write stall timeout on the home-to-client copy, stalled-close metric
- [x] 1.3 Per-identity stream limiter shared by live and superseded carriers
- [x] 1.4 `relayd` flags, env defaults and the Go memory limit
- [x] 1.5 A stream cut short keeps its slot until the carrier releases it

## 2. Tests

- [x] 2.1 Stalled readers stay inside the budget; streams beyond it are refused
- [x] 2.2 Stalled reader closed; paused reader that resumes keeps its stream
- [x] 2.3 Superseded carrier streams count against the identity cap
- [x] 2.5 Aborted stream keeps its slot while the home sends, frees it when the home closes
- [x] 2.4 Default budget plus headroom fits 512 MiB; flag and memory-limit wiring

## 3. Docs and packaging

- [x] 3.1 systemd and compose memory comments state the sizing rule
- [x] 3.2 Env example and operator guide: flags, metrics, sizing rule
