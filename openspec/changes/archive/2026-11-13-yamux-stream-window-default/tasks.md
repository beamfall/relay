## 1. Relay

- [x] 1.1 Raise `DefaultYamuxStreamWindowBytes` to 4 MiB and correct the window comments
- [x] 1.2 Update the `relayd` and `tunnel-client` flag help and the operator guide
- [x] 1.3 Add the RTT-injected throughput benchmark and the default-window test

## 2. Verify and close

- [ ] 2.1 Run `openspec validate --all --strict`
- [ ] 2.2 Run `make gate`
- [ ] 2.3 Land core's matching default, override and `StreamCloseTimeout`
- [ ] 2.4 Run `openspec archive yamux-stream-window-default` after landing, before completing CORE-1386
