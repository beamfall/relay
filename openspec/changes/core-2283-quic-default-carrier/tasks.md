## 1. Carrier

- [ ] 1.1 `tunnel.TransportAuto` is the default: QUIC first, TLS/TCP fallback with a fresh token, 10 minute hold-off
- [ ] 1.2 `tunnel-client -transport` defaults to `auto`; the connect log names the transport
- [ ] 1.3 `relayd --quic-addr` defaults to the carrier address; `off` disables

## 2. Tests

- [ ] 2.1 A client that cannot reach the relay over UDP goes live over TLS/TCP with a fresh token
- [ ] 2.2 Hold-off, relay refusal over QUIC, explicit transports do not fall back
- [ ] 2.3 `relayd` QUIC address default and `off`

## 3. Measurement and docs

- [ ] 3.1 Harness: default transport, external carrier on any transport, UDP-blocked link
- [ ] 3.2 `script/netem-latency.sh` numbers with real 1% loss on the default configuration
- [ ] 3.3 `docs/relay-latency-budget.md` decision and numbers; operator guide and packaging examples
