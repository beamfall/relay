## 1. Carrier

- [x] 1.1 `tunnel.TransportAuto` is the default: QUIC first, TLS/TCP fallback with a fresh token, 10 minute hold-off
- [x] 1.2 `tunnel-client -transport` defaults to `auto`; the connect log names the transport
- [x] 1.3 `relayd --quic-addr` defaults to the carrier address; `off` disables

## 2. Tests

- [x] 2.1 A client that cannot reach the relay over UDP goes live over TLS/TCP with a fresh token
- [x] 2.2 Hold-off, relay refusal over QUIC, explicit transports do not fall back
- [x] 2.3 `relayd` QUIC address default and `off`

## 3. Measurement and docs

- [x] 3.1 Harness: default transport, external carrier on any transport, UDP-blocked link
- [x] 3.2 `script/netem-latency.sh` numbers with real 1% loss on the default configuration
- [x] 3.3 `docs/relay-latency-budget.md` decision and numbers; operator guide and packaging examples
