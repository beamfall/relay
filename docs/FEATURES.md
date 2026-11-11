# Beamfall Relay — Feature Inventory

Every relay and tunnel-client feature, the file(s) that implement it, and the
test(s) that prove it. This is the relay's equivalent of core's
`testing/features.yaml` (which covers only the server + clients); the relay is not
in that registry, so coverage is tracked here.

Conventions: paths are repo-relative. A row marked **GAP** had no proving test
before this inventory; **(closed)** marks a gap a new test now covers. Run the
whole suite with `make gate` (or `go test -race ./...`).

## Carrier surface (authenticated home-server tunnel)

| Feature | Summary | Implemented in | Proven by |
| --- | --- | --- | --- |
| Carrier handshake (length-prefixed JSON hello/ack) | Reads one length-prefixed JSON `hello`, replies with `ack`, then starts yamux over the same TLS conn. | `internal/protocol/protocol.go`, `internal/relay/relay.go` (`handleCarrierConn`), `internal/tunnel/client.go` (`serveOnce`) | `internal/protocol/protocol_test.go::TestFrameRoundTrip`; end-to-end via `internal/relay/relay_test.go::TestRelayPassesTLSBytesEndToEndAndDoesNotLogPayload`; `internal/tunnel/client_test.go::TestClientServesStreamToBackend` |
| Token auth via TokenVerifier seam | Carrier hello token + requested hostnames are checked through the `TokenVerifier` interface; unauthorized carriers are rejected and never registered. | `internal/relay/token.go`, `internal/relay/relay.go` (`handleCarrierConn`) | `internal/relay/resilience_test.go::TestCarrierHandshakeRejectsUnauthorized`; **(closed)** `internal/relay/relay_test.go::TestRelayRejectsUnauthorizedCarrierAndDoesNotLogToken` |
| StaticTokenVerifier (development only) | Single shared replayable token, constant-time compared and scoped to a fixed hostname allow-list; requires `BEAMFALL_RELAY_DEV=1`; empty token never auto-accepts; CarrierID defaults to first host. | `internal/relay/token.go` | **GAP (closed)** `internal/relay/token_test.go::TestStaticTokenVerifierAcceptsExactToken`, `::TestStaticTokenVerifierRejectsBadInput`, `::TestStaticTokenVerifierHonorsCancelledContext` |
| HMACTokenVerifier (default for production and self-hosting) | Expiring, replay-resistant HMAC token; `hmac.Equal` compare; host allow-list. | `internal/relay/hmac_token.go` | `internal/relay/token_test.go::TestHMACTokenVerifierAcceptsMintedToken`, `::TestHMACTokenVerifierRejectsWrongHost` |
| Hostname allow-list enforcement | Requested hostnames must all be in the carrier's allowed set; empty request rejected. | `internal/relay/hmac_token.go` (`allowedHostnames`) | `internal/relay/token_test.go::TestHMACTokenVerifierRejectsWrongHost`, `::TestStaticTokenVerifierRejectsBadInput` |
| Carrier handshake deadline (reap silent conns) | First-frame read is bounded by `CarrierHandshakeTimeout`; a conn that sends nothing is reaped, not held forever. | `internal/relay/relay.go` (`handleCarrierConn`) | `internal/relay/resilience_test.go::TestCarrierHandshakeDeadlineReapsSilentConn` |
| Handshake deadline cleared post-hello | After the hello frame, the read deadline is cleared so the long-lived yamux session is not subject to the handshake timeout. | `internal/relay/relay.go` (`handleCarrierConn`) | **GAP (closed)** `internal/relay/resilience_test.go::TestCarrierSessionSurvivesPastHandshakeDeadline` (short timeout, idle 4x past it, then assert relay still works; mutation-verified) |
| Bad-version / non-hello rejection | A hello with the wrong protocol version, or a first frame that is not a hello, is rejected with an `error` frame. | `internal/relay/relay.go` (`handleCarrierConn`) | `internal/relay/resilience_test.go::TestCarrierHandshakeRejectsBadVersion`, `::TestCarrierHandshakeRejectsNonHello` |
| Protocol frame size bound (64 KiB) | Read/write frames over `MaxFrameSize` are rejected before allocation. | `internal/protocol/protocol.go` | `internal/protocol/protocol_test.go::TestReadFrameRejectsOversizedPayload`; `internal/protocol/protocol_fuzz_test.go::FuzzReadFrame` |
| Protocol malformed-frame regression | Truncated length, missing payload, oversized prefix, and malformed JSON are all rejected without panic. | `internal/protocol/protocol.go` | **GAP (closed)** `internal/protocol/protocol_malformed_test.go::TestReadFrameRejectsMalformedFrames`; fuzz seed corpus runs under `go test` (`internal/protocol/testdata/fuzz/...`) |
| Hostname routing, first-writer-wins | Hostnames map to carriers first-writer-wins; a live carrier's host is never silently stolen (takeover vector); a dead carrier's host is reclaimable. | `internal/relay/relay.go` (`registry`) | `internal/relay/registry_metrics_test.go::TestRegistryRefusesLiveHostTakeover`, `::TestRegistryReclaimsDeadCarrierHost` |
| Auto-reconnect w/ bounded backoff + jitter | Tunnel client re-dials on session loss with exponential backoff (1s..60s default), ±20% jitter, reset after a live session; cancellable. | `internal/tunnel/client.go` (`run`, `nextBackoff`, `jitter`) | `internal/tunnel/client_test.go::TestClientReconnectsAfterRelayDrops`, `::TestNextBackoffCapsAtMax`, `::TestJitterStaysWithinBounds`, `::TestClientContextCancelEndsLoopPromptly`, `::TestClientCloseStopsReconnect` |
| Tunnel client token re-presentation | Token is re-sent on every (re)connect; stays in memory only, never logged. | `internal/tunnel/client.go` (`serveOnce`) | `internal/tunnel/client_test.go::TestClientReconnectsAfterRelayDrops` (re-handshake on reconnect) |
| Tunnel client backend forwarding | Each inbound yamux stream is dialed to the local backend and spliced both ways. | `internal/tunnel/client.go` (`handleStream`) | `internal/tunnel/client_test.go::TestClientServesStreamToBackend`, `::TestClientHandlesBackendDialFailure` |
| Tunnel client half-close (upload drains) | Two-direction wait in `handleStream` lets an in-flight upload finish after the backend half-closes its write side. | `internal/tunnel/client.go` (`handleStream`) | `internal/tunnel/client_test.go::TestClientDeliversFullUploadAfterBackendHalfClose` |

## Public surface (byte-blind SNI-peek passthrough)

| Feature | Summary | Implemented in | Proven by |
| --- | --- | --- | --- |
| SNI peek / parse | Reads exactly one TLS ClientHello record, extracts the SNI hostname, preserves the raw prefix bytes for replay. | `internal/sni/sni.go` | `internal/sni/sni_test.go::TestPeekClientHelloExtractsSNIAndPreservesBytes` |
| Absent-SNI rejection | A ClientHello with no SNI extension is rejected (`ErrNoSNI`). | `internal/sni/sni.go` | `internal/sni/sni_test.go::TestPeekClientHelloRejectsAbsentSNI` |
| SNI read deadline (slowloris) | The SNI peek is bounded by a read deadline; a slow/partial sender is dropped. | `internal/sni/sni.go`, `internal/relay/relay.go` (`handlePublicConn`, 5s) | `internal/sni/sni_test.go::TestPeekClientHelloHonorsSlowlorisDeadline` |
| Oversized-ClientHello bound | A ClientHello whose record length exceeds the configured max is rejected (`ErrTooLarge`). | `internal/sni/sni.go` | `internal/sni/sni_test.go::TestPeekClientHelloRejectsOversizedHello` |
| SNI malformed-input / NUL handling | Truncated records, length-field overruns, wrong content/handshake types, and NUL-bearing hostnames are all rejected; valid names are normalized lowercase, NUL-free. | `internal/sni/sni.go` (`parseClientHelloRecord`, `validServerName`) | **GAP (closed)** `internal/sni/sni_malformed_test.go::TestParseClientHelloRejectsMalformedRecords`, `::TestParseClientHelloRejectsNULInServerName`, `::TestParseClientHelloNormalizesServerName`; `internal/sni/sni_fuzz_test.go::FuzzParseClientHelloRecord` (+ committed corpus runs under `go test`) |
| Unknown-SNI rejection | A public conn whose SNI has no registered carrier is closed with no application response. | `internal/relay/relay.go` (`handlePublicConn`) | `internal/relay/relay_test.go::TestRelayRejectsUnknownSNI` |
| Reject after carrier teardown | Once the carrier closes, its host is unregistered and new public dials are refused. | `internal/relay/relay.go` (`registry.unregister`) | `internal/relay/relay_test.go::TestRelayRejectsAfterCarrierIsTornDown` |
| Byte-blind splice (raw bytes, pristine ClientHello) | Peeked prefix is replayed ahead of the rest of the conn; raw bytes are spliced both ways; TLS is never terminated. | `internal/relay/relay.go` (`handlePublicConn`, `splice`, `bytesReader`) | `internal/relay/relay_test.go::TestRelayPassesTLSBytesEndToEndAndDoesNotLogPayload` |
| Half-close two-direction wait (download drains) | The splice waits for both directions so a graceful client half-close (clean EOF) does not truncate an in-flight download. | `internal/relay/relay.go` (`splice`) | `internal/relay/relay_test.go::TestRelayDeliversFullDownloadAfterClientHalfClose`; `internal/relay/splice_test.go::TestSpliceWaitsForBothHalvesOnCleanHalfClose` |
| Both-halves teardown on abrupt disconnect | When one direction ends with an **error** (abrupt disconnect / RST, not a graceful EOF), the splice force-closes both conns so the surviving direction — possibly parked reading a silent-but-open peer — is unblocked, preventing a goroutine/fd/stream-slot/semaphore-slot leak. (Graceful-FIN + silent-upstream is byte-indistinguishable from a half-close and is not covered — see `docs/agent-memory/questions.md`.) | `internal/relay/relay.go` (`splice`) | `internal/relay/splice_test.go::TestSpliceTearsDownBothHalvesOnAbruptDisconnect` |
| Per-carrier concurrent stream cap | Each carrier bounds concurrent streams; over-cap opens are refused. | `internal/relay/relay.go` (`carrier.open`) | `internal/relay/relay_test.go::TestRelayEnforcesStreamCap` |
| MaxPublicConns bound | A global semaphore bounds concurrently-handled public conns; over the cap, accepts are immediately closed (flood cannot exhaust goroutines/FDs) and counted. | `internal/relay/relay.go` (`acceptPublic`, `publicSlots`) | `internal/relay/resilience_test.go::TestPublicAcceptBoundClosesOverCapConnections` |
| Per-carrier byte rate limit | Token-bucket limiter paces bytes at a configured rate with burst; coalesced sleeps keep throughput near rate. | `internal/relay/limiter.go` (`byteLimiter`), `internal/relay/relay.go` (`copyWithLimit`) | `internal/relay/limiter_test.go::TestCopyWithLimitEnforcesByteRate`, `::TestCopyWithLimitBoundsThroughputNearRate` |

## Fair-use accounting

| Feature | Summary | Implemented in | Proven by |
| --- | --- | --- | --- |
| Rolling-window byte accounting | Per-tunnel hourly buckets over a rolling window; old buckets expire; idle tunnels are evicted. | `internal/relay/fairuse.go` | `internal/relay/fairuse_test.go::TestFairUseWindowRollsAndEvictsIdleTunnels` |
| Soft/hard limit crossings + sampled logs | Crossing soft/hard limits is logged once per crossing; refusal logs are rate-sampled. | `internal/relay/fairuse.go` (`updateLevelLocked`, `shouldLogRefusal`) | `internal/relay/fairuse_test.go::TestFairUseHardLimitAndSampledRefusalLogs` |
| Hard-limit throttle (refuse new only) | Over the hard limit, new public connections are refused down to `ThrottledMaxConns`; established streams are never killed. | `internal/relay/fairuse.go`, `internal/relay/relay.go` (`carrier.open`, `handlePublicConn`) | `internal/relay/relay_test.go::TestRelayFairUseThrottleRefusesOnlyNewConnections` |
| Fair-use disabled passthrough | With fair-use disabled, no throttling occurs even past the configured limits. | `internal/relay/fairuse.go` (`newFairUseLimiter` returns nil) | `internal/relay/relay_test.go::TestRelayFairUseDisabledDoesNotThrottle` |
| Concurrent accounting correctness | Concurrent `add` calls account exactly (no lost updates). | `internal/relay/fairuse.go` (`tunnelUsage.add`) | `internal/relay/fairuse_test.go::TestFairUseConcurrentAccounting` |
| Cached per-tunnel usage on hot path | `recordBytes` accounts via a pointer cached at connect time, avoiding the global lock + full scan per chunk. | `internal/relay/relay.go` (`carrier.recordBytes`) | `internal/relay/fairuse_test.go::TestRecordBytesUsesCachedTunnelUsage` |
| Durable shared hosted accounting | Optional Redis storage uses rolling buckets, bounded 1 MiB/250 ms idempotent batches with stable relay-recorded hours and monotonic dedupe lifetimes, opaque fleet-wide TTL reservations, and a digest-only local outbox that survives Redis outage/restart; self-hosting defaults to memory. | `internal/relay/fairuse_redis.go`, `internal/relay/fairuse_outbox.go`, `internal/relay/fairuse.go` | `internal/relay/fairuse_redis_test.go`, `internal/relay/fairuse_outbox_test.go` |

## Lifecycle, observability, secrets

| Feature | Summary | Implemented in | Proven by |
| --- | --- | --- | --- |
| Graceful drain on shutdown | Public listener closes first (no new conns), in-flight streams drain up to a grace window, then carrier sessions force-close. | `internal/relay/relay.go` (`Shutdown`, `streamWG`) | `internal/relay/resilience_test.go::TestGracefulShutdownDrainsInFlightStream`, `::TestGracefulShutdownForceClosesOverGrace` |
| Admin /healthz + /readyz + /metrics | Localhost admin listener serves liveness (`/healthz`, always `ok`), readiness (`/readyz`, `ok`/503 based on connected carriers), and Prometheus aggregate-only counters/gauges. | `internal/relay/metrics.go`, `internal/relay/relay.go` (`Start`) | `internal/relay/relay_test.go::TestRelayAdminHealthAndMetrics`, `internal/relay/metrics_test.go::TestReadyzReflectsCarrierConnections` |
| Metric gauges map to distinct counters | `active_tunnels` tracks tunnels relaying ≥1 stream, distinct from `carriers_connected`; handshake-failure / over-cap / fair-use counters are wired separately. | `internal/relay/metrics.go`, `internal/relay/relay.go` | `internal/relay/registry_metrics_test.go::TestMetricsGaugesMapToDistinctCounters`; counter increments asserted in `resilience_test.go::assertHandshakeFailures` and `relay_test.go` fair-use metrics |
| Byte-blindness: no payload in logs | Relayed payload bytes never appear in relay logs. | `internal/relay/relay.go` (logging only metadata) | `internal/relay/relay_test.go::TestRelayPassesTLSBytesEndToEndAndDoesNotLogPayload` |
| Byte-blindness: no token in logs | Token bytes are never logged on either the accept or reject path. | `internal/relay/relay.go` (`handleCarrierConn`), `internal/tunnel/client.go` | **GAP (closed)** `internal/relay/relay_test.go::TestRelayNeverLogsTokenBytes`, `::TestRelayRejectsUnauthorizedCarrierAndDoesNotLogToken` |
| Secret loading (env or 0600 file) | Token/key secrets come from an env var or a file that must not be group/world-readable; empty rejected. | `internal/config/secrets.go` | `internal/config/secrets_test.go::TestSecretFromEnvOrFilePrefersEnv`, `::TestSecretFromEnvOrFileRequires0600File` |
| Env/flag default helpers | `bool`/`int`/`int64`/string env-or-default parsers backing the `RELAYD_*` flag defaults. | `internal/config/env.go`, `internal/config/secrets.go` (`EnvOrDefault`) | **GAP (closed)** `internal/config/env_test.go::TestBoolEnvOrDefault`, `::TestIntEnvOrDefault`, `::TestInt64EnvOrDefault`, `::TestEnvOrDefault` |

## Not unit-tested (with reason)

- **`cmd/` wiring** (`relayd`, `tunnel-client`, `relay-loadgen`): thin flag/env
  parsing and process glue over the `internal/` libraries (which are the product
  and are tested); most flag-building helpers and defaults are covered by
  `cmd/relayd/main_test.go`, and `cmd/relayd/flagdocs_test.go` proves every flag
  the built binary accepts is documented (RELAY-PROD-OPERATOR-DOCS-DRIFT-1). Full
  process-level harnessing of the remaining glue would still add little signal.
  Tracked in `docs/agent-memory/tests.md`.
- **Carrier/public TLS 1.3 enforcement**: `MinVersion: tls.VersionTLS13` is set by
  the `cmd/` wiring and test harnesses, not by the `internal/` libraries, so it is
  a deployment/config assertion rather than a library behavior.
