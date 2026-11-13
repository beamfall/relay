# Self-hosted Relay Operator Guide

Beamfall Relay is a byte-blind SNI relay for operators who want a public relay they control.
Clients connect to the relay public listener, the home server opens an outbound carrier, and
the relay forwards encrypted bytes without terminating client TLS.

## Flag and Environment Variable Reference

Every flag `relayd` accepts, generated from `go run ./cmd/relayd --help` (and, for the two
subcommands, `go run ./cmd/relayd cache-serve --help` / `cache-supervise --help`). A test
(`cmd/relayd/flagdocs_test.go`) builds the binary, parses its `--help` output, and fails the
build if a flag is ever added or renamed here without this table changing to match — treat a
missing row as a doc bug, not a flag to skip.

### Top-level `relayd`

| Flag | Env var | Default | Purpose |
| --- | --- | --- | --- |
| `--public-addr` | `RELAYD_PUBLIC_ADDR` | `:8443` | public TLS passthrough listener address |
| `--carrier-addr` | `RELAYD_CARRIER_ADDR` | `:9443` | carrier TLS listener address |
| `--quic-addr` | `RELAYD_QUIC_ADDR` | *(empty; disabled)* | ADR-0018 v2 QUIC carrier listener address (UDP); empty disables it |
| `--admin-addr` | `RELAYD_ADMIN_ADDR` | `127.0.0.1:9080` | localhost admin listener address (`/healthz`, `/readyz`, `/metrics`) |
| `--admin-allow-public` | `RELAYD_ADMIN_ALLOW_PUBLIC` | `false` | explicitly allow `--admin-addr` to bind a non-loopback, non-private address; without this a public admin bind refuses to start |
| `--admin-metrics-token-file` | `RELAYD_ADMIN_METRICS_TOKEN_FILE` (value form: `RELAYD_ADMIN_METRICS_TOKEN`) | *(empty)* | file holding the bearer credential that guards `/metrics` when `--admin-addr` is non-loopback; a non-loopback admin bind refuses to start without it |
| `--carrier-cert` | `RELAYD_CARRIER_CERT` | *(empty; required)* | carrier TLS certificate file |
| `--carrier-key` | `RELAYD_CARRIER_KEY` | *(empty; required)* | carrier TLS key file |
| `--token-file` | `RELAYD_TOKEN_FILE` (value form: `RELAYD_TOKEN`) | *(empty)* | carrier token/secret file for self-hosted/test deployments (see `--token-mode`) |
| `--token-mode` | `RELAYD_TOKEN_MODE` | `hmac` | `hmac` (production default) or `static` (insecure, dev-only, requires `BEAMFALL_RELAY_DEV=1`) |
| `--hmac-nonce-store` | `RELAYD_HMAC_NONCE_STORE` | `/var/lib/beamfall-relay/hmac-nonces.json` | hmac mode only: persistent replay-state file |
| `--hmac-nonce-store-capacity` | `RELAYD_HMAC_NONCE_STORE_CAPACITY` | `259200` | hmac mode only: live replay nonces held before new carrier dials are refused (fail closed); accepted range `1`–`1000000`; see "Replay Nonce Store Sizing" |
| `--hostnames` | `RELAYD_HOSTNAMES` | *(empty; required)* | comma-separated hostnames this relay accepts |
| `--max-public-conns` | `RELAYD_MAX_PUBLIC_CONNS` | `1024` | global concurrent public-connection cap; `0` uses the default |
| `--max-public-conns-per-ip` | `RELAYD_MAX_PUBLIC_CONNS_PER_IP` | `64` | per-source-prefix (IPv4 /32, IPv6 /64) concurrent public-connection cap; `0` uses the default |
| `--max-streams-per-ip-per-carrier` | `RELAYD_MAX_STREAMS_PER_IP_PER_CARRIER` | one quarter of `--stream-cap`, min 1 | per-source-prefix, per-carrier concurrent-stream cap; `0` uses the derived default |
| `--public-peek-timeout` | *(flag-only)* | `3s` | how long the public listener waits to read a ClientHello before closing; `0` uses the default |
| `--max-carrier-conns` | *(flag-only)* | `256` | max authenticated carrier sessions; a connection takes a slot only after its token verifies. Core rotates its carrier every two minutes and the old one stays until its streams drain, so size this for **twice** the number of home servers (the default fits about 128). Over the cap an authenticated carrier is refused with `"over capacity"` and retries; `0` uses the default |
| `--max-pending-carrier-conns` | *(flag-only)* | `64` | max carrier connections not yet authenticated (in handshake back-off or the handshake itself); over the cap accepts are closed; `0` uses the default |
| `--max-pending-carrier-conns-per-ip` | *(flag-only)* | `8` | per-source-prefix (IPv4 /32, IPv6 /64) cap on unauthenticated carrier connections, so one source cannot hold the whole pending budget; `0` uses the default |
| `--rate-bytes-per-sec` | *(flag-only)* | `0` (disabled) | per-carrier byte rate limit |
| `--rate-burst-bytes` | *(flag-only)* | rate value | per-carrier byte rate burst |
| `--stream-cap` | `RELAYD_STREAM_CAP` | `64` | per-carrier concurrent stream cap |
| `--shutdown-grace` | *(flag-only)* | `30s` | on shutdown, wait this long for in-flight streams to drain before force-close; `0` = immediate |
| `--expired-session-drain` | *(flag-only)* | `30s` | additional grace after token expiry for streams on a superseded carrier to drain |
| `--yamux-stream-window-bytes` | *(flag-only)* | `0` (uses the 1 MiB built-in default) | v1 (TLS/TCP) carrier per-stream flow-control window; the tunnel client's matching flag MUST agree |
| `--redact-connection-logs` | `RELAYD_REDACT_CONNECTION_LOGS` | `true` | omit public remote address, SNI hostname, and carrier id from connection logs |
| `--fair-use-enabled` | `RELAYD_FAIR_USE_ENABLED` | `false` | enable rolling-window fair-use accounting and hard-limit throttling |
| `--fair-use-window-days` | `RELAYD_FAIR_USE_WINDOW_DAYS` | `30` | fair-use rolling window in days |
| `--fair-use-soft-limit-bytes` | `RELAYD_FAIR_USE_SOFT_LIMIT_BYTES` | `0` (disabled) | fair-use soft limit in bytes |
| `--fair-use-hard-limit-bytes` | `RELAYD_FAIR_USE_HARD_LIMIT_BYTES` | `0` (disabled) | fair-use hard limit in bytes |
| `--fair-use-throttled-max-conns` | `RELAYD_FAIR_USE_THROTTLED_MAX_CONNS` | `4` | new-connection ceiling for tunnels over the hard fair-use limit |
| `--fair-use-store` | `RELAYD_FAIR_USE_STORE` | `memory` | `memory` (single instance) or `redis` (shared hosted instances) |
| `--fair-use-redis-url` | `RELAYD_FAIR_USE_REDIS_URL` | *(empty)* | Redis URL for shared fair-use accounting; prefer the env var so credentials never appear in process arguments |
| `--fair-use-outbox` | `RELAYD_FAIR_USE_OUTBOX` | `/var/lib/beamfall-relay/fairuse-outbox.json` | redis mode only: durable final-delta outbox |
| `--fair-use-lease-ttl` | `RELAYD_FAIR_USE_LEASE_TTL` | `90s` | redis mode only: stream lease TTL |
| `--fair-use-fence-margin` | `RELAYD_FAIR_USE_FENCE_MARGIN` | `10s` | redis mode only: the relay closes a stream this long before its unconfirmed lease can expire in Redis |

### `cache-serve` subcommand

HTTPS Media Cache segment server; a separate process from the relay carrier/public listeners
above, started as `relayd cache-serve`.

| Flag | Env var | Default | Purpose |
| --- | --- | --- | --- |
| `--cache-addr` | `RELAYD_CACHE_ADDR` | `:9444` | HTTPS Media Cache segment listener address |
| `--cache-admin-addr` | `RELAYD_CACHE_ADMIN_ADDR` | `127.0.0.1:9081` | cache health/metrics listener address |
| `--cache-admin-allow-public` | `RELAYD_CACHE_ADMIN_ALLOW_PUBLIC` | `false` | explicitly allow `--cache-admin-addr` to bind a non-loopback, non-private address |
| `--cache-admin-metrics-token-file` | `RELAYD_CACHE_ADMIN_METRICS_TOKEN_FILE` (value form: `RELAYD_CACHE_ADMIN_METRICS_TOKEN`) | *(empty)* | file holding the bearer credential that guards cache `/metrics` when `--cache-admin-addr` is non-loopback |
| `--cache-cert` | `RELAYD_CACHE_CERT` | *(empty; required)* | cache HTTPS certificate file |
| `--cache-key` | `RELAYD_CACHE_KEY` | *(empty; required)* | cache HTTPS key file |
| `--cache-token-key-file` | `RELAYD_CACHE_TOKEN_KEY_FILE` (value form: `RELAYD_CACHE_TOKEN_KEY`) | *(empty; required)* | CacheAccessToken HMAC verification key file |
| `--cache-store-dir` | `RELAYD_CACHE_STORE_DIR` | `/var/lib/beamfall-relay/cache` | cache segment store directory |
| `--cache-tenant-cap-bytes` | `RELAYD_CACHE_TENANT_CAP_BYTES` | `0` (min of 25 GiB or 10% free disk) | per-tenant cache hard cap in bytes |

### `cache-supervise` subcommand

Crash-loop supervisor that runs `cache-serve` as a monitored child, started as `relayd
cache-supervise`.

| Flag | Env var | Default | Purpose |
| --- | --- | --- | --- |
| `--restart-budget` | *(flag-only)* | `5` | `cache-serve` restart budget before operator alert and supervisor exit |
| `--restart-window` | *(flag-only)* | `10m` | window for the `cache-serve` restart budget |
| `--restart-backoff` | *(flag-only)* | `1s` | initial `cache-serve` crash-loop backoff |
| `--restart-max-backoff` | *(flag-only)* | `30s` | max `cache-serve` crash-loop backoff |
| `--cache-uid` | `RELAYD_CACHE_UID` | `-1` (leaves the current uid) | numeric OS uid for the `cache-serve` child |
| `--cache-gid` | `RELAYD_CACHE_GID` | `-1` (leaves the current gid) | numeric OS gid for the `cache-serve` child |
| `--cache-log-file` | `RELAYD_CACHE_LOG_FILE` | *(empty; inherits supervisor logs)* | append-only log file for `cache-serve` stdout/stderr |

`RELAYD_CACHE_*` variables configure the `cache-serve`/`cache-supervise` subcommands only; they
are not read by plain `relayd` and are intentionally absent from
`packaging/systemd/relayd.env.example`, which packages the top-level relay unit. A cache
deployment needs its own environment file and systemd unit sourcing the `RELAYD_CACHE_*` rows
above.

## CGNAT Bootstrap

For native Beamfall clients behind CGNAT, the canonical bootstrap is **self-signed identity + SPKI
pin through the relay**, not ACME-through-relay issuance:

1. Pair the client on the home LAN once. Core generates a persistent self-signed TLS identity and
   the client records that identity's SPKI pin during enrollment.
2. Point a relay-routable hostname, such as `home.relay.example`, at the relay's public address and
   register the same hostname in `RELAYD_HOSTNAMES` and the home server's relay config.
3. Run `relayd` on the public host and the Core relay carrier/tunnel client next to the home server.
   The home server makes the only inbound-blocked-side connection: an outbound carrier to the relay.
4. Remote native clients connect to `https://home.relay.example`; the relay routes by SNI and stays
   byte-blind, while Core terminates TLS with the already-pinned self-signed identity.

ACME remains useful for browser-trusted direct public domains, but it is not required for the CGNAT
native-client relay path. See `docs/relay-cgnat-bootstrap.md` for the audit evidence that made the
older ACME-through-relay bootstrap requirement moot.

## Privacy Posture

The relay sees SNI hostnames, connection metadata, and traffic volumes. It never sees content,
HTTP requests, Stream Tokens, or plaintext media bytes because TLS terminates on the home
server.

Public connection logs redact hostnames, remote addresses, and carrier ids by default. Operators
can opt into those fields with `--redact-connection-logs=false` or
`RELAYD_REDACT_CONNECTION_LOGS=false`. Logs must not include tunnel token bytes or relayed payload
bytes.

### Log Retention

The published operational-log retention window for this deployment is **24 hours**
(`internal/relay/retention.go`'s `OperationalLogRetentionWindow`, bounded by the ADR-0103 ceiling of
7 days — "days, not months"). The shipped configs do not enforce this on their own; bound your log
transport to it explicitly:

- **Compose:** `packaging/compose/compose.self-hosted.yml` sets `logging.driver: json-file` with
  `max-size: "10m"` / `max-file: "3"` so container logs rotate and get pruned instead of growing
  unbounded. Tune `max-size`/`max-file` to your traffic volume, but keep the effective retention
  within the published window.
- **systemd/journald:** the unit does not bound journald retention by default. Add a per-unit
  drop-in at `/etc/systemd/journald@beamfall-relayd.conf.d/retention.conf`:

  ```ini
  [Journal]
  MaxRetentionSec=1day
  ```

  (or scope it to the whole journal via `/etc/systemd/journald.conf.d/beamfall-relay-retention.conf`
  if this host runs no other service needing longer retention), then
  `sudo systemctl restart systemd-journald`.

## Ports

- Public listener: expose to clients as external `443/tcp`. The relay may still listen on
  internal `:8443` behind Docker, NAT, or a TCP load balancer.
- Carrier listener: expose as external `443/tcp` when home-server networks only allow
  outbound `443`. It must be a distinct socket from the public listener: use a separate
  public IP, separate relay host, or ALPN-demux/TCP proxy/NAT endpoint mapping to
  internal `:9443`.
- Single-IP fallback: keep carrier on `9443/tcp` only when your home-server network allows
  outbound non-443 ports.
- `9080/tcp`: admin listener. Bind to localhost or a private network only.

Do not map both public and carrier listeners to the same external `IP:443` directly; `relayd`
does not multiplex those protocols on one socket.

## Required Secrets

Create these files with mode `0600`:

- `carrier.crt`: TLS certificate presented by the carrier listener.
- `carrier.key`: private key for `carrier.crt`.
- `token`: shared self-hosted token accepted by `relayd` and presented by the tunnel client.

### Host-side ownership for Docker Compose

`relayd` runs as **uid 65532** (nonroot distroless), and plain `docker compose` bind-mounts each
secret file into the container with the file's existing **host** owner and mode — the per-secret
`uid`/`gid`/`mode` keys in the compose `secrets:` block are a Docker Swarm feature that plain
compose silently ignores. A `0600` file owned by root (or your login user) is therefore **not
readable by uid 65532 inside the container**, and `relayd`'s startup permission check will fail.
Make each secret owned by that uid on the host after creating it:

```sh
sudo chown 65532:65532 secrets/carrier.crt secrets/carrier.key secrets/token
chmod 400 secrets/carrier.crt secrets/carrier.key secrets/token
```

`0400` owned by 65532 gives the container read access while denying every other host user. (The
systemd deployment below runs as a dedicated `beamfall-relay` host user instead, so its `install`
steps use that owner rather than a raw uid.)

Production hosted relay authorization is intentionally outside this repo. The relay binary
only consumes the `TokenVerifier` seam described in `docs/friction-report-milestone-1.md`.

### Carrier Token Strength

The carrier token is the only secret guarding the carrier port. `relayd` enforces a
minimum-entropy floor on it at startup and **refuses to start** on a weak token (too short or
too few distinct byte values), failing fast before any listener binds. The error never echoes
the token bytes.

- Minimum length: 32 bytes.
- Generate a strong token, never a hand-typed passphrase:

  ```sh
  openssl rand -base64 48 > secrets/token
  chmod 600 secrets/token
  ```

### Expiring, Replay-Resistant Tunnel Tokens (v2)

By default (`--token-mode hmac`) the token file/env value is a shared secret used to mint
expiring, replay-resistant v2 tunnel tokens:

- The token file/env value becomes a shared **secret** (same file on both sides, same strength
  requirement). The tunnel client mints a fresh v2 token from it on **every carrier dial**
  (`--token-ttl`, default and hard maximum **`5m`**): a self-contained signed claim carrying an
  **issued-at**, an **expires-at**, and a random **mint-time nonce** alongside the HMAC over the
  hostname set. The client refuses a larger configured TTL before dialing, and the relay
  independently rejects a signed lifetime above five minutes.
- The relay **refuses a token past its expires-at** and **refuses a nonce it has already seen**
  within the token's validity window. The client proactively registers a fresh same-identity
  carrier at about half the TTL, so new streams move before expiry. Existing streams on the old
  carrier may drain until `expires-at` plus `--expired-session-drain` (default `30s`); without a
  successful replacement the old carrier is still torn down exactly at expiry. No revocation list
  is fetched and no verify-time network call is made — the claim is entirely self-contained.
- In HMAC mode, `relayd` persists admitted nonces at
  `/var/lib/beamfall-relay/hmac-nonces.json` and fails startup if that state cannot be opened,
  locked, or durably written. Override it with `--hmac-nonce-store` or
  `RELAYD_HMAC_NONCE_STORE`. Development-only static-token mode does not create or use this state.
- Switch the relay (`RELAYD_TOKEN_MODE=hmac`) and every tunnel client
  (`TUNNEL_TOKEN_MODE=hmac`) **together**: the modes speak different token formats, so a
  mixed-mode pair fails the carrier handshake (`unauthorized`) until both sides match.

`--token-mode static` presents the shared token verbatim and is refused unless
`BEAMFALL_RELAY_DEV=1`. That development switch also enables other insecure controls; never set it
in production. If static mode is needed for local testing, set it on both binaries only for the
life of that test.

**Multi-instance HMAC requirement:** every relay instance accepting the same shared secret must
point at the **same persistent nonce-store path**. The backing filesystem must provide coherent
POSIX advisory locks and atomic same-directory rename across all hosts; otherwise use one relay
instance rather than weakening replay protection. A local disk or a per-replica container volume
is restart-safe for one instance but is not shared multi-instance state.

Library embedders only: `HMACTokenVerifier` also accepts the legacy **v1** bare-HMAC format
(no expiry, no nonce — replayable) while its `AcceptLegacyV1` flag is set, as a one-release
in-place upgrade path. The shipped binaries never minted v1 tokens, so `relayd --token-mode
hmac` runs strict-v2 with legacy acceptance off. In development-only `static` mode (with
`BEAMFALL_RELAY_DEV=1`), treat the shared token as the only guard and keep the carrier port
firewalled (below).

### Replay Nonce Store Sizing

The replay nonce store holds every admitted nonce until its token expires. Once it holds
`--hmac-nonce-store-capacity` (`RELAYD_HMAC_NONCE_STORE_CAPACITY`) live nonces it refuses every
new carrier dial until entries expire. Every carrier dial mints a fresh token, so the store fills
at the fleet-wide dial rate and drains as tokens expire.

- **Default `259200`** = the 24h `MaxHostedTokenTTL` (86,400 s, the longest signed lifetime any
  carrier token may carry) × a stated peak mint rate of **2 distinct valid tokens/s** summed across
  every instance sharing the store × **150%** headroom. With 24h tokens the default saturates at a
  sustained 3 tokens/s.
- `relayd --token-mode hmac` tokens live at most `5m`, so the same default holds a sustained
  259,200 / 300 s = 864 carrier dials/s across all instances before it fills.
- To resize: capacity = longest token TTL in seconds × peak fleet-wide dials/s × 1.5. Startup fails
  outside `1`–`1000000`. Set the same value on every instance sharing `--hmac-nonce-store`.
- The file store rewrites its whole state file on every admission (about 56 bytes per live entry),
  so a large, busy store costs proportionally more I/O per dial. Deployments sustaining hundreds of
  dials per second should implement `HMACNonceStore` on a transactional database instead.
- Lowering the capacity below the current live entry count does not fail startup: new dials are
  refused and the fill ratio reads above `1` until enough entries expire.

A full store still fails closed: the dial is refused and the tunnel client receives the same
`unauthorized` handshake error frame as for any refused token (the wire format is unchanged). The
relay records the refusal under its own reason, distinct from a bad token:

- Log: the `carrier unauthorized` Warn line carries `code=nonce_store_full` (a bad or replayed
  token logs `code=unauthorized`).
- Metrics: `beamfall_relay_tunnel_dials_total{outcome="nonce_store_full"}` (a bad token counts under
  `outcome="unauthorized"`); `beamfall_relay_handshake_failures_total` counts both. The handshake
  trace span outcome is also `nonce_store_full`.
- A full-store refusal does not feed the per-source failed-handshake backoff, because the carrier's
  token was valid.

**Alerting:** warn when `max(beamfall_relay_nonce_store_fill_ratio)` across instances stays at or
above **`0.8`** for 5 minutes, and page on any increase of
`beamfall_relay_tunnel_dials_total{outcome="nonce_store_full"}`. Refusal begins at a ratio of `1`.
Each instance reports the entries it read at its own most recent admission, so a quiet instance can
lag the shared store; the maximum across instances is the representative value.

### Token Rotation

Rotate the carrier secret on any suspected compromise, when an operator with access leaves, and
periodically as hygiene:

1. Generate a new secret (`openssl rand -base64 48`).
2. Update the relay: write the new value to the relay's `token` file (or `RELAYD_TOKEN`) and
   restart `relayd`.
3. Update every home-server tunnel client with the same new secret and restart it.

The relay and all tunnel clients must share the same secret, so plan a brief reconnect window:
clients whose tokens are signed with the old secret are rejected once the relay restarts. There is
no in-place multi-secret grace period — coordinate the relay and client cutover together. (Secret
rotation is orthogonal to the v1→v2 format upgrade above: v2's short TTL bounds a captured token's
usefulness automatically, but a compromised **secret** still requires this rotation.)

### Carrier Port Firewalling

The carrier port (`9443/tcp`) authenticates carriers by shared token only; treat it as a
sensitive control plane and do not expose it to the open internet when avoidable.

- Restrict `9443/tcp` at the host or cloud firewall to the known source IP(s) of your
  home server(s). Everything else should be dropped before it reaches `relayd`.
- If you expose the carrier listener on external `443/tcp`, apply the same source-IP
  firewall rule to that listener or to the TCP proxy/NAT target.
- Keep the admin port (`9080/tcp`) bound to localhost or a private network only.
- As defense in depth, `relayd` rate-limits repeated **failed** carrier handshakes per source
  IP with a growing, capped backoff, so a brute-force flood against the carrier port is slowed
  even if the firewall is misconfigured. This complements — it does not replace — firewalling.
  Failed handshakes are visible in `beamfall_relay_handshake_failures_total`; a rising counter
  signals misconfiguration or an attack.

#### Docker bypasses host firewalls (ufw/firewalld)

**This matters even if you have never touched iptables yourself.** The Docker daemon manages
its own iptables/nftables rules and inserts `DNAT`/`ACCEPT` rules for every published container
port *ahead of* the `ufw`/`firewalld` chains that normally filter incoming traffic. A host
firewall rule that appears to restrict `9443/tcp` to a source IP has **no effect** on a port
published via Docker's `ports:` mapping — Docker's own rules accept the traffic first. This is
long-standing, documented Docker behavior, not a bug specific to this relay.

The bundled `packaging/compose/compose.self-hosted.yml` defaults the carrier port mapping to
`RELAYD_CARRIER_BIND=127.0.0.1`, so out of the box the carrier port is not published to any
external interface. To expose it, an operator must explicitly opt in, and must pick one of:

1. **Bind to a specific host IP** (recommended for most self-hosted setups): set
   `RELAYD_CARRIER_BIND` to the host's real interface IP (never `0.0.0.0`) so only that
   interface's traffic reaches Docker's NAT rules, then firewall upstream (router/cloud
   security group) to the known home-server source IP(s).
2. **Add a `DOCKER-USER` iptables rule**: this chain runs *before* Docker's own NAT/forward
   rules and is never overwritten by `docker` or `dockerd` restarts, so it is the correct place
   to enforce source-IP filtering on a Docker-published port:

   ```sh
   # Allow only the known home-server source IP(s) to the carrier port, drop everything else.
   sudo iptables -I DOCKER-USER -p tcp --dport 9443 -s <home-server-ip> -j RETURN
   sudo iptables -I DOCKER-USER -p tcp --dport 9443 -j DROP
   ```

   Persist these with your distro's iptables-persistent mechanism; a `DOCKER-USER` rule set
   only in the running ruleset does not survive a reboot.
3. **Disable Docker's iptables management** (`"iptables": false` in `/etc/docker/daemon.json`)
   and take full responsibility for your own port-forwarding and filtering rules. Only do this
   if you understand the full implications — Docker will no longer set up *any* forwarding for
   published ports, including the public listener, so you must replace that too.

Whichever remedy you choose, verify it: from a host that is **not** in your allow-list, attempt
a TCP connection to the carrier port and confirm it is refused or times out, not accepted.

## Docker Compose

```sh
mkdir -p secrets
chmod 700 secrets
openssl rand -base64 48 > secrets/token   # relayd refuses to start on a weak token

# relayd runs as uid 65532; plain compose bind-mounts these with their host owner/mode,
# so the container can only read them if they are owned by 65532 (see "Host-side
# ownership for Docker Compose" above). carrier.crt/carrier.key must already exist here.
sudo chown 65532:65532 secrets/carrier.crt secrets/carrier.key secrets/token
chmod 400 secrets/carrier.crt secrets/carrier.key secrets/token

BEAMFALL_RELAY_DIGEST=replace-with-verified-64-hex-digest \
RELAYD_HOSTNAMES=home.relay.example \
docker compose -f packaging/compose/compose.self-hosted.yml up -d
```

`BEAMFALL_RELAY_DIGEST` is required and deliberately omits the `sha256:` prefix because the
Compose file supplies it. This keeps normal deployment bound to the signed immutable manifest even
if a registry tag later moves.

The mutable channel tag is an explicit emergency fallback, not the default. If an operator has
approved that loss of digest pinning, render a temporary Compose file and name the channel:

```sh
BEAMFALL_RELAY_CHANNEL=${BEAMFALL_RELAY_CHANNEL:-stable}
sed "s|image: ghcr.io/beamfall/relay@sha256:.*|image: ghcr.io/beamfall/relay:$BEAMFALL_RELAY_CHANNEL|" \
  packaging/compose/compose.self-hosted.yml >/tmp/beamfall-relay-channel-compose.yml
RELAYD_HOSTNAMES=home.relay.example \
docker compose --project-directory packaging/compose \
  -f /tmp/beamfall-relay-channel-compose.yml up -d
rm -f /tmp/beamfall-relay-channel-compose.yml
```

Return to `BEAMFALL_RELAY_DIGEST` as soon as the verified digest is available.

The compose file binds the admin listener to `127.0.0.1:9080` (both the container's own
listener and the host port mapping), so `/metrics`, `/healthz`, and `/readyz` are reachable
only from the host loopback, not from sibling containers on the bridge network.

The image declares `/var/lib/beamfall-relay` as its state volume, and Compose attaches the named
`relayd_state` volume so it persists across container replacement. It is initialized from the
image with uid 65532 and mode `0700`, so the distroless nonroot process can durably maintain HMAC
replay state. That named volume is single-host/single-instance;
for multiple relay hosts, replace it with storage shared by every instance and set
`RELAYD_HMAC_NONCE_STORE` to the common mounted path as described above.

The carrier port mapping defaults to `RELAYD_CARRIER_BIND=127.0.0.1` for the same reason: a
Docker-published port is not filtered by host firewalls (see "Docker bypasses host firewalls"
above), so the compose file does not expose it externally unless you explicitly set
`RELAYD_CARRIER_BIND` to a real interface IP and apply the `DOCKER-USER` (or equivalent)
remedy documented there.

Point DNS for each served hostname at the relay's public address. Native clients validate the home
server's pinned self-signed identity through the relay; browser-trusted direct public domains still
need the home server's ACME certificate and key. The relay carrier certificate is only for the
home-server-to-relay carrier connection.

### ECH and Relay DNS

The relay reads only the visible ClientHello SNI. Do not publish ECH or HTTPS-RR ECH configs
for relay-served hostnames unless the ECH outer `public_name` is itself registered in
`RELAYD_HOSTNAMES` and `TUNNEL_HOSTNAMES` for that carrier. A shared provider outer name
causes a safe outage: the relay sees only that outer name, finds no registered carrier, and
closes the connection as unknown SNI. For self-hosted deployments, either disable ECH on
relay DNS records or use a per-server outer name that routes to the same carrier. Longer-term
public-name routing belongs with the hostname/token issuer; see `docs/ech-hostname-evaluation.md`.

### Verify the Release Image

The `v0.1.0` image is cut by a human from an authenticated exact-local-gate receipt using
`docs/hosted-relay-launch-runbook.md`; the release script emits the digest-bound signing command.
The release script always uses the verifier committed at `script/local-gate-receipt-verify.py`;
the operator does not supply or select a verifier path.
If a release was signed by the tag-push `release.yml` workflow, verify its keyless signature
against this repo's GitHub OIDC identity before deploying it:

```sh
IMAGE=ghcr.io/beamfall/relay
DIGEST=sha256:replace-with-release-digest

cosign verify \
  --certificate-identity-regexp '^https://github.com/beamfall/relay/.github/workflows/release.yml@refs/tags/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${IMAGE}@${DIGEST}"
```

## systemd

```sh
sudo useradd --system --home /var/lib/beamfall-relay --shell /usr/sbin/nologin beamfall-relay
sudo install -d -o beamfall-relay -g beamfall-relay -m 0700 /etc/beamfall-relay /var/lib/beamfall-relay
sudo install -o beamfall-relay -g beamfall-relay -m 0600 carrier.crt /etc/beamfall-relay/carrier.crt
sudo install -o beamfall-relay -g beamfall-relay -m 0600 carrier.key /etc/beamfall-relay/carrier.key
sudo install -o beamfall-relay -g beamfall-relay -m 0600 token /etc/beamfall-relay/token
sudo install -o beamfall-relay -g beamfall-relay -m 0600 packaging/systemd/relayd.env.example /etc/beamfall-relay/relayd.env
sudo install -m 0644 packaging/systemd/beamfall-relayd.service /etc/systemd/system/beamfall-relayd.service
sudo systemctl daemon-reload
sudo systemctl enable --now beamfall-relayd
```

Edit `/etc/beamfall-relay/relayd.env` before starting if your hostnames, ports, or certificate
paths differ. The unit's `StateDirectory=beamfall-relay` creates `/var/lib/beamfall-relay` as
the service user with mode `0700` and keeps only that state directory writable under
`ProtectSystem=strict`, so the default HMAC nonce-store and Redis fair-use outbox paths persist
across restarts without weakening the rest of the filesystem sandbox.

## Carrier TLS certificate rotation

The certificate configured by `RELAYD_CARRIER_CERT` terminates TLS only on the carrier listener;
it is separate from the home server certificate passed through the public listener. ACME
certificates are commonly valid for 90 days, so automate renewal and alert well before the actual
`notAfter` value instead of relying on that nominal lifetime.

Install renewed certificate and key files at the configured paths, then make the new pair active
for the next carrier handshake without restarting `relayd`:

```sh
sudo systemctl reload beamfall-relayd
```

The packaged unit maps that exact command to `SIGHUP`. A certbot renewal can trigger it directly:

```sh
sudo certbot renew --deploy-hook 'systemctl reload beamfall-relayd'
```

`relayd` also checks the certificate and key mtimes once per minute, so an atomic file replacement
is discovered even if the deploy hook is missed. Each successful reload logs the active
certificate's `not_after`. If the replacement pair is unreadable, corrupt, or mismatched, reload
logs a Warn and keeps the last good pair; fix both files and reload again. Existing carrier
sessions are unchanged, while the next carrier TLS handshake receives the newly loaded pair.

Probe the carrier endpoint with Prometheus blackbox exporter and alert on its Unix-timestamp gauge
`probe_ssl_earliest_cert_expiry`, for example when
`probe_ssl_earliest_cert_expiry - time() < 14 * 24 * 60 * 60`. Probe the carrier address, not the
public passthrough address, and investigate both renewal automation and reload Warn logs when the
alert fires.

## Health and Metrics

- `GET /healthz` returns `ok` when the admin listener is alive. This is a **liveness** probe
  only — a relay with zero connected carriers still returns `ok`. Don't use it to decide
  whether the relay is ready to carry traffic.
- `GET /readyz` returns `ok` (200) when at least one carrier is connected and `not ready`
  (503) otherwise. This is the **readiness** probe — point load balancer / orchestrator
  readiness checks here, not at `/healthz`.
- `GET /metrics` exposes Prometheus text metrics:
  - `beamfall_relay_carriers_connected` — carriers with a live handshaked session (includes idle ones).
  - `beamfall_relay_active_tunnels` — carriers currently relaying at least one in-flight stream (a strict subset of `carriers_connected`).
  - `beamfall_relay_streams_active`
  - `beamfall_relay_bytes_relayed_total`
  - `beamfall_relay_handshake_failures_total`
  - `beamfall_relay_tunnel_dials_total{outcome}` — carrier handshake attempts by outcome: `success`, `unauthorized` (bad, expired, or replayed token), `nonce_store_full` (valid token refused because the replay nonce store is full; see "Replay Nonce Store Sizing"), `invalid`, `error`.
  - `beamfall_relay_nonce_store_fill_ratio` — hmac mode only: live replay nonce-store entries divided by `--hmac-nonce-store-capacity`. New carrier dials are refused at `1`; alert at `0.8` (see "Replay Nonce Store Sizing").
  - `beamfall_relay_public_over_cap_total` — public connections dropped at accept because the global concurrent-connection cap (`MaxPublicConns`) was exhausted; a rising counter signals a connection flood or an undersized cap. Raise or lower the cap with `--max-public-conns` / `RELAYD_MAX_PUBLIC_CONNS` (default 1024; 0 uses the built-in default).
  - `beamfall_relay_public_per_ip_over_cap_total` — public connections dropped at accept because a single source prefix (IPv4 /32 or IPv6 /64) already held its concurrent-connection cap (`--max-public-conns-per-ip` / `RELAYD_MAX_PUBLIC_CONNS_PER_IP`, default 64; 0 uses the built-in default). A rising counter with a small distinct-source set signals a slow-loris / partial-record flood from one origin. See "Public-listener flood posture" below.
  - `beamfall_relay_fairuse_refused_connections_total`
  - `beamfall_relay_fairuse_window_bytes`
  - `beamfall_relay_fairuse_soft_limited_tunnels`
  - `beamfall_relay_fairuse_throttled_tunnels`

Metrics are aggregate-only and label-free. They do not export tunnel ids, hostnames,
account ids, tokens, payload bytes, or per-stream records. Operational logs are separate
transient operator logs; public connection logs redact hostnames, remote addresses, and carrier ids
unless explicitly disabled, and never include tunnel token bytes or relayed payload bytes.

### Readiness vs. Liveness, and the No-Carrier-Yet Window

The bundled `cmd/relay-healthcheck` binary (the Docker `HEALTHCHECK` in
`packaging/compose/compose.self-hosted.yml`) probes `/readyz`, not `/healthz` — a deliberate
choice so Docker actually marks the container unhealthy when the relay has no connected carrier,
rather than reporting healthy on process liveness alone.

This has one operational consequence worth planning for: a freshly started `relayd` is correctly
**unready** ("no ready" / 503) for the entire window between the container starting and its first
home-server carrier connecting. That is expected, not a bug — do not treat the first
`/readyz` 503s after a (re)start as a failure. Plain `docker compose` with `restart:
unless-stopped` does not itself restart a container for being unhealthy, so the shipped Compose
file is safe as-is. If you front this container with an orchestrator that *does* map "unhealthy"
to a forced restart (a Swarm `restart_policy` keyed on health, or a Kubernetes `livenessProbe`
pointed at the same endpoint), size its failure threshold and start-up grace period to comfortably
exceed how long your home-server tunnel client normally takes to reconnect — otherwise the
orchestrator can restart a relay that is simply waiting for its first carrier, which only delays
that carrier's connection further (a crash loop with no path to becoming ready). Point a
liveness-only check at `/healthz` instead if your orchestrator distinguishes the two probe types.

## Stream concurrency

`--stream-cap` / `RELAYD_STREAM_CAP` (default 64) bounds the concurrent
public-to-backend streams opened through each carrier. Each routed public connection consumes one
stream until its byte splice closes; attempts above the cap are refused with `stream cap reached`.

This carrier limit is independent of `--max-public-conns-per-ip` /
`RELAYD_MAX_PUBLIC_CONNS_PER_IP` (default 64), which limits concurrently handled public TCP
connections from one source IP before routing. For one source IP targeting one carrier, effective
concurrency cannot exceed the lower of the two caps. Raising the per-IP limit alone therefore does
not raise that carrier's stream concurrency; raise `--stream-cap` too when legitimate shared-NAT
or CDN traffic needs more than 64 simultaneous streams, while retaining an appropriate per-IP
flood ceiling.

## Public-listener flood posture (defense-in-depth)

The public listener does not terminate TLS: for each accepted connection it peeks the
client's TLS ClientHello to read the SNI and route the byte-blind splice. A **partial-record
flood** — an attacker that completes the TCP handshake then dribbles (or never sends) the
ClientHello — holds a public slot for the whole peek window without ever completing a
handshake. Three controls bound that occupancy, so a flood cannot pin the public slot pool
and starve legitimate clients:

- **Global slot cap** — `--max-public-conns` / `RELAYD_MAX_PUBLIC_CONNS` (default 1024) bounds
  total concurrently-handled public connections; over the cap, accepts are closed immediately
  (`beamfall_relay_public_over_cap_total`).
- **Per-IP slot cap** — `--max-public-conns-per-ip` / `RELAYD_MAX_PUBLIC_CONNS_PER_IP`
  (default 64) bounds concurrently-handled public connections **from any single source prefix**, so
  one origin cannot occupy the whole global pool regardless of how long each connection stalls
  in the peek; over the per-IP cap, accepts are closed immediately
  (`beamfall_relay_public_per_ip_over_cap_total`). This is the primary defense against a
  single-source slow-loris flood. IPv4 is keyed by /32; all IPv6 addresses in one /64 share a
  budget, preventing interface-identifier rotation from bypassing the cap.
- **Per-source/per-carrier stream cap** — `--max-streams-per-ip-per-carrier` /
  `RELAYD_MAX_STREAMS_PER_IP_PER_CARRIER` bounds established streams from one IPv4 /32 or IPv6
  /64 to one carrier. The default is one quarter of `--stream-cap`, with a minimum of one (16
  when the library's default stream cap is 64). This leaves carrier capacity for other source
  prefixes even when one source holds idle keep-alive TLS sessions. `0` selects the derived
  default; the carrier-wide `--stream-cap` remains the final ceiling.
- **Peek deadline** — `--public-peek-timeout` (default 3s) bounds how long a connection may
  stall waiting for the ClientHello before it is reaped, shrinking the window each stalled
  connection can hold a slot.

**Chosen posture:** the per-IP cap is the load-bearing control (it caps a single flooding
source at a small fraction of the pool no matter the peek duration); the shortened peek
deadline is a secondary bound on how long each admitted connection can stall. Both defaults
are conservative for a self-hosted single-tenant relay. **For an internet-facing / multi-tenant
deployment behind a shared public NAT or CDN**, many legitimate clients may share one source IP —
raise `--max-public-conns-per-ip` accordingly (or terminate the flood at an upstream L4/L7
front). Where a fronting proxy already enforces per-client connection limits, this cap is pure
defense-in-depth. Watch `beamfall_relay_public_per_ip_over_cap_total`: sustained growth from a
small set of sources indicates an active flood; growth spread across many legitimate shared-NAT
sources indicates the per-IP cap is set too low for the deployment.

## Resource Limits

Both shipped deployment configs cap the process's memory and open-file-descriptor ceilings so a
connection flood or misconfiguration fails predictably (OOM-killed or refusing new fds) instead of
degrading the host:

- **systemd** (`packaging/systemd/beamfall-relayd.service`): `MemoryMax=512M`,
  `LimitNOFILE=65536`.
- **Compose** (`packaging/compose/compose.self-hosted.yml`): `mem_limit: 512m`, `ulimits.nofile`
  soft/hard `65536`.

Both are conservative starting points derived from the shipped connection caps above — each
public/carrier connection holds one file descriptor and, while relaying, a 32 KiB splice buffer
per direction — not a benchmarked ceiling for your traffic. If you raise `--max-public-conns`,
`--max-carrier-conns`, `--max-pending-carrier-conns`, or `--stream-cap` well past their defaults, raise these limits
proportionally and confirm the real ceiling against observed memory/fd usage
(`systemctl status beamfall-relayd` or the container's cgroup stats) rather than trusting the
shipped numbers unmeasured.

## Fair-use Accounting

Self-hosted operators can opt into rolling-window fair-use accounting. The relay remains
byte-blind: it counts encrypted bytes at the copy loop and never inspects payloads, HTTP
requests, Stream Tokens, or media content.

Equivalent config shape:

```yaml
fairUse:
  enabled: false
  windowDays: 30
  softLimitBytes: 0
  hardLimitBytes: 0
  throttledMaxConns: 4
```

`enabled: false` is the default and leaves fair-use policy inactive. When enabled, the relay
keeps an in-memory per-tunnel ring of hourly buckets for the configured window. State is not
persisted in v1, so counters reset when `relayd` restarts; that is acceptable for the beta
self-hosted posture.

**Single-instance ceiling.** Fair-use accounting lives only in the memory of one `relayd`
process. Two consequences follow, both intentional for the self-hosted launch:

- A restart (or crash) zeroes the rolling window. A tunnel that can trigger restarts can reset
  its own counters, so fair-use is a soft, best-effort ceiling rather than a hard guarantee.
- Counters are **not** shared across `relayd` instances. Do **not** run fair-use behind a
  load balancer fanning one tunnel across multiple relays — each instance counts only the
  traffic it sees, so the effective limit multiplies by the instance count.

For the beta posture this is by design: the in-memory choice keeps the relay free of any
durable per-connection record (see the privacy note below) and matches the single-instance
self-hosted deployment. Shared multi-instance deployments instead select the Redis backend
described below.

Crossing the soft limit emits one structured log entry for the crossing and updates aggregate
metrics. Crossing the hard limit does not close existing streams. It only reduces the allowed
new concurrent connections for that tunnel to `throttledMaxConns`; new attempts above that
ceiling are refused the same way an exhausted stream cap is refused. Refusal logs are sampled.
When the rolling window falls back under the limits, the tunnel restores silently.

Flags and matching environment variables:

- `--fair-use-enabled` / `RELAYD_FAIR_USE_ENABLED`
- `--fair-use-window-days` / `RELAYD_FAIR_USE_WINDOW_DAYS`
- `--fair-use-soft-limit-bytes` / `RELAYD_FAIR_USE_SOFT_LIMIT_BYTES`
- `--fair-use-hard-limit-bytes` / `RELAYD_FAIR_USE_HARD_LIMIT_BYTES`
- `--fair-use-throttled-max-conns` / `RELAYD_FAIR_USE_THROTTLED_MAX_CONNS`
- `--fair-use-store` / `RELAYD_FAIR_USE_STORE` (`memory`, the default, or `redis`)
- `--fair-use-redis-url` / `RELAYD_FAIR_USE_REDIS_URL` (prefer the environment variable so
  credentials never appear in process arguments)
- `--fair-use-outbox` / `RELAYD_FAIR_USE_OUTBOX` (Redis mode; default
  `/var/lib/beamfall-relay/fairuse-outbox.json`)
- `--fair-use-lease-ttl` / `RELAYD_FAIR_USE_LEASE_TTL` (Redis mode; default `90s`)
- `--fair-use-fence-margin` / `RELAYD_FAIR_USE_FENCE_MARGIN` (Redis mode; default `10s`)

### Hosted / multi-tenant deployments

This guide targets a single-tenant self-hosted relay, where the operator and every carrier
are the same trusted party. If you instead expose a relay to **untrusted or multiple tenants**
(a hosted or shared deployment), you **must** enable **both** abuse controls, not one:

- **Per-carrier byte rate limit** (`--rate-bytes-per-sec`, with an optional
  `--rate-burst-bytes`) — caps sustained throughput per carrier so no single tunnel monopolizes
  bandwidth. It is **off by default** (`0` disables it).
- **Fair-use accounting** (`--fair-use-enabled` plus a non-zero `--fair-use-hard-limit-bytes`) —
  caps cumulative volume over a rolling window and throttles a tunnel's new connections once it
  crosses the hard limit. It too is **off by default** (`enabled: false`).

Each covers a different axis: the rate limit bounds instantaneous bandwidth, fair-use bounds
total volume over time. Enabling only one leaves the other axis unbounded, so a hosted relay
needs both. `relayd` emits a startup **warning** when it launches with neither control active
(`no abuse controls enabled …`); treat that warning as a hard blocker for any multi-tenant
deployment.

Hosted multi-instance deployments must set `RELAYD_FAIR_USE_STORE=redis` and point every relay
at the same Redis deployment. The shared backend uses Redis server time, atomic rolling-window
increments, and fleet-wide stream reservations. The normal hosted cap remains three streams per
opaque server across the whole fleet (not three per relay); the fair-use hard cap can only reduce
that value. A reservation is refreshed every 5 seconds and expires after the lease TTL (default
90 seconds). If refresh cannot be confirmed, the relay turns readiness red, refuses new
admissions, and closes the stream one fence margin (default 10 seconds) before its last confirmed
reservation expires. Live streams therefore survive a Redis outage shorter than lease TTL − fence
margin − 10s (70 seconds at the defaults). Recovery stays unready until every surviving stream
has reconfirmed its reservation under the current fleet cap. The full per-duration outage
behaviour table is in `docs/hosted-relay-launch-runbook.md` (Redis Fair-Use Outage Policy).

Byte writes are coalesced at 1 MiB or 250 ms, so Redis is not called for each copied chunk.
Redis byte commits run on the tunnel's background flush worker and the outbox replayer, never on
the copy goroutine, so byte copying never waits on a Redis round trip. While Redis is unhealthy,
partial batches stay in memory and only full 1 MiB batches are written to the outbox.
Before Redis receives a batch, the relay durably appends it to the local outbox with a stable
batch id and relay-recorded creation hour: one newline-terminated log entry, written and fsynced
before the append reports success. The outbox file is a base state object followed by those
entries (outbox format version 2), periodically compacted back to a single object through a
same-directory rename. A clean shutdown compacts it once more, to a single version-1 object with no
entries, the only shape that relay builds from before the append log can read. If an
append fails part-way (for example, a full disk), the relay truncates the file back to its length
before that append, keeps the batch in memory, and holds readiness red until restart; on restart
an unterminated final entry is discarded, because its append never reported success, while a
complete but malformed entry still fails closed. The live write and every replay use that same
durable authority. Redis deduplicates retries, including an ambiguous commit followed by process loss, and
an older delayed replay never shortens the dedupe lifetime established by a newer batch.
Shutdown stops admissions, durably stages every accepted final delta, makes a bounded replay
attempt, joins all flush/replay workers, and only then closes Redis; permanent Redis failure leaves
the records for restart. Startup validates and drains existing records before any Relay socket
binds. The outbox file/lock require mode `0600` in a current-user-owned `0700` directory on
persistent local storage with POSIX advisory-lock, atomic-rename, file-fsync, and directory-fsync
semantics. Corruption, overflow, unsafe provenance, or disk failure fails closed. Records contain
only an opaque tunnel digest, aggregate bytes, random batch id, and creation/expiry times; they
expire with the configured fair-use window and are never account-joined. When the outbox reaches
its record limit (8192 batches), readiness turns red and stays red until replay drains it below the
limit minus a 1/64 band (under 8064 records), so readiness does not flip with each batch while the
outbox sits at the limit; admission of new batches still follows the limit alone.

**Outbox rollback rule: clean shutdown first.** Before downgrading to a relay build that predates
the append-log outbox, stop the running relay cleanly (SIGTERM or SIGINT, then wait for the
process to exit) so it leaves the single version-1 object. A crash, a `SIGKILL`, or a shutdown
after an outbox write failure (readiness already red) leaves the version-2 file with its entries;
the older build refuses that file at startup (`unsupported state` or `trailing state data`) and
fails closed without dropping any record. To recover, start the current build once on the same
file, which replays every record, stop it cleanly, and then start the older build. A clean
shutdown whose final compaction fails logs `fair_use_outbox_close_failed` and needs the same
recovery. Upgrading needs no step: current builds read version-1 files.

Redis `TIME` remains authoritative for the rolling-window cutoff; both the initial write and a
delayed outbox replay retain the batch's original relay-recorded hour. Keep Relay and Redis host
time synchronized and never rewind either clock. Redis
persistence/backups may retain opaque reservation nonces, but each member carries an absolute
expiry score and every reservation operation deletes scores older than current Redis time. An
RDB/AOF restore therefore cannot make an expired lease live again; do not use restore tooling
that rewrites expiry scores or restores the Redis host clock. The Redis URL may contain a secret:
keep it in the platform secret store and never place it in logs or command arguments.

## Soak Harness

Run a bounded local load session:

```sh
make soak STREAMS=8 MBPS=32
```

The harness starts an in-process relay, tunnel client, and fake home TLS server. It reports
streams per second, bytes relayed, p50/p99 stream setup latency, and the process max RSS.
Use `go run ./cmd/relay-loadgen -fair-use` to run the same harness with fair-use accounting
enabled and high limits that do not throttle the test streams.

The current harness is local-only and does not simulate WAN RTT. Treat a passing
`STREAMS=8 MBPS=32` run as bounded local soak evidence, not proof of a 50 ms RTT profile.

### QUIC vs TCP Carrier Throughput

The relay supports two carriers: the v1 yamux-over-TLS/TCP carrier and the ADR-0018 QUIC
carrier (`relay-loadgen -transport tcp|quic`). Expect them to behave differently depending on
network conditions, not uniformly better or worse:

- **On a clean, low-RTT LAN**, QUIC is typically on par with or slightly behind TCP+TLS+yamux.
  QUIC's congestion control and crypto run in userspace, which costs more CPU per byte than the
  kernel TCP stack plus a single yamux-multiplexed TLS connection. Do not expect a LAN win from
  switching carriers.
- **Under RTT and packet loss**, QUIC's per-stream flow control avoids the head-of-line blocking
  that yamux's single multiplexed TCP connection suffers: one lossy stream stalls only itself on
  QUIC, whereas on the TCP carrier a lost segment blocks every multiplexed stream until it is
  retransmitted. Expect the gap to widen as configured loss/RTT increases.

These are qualitative expectations, not measured numbers — this repo does not ship pre-recorded
throughput figures because they are host- and network-dependent. To generate real numbers for
your environment:

```sh
sudo make netem-soak
```

This runs `script/netem-soak.sh`, which drives `relay-loadgen` over both carriers across a grid
of injected RTT/loss values (Linux `tc`/`netem` on loopback) and tabulates aggregate and
per-stream throughput so the head-of-line-blocking difference shows up as numbers. The harness:

- **requires Linux with `tc` (iproute2) and CAP_NET_ADMIN** — run it as root or via `sudo`.
  `netem` is Linux-only; there is no macOS/BSD equivalent implemented here (would be
  `dnctl`/`pfctl`).
- **preflights and refuses cleanly** on a non-Linux host, a missing `tc`, or without root — it
  never hangs waiting for a privileged command and never fabricates numbers.
- always tears down its `tc` qdisc on exit, including on error or interrupt.

Override the grid with `DURATION`, `STREAMS`, `MBPS`, `RTTS`, `LOSSES`, or write a TSV table with
`RESULTS=out.tsv`; see `script/netem-soak.sh` for the full flag list.
