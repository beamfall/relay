<p align="center">
  <img src=".github/brand/beamfall-logo.png" alt="Beamfall" width="96" height="96">
</p>

# Beamfall Relay

A byte-blind, SNI-peek remote-access relay written in Go. Public clients connect to the
relay; it peeks **only** the TLS ClientHello SNI hostname, then splices the raw client bytes
over an authenticated [yamux](https://github.com/hashicorp/yamux) carrier session to the
home server. It **never terminates client TLS**, holds no public-hostname certificates, and
**never logs tokens or relayed payload bytes** — TLS terminates on the home server, so the
relay only ever sees encrypted bytes, SNI hostnames, connection metadata, and traffic volume.

The repo ships two binaries plus a soak harness:

- `relayd` — the relay daemon (public + carrier + admin listeners).
- `tunnel-client` — the home-server side that opens the outbound carrier and forwards
  inbound streams to a local backend.
- `relay-loadgen` — an in-process soak/load harness (no network deployment).

The product is the libraries under `internal/`; `cmd/` is thin wiring. See
[`PROTOCOL.md`](PROTOCOL.md) for the wire contract and [`AGENTS.md`](AGENTS.md) for the
build/contributor conventions.

## Prerequisites

- Go at the version declared by `go.mod`.
- `make`; the full gate also invokes the repository-pinned lint, vulnerability, and vector checks.
- Docker only when building or running the container image.

The protocol security boundary is defined in [`PROTOCOL.md`](PROTOCOL.md). Deployment, secrets,
TLS, and operational hardening live in
[`docs/operator-self-hosted-relay.md`](docs/operator-self-hosted-relay.md); hosted launch controls
live in [`docs/hosted-relay-launch-runbook.md`](docs/hosted-relay-launch-runbook.md).

## Launch posture (ADR-0025 / ADR-0018)

Per **ADR-0025**, the launch promise is the **user-run self-hosted relay**: an operator runs
`relayd` on their own VPS and runs `tunnel-client` next to their home server. Self-hosted
ships first, and RELAY-1 readiness is scoped to the hosted token verifier/client boundary
described below. The SniTun-style relay contract and hosted internals are specified in
**ADR-0018**. Both ADRs live in the [Core ADR index](../beamfall/docs/adr/README.md), not in this repo.

RELAY-1 has implemented only the hosted token-boundary seam: `relayd` can consume a
cloud-minted short-lived tunnel token through `TokenVerifier`, and `tunnel-client` can
hand off an externally supplied token before carrier dial. That is not a hosted relay
runtime release: DNS-01 delegation, claim codes, hosted deployment/control-plane rollout,
and production entitlement operations remain deferred future-roadmap work.

Any future Hosted Relay beta/GA must pass the launch gates in
[`docs/hosted-relay-launch-runbook.md`](docs/hosted-relay-launch-runbook.md) before serving real
users.

For end-to-end operator setup (Docker Compose, systemd, ports, secrets, fair-use), see
[`docs/operator-self-hosted-relay.md`](docs/operator-self-hosted-relay.md).

## Authorization boundary (out of repo)

This repo is licensed under AGPL v3 (see [LICENSE](LICENSE)) and legitimately holds the `TokenVerifier` seam and the
test/self-hosted verifiers (`StaticTokenVerifier`, `HMACTokenVerifier`). The **production
hosted token mint / entitlement check lives outside this repo** — there is no token-mint code
in-tree. The relay only ever calls the `TokenVerifier` interface
(`internal/relay/token.go`) with the opaque token bytes and the requested hostnames; the
hosted control plane supplies the real verifier behind that seam. Per the workspace firewall
(see `AGENTS.md`), entitlement/licensing/account logic never moves toward the AGPL core.

For self-hosted deployments, `relayd` defaults to `HMACTokenVerifier`: tunnel clients mint
expiring, replay-resistant v2 tokens from a shared secret. `StaticTokenVerifier` is available
only for development with `BEAMFALL_RELAY_DEV=1`; static bearer tokens are replayable if
captured. Keep `relayd` and `tunnel-client` on the same mode (see the operator guide's
"Expiring, Replay-Resistant Tunnel Tokens (v2)").

## Build

Build caches are redirected into `.cache/` (gitignored) via `GOCACHE`/`GOMODCACHE`, so prefer
the Makefile targets, which set those automatically.

- `make gate` — the full gate: `gofmt-check`, `build`, `vet`, `lint`, `vuln`, `cover` (race-enabled
  `go test -coverprofile` with a 70% floor), `verify-vectors`. Run this by hand before submitting.
  CI (`.github/workflows/gate.yml`) runs a parallel gate on push/PR to `main`: `go build`, `go vet`,
  `go test -race`, plus a 30s fuzz smoke of `FuzzReadFrame` and `FuzzParseClientHelloRecord`. CI
  does not run `gofmt-check`, `lint`, `vuln`, or `verify-vectors`, so keep running `make gate`
  locally to catch those.
- `make build` — `go build ./...`.
- `make vet` / `make test` — vet / test individually.
- `make soak STREAMS=8 MBPS=32` — bounded in-process load session (heavy; perf only).

A multi-stage [`Dockerfile`](Dockerfile) builds static `relayd` and `tunnel-client` binaries
into a distroless nonroot image (entrypoint `relayd`, exposes `8443`, `9443`, `9080`).
Release images are signed with keyless cosign; see the operator guide for the verification
command before deploying a new digest.

## Run

### relayd

Listens on three surfaces (binary defaults shown): public TLS passthrough `:8443`, carrier
TLS 1.3 `:9443`, and a localhost admin listener `127.0.0.1:9080` serving `/healthz` and
`/metrics`. Production deployments should expose public traffic on external TCP `443`; if
home-server egress is restricted to `443`, expose the carrier listener on a separate
`IP:443`, or behind an ALPN-demux/TCP proxy/NAT endpoint. The public and carrier listeners
cannot share one external `IP:443` directly. Every flag has a matching `RELAYD_*` environment
variable (see [Environment](#environment)).

```sh
relayd \
  --carrier-cert /etc/beamfall-relay/carrier.crt \
  --carrier-key  /etc/beamfall-relay/carrier.key \
  --token-file   /etc/beamfall-relay/token \
  --hostnames    home.relay.example
```

`--carrier-cert`/`--carrier-key` are the relay carrier listener's TLS material (not the
public-hostname certificate — that lives on the home server). The token may instead be
supplied via `RELAYD_TOKEN`. At least one hostname is required.

### tunnel-client

Runs next to the home server, dials the relay carrier listener, authenticates with the shared
token, and forwards each inbound stream to the local backend. Auto-reconnects.

```sh
tunnel-client \
  --relay-addr   relay-carrier.example:443 \
  --backend-addr 127.0.0.1:8443 \
  --hostnames    home.relay.example \
  --token-file   /etc/beamfall-relay/token \
  --relay-ca     /etc/beamfall-relay/carrier-ca.pem
```

`--relay-ca` pins the relay carrier CA. `--insecure-skip-verify` skips carrier TLS
verification and is for local tests only; it is refused at startup unless
`BEAMFALL_RELAY_DEV=1` is set, so release/systemd deployments must never enable it.
The token may instead be supplied via `TUNNEL_TOKEN`.

The relay routes public traffic by the visible ClientHello SNI only. Do not publish ECH or
HTTPS-RR ECH configs for relay-served hostnames unless the ECH outer `public_name` is itself
one of the relay-routable hostnames registered by the carrier; a shared provider
`public_name` fails closed as unknown SNI.

## Environment

Every `relayd` flag and the `tunnel-client` connection flags can be set via environment
variables. See [`.env.example`](.env.example) for the full list with descriptions and secret
markers. Token/key values are secrets — supply them via a `0600` file (`*_TOKEN_FILE`) or a
secrets manager rather than committing them.

## Observability

The admin listener (`/metrics`, Prometheus text format) exports aggregate-only, label-free
counters and gauges — connected carriers, active tunnels/streams, total bytes relayed,
handshake failures, public over-cap refusals, and fair-use counters. Metrics never export
tunnel ids, hostnames, tokens, payload bytes, or per-stream records.

Operational logs are transient operator logs. They may include hostnames, remote addresses,
carrier ids, byte counts, errors, and durations for abuse/debugging, but must never include
tunnel token bytes or relayed payload bytes. See `docs/operator-self-hosted-relay.md` for
the full metric list.

If `--admin-addr` binds anywhere other than loopback, `/metrics` requires a bearer credential:
set it via `--admin-metrics-token-file` (or `RELAYD_ADMIN_METRICS_TOKEN`/
`RELAYD_ADMIN_METRICS_TOKEN_FILE`) per ADR-0146 §5. A non-loopback admin bind refuses to start
without one; loopback-only admin listeners don't need it.
