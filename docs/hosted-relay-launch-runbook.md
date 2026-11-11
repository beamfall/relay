# Hosted Relay Launch Runbook

Hosted Relay is future-roadmap per ADR-0025. Before any beta or GA serving real users, this
runbook is the release gate for the relay path.

## Hard Gate: Apple SPKI Pinning

Hosted Relay must not serve real user traffic until native Apple clients prove they reject a relay
path whose presented server key does not match the LAN-captured SPKI pin.

- Blocking proof: `beamfall-apple` `swift test --filter SPKIPinRepairTests`.
- Required regression: `testRelayPathKeepsLANCapturedPinWhenEndpointHashChanges`.
- Required behavior: the selected relay URL still builds a pinned session using the original
  LAN-captured SPKI hash, not a relay-presented replacement hash.
- Required archive: write the release attempt, command output, commit SHA, and reviewer sign-off to
  `docs/plans/roadmap/evidence/NGAUDIT-D5-pinning-gate.md` in the launch evidence bundle.

## Cut the `v0.1.0` Relay Image

This is a human operator ceremony. Do not substitute a hosted check for the exact-head local gate,
and do not continue while the authenticated local-gate trust store is unprovisioned. The approved
issuer scope must name repository `beamfall/relay` and command `["/usr/bin/make","gate"]`.

Use a clean canonical `main` checkout and the workspace receipt tooling:

```sh
export RELAY_ROOT=/absolute/path/to/beamfall-relay
export WORKSPACE_ROOT=/absolute/path/to/beamfall-workspace
cd "$RELAY_ROOT"
git switch main
git pull --ff-only origin main
test -z "$(git status --porcelain --untracked-files=all)"

HEAD_SHA=$(git rev-parse HEAD)
TREE_SHA=$(git rev-parse 'HEAD^{tree}')
TOOLCHAIN="$(go version); $(docker version --format 'docker client={{.Client.Version}} server={{.Server.Version}}'); $(docker buildx version)"

"$WORKSPACE_ROOT/script/gate-digest.sh" \
  --receipt-evidence /tmp/beamfall-relay-v0.1.0-gate-evidence.json \
  --receipt-root "$RELAY_ROOT" \
  --receipt-repository beamfall/relay \
  --receipt-toolchain "$TOOLCHAIN" \
  -- /usr/bin/make gate

read -r -s LOCAL_OPERATOR_KEY_SELECTOR
printf '%s\n' "$LOCAL_OPERATOR_KEY_SELECTOR" |
swift "$WORKSPACE_ROOT/script/local-gate-receipt-issue.swift" \
  --issue \
  --key-selector-stdin true \
  --evidence /tmp/beamfall-relay-v0.1.0-gate-evidence.json \
  --candidate-root "$RELAY_ROOT" \
  --repository beamfall/relay \
  --issuer-id operator-signer \
  --key-id operator-signer-2026-01 \
  --issuer-scope relay-release-gate \
  --policy-version 2026-07-28.1 \
  --output /tmp/beamfall-relay-v0.1.0-gate-receipt.json
unset LOCAL_OPERATOR_KEY_SELECTOR

python3 - \
  /tmp/beamfall-relay-v0.1.0-gate-evidence.json \
  /tmp/beamfall-relay-v0.1.0-gate-expected.json <<'PY'
import json
import sys

with open(sys.argv[1], "rb") as source:
    evidence = json.load(source)
expected = {key: evidence[key] for key in (
    "repository", "commit", "tree", "command", "outputSHA256", "result",
    "host", "toolchain",
)}
expected.update({
    "issuerId": "operator-signer",
    "issuerScope": "relay-release-gate",
    "policyVersion": "2026-07-28.1",
})
with open(sys.argv[2], "w", encoding="utf-8", newline="\n") as output:
    json.dump(expected, output, separators=(",", ":"), sort_keys=True)
    output.write("\n")
PY

GOTOOLCHAIN=local script/release.sh v0.1.0 \
  --gate-receipt /tmp/beamfall-relay-v0.1.0-gate-receipt.json \
  --gate-expected /tmp/beamfall-relay-v0.1.0-gate-expected.json
```

The release script makes no outward changes. It writes a local Docker image tarball, the Buildx
manifest digest, and the exact `cosign sign` command under `script/dist/`; it tags the local image
as both `:v0.1.0` and `:sha-${HEAD_SHA%${HEAD_SHA#????????????}}`. Compare the digest files from two
runs on the same platform before publishing:

```sh
cp script/dist/beamfall-relay-v0.1.0-linux-amd64.digest /tmp/relay-first.digest
GOTOOLCHAIN=local script/release.sh v0.1.0 \
  --gate-receipt /tmp/beamfall-relay-v0.1.0-gate-receipt.json \
  --gate-expected /tmp/beamfall-relay-v0.1.0-gate-expected.json
cmp /tmp/relay-first.digest script/dist/beamfall-relay-v0.1.0-linux-amd64.digest
```

Only the human operator authenticates to GHCR, pushes the three tags, signs the immutable digest,
and updates the deployment digest. Replace `linux-amd64` with `linux-arm64` on an arm64 Docker host:

```sh
IMAGE=ghcr.io/beamfall/relay
VERSION=v0.1.0
SHORT_SHA=${HEAD_SHA%${HEAD_SHA#????????????}}
DIGEST=$(cat script/dist/beamfall-relay-v0.1.0-linux-amd64.digest)

docker image tag "$IMAGE:$VERSION" "$IMAGE:stable"
docker image push "$IMAGE:$VERSION"
docker image push "$IMAGE:sha-$SHORT_SHA"
docker image push "$IMAGE:stable"
REMOTE_DIGEST=$(docker buildx imagetools inspect "$IMAGE:$VERSION" |
  awk '$1 == "Digest:" { print $2; exit }')
test "$REMOTE_DIGEST" = "$DIGEST"

cosign sign --yes "$IMAGE@$DIGEST"
: "${COSIGN_CERTIFICATE_IDENTITY:?set the approved operator OIDC identity}"
: "${COSIGN_OIDC_ISSUER:?set the approved operator OIDC issuer}"
cosign verify \
  --certificate-identity "$COSIGN_CERTIFICATE_IDENTITY" \
  --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
  "$IMAGE@$DIGEST"

BEAMFALL_RELAY_DIGEST=${DIGEST#sha256:} \
RELAYD_HOSTNAMES=home.relay.example \
docker compose -f packaging/compose/compose.self-hosted.yml pull
```

Record the exact receipt, SHA, digest, signature verification output, and successful Compose pull
before declaring the image released. Git tag creation or push, if separately approved, remains a
human action; pushing a `v*` Git tag also invokes the existing hosted release workflow and must not
be allowed to replace the manually verified digest.

## Redis Fair-Use Outage Policy

Applies to hosted multi-instance relays running `RELAYD_FAIR_USE_STORE=redis` (ADR 0018). The
shared Redis store enforces the fleet-wide stream cap, so while it is unreachable no relay can
prove a new stream fits under that cap. The policy is:

- **New stream opens fail closed.** An open the relay cannot reserve in Redis is refused
  (`fair-use shared store unavailable`) and `/readyz` returns 503.
- **Live streams fail open for a bounded time.** A stream that already holds a lease keeps
  copying bytes. The relay closes it (the fence) only once its last confirmed lease refresh is
  older than lease TTL minus fence margin, which is before Redis could expire the lease and let
  another relay admit a replacement over the fleet cap.
- **Byte copying never waits on Redis.** Copied bytes are counted in RAM; each full 1 MiB batch
  is committed by the tunnel's background flush worker, not the copy goroutine. When that worker
  is itself waiting out a Redis timeout, the copy path moves a batch to the local durable outbox
  (disk only) and the replayer commits it to Redis once Redis answers.

| Knob | Flag | Environment | Default |
|---|---|---|---|
| Stream lease TTL in Redis (refreshed every 5s) | `--fair-use-lease-ttl` | `RELAYD_FAIR_USE_LEASE_TTL` | `90s` |
| Fence margin before an unconfirmed lease lapses | `--fair-use-fence-margin` | `RELAYD_FAIR_USE_FENCE_MARGIN` | `10s` |

The guaranteed outage budget is lease TTL − fence margin − 10s (two 5s heartbeats): **70s** at the
defaults, less the first post-outage refresh round trip. That covers a typical managed-Redis
failover. `relayd` refuses to start with a negative fence margin or a budget of zero or less.
Raising the lease TTL buys a longer budget at a cost: a relay that crashes leaves its streams'
leases counted against the fleet stream cap for up to one lease TTL.

Behaviour of one relay during a Redis outage at the defaults. "Outage" means Redis does not answer
this relay. The duration counts from the start of the outage.

| Outage duration | Live streams | New stream opens | `/readyz` | Byte accounting |
|---|---|---|---|---|
| First seconds | Continue | Refused once any Redis call has failed; each refusal takes up to the Redis client read timeout (3s by default) | 503 after the first failed Redis call (a lease refresh fails within 5s plus the read timeout) | Counted in RAM; full 1 MiB batches go to the local outbox |
| Up to 70s | **All continue; none are cut.** Tested with a 30s pause (evidence below) | Refused | 503 | One outbox record per MiB copied; partial batches stay in RAM while Redis is unhealthy |
| 70s to 80s | Depends on refresh phase: each stream was last confirmed 0–5s before the outage and is closed 80s after that confirmation | Refused | 503 | As above |
| Over 80s | Every stream on every relay has been closed by the fence | Refused | 503 | Accepted bytes stay in the outbox until Redis returns |
| Redis returns | Surviving streams reconfirm on their next 5s refresh | Admitted again once the store is healthy | 200 once every surviving stream has reconfirmed and the store is healthy; an idle relay recovers through the replayer's health probe — this also covers a relay whose outbox had hit its record/byte cap, since capacity is rechecked live rather than latched | The replayer drains the outbox into Redis, each batch exactly once |

The outbox caps what one relay can hold during an outage at 8192 records, which is 8 GiB of copied
bytes. Hitting the cap is no longer fatal to that relay: every live stream is still closed once its
tunnel holds about 2 MiB of unflushed bytes and new opens stay refused, but `/readyz` recovers on its
own. The outbox's health check recomputes the cap live on every call instead of latching unready
forever, so as soon as the replayer drains recorded entries back below the limit — once Redis is
reachable again — `/readyz` returns to 200 with **no relay restart**. A relay carrying more than about
1 Gbit/s still exhausts the cap before the 70s lease budget, so on such relays the cap, not the lease,
still bounds how long streams survive the outage.

Operational rules:

- Wire `/readyz` to routing only, never to a restart or liveness policy. Restarting relays because
  they are unready during a Redis outage would close every live stream that the lease budget
  exists to keep.
- Alert on sustained `/readyz` 503s across the fleet together with Redis health. A shared Redis
  outage makes every relay unready at once.

## Launch Checklist

- [ ] Apple SPKI proof above is green on the release candidate.
- [ ] iOS and tvOS builds include the same `BeamfallMobile` / `BeamfallTV` pinning code under test.
- [ ] Relay threat model still states Apple pinning as a byte-blindness dependency.
- [ ] Hosted-relay control plane has not added account, entitlement, or token-minting logic to AGPL
      Core.
- [ ] Reviewer records PASS/FAIL and evidence SHA before enabling hosted relay for real users.
- [ ] The `v0.1.0` image receipt binds the exact released `main` SHA and `/usr/bin/make gate`.
- [ ] Two same-platform release builds produced identical digest files.
- [ ] `docker compose pull` succeeded with `BEAMFALL_RELAY_DIGEST` set to the signed digest.
- [ ] The fair-use lease budget (lease TTL − fence margin − 10s) exceeds the managed Redis
      failover time, and no restart policy keys off `/readyz` (see Redis Fair-Use Outage Policy).
