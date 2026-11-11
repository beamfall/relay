# AGENTS.md

> **This file is canonical.** `CLAUDE.md` is a symlink to it — edit `AGENTS.md`,
> never maintain a second copy.

> **Documentation:** before adding, moving, or archiving any doc, follow the workspace
> [documentation governance](../DOCUMENTATION-GOVERNANCE.md) (doc map: [`../DOCS.md`](../DOCS.md)).
> The only active work source is `beamfall/docs/plans/roadmap.md`; handoffs, artifacts, and
> agent-memory files are reference only.

## Testing contract (ADR-0121 §8)

A tier is listed only if its blocking smoke test actually runs in `make gate` — verified, not aspirational.

- **Owned tiers + in-gate smoke** (blocking via `make gate`):
  - Unit/integration — `go test -race -coverprofile=coverage.out ./...` (the `cover` target; tunnel
    protocol-interop tests run here under the race detector).
  - Static — `go vet ./...` + `golangci-lint run ./...`.
  - Dependency/release hermeticity — nested `relaytoken` vet/tests, a clean-tree
    credential-free `GOPROXY=off` build/vet/test, and the release `docker build`.
- **Coverage floor:** total-coverage floor enforced in `make cover` (`COVERAGE_FLOOR`); the gate REDs
  if total drops below it.
- **Nightly tiers:** load/soak (`make soak`, `cmd/relay-loadgen`) — not in the PR gate.
- **Device residual:** none — relay is a host Go service.
- **Release-gate command:** `make gate` (full `-race ./...`, coverage floor, and release image build
  already run per-PR); load/soak (`make soak`) is the additional pre-ship evidence.

## Corvint context

Before editing, read `corvint context "<task>"` or `corvint impact <path>...`; before choosing tests,
run `corvint affected --base <origin/main sha>`. **Verify:** `make gate`.

## Hermetic relaytoken dependency

`go.mod` resolves `github.com/beamfall/relay/relaytoken` through the commit-local
`replace => ./relaytoken`. The nested module boundary is retained because its provenance tests audit
the transferred Cloud-owned schema as a self-contained zero-dependency module; folding it into the
root would erase that boundary without improving hermeticity. No build needs a Cloud sibling,
repository credential, or network fetch for relaytoken.

All six build workflows use this in-tree dependency, including `fuzz-nightly.yml`'s
`internal/relay` target. `make hermetic-check` uses an empty credential environment to prefetch only
ordinary dependencies from the public Go proxy, then builds, vets, and tests a clean committed tree
with the module proxy and VCS disabled. `make release-image` builds the same repository-root Docker
context; the Dockerfile downloads public dependencies before compiling with module-proxy and VCS
resolution disabled.

## Spec-driven changes (OpenSpec)

New or changed behaviour needs an OpenSpec change in `openspec/changes/<id>/` committed before the
code: `proposal.md` (naming its `CORE` ticket), the spec delta and `tasks.md`. A fix that restores an
existing requirement or ADR cites it instead. Tickets stay the work queue; `tasks.md` is a
checklist. Existing ADRs and `docs/` stay canonical; do not backfill specs. Run
`openspec validate --all --strict` before review and `openspec archive <id>` after landing, before
completing the ticket. Agent commands are generated per checkout with `openspec update`. The
workflow is specified in beamfall/core, `openspec/changes/adopt-openspec/`.
