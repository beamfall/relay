#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE_REPO="${BEAMFALL_CORE_REPO:-"$ROOT/../beamfall"}"
if [ -z "${BEAMFALL_E2E_BIN_DIR:-}" ]; then
  BIN_DIR="$(mktemp -d)"
  trap 'rm -rf "$BIN_DIR"' EXIT
else
  BIN_DIR="$BEAMFALL_E2E_BIN_DIR"
fi

[ -d "$CORE_REPO" ] || { echo "core repo not found: $CORE_REPO" >&2; exit 1; }
mkdir -p "$BIN_DIR"

export GOCACHE="${GOCACHE:-"$ROOT/.cache/go-build"}"

go build -o "$BIN_DIR/relayd" "$ROOT/cmd/relayd"
(
  cd "$CORE_REPO"
  go build -o "$BIN_DIR/beamfall" ./cmd/beamfall
)

BEAMFALL_RELAY_CORE_E2E=1 \
BEAMFALL_RELAYD_BIN="$BIN_DIR/relayd" \
BEAMFALL_CORE_BIN="$BIN_DIR/beamfall" \
go test -count=1 -run '^TestRelayCoreRealBinaryE2E$' ./internal/e2e -v
