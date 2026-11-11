#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'verify-cloud-checkout: %s\n' "$1" >&2
  exit 1
}

[[ $# -eq 2 ]] || die 'usage: verify-cloud-checkout.sh REVISION_FILE CLOUD_CHECKOUT'

revision_file=$1
cloud_checkout=$2

[[ -f "$revision_file" ]] || die "missing revision file: $revision_file"
expected_sha=$(<"$revision_file")
[[ "$expected_sha" =~ ^[0-9a-f]{40}$ ]] || die "invalid revision: $expected_sha"

actual_sha=$(git -C "$cloud_checkout" rev-parse --verify 'HEAD^{commit}' 2>/dev/null) || die "invalid Git checkout: $cloud_checkout"
[[ "$actual_sha" == "$expected_sha" ]] || die "checkout HEAD $actual_sha does not match $expected_sha"
[[ -f "$cloud_checkout/relaytoken/go.mod" ]] || die 'missing relaytoken/go.mod'
