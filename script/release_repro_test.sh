#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
fixture="$tmp/repository"
mkdir -p "$fixture"
git -C "$root" archive --format=tar HEAD | tar -xf - -C "$fixture"

cat >"$fixture/script/local-gate-receipt-verify.py" <<'PY'
#!/usr/bin/env python3
import argparse
import json

parser = argparse.ArgumentParser()
parser.add_argument("--receipt", required=True)
parser.add_argument("--expected", required=True)
args = parser.parse_args()
with open(args.expected, "rb") as source:
    expected = json.load(source)
print(json.dumps({
    "authorized": True,
    "repository": expected["repository"],
    "commit": expected["commit"],
    "tree": expected["tree"],
}, separators=(",", ":"), sort_keys=True))
PY
chmod +x "$fixture/script/local-gate-receipt-verify.py"
git -C "$fixture" init -q -b main
git -C "$fixture" config user.email release-repro-test@beamfall.invalid
git -C "$fixture" config user.name release-repro-test
git -C "$fixture" add .
git -C "$fixture" commit -q -m fixture

head=$(git -C "$fixture" rev-parse HEAD)
tree=$(git -C "$fixture" rev-parse 'HEAD^{tree}')
receipt="$tmp/receipt.json"
expected="$tmp/expected.json"
printf '%s\n' '{}' >"$receipt"
python3 - "$expected" "$head" "$tree" <<'PY'
import json
import sys

path, head, tree = sys.argv[1:]
with open(path, "w", encoding="utf-8") as output:
    json.dump({
        "repository": "beamfall/relay",
        "commit": head,
        "tree": tree,
        "command": ["/usr/bin/make", "gate"],
        "outputSHA256": "0" * 64,
        "result": "success",
        "host": {"os": "fixture", "architecture": "fixture", "hardware": "fixture"},
        "toolchain": "fixture",
        "issuerId": "fixture",
        "issuerScope": "fixture",
        "policyVersion": "fixture",
    }, output)
PY

run_release() {
  GOTOOLCHAIN=local "$fixture/script/release.sh" v0.1.0 \
    --gate-receipt "$receipt" \
    --gate-expected "$expected"
}

platform=$(docker version --format '{{.Server.Os}}-{{.Server.Arch}}')
digest="$fixture/script/dist/beamfall-relay-v0.1.0-$platform.digest"
tarball="$fixture/script/dist/beamfall-relay-v0.1.0-$platform.docker.tar"
run_release >"$tmp/first.log"
cp "$digest" "$tmp/first.digest"
cp "$tarball" "$tmp/first.docker.tar"
run_release >"$tmp/second.log"
cmp "$tmp/first.digest" "$digest"
cmp "$tmp/first.docker.tar" "$tarball"

printf 'source head: %s\n' "$(git -C "$root" rev-parse HEAD)"
printf 'fixture head: %s\n' "$head"
printf 'platform: %s\n' "$platform"
printf 'image digest: %s\n' "$(cat "$digest")"
sha256sum "$tmp/first.digest" "$digest" "$tmp/first.docker.tar" "$tarball"
echo 'PASS: two real same-SHA same-platform release builds emitted identical digest files and tarballs'
