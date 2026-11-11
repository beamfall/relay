#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

mkdir -p "$tmp/bin"
cat >"$tmp/bin/docker" <<'EOF'
#!/bin/sh
set -eu

case "${1-} ${2-}" in
  "context inspect")
    printf '%s\n' 'unix:///fixture/docker.sock'
    ;;
  "version --format")
    printf '%s\n' 'linux/amd64'
    ;;
  "buildx build")
    : "${DOCKER_CAPTURE:?}"
    printf 'GOTOOLCHAIN=%s\n' "${GOTOOLCHAIN-}" >>"$DOCKER_CAPTURE"
    printf 'SOURCE_DATE_EPOCH=%s\n' "${SOURCE_DATE_EPOCH-}" >>"$DOCKER_CAPTURE"
    printf '%s\n' "$@" >>"$DOCKER_CAPTURE"
    shift 2
    metadata=""
    output=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--metadata-file" ]; then
        metadata=$2
        shift 2
      elif [ "$1" = "--output" ]; then
        output=${2#type=docker,dest=}
        output=${output%,rewrite-timestamp=true}
        shift 2
      else
        shift
      fi
    done
    [ -n "$metadata" ]
    [ -n "$output" ]
    digest=${MOCK_IMAGE_DIGEST:-sha256:$(printf '%064d' 7)}
    printf '{"containerimage.digest":"%s"}\n' "$digest" >"$metadata"
    printf '%s\n' fixture-image-tar >"$output"
    ;;
  *)
    echo "unexpected docker invocation: $*" >&2
    exit 1
    ;;
esac
EOF
chmod +x "$tmp/bin/docker"
cat >"$tmp/bin/docker-buildx" <<'EOF'
#!/bin/sh
exec "$(dirname "$0")/docker" buildx "$@"
EOF
chmod +x "$tmp/bin/docker-buildx"

cat >"$tmp/verifier.py" <<'PY'
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
    "receiptSHA256": "0" * 64,
}, separators=(",", ":"), sort_keys=True))
PY

new_fixture() {
  name=$1
  fixture="$tmp/$name"
  mkdir -p "$fixture/script"
  cp "$root/script/release.sh" "$fixture/script/release.sh"
  cp "$tmp/verifier.py" "$fixture/script/local-gate-receipt-verify.py"
  chmod +x "$fixture/script/release.sh"
  printf '%s\n' 'FROM scratch' >"$fixture/Dockerfile"
  printf '%s\n' 'script/dist/' >"$fixture/.gitignore"
  git -C "$fixture" init -q -b main
  git -C "$fixture" config user.email release-test@beamfall.invalid
  git -C "$fixture" config user.name release-test
  git -C "$fixture" add .
  git -C "$fixture" commit -q -m fixture

  head=$(git -C "$fixture" rev-parse HEAD)
  tree=$(git -C "$fixture" rev-parse 'HEAD^{tree}')
  receipt="$tmp/$name-receipt.json"
  expected="$tmp/$name-expected.json"
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
}

run_release() {
  PATH="$tmp/bin:$PATH" DOCKER_CAPTURE="$tmp/docker-capture" \
    "$fixture/script/release.sh" v0.1.0 \
    --gate-receipt "$receipt" \
    --gate-expected "$expected" \
    "$@"
}

assert_refused() {
  expected_error=$1
  shift
  if "$@" >"$tmp/refused.out" 2>"$tmp/refused.err"; then
    echo "FAIL: release command unexpectedly succeeded" >&2
    exit 1
  fi
  if ! grep -F -- "$expected_error" "$tmp/refused.err" >/dev/null; then
    echo "FAIL: refusal did not contain '$expected_error'" >&2
    cat "$tmp/refused.err" >&2
    exit 1
  fi
}

new_fixture dirty
printf '%s\n' dirty >>"$fixture/Dockerfile"
assert_refused "worktree must be clean" run_release

new_fixture missing-receipt
assert_refused "--gate-receipt is required" \
  env PATH="$tmp/bin:$PATH" DOCKER_CAPTURE="$tmp/docker-capture" \
  "$fixture/script/release.sh" v0.1.0 \
  --gate-expected "$expected"

new_fixture auto-toolchain
assert_refused "automatic toolchain download is forbidden" \
  env GOTOOLCHAIN=auto PATH="$tmp/bin:$PATH" DOCKER_CAPTURE="$tmp/docker-capture" \
  "$fixture/script/release.sh" v0.1.0 \
  --gate-receipt "$receipt" \
  --gate-expected "$expected"

new_fixture wrong-head
python3 - "$expected" <<'PY'
import json
import sys

with open(sys.argv[1], "r+", encoding="utf-8") as source:
    expected = json.load(source)
    expected["commit"] = "f" * 40
    source.seek(0)
    json.dump(expected, source)
    source.truncate()
PY
assert_refused "gate expected tuple does not match this exact gated head" run_release

new_fixture missing-verifier
rm "$fixture/script/local-gate-receipt-verify.py"
git -C "$fixture" add -u
git -C "$fixture" commit -q -m missing-verifier
head=$(git -C "$fixture" rev-parse HEAD)
tree=$(git -C "$fixture" rev-parse 'HEAD^{tree}')
python3 - "$expected" "$head" "$tree" <<'PY'
import json
import sys

with open(sys.argv[1], "r+", encoding="utf-8") as source:
    expected = json.load(source)
    expected["commit"] = sys.argv[2]
    expected["tree"] = sys.argv[3]
    source.seek(0)
    json.dump(expected, source)
    source.truncate()
PY
assert_refused "committed receipt verifier is missing" run_release

new_fixture caller-verifier
assert_refused "usage: script/release.sh" run_release \
  --receipt-verifier "$tmp/verifier.py"

new_fixture happy
: >"$tmp/docker-capture"
digest="$fixture/script/dist/beamfall-relay-v0.1.0-linux-amd64.digest"
tarball="$fixture/script/dist/beamfall-relay-v0.1.0-linux-amd64.docker.tar"
cosign="$fixture/script/dist/beamfall-relay-v0.1.0-linux-amd64.cosign-command.txt"
expected_digest="sha256:$(printf '%064d' 7)"
run_release --expect-digest "$expected_digest" >"$tmp/happy.out"
[ "$(cat "$digest")" = "$expected_digest" ]
[ "$(cat "$tarball")" = "fixture-image-tar" ]
[ "$(cat "$cosign")" = "cosign sign --yes ghcr.io/beamfall/relay@$expected_digest" ]
grep -Fx -- '--pull' "$tmp/docker-capture" >/dev/null
grep -Fx -- 'type=docker,dest='"$tarball"',rewrite-timestamp=true' \
  "$tmp/docker-capture" >/dev/null
grep -Fx -- '--build-arg' "$tmp/docker-capture" >/dev/null
grep -Fx -- "SOURCE_DATE_EPOCH=$(git -C "$fixture" show -s --format=%ct HEAD)" \
  "$tmp/docker-capture" >/dev/null
grep -Fx -- '--platform' "$tmp/docker-capture" >/dev/null
grep -Fx -- 'linux/amd64' "$tmp/docker-capture" >/dev/null
grep -Fx -- 'ghcr.io/beamfall/relay:v0.1.0' "$tmp/docker-capture" >/dev/null
grep -Fx -- "ghcr.io/beamfall/relay:sha-$(printf %.12s "$head")" "$tmp/docker-capture" >/dev/null
grep -Fx -- 'GOTOOLCHAIN=local' "$tmp/docker-capture" >/dev/null
grep -E '^SOURCE_DATE_EPOCH=[0-9]+$' "$tmp/docker-capture" >/dev/null

: >"$tmp/docker-capture"
different_digest="sha256:$(printf '%064d' 8)"
assert_refused "image digest mismatch: expected $different_digest, got $expected_digest" \
  run_release --expect-digest "$different_digest"
printf 'PASS: expected-digest refusal: %s\n' "$(cat "$tmp/refused.err")"

grep -F 'image: ghcr.io/beamfall/relay@sha256:${BEAMFALL_RELAY_DIGEST:' \
  "$root/packaging/compose/compose.self-hosted.yml" >/dev/null
if grep -F 'image: ghcr.io/beamfall/relay:${BEAMFALL_RELAY_CHANNEL:-stable}' \
  "$root/packaging/compose/compose.self-hosted.yml" >/dev/null; then
  echo "FAIL: Compose still defaults to a mutable channel tag" >&2
  exit 1
fi

echo "PASS: release refuses unsafe inputs and emits reproducible exact-head image metadata"
