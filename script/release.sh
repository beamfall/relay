#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ROOT}/script/dist"
IMAGE="ghcr.io/beamfall/relay"
RECEIPT_VERIFIER="${ROOT}/script/local-gate-receipt-verify.py"

usage() {
  cat >&2 <<'EOF'
usage: script/release.sh v<semver> \
  --gate-receipt <receipt.json> \
  --gate-expected <expected.json> \
  [--expect-digest <sha256:...>]
EOF
  exit 2
}

fail() {
  echo "release: refused: $*" >&2
  exit 1
}

VERSION="${1:-}"
[ -n "${VERSION}" ] || usage
shift

GATE_RECEIPT=""
GATE_EXPECTED=""
EXPECTED_DIGEST=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --gate-receipt)
      [ "$#" -ge 2 ] || usage
      GATE_RECEIPT=$2
      shift 2
      ;;
    --gate-expected)
      [ "$#" -ge 2 ] || usage
      GATE_EXPECTED=$2
      shift 2
      ;;
    --expect-digest)
      [ "$#" -ge 2 ] || usage
      EXPECTED_DIGEST=$2
      shift 2
      ;;
    *) usage ;;
  esac
done

printf '%s\n' "${VERSION}" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' ||
  fail "version must be v<semver>"

[ -z "$(git -C "${ROOT}" status --porcelain --untracked-files=all -- . ':(exclude)script/dist')" ] ||
  fail "worktree must be clean"

case "${GOTOOLCHAIN:-local}" in
  local) export GOTOOLCHAIN=local ;;
  *) fail "GOTOOLCHAIN must be local; automatic toolchain download is forbidden" ;;
esac

[ -n "${GATE_RECEIPT}" ] || fail "--gate-receipt is required"
[ -f "${GATE_RECEIPT}" ] || fail "gate receipt does not exist: ${GATE_RECEIPT}"
[ -n "${GATE_EXPECTED}" ] || fail "--gate-expected is required"
[ -f "${GATE_EXPECTED}" ] || fail "gate expected tuple does not exist: ${GATE_EXPECTED}"
[ -f "${RECEIPT_VERIFIER}" ] || fail "committed receipt verifier is missing: ${RECEIPT_VERIFIER}"
if [ -n "${EXPECTED_DIGEST}" ]; then
  printf '%s\n' "${EXPECTED_DIGEST}" | grep -Eq '^sha256:[0-9a-f]{64}$' ||
    fail "--expect-digest must be sha256:<64 lowercase hex characters>"
fi

HEAD_SHA="$(git -C "${ROOT}" rev-parse HEAD)"
TREE_SHA="$(git -C "${ROOT}" rev-parse 'HEAD^{tree}')"

assert_exact_source() {
  [ "$(git -C "${ROOT}" rev-parse HEAD)" = "${HEAD_SHA}" ] ||
    fail "HEAD changed after gate-receipt validation"
  [ "$(git -C "${ROOT}" rev-parse 'HEAD^{tree}')" = "${TREE_SHA}" ] ||
    fail "tree changed after gate-receipt validation"
  [ -z "$(git -C "${ROOT}" status --porcelain --untracked-files=all -- . ':(exclude)script/dist')" ] ||
    fail "worktree changed after gate-receipt validation"
}

if ! python3 - "${GATE_EXPECTED}" "${HEAD_SHA}" "${TREE_SHA}" <<'PY'
import json
import sys

path, head, tree = sys.argv[1:]
with open(path, "rb") as source:
    expected = json.load(source)
required = {
    "repository": "beamfall/relay",
    "commit": head,
    "tree": tree,
    "command": ["/usr/bin/make", "gate"],
    "result": "success",
}
for key, value in required.items():
    if expected.get(key) != value:
        raise SystemExit(f"expected.{key} does not match: {expected.get(key)!r}")
PY
then
  fail "gate expected tuple does not match this exact gated head"
fi

VERIFICATION="$({ python3 "${RECEIPT_VERIFIER}" \
  --receipt "${GATE_RECEIPT}" \
  --expected "${GATE_EXPECTED}"; } 2>&1)" || {
  printf '%s\n' "${VERIFICATION}" >&2
  fail "local gate receipt verification failed"
}

if ! python3 - "${HEAD_SHA}" "${TREE_SHA}" "${VERIFICATION}" <<'PY'
import json
import sys

head, tree, raw = sys.argv[1:]
authorization = json.loads(raw)
required = {
    "authorized": True,
    "repository": "beamfall/relay",
    "commit": head,
    "tree": tree,
}
for key, value in required.items():
    if authorization.get(key) != value:
        raise SystemExit(f"authorization.{key} does not match: {authorization.get(key)!r}")
PY
then
  fail "local gate receipt authorization is not bound to this exact head"
fi

assert_exact_source

docker_host="$(docker context inspect --format '{{.Endpoints.docker.Host}}')"
docker_platform="$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')"
case "${docker_platform}" in
  linux/amd64|linux/arm64) ;;
  *) fail "unsupported release platform: ${docker_platform}" ;;
esac

platform_name="${docker_platform%/*}-${docker_platform#*/}"
short_sha="${HEAD_SHA:0:12}"
version_tag="${IMAGE}:${VERSION}"
sha_tag="${IMAGE}:sha-${short_sha}"
tarball="${DIST}/beamfall-relay-${VERSION}-${platform_name}.docker.tar"
digest_file="${DIST}/beamfall-relay-${VERSION}-${platform_name}.digest"
cosign_file="${DIST}/beamfall-relay-${VERSION}-${platform_name}.cosign-command.txt"
metadata_file="${DIST}/.build-metadata.json"
docker_config="$(mktemp -d)"
build_context="$(mktemp -d)"
trap 'rm -rf "${docker_config}" "${build_context}"; rm -f "${metadata_file}"' EXIT INT TERM

mkdir -p "${DIST}"
rm -f "${tarball}" "${digest_file}" "${cosign_file}" "${metadata_file}"
git -C "${ROOT}" archive --format=tar "${HEAD_SHA}" | tar -xf - -C "${build_context}"
assert_exact_source

if command -v docker-buildx >/dev/null 2>&1; then
  buildx=(docker-buildx)
else
  buildx=(docker buildx)
fi

SOURCE_DATE_EPOCH="$(git -C "${ROOT}" show -s --format=%ct "${HEAD_SHA}")"
export SOURCE_DATE_EPOCH
DOCKER_CONFIG="${docker_config}" DOCKER_HOST="${docker_host}" "${buildx[@]}" build --pull \
  --output "type=docker,dest=${tarball},rewrite-timestamp=true" \
  --platform "${docker_platform}" \
  --build-arg "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" \
  --tag "${version_tag}" \
  --tag "${sha_tag}" \
  --metadata-file "${metadata_file}" \
  "${build_context}"

digest="$(python3 - "${metadata_file}" <<'PY'
import json
import re
import sys

with open(sys.argv[1], "rb") as source:
    metadata = json.load(source)
digest = metadata.get("containerimage.digest", "")
if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
    raise SystemExit("Buildx metadata has no valid containerimage.digest")
print(digest)
PY
)" || fail "could not read the image digest from Buildx metadata"

if [ -n "${EXPECTED_DIGEST}" ] && [ "${digest}" != "${EXPECTED_DIGEST}" ]; then
  fail "image digest mismatch: expected ${EXPECTED_DIGEST}, got ${digest}"
fi

assert_exact_source
printf '%s\n' "${digest}" >"${digest_file}"
printf 'cosign sign --yes %s@%s\n' "${IMAGE}" "${digest}" >"${cosign_file}"

echo "release image tarball: ${tarball}"
echo "release image digest:  ${digest_file}"
echo "sign after the operator pushes both tags:"
cat "${cosign_file}"
