#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

checkout_a="$tmp/checkout-a"
checkout_b="$tmp/checkout-b"
bin="$tmp/bin"
mkdir -p "$checkout_a" "$checkout_b" "$bin"
checkout_a=$(cd "$checkout_a" && pwd -P)
checkout_b=$(cd "$checkout_b" && pwd -P)

cat >"$bin/golangci-lint" <<'EOF'
#!/bin/sh
set -eu
: "${LINT_CACHE_CAPTURE:?}"
: "${LINT_ARGS_CAPTURE:?}"
printf '%s\n' "${GOLANGCI_LINT_CACHE-}" >"$LINT_CACHE_CAPTURE"
printf '%s\n' "$@" >"$LINT_ARGS_CAPTURE"
EOF
chmod +x "$bin/golangci-lint"

run_lint() {
	checkout=$1
	cache_capture=$2
	args_capture=$3
	PATH="$bin:$PATH" \
		GOLANGCI_LINT_CACHE="$tmp/shared-global-cache" \
		LINT_CACHE_CAPTURE="$cache_capture" \
		LINT_ARGS_CAPTURE="$args_capture" \
		make --no-print-directory -s -C "$checkout" -f "$root/Makefile" lint
}

assert_capture() {
	checkout=$1
	cache_capture=$2
	args_capture=$3
	expected_cache="$checkout/.cache/golangci-lint"
	actual_cache=$(cat "$cache_capture")

	if [ "$actual_cache" != "$expected_cache" ]; then
		echo "FAIL: lint cache is not checkout-local and absolute: got '$actual_cache', want '$expected_cache'" >&2
		exit 1
	fi
	if [ "$(wc -l <"$args_capture" | tr -d ' ')" -ne 3 ] ||
		[ "$(sed -n '1p' "$args_capture")" != "run" ] ||
		[ "$(sed -n '2p' "$args_capture")" != "./..." ] ||
		[ "$(sed -n '3p' "$args_capture")" != "--allow-parallel-runners" ]; then
		echo "FAIL: lint target must run the full 'golangci-lint run ./... --allow-parallel-runners' command" >&2
		exit 1
	fi
}

run_lint "$checkout_a" "$tmp/cache-a" "$tmp/args-a"
run_lint "$checkout_b" "$tmp/cache-b" "$tmp/args-b"
assert_capture "$checkout_a" "$tmp/cache-a" "$tmp/args-a"
assert_capture "$checkout_b" "$tmp/cache-b" "$tmp/args-b"

if [ "$(cat "$tmp/cache-a")" = "$(cat "$tmp/cache-b")" ]; then
	echo "FAIL: separate checkout paths resolved to the same golangci-lint cache" >&2
	exit 1
fi

echo "PASS: golangci-lint cache is isolated per checkout and lint still covers ./..."
