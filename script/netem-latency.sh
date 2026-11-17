#!/usr/bin/env bash
# netem-latency.sh: control-stream latency under media load through a real
# tc/netem carrier link (docs/relay-latency-budget.md, CORE-2262).
#
# The in-process harness (relay-loadgen -mode latency) emulates the link and
# only models TCP loss. This runs the same measurement with the kernel's own
# TCP loss recovery: the loadgen dials the relay's carrier port directly and
# netem shapes that port, each direction separately, to the reference link.
#
# It runs in a private network namespace, so the host's loopback is never
# touched and other work on the host is unaffected. Only carrier traffic is
# shaped; the viewer and home-server legs stay unshaped loopback.
#
# Requirements: Linux, root, tc with sch_netem, sch_prio and cls_u32, unshare.
# Root often has no Go toolchain, so build first and pass the binary:
#
#   go build -o /tmp/relay-loadgen ./cmd/relay-loadgen
#   sudo BIN=/tmp/relay-loadgen script/netem-latency.sh
#
# Tunables: DURATION (10s), RATE_MBIT (20), DELAY_MS (10, one way), QUEUE_MS
# (50), LOSSES ("0 1", percent), PORT (47443), TRANSPORTS (comma-separated tcp,
# quic, auto; default all three, auto being the tunnel client's default).
#
# BLOCK_UDP=1 drops UDP to the carrier port, the network of a client that
# cannot reach the relay over UDP, and measures the default transport only: it
# has to fall back to TLS/TCP (CORE-2283).
#
# To measure another tunnel client (core's home server client) as the carrier,
# set CARRIER_CMD to a command that reads $CARRIER_DIR/carrier.env once it
# appears, registers with the relay and carries until the relay goes away. It
# runs inside the namespace, once per loss value, on whichever carrier that
# client chooses at the relay's address. See docs/relay-latency-budget.md.
set -euo pipefail

BIN="${BIN:-}"
DURATION="${DURATION:-10s}"
RATE_MBIT="${RATE_MBIT:-20}"
DELAY_MS="${DELAY_MS:-10}"
QUEUE_MS="${QUEUE_MS:-50}"
LOSSES="${LOSSES:-0 1}"
PORT="${PORT:-47443}"
CARRIER_CMD="${CARRIER_CMD:-}"
TRANSPORTS="${TRANSPORTS:-}"
BLOCK_UDP="${BLOCK_UDP:-0}"
[ "$BLOCK_UDP" != "1" ] || TRANSPORTS="auto"
MTU=1500

fail() { echo "netem-latency: $*" >&2; exit 1; }

[ "$(uname -s)" = "Linux" ] || fail "netem is Linux-only; this host is $(uname -s)."
[ "$(id -u)" = "0" ] || fail "needs root for a network namespace and tc."
[ -n "$BIN" ] && [ -x "$BIN" ] || fail "set BIN to a built relay-loadgen binary."
command -v tc >/dev/null 2>&1 || fail "tc (iproute2) not found."
command -v unshare >/dev/null 2>&1 || fail "unshare (util-linux) not found."

if [ "${NETEM_LATENCY_IN_NS:-}" != "1" ]; then
  NETEM_LATENCY_IN_NS=1 exec unshare --net -- "$0" "$@"
fi

# Never shape the host's loopback, whatever the environment says.
[ "$(readlink /proc/self/ns/net)" != "$(readlink /proc/1/ns/net)" ] || fail "not in a private network namespace; refusing to touch the host's loopback."

# Inside the private namespace from here on. It disappears with this process,
# so there is nothing to tear down.
ip link set lo up
# Loopback's 64 KiB MTU and segmentation offload would hand netem packets far
# larger than anything a real uplink carries.
ip link set lo mtu "$MTU"
if command -v ethtool >/dev/null 2>&1; then
  ethtool -K lo tso off gso off gro off >/dev/null 2>&1 || echo "# warning: could not turn segmentation offload off" >&2
else
  echo "# warning: ethtool not found; segmentation offload left on" >&2
fi

# Bottleneck queue in packets: QUEUE_MS at the link rate.
limit=$(( RATE_MBIT * 1000000 / 8 * QUEUE_MS / 1000 / MTU ))
[ "$limit" -ge 1 ] || limit=1

shape() {
  local loss="$1" netem
  tc qdisc del dev lo root 2>/dev/null || true
  # Band 1 carries everything unshaped. Bands 2 and 3 are the two directions
  # of the carrier link, each with its own rate, delay and queue.
  tc qdisc add dev lo root handle 1: prio bands 3 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 \
    || fail "cannot add the prio qdisc (sch_prio missing?)."
  netem=(netem delay "${DELAY_MS}ms" rate "${RATE_MBIT}mbit" limit "$limit")
  [ "$loss" = "0" ] || netem+=(loss "${loss}%")
  tc qdisc add dev lo parent 1:2 handle 20: "${netem[@]}" || fail "cannot add netem (sch_netem missing?)."
  tc qdisc add dev lo parent 1:3 handle 30: "${netem[@]}"
  # The port offsets are the same for TCP and UDP, so one pair of filters
  # covers both carriers.
  tc filter add dev lo parent 1: protocol ip prio 2 u32 match ip dport "$PORT" 0xffff flowid 1:2 \
    || fail "cannot add the u32 filter (cls_u32 missing?)."
  tc filter add dev lo parent 1: protocol ip prio 2 u32 match ip sport "$PORT" 0xffff flowid 1:3
  if [ "$BLOCK_UDP" = "1" ]; then
    # Ahead of the classifiers: UDP to the carrier port never arrives.
    tc filter add dev lo parent 1: protocol ip prio 1 u32 match ip protocol 17 0xff \
      match ip dport "$PORT" 0xffff action drop \
      || fail "cannot add the UDP drop filter (act_gact missing?)."
  fi
}

echo "# netem-latency: rate=${RATE_MBIT}mbit delay=${DELAY_MS}ms queue=${QUEUE_MS}ms (${limit} packets) duration=$DURATION port=$PORT"
echo "# kernel=$(uname -r) transports=${TRANSPORTS:-default} block_udp=$BLOCK_UDP"
args=(-mode latency -external-link -carrier-port "$PORT" -duration "$DURATION")
[ -z "$TRANSPORTS" ] || args+=(-latency-transports "$TRANSPORTS")
for loss in $LOSSES; do
  shape "$loss"
  echo "# netem loss=${loss}%"
  if [ -n "$CARRIER_CMD" ]; then
    carrier_dir="$(mktemp -d)"
    CARRIER_DIR="$carrier_dir" sh -c "$CARRIER_CMD" &
    carrier_pid=$!
    rc=0
    "$BIN" "${args[@]}" -external-carrier-dir "$carrier_dir" || rc=$?
    wait "$carrier_pid" || echo "# carrier command exited $?" >&2
    rm -rf "$carrier_dir"
    [ "$rc" = "0" ] || exit "$rc"
  else
    "$BIN" "${args[@]}"
  fi
  for band in 20 30; do
    tc -s qdisc show dev lo handle "$band:" | sed -n 's/^ *Sent/# band '"$band"': Sent/p'
  done
done
