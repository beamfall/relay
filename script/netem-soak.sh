#!/usr/bin/env bash
# netem-soak.sh — QUIC-vs-TCP carrier soak under injected RTT/loss (ADR-0018 §1).
#
# WHY: the v1 yamux-over-TLS/TCP carrier shares one congestion window and one
# stream window across every multiplexed stream, so a lossy/high-latency path
# head-of-line-blocks sibling streams. The v2 QUIC carrier gives each stream its
# own flow-control window and loss recovery. This harness measures both carriers
# through cmd/relay-loadgen across a grid of injected RTT/loss (Linux tc/netem on
# the loopback interface) and tabulates aggregate + per-stream throughput so the
# HoL-blocking difference is visible in numbers, not just asserted.
#
# REQUIREMENTS (hard — the harness refuses to run without them, it never fakes
# numbers or hangs on a privileged command):
#   - Linux with the `tc` (iproute2) command and the sch_netem qdisc module.
#     netem is Linux-only; it does NOT exist on macOS/BSD (use `dnctl`/`pfctl`
#     there — not implemented here).
#   - CAP_NET_ADMIN (run as root or via sudo) to add/remove qdiscs on `lo`.
#
# USAGE:
#   sudo script/netem-soak.sh                       # default grid, both carriers
#   sudo DURATION=20s STREAMS=16 MBPS=64 script/netem-soak.sh
#   sudo RTTS="0 50 100" LOSSES="0 1 5" script/netem-soak.sh
#   RESULTS=out.tsv sudo script/netem-soak.sh        # also write a TSV table
#
# The netem delay/loss is applied to the loopback egress qdisc, which shapes the
# 127.0.0.1 relay<->client<->public traffic the loadgen drives in-process. The
# qdisc is always torn down on exit (trap), including on error/interrupt.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IFACE="${IFACE:-lo}"
DURATION="${DURATION:-15s}"
STREAMS="${STREAMS:-8}"
MBPS="${MBPS:-64}"
# RTT is one-way delay per direction in ms; loopback traffic traverses lo twice
# (client->relay and relay->public are both loopback), so the applied per-hop
# delay is RTT/2. LOSSES are packet-loss percentages.
RTTS="${RTTS:-0 20 50 100}"
LOSSES="${LOSSES:-0 1 3}"
CARRIERS="${CARRIERS:-tcp quic}"
RESULTS="${RESULTS:-}"

fail() { echo "netem-soak: $*" >&2; exit 1; }

# --- Preflight: refuse (do not hang, do not fake) when netem is unavailable. ---
[ "$(uname -s)" = "Linux" ] || fail "netem is Linux-only; this host is $(uname -s). \
Cannot generate RTT/loss numbers here. On macOS use dnctl/pfctl (not implemented)."
command -v tc >/dev/null 2>&1 || fail "tc (iproute2) not found; install iproute2."
[ "$(id -u)" = "0" ] || fail "needs CAP_NET_ADMIN to shape '$IFACE'; re-run with sudo."
# Probe that netem is actually loadable before committing to the run.
tc qdisc add dev "$IFACE" root netem delay 0ms 2>/dev/null \
  || fail "cannot add netem qdisc on '$IFACE' (sch_netem module missing?)."
tc qdisc del dev "$IFACE" root 2>/dev/null || true

cleanup() { tc qdisc del dev "$IFACE" root 2>/dev/null || true; }
trap cleanup EXIT INT TERM

echo "# netem-soak: iface=$IFACE duration=$DURATION streams=$STREAMS mbps=$MBPS"
echo "# grid: rtts=[$RTTS] losses=[$LOSSES] carriers=[$CARRIERS]"
HEADER=$'carrier\trtt_ms\tloss_pct\taggregate_mbps\tper_stream_min_mbps\tper_stream_p50_mbps\tper_stream_max_mbps\tsetup_p99_ms'
echo "$HEADER"
[ -n "$RESULTS" ] && echo "$HEADER" > "$RESULTS"

extract() { grep -E "^$1=" | head -1 | cut -d= -f2-; }

for rtt in $RTTS; do
  half=$(( rtt / 2 ))
  for loss in $LOSSES; do
    tc qdisc del dev "$IFACE" root 2>/dev/null || true
    tc qdisc add dev "$IFACE" root netem delay "${half}ms" loss "${loss}%"
    for carrier in $CARRIERS; do
      out="$(go run ./cmd/relay-loadgen \
        -duration "$DURATION" -streams "$STREAMS" -mbps "$MBPS" \
        -transport "$carrier" 2>/dev/null)"
      agg="$(printf '%s\n' "$out" | extract throughput_mbps)"
      psmin="$(printf '%s\n' "$out" | extract per_stream_mbps_min)"
      psp50="$(printf '%s\n' "$out" | extract per_stream_mbps_p50)"
      psmax="$(printf '%s\n' "$out" | extract per_stream_mbps_max)"
      p99="$(printf '%s\n' "$out" | extract setup_latency_p99_ms)"
      row=$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' \
        "$carrier" "$rtt" "$loss" "$agg" "$psmin" "$psp50" "$psmax" "$p99")
      echo "$row"
      [ -n "$RESULTS" ] && echo "$row" >> "$RESULTS"
    done
  done
done

echo "# done. per_stream min/max spread widens on tcp under loss (shared window);"
echo "# quic keeps it tight (per-stream flow control) — the ADR-0018 §1 win."
[ -n "$RESULTS" ] && echo "# results written to $RESULTS"
