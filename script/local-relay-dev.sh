#!/usr/bin/env bash
# local-relay-dev.sh — run beamfall-relay 100% locally on 127.0.0.1 with zero
# internet access (local CA, carrier TLS cert, HMAC v2 secret, and nonce store).
#
# Usage:
#   script/local-relay-dev.sh           # run relayd interactively (Ctrl-C to stop)
#   script/local-relay-dev.sh --smoke   # run offline end-to-end smoke test and exit
#
# Optional environment overrides:
#   RELAY_HOST=home.relay.test
#   RELAY_PUBLIC_ADDR=127.0.0.1:8443
#   RELAY_CARRIER_ADDR=127.0.0.1:9443
#   RELAY_ADMIN_ADDR=127.0.0.1:9080
#   RELAY_STATE_DIR=/tmp/beamfall-relay-local   (persists certs/token across runs)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="interactive"
if [ "${1:-}" = "--smoke" ]; then
  MODE="smoke"
elif [ "${1:-}" != "" ]; then
  echo "usage: $0 [--smoke]" >&2
  exit 2
fi

RELAY_HOST="${RELAY_HOST:-home.relay.test}"
RELAY_PUBLIC_ADDR="${RELAY_PUBLIC_ADDR:-127.0.0.1:8443}"
RELAY_CARRIER_ADDR="${RELAY_CARRIER_ADDR:-127.0.0.1:9443}"
RELAY_ADMIN_ADDR="${RELAY_ADMIN_ADDR:-127.0.0.1:9080}"

CLEAN_STATE=0
if [ -z "${RELAY_STATE_DIR:-}" ]; then
  STATE_DIR="$(mktemp -d)"
  CLEAN_STATE=1
else
  STATE_DIR="$RELAY_STATE_DIR"
  mkdir -p "$STATE_DIR"
fi
chmod 700 "$STATE_DIR"

BIN_DIR="$(mktemp -d)"
PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -rf "$BIN_DIR"
  if [ "$CLEAN_STATE" -eq 1 ]; then
    rm -rf "$STATE_DIR"
  fi
}
trap cleanup EXIT INT TERM

# 1. Generate local CA + carrier TLS certificate (SAN: 127.0.0.1, localhost) if absent.
if [ ! -f "$STATE_DIR/ca.crt" ] || [ ! -f "$STATE_DIR/carrier.crt" ] || [ ! -f "$STATE_DIR/carrier.key" ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out "$STATE_DIR/ca.key" 2>/dev/null
  openssl req -x509 -sha256 -new -key "$STATE_DIR/ca.key" \
    -days 30 -subj "/CN=Beamfall Local Relay CA" \
    -out "$STATE_DIR/ca.crt" 2>/dev/null
  openssl ecparam -name prime256v1 -genkey -noout -out "$STATE_DIR/carrier.key" 2>/dev/null
  openssl req -new -sha256 -key "$STATE_DIR/carrier.key" \
    -subj "/CN=127.0.0.1" \
    -out "$STATE_DIR/carrier.csr" 2>/dev/null
  cat >"$STATE_DIR/carrier.ext" <<'EOF'
subjectAltName=IP:127.0.0.1,DNS:localhost
extendedKeyUsage=serverAuth
EOF
  openssl x509 -req -sha256 -in "$STATE_DIR/carrier.csr" \
    -CA "$STATE_DIR/ca.crt" -CAkey "$STATE_DIR/ca.key" -CAcreateserial \
    -out "$STATE_DIR/carrier.crt" -days 30 -extfile "$STATE_DIR/carrier.ext" 2>/dev/null
  chmod 600 "$STATE_DIR/ca.key" "$STATE_DIR/carrier.key"
fi

# 2. Generate high-entropy shared HMAC v2 carrier secret (0600) if absent.
if [ ! -f "$STATE_DIR/relay-token" ]; then
  (
    umask 077
    openssl rand -base64 48 | tr -d '\n' >"$STATE_DIR/relay-token"
  )
  chmod 600 "$STATE_DIR/relay-token"
fi

# 3. Build relayd (and tunnel-client for --smoke) using local Go caches.
export GOCACHE="${GOCACHE:-"$ROOT/.cache/go-build"}"
if [ -z "${GOMODCACHE:-}" ] && [ -d "$ROOT/.cache/go-mod/cache" ]; then
  export GOMODCACHE="$ROOT/.cache/go-mod"
fi
(
  cd "$ROOT"
  go build -o "$BIN_DIR/relayd" ./cmd/relayd
  if [ "$MODE" = "smoke" ]; then
    go build -o "$BIN_DIR/tunnel-client" ./cmd/tunnel-client
  fi
)

# 4. Start relayd bound strictly to loopback.
"$BIN_DIR/relayd" \
  --public-addr "$RELAY_PUBLIC_ADDR" \
  --carrier-addr "$RELAY_CARRIER_ADDR" \
  --admin-addr "$RELAY_ADMIN_ADDR" \
  --carrier-cert "$STATE_DIR/carrier.crt" \
  --carrier-key "$STATE_DIR/carrier.key" \
  --token-file "$STATE_DIR/relay-token" \
  --hmac-nonce-store "$STATE_DIR/hmac-nonces.json" \
  --hostnames "$RELAY_HOST" &
PIDS+=("$!")

# Wait for /healthz on the local admin listener, failing fast if relayd exited
# (e.g. port already in use by another instance).
for _ in $(seq 1 50); do
  if ! kill -0 "${PIDS[0]}" 2>/dev/null; then
    echo "relayd exited early" >&2
    exit 1
  fi
  if curl -fsS "http://$RELAY_ADMIN_ADDR/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
kill -0 "${PIDS[0]}" 2>/dev/null || { echo "relayd exited early" >&2; exit 1; }
curl -fsS "http://$RELAY_ADMIN_ADDR/healthz" >/dev/null

if [ "$MODE" = "smoke" ]; then
  # Spin up a tiny local HTTPS echo backend (python3 HTTPS server) + tunnel-client.
  BACKEND_PORT="${RELAY_SMOKE_BACKEND_PORT:-18443}"
  openssl ecparam -name prime256v1 -genkey -noout -out "$STATE_DIR/backend.key" 2>/dev/null
  cat >"$STATE_DIR/backend.ext" <<EOF
subjectAltName=DNS:$RELAY_HOST
extendedKeyUsage=serverAuth
EOF
  openssl req -new -sha256 -key "$STATE_DIR/backend.key" -subj "/CN=$RELAY_HOST" \
    -out "$STATE_DIR/backend.csr" 2>/dev/null
  openssl x509 -req -sha256 -in "$STATE_DIR/backend.csr" \
    -CA "$STATE_DIR/ca.crt" -CAkey "$STATE_DIR/ca.key" -CAcreateserial \
    -out "$STATE_DIR/backend.crt" -days 1 -extfile "$STATE_DIR/backend.ext" 2>/dev/null
  chmod 600 "$STATE_DIR/backend.key"

  python3 - "$BACKEND_PORT" "$STATE_DIR/backend.crt" "$STATE_DIR/backend.key" <<'PY' &
import http.server, ssl, sys
port, cert, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"beamfall-relay-smoke-ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args): pass
srv = http.server.HTTPServer(("127.0.0.1", port), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(certfile=cert, keyfile=key)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
PY
  BACKEND_PID="$!"
  PIDS+=("$BACKEND_PID")

  for _ in $(seq 1 50); do
    if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
      echo "smoke backend exited early" >&2
      exit 1
    fi
    if curl -fsS --cacert "$STATE_DIR/ca.crt" --resolve "$RELAY_HOST:$BACKEND_PORT:127.0.0.1" \
      "https://$RELAY_HOST:$BACKEND_PORT/" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done
  kill -0 "$BACKEND_PID" 2>/dev/null || { echo "smoke backend exited early" >&2; exit 1; }
  curl -fsS --cacert "$STATE_DIR/ca.crt" --resolve "$RELAY_HOST:$BACKEND_PORT:127.0.0.1" \
    "https://$RELAY_HOST:$BACKEND_PORT/" >/dev/null

  "$BIN_DIR/tunnel-client" \
    --relay-addr "$RELAY_CARRIER_ADDR" \
    --backend-addr "127.0.0.1:$BACKEND_PORT" \
    --hostnames "$RELAY_HOST" \
    --token-file "$STATE_DIR/relay-token" \
    --relay-ca "$STATE_DIR/ca.crt" &
  PIDS+=("$!")

  for _ in $(seq 1 50); do
    if curl -fsS "http://$RELAY_ADMIN_ADDR/readyz" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done
  curl -fsS "http://$RELAY_ADMIN_ADDR/readyz" >/dev/null

  PUBLIC_PORT="${RELAY_PUBLIC_ADDR##*:}"
  curl -fsS --cacert "$STATE_DIR/ca.crt" --resolve "$RELAY_HOST:$PUBLIC_PORT:127.0.0.1" \
    "https://$RELAY_HOST:$PUBLIC_PORT/" | grep -q "beamfall-relay-smoke-ok"
  echo "OK: offline relay smoke passed ($RELAY_HOST via $RELAY_PUBLIC_ADDR -> $RELAY_CARRIER_ADDR -> 127.0.0.1:$BACKEND_PORT)"
  exit 0
fi

PUBLIC_PORT="${RELAY_PUBLIC_ADDR##*:}"
cat <<EOF

Beamfall Relay is running locally (100% offline):
  Public SNI : $RELAY_PUBLIC_ADDR  (host: $RELAY_HOST)
  Carrier    : $RELAY_CARRIER_ADDR (TCP + QUIC)
  Admin      : http://$RELAY_ADMIN_ADDR/healthz  |  /readyz  |  /metrics
  State dir  : $STATE_DIR

Attach a local Beamfall Core server:
  mkdir -p ./core-data/secrets && cp "$STATE_DIR/relay-token" ./core-data/secrets/relay-token && chmod 600 ./core-data/secrets/relay-token
  beamfall serve \\
    --addr 127.0.0.1:2326 \\
    --data-dir ./core-data \\
    --relay-endpoint $RELAY_CARRIER_ADDR \\
    --relay-public-host $RELAY_HOST \\
    --relay-ca "$STATE_DIR/ca.crt"

Test end-to-end through the relay (no DNS / no internet):
  curl -k --resolve $RELAY_HOST:$PUBLIC_PORT:127.0.0.1 https://$RELAY_HOST:$PUBLIC_PORT/healthz

Press Ctrl-C to stop.
EOF

wait "${PIDS[0]}"
