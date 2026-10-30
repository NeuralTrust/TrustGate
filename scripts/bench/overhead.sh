#!/usr/bin/env bash
# Measures the latency and CPU the proxy plane adds over an instant upstream,
# with no policy attached. Boots a mock upstream, the admin plane and the proxy
# plane against an existing Postgres + Redis, provisions one gateway/consumer/key
# and drives the same load directly at the mock and through the proxy.
#
#   PROFILE=prod    (default) logs at info, plan rate limit on, telemetry,
#                   metrics and ops traces/metrics exported to a local OTLP sink
#   PROFILE=minimal everything optional off: the floor of the forwarding path
#
#   DBLESS=true     (default) proxy pulls its config over gRPC like production;
#                   false runs it on the Postgres-backed finders + TTL caches
#
# CPU pinning (taskset) keeps the proxy, the upstream and the load generator
# from stealing each other's cores. Override with PROXY_CPUS, UPSTREAM_CPUS,
# LOADGEN_CPUS; anything left over (admin, Postgres, Redis, sink) shares
# UPSTREAM_CPUS. Extra flags after "--" go to `bench-overhead run`.
#
#   scripts/bench/overhead.sh -- -concurrency 1,16,64 -rates 1000,2000 -duration 30s
set -euo pipefail

cd "$(dirname "$0")/../.."

PROFILE="${PROFILE:-prod}"
DBLESS="${DBLESS:-true}"
OUT_DIR="${OUT_DIR:-var/bench}"
NCPU="$(nproc)"
PROXY_CPUS="${PROXY_CPUS:-0-$(( NCPU > 3 ? NCPU - 3 : 0 ))}"
UPSTREAM_CPUS="${UPSTREAM_CPUS:-$(( NCPU > 2 ? NCPU - 2 : 0 ))}"
LOADGEN_CPUS="${LOADGEN_CPUS:-$(( NCPU > 1 ? NCPU - 1 : 0 ))}"
ADMIN_PORT="${BENCH_ADMIN_PORT:-18080}"
PROXY_PORT="${BENCH_PROXY_PORT:-18081}"
MCP_PORT="${BENCH_MCP_PORT:-18082}"
SYNC_PORT="${BENCH_SYNC_PORT:-18083}"
UPSTREAM_ADDR="${BENCH_UPSTREAM_ADDR:-127.0.0.1:19999}"
SINK_ADDR="${BENCH_SINK_ADDR:-127.0.0.1:19998}"

if [[ "${1:-}" == "--" ]]; then shift; fi

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-${PROFILE}"
LOG_DIR="$OUT_DIR/$RUN_ID"
mkdir -p "$LOG_DIR"

pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT

wait_http() {
  local url="$1" name="$2"
  for _ in $(seq 1 120); do
    if curl -fsS -o /dev/null "$url" 2>/dev/null; then return 0; fi
    sleep 0.5
  done
  echo "overhead: $name never answered $url (logs in $LOG_DIR)" >&2
  exit 1
}

echo "overhead: building binaries"
TRUSTGATE_BIN="${TRUSTGATE_BIN:-bin/trustgate}"
if [[ "$TRUSTGATE_BIN" == "bin/trustgate" ]]; then go build -o bin/trustgate ./cmd/trustgate; fi
go build -o bin/bench-overhead ./cmd/bench-overhead

export APP_ENV=bench
export SERVER_ADMIN_PORT="$ADMIN_PORT" SERVER_PROXY_PORT="$PROXY_PORT" SERVER_MCP_PORT="$MCP_PORT"
export SERVER_SECRET_KEY="${SERVER_SECRET_KEY:-bench-secret-0123456789abcdef0123456789abcdef}"
export GATEWAY_BASE_DOMAIN="${GATEWAY_BASE_DOMAIN:-gw.bench.local}"
export DB_HOST="${DB_HOST:-localhost}" DB_PORT="${DB_PORT:-5432}" DB_USER="${DB_USER:-postgres}"
export DB_PASSWORD="${DB_PASSWORD:-postgres}" DB_NAME="${DB_NAME:-trustgate_bench}" DB_SSL_MODE="${DB_SSL_MODE:-disable}"
export REDIS_HOST="${REDIS_HOST:-localhost}" REDIS_PORT="${REDIS_PORT:-6379}" REDIS_DB="${REDIS_DB:-5}"
export OUTBOUND_ALLOW_PRIVATE_NETWORKS=true
export MCP_CONNECT_RATE_LIMIT_ENABLED=false
export CONFIG_SYNC_TOKEN=bench-config-sync-token
export CONFIG_SYNC_GRPC_LISTEN_ADDR=":$SYNC_PORT"
export CONFIG_SYNC_RECOMPILE_DEBOUNCE=250ms

case "$PROFILE" in
  prod)
    export LOG_LEVEL=info LOG_FORMAT=json
    export RATE_LIMIT_ENABLED=true
    export TELEMETRY_ENABLED=true METRICS_ENABLED=true
    export TELEMETRY_EXPORTERS_FILE= TELEMETRY_EXPORTERS_METADATA=otlp TELEMETRY_EXPORTERS_RAW=otlp
    export OTEL_EXPORTER_OTLP_ENDPOINT="http://$SINK_ADDR/v1/logs" OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf OTEL_EXPORTER_OTLP_INSECURE=true
    export OPS_TRACES_ENABLED=true OPS_TRACES_SAMPLING_RATIO=1.0 OTEL_EXPORTER_OTLP_TRACES_ENDPOINT="http://$SINK_ADDR/v1/traces"
    export OPS_METRICS_ENABLED=true OTEL_EXPORTER_OTLP_METRICS_ENDPOINT="http://$SINK_ADDR/v1/metrics"
    ;;
  minimal)
    export LOG_LEVEL=warn LOG_FORMAT=json
    export RATE_LIMIT_ENABLED=false
    export TELEMETRY_ENABLED=false METRICS_ENABLED=false
    export OPS_TRACES_ENABLED=false OPS_METRICS_ENABLED=false
    export USAGE_RECORDS_ENABLED=false PLAYGROUND_TRACE_STORE_ENABLED=false
    ;;
  *)
    echo "overhead: unknown PROFILE=$PROFILE (prod|minimal)" >&2
    exit 2
    ;;
esac

PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -qc "DROP DATABASE IF EXISTS $DB_NAME WITH (FORCE);" >/dev/null
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -qc "CREATE DATABASE $DB_NAME;" >/dev/null
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -n "$REDIS_DB" FLUSHDB >/dev/null

taskset -c "$UPSTREAM_CPUS" bin/bench-overhead mock -addr "$UPSTREAM_ADDR" >"$LOG_DIR/upstream.log" 2>&1 &
pids+=($!)
taskset -c "$UPSTREAM_CPUS" bin/bench-overhead mock -addr "$SINK_ADDR" >"$LOG_DIR/sink.log" 2>&1 &
pids+=($!)

taskset -c "$UPSTREAM_CPUS" "$TRUSTGATE_BIN" admin >"$LOG_DIR/admin.log" 2>&1 &
pids+=($!)
wait_http "http://localhost:$ADMIN_PORT/healthz" admin

proxy_env=()
if [[ "$DBLESS" == "true" ]]; then
  proxy_env=(
    CONFIG_SYNC_DATA_PLANE_ENABLED=true
    CONFIG_SYNC_GRPC_ENDPOINT="localhost:$SYNC_PORT"
    CONFIG_SYNC_TLS_INSECURE=true
    CONFIG_SYNC_LKG_PATH="$LOG_DIR/snapshot.lkg"
    CONFIG_SYNC_LKG_KEY="$(printf '0123456789abcdef0123456789abcdef' | base64)"
    CONFIG_SYNC_POLL_INTERVAL=5m
  )
fi
env "${proxy_env[@]}" taskset -c "$PROXY_CPUS" "$TRUSTGATE_BIN" proxy >"$LOG_DIR/proxy.log" 2>&1 &
PROXY_PID=$!
pids+=("$PROXY_PID")
wait_http "http://localhost:$PROXY_PORT/healthz" proxy

bin/bench-overhead provision -admin-url "http://localhost:$ADMIN_PORT" -upstream "http://$UPSTREAM_ADDR/v1" -out "$LOG_DIR/target.env"
# shellcheck disable=SC1091
source "$LOG_DIR/target.env"

echo "overhead: waiting for the proxy to serve the provisioned consumer"
for i in $(seq 1 120); do
  code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://localhost:$PROXY_PORT$CONSUMER_PATH" \
    -H "Host: $GATEWAY_HOST" -H "X-AG-API-Key: $API_KEY" -H 'Content-Type: application/json' \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"ping"}]}')"
  [[ "$code" == "200" ]] && break
  if [[ "$i" == 120 ]]; then echo "overhead: proxy never served 200 (last $code)" >&2; exit 1; fi
  sleep 0.5
done

echo "overhead: profile=$PROFILE dbless=$DBLESS proxy_cpus=$PROXY_CPUS upstream_cpus=$UPSTREAM_CPUS loadgen_cpus=$LOADGEN_CPUS"
taskset -c "$LOADGEN_CPUS" bin/bench-overhead run \
  -direct-url "http://$UPSTREAM_ADDR/v1/chat/completions" \
  -gateway-url "http://127.0.0.1:$PROXY_PORT$CONSUMER_PATH" \
  -gateway-host "$GATEWAY_HOST" \
  -api-key "$API_KEY" \
  -proxy-pid "$PROXY_PID" \
  -json "$LOG_DIR/results.json" \
  "$@" | tee "$LOG_DIR/results.md"

echo "overhead: results and logs in $LOG_DIR"
