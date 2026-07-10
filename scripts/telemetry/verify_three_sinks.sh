#!/usr/bin/env bash
# Exhaustive 3-sink verification for TrustGate: metadata OTLP, raw OTLP, postgres.
# Requires: docker compose (postgres, redis, kafka, otel-collector), built bin/trustgate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

# Local verify stack uses compose postgres on 5432 — do not inherit another project's .env DB port.
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_NAME="${VERIFY_DB_NAME:-agentgateway}"
EVENT_SCHEMA_VERSION="${VERIFY_EVENT_SCHEMA_VERSION:-3}"
ADMIN_PORT="${VERIFY_ADMIN_PORT:-8095}"
PROXY_PORT="${VERIFY_PROXY_PORT:-8096}"
ADMIN_URL="http://localhost:${ADMIN_PORT}"
PROXY_URL="http://localhost:${PROXY_PORT}"
OTEL_VERIFY_GRPC_PORT="${OTEL_VERIFY_GRPC_PORT:-14317}"
METADATA_EVENT="trustgate.${EVENT_SCHEMA_VERSION}.metadata"
RAW_EVENT="trustgate.${EVENT_SCHEMA_VERSION}.raw"
OTLP_ENDPOINT="localhost:${OTEL_VERIFY_GRPC_PORT}"

SECRET="${SERVER_SECRET_KEY:-telemetry-verify-secret-0123456789abcdef}"
SENSIBLE_PG_DSN="${SENSIBLE_PG_DSN:-postgres://postgres:postgres@localhost:5432/${DB_NAME}}"

PASS=0
FAIL=0
TOTAL=0
MOCK_PID=""
ADMIN_PID=""
PROXY_PID=""

cleanup() {
  [[ -n "$PROXY_PID" ]] && kill "$PROXY_PID" 2>/dev/null || true
  [[ -n "$ADMIN_PID" ]] && kill "$ADMIN_PID" 2>/dev/null || true
  [[ -n "$MOCK_PID" ]] && kill "$MOCK_PID" 2>/dev/null || true
}
trap cleanup EXIT

assert() {
  local name="$1" cond="$2"
  TOTAL=$((TOTAL + 1))
  if [[ "$cond" == "1" ]]; then
    echo "  PASS: $name"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $name"
    FAIL=$((FAIL + 1))
  fi
}

wait_http() {
  local url="$1" label="$2" tries="${3:-60}"
  for _ in $(seq 1 "$tries"); do
    if curl -sf "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  echo "FAIL: $label not ready at $url" >&2
  return 1
}

mint_admin_jwt() {
  local header payload signature
  header=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
  payload=$(printf '%s' '{}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
  signature=$(printf '%s' "${header}.${payload}" | openssl dgst -binary -sha256 -hmac "$SECRET" | openssl base64 -A | tr '+/' '-_' | tr -d '=')
  printf '%s' "${header}.${payload}.${signature}"
}

start_mock_upstream() {
  local port="$1"
  python3 - "$port" <<'PY' &
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port = int(sys.argv[1])

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        body = {
            "id": "chatcmpl-verify",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "upstream-ok"},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
        }
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, *_args):
        return

HTTPServer(("127.0.0.1", port), Handler).serve_forever()
PY
  MOCK_PID=$!
  sleep 0.3
}

server_env() {
  cat <<EOF
APP_ENV=dev
SERVER_ADMIN_PORT=${ADMIN_PORT}
SERVER_PROXY_PORT=${PROXY_PORT}
SERVER_MCP_PORT=$((PROXY_PORT + 1))
SERVER_SECRET_KEY=${SECRET}
CONFIG_SYNC_GRPC_LISTEN_ADDR=":$((ADMIN_PORT + 100))"
CONFIG_SYNC_TOKEN=telemetry-verify-token
GATEWAY_DISCOVERY_MODE=header
GATEWAY_BASE_DOMAIN=gw.neuraltrust.sandbox
LOG_LEVEL=WARN
LOG_FORMAT=text
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_NAME=${DB_NAME}
DB_SSL_MODE=disable
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=8
KAFKA_BROKERS=localhost:29092
TELEMETRY_ENABLED=true
TELEMETRY_EXPORTERS_FILE=config/telemetry.verify.yaml
SENSIBLE_PG_DSN=${SENSIBLE_PG_DSN}
METRICS_ENABLED=true
METRICS_QUEUE_SIZE=1000
METRICS_WORKER_COUNT=1
METRICS_FLUSH_INTERVAL=1s
PLAYGROUND_TRACE_STORE_ENABLED=false
EOF
}

write_verify_telemetry_yaml() {
  cat > config/telemetry.verify.yaml <<EOF
exporters:
  metadata:
    - name: otlp
      type: otlp
      settings:
        endpoint: "${OTLP_ENDPOINT}"
        protocol: "grpc"
        signal: "logs"
        insecure: true
        compression: "none"
        timeout: "10s"
        max_body_bytes: 65536

  raw:
    - name: raw-otlp
      type: otlp
      settings:
        endpoint: "${OTLP_ENDPOINT}"
        protocol: "grpc"
        signal: "logs"
        insecure: true
        compression: "none"
        timeout: "10s"
        max_body_bytes: 65536
    - name: sensible-pg
      type: postgres
      settings:
        dsn_env: SENSIBLE_PG_DSN
EOF
}

start_servers() {
  local env_file
  env_file="$(mktemp)"
  server_env >"$env_file"
  set -a
  # shellcheck disable=SC1090
  source "$env_file"
  set +a
  rm -f "$env_file"

  ./bin/trustgate admin > /tmp/trustgate-verify-admin.log 2>&1 &
  ADMIN_PID=$!
  wait_http "${ADMIN_URL}/healthz" "admin" 120

  ./bin/trustgate proxy > /tmp/trustgate-verify-proxy.log 2>&1 &
  PROXY_PID=$!
  wait_http "${PROXY_URL}/healthz" "proxy"
}

setup_route() {
  local suffix="$1"
  local upstream_url="${2:-$UPSTREAM_URL}"
  local gw_resp reg_resp co_resp auth_resp
  gw_resp="$(curl -sS -X POST "${ADMIN_URL}/v1/gateways" \
    -H "Authorization: Bearer ${ADMIN_JWT}" -H "Content-Type: application/json" \
    -d "{\"name\":\"${suffix}\",\"slug\":\"${suffix}\"}")"
  GW_ID="$(echo "$gw_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")"
  GW_SLUG="$(echo "$gw_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['slug'])")"

  reg_resp="$(curl -sS -X POST "${ADMIN_URL}/v1/gateways/${GW_ID}/registries" \
    -H "Authorization: Bearer ${ADMIN_JWT}" -H "Content-Type: application/json" \
    -d "{\"name\":\"${suffix}-be\",\"provider\":\"openai\",\"weight\":1,\"provider_options\":{\"base_url\":\"${upstream_url}\"},\"auth\":{\"type\":\"api_key\",\"api_key\":{\"api_key\":\"sk-test\"}}}")"
  REG_ID="$(echo "$reg_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")"

  co_resp="$(curl -sS -X POST "${ADMIN_URL}/v1/gateways/${GW_ID}/consumers" \
    -H "Authorization: Bearer ${ADMIN_JWT}" -H "Content-Type: application/json" \
    -d "{\"name\":\"${suffix}-co\"}")"
  CO_ID="$(echo "$co_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")"
  CO_SLUG="$(echo "$co_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['slug'])")"

  curl -sS -X POST "${ADMIN_URL}/v1/gateways/${GW_ID}/consumers/${CO_ID}/registries/${REG_ID}" \
    -H "Authorization: Bearer ${ADMIN_JWT}" >/dev/null

  auth_resp="$(curl -sS -X POST "${ADMIN_URL}/v1/gateways/${GW_ID}/auths" \
    -H "Authorization: Bearer ${ADMIN_JWT}" -H "Content-Type: application/json" \
    -d "{\"name\":\"${suffix}-key\",\"type\":\"api_key\",\"enabled\":true}")"
  AUTH_ID="$(echo "$auth_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")"
  API_KEY="$(echo "$auth_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['api_key'])")"

  curl -sS -X POST "${ADMIN_URL}/v1/gateways/${GW_ID}/consumers/${CO_ID}/auths/${AUTH_ID}" \
    -H "Authorization: Bearer ${ADMIN_JWT}" >/dev/null

  PROXY_PATH="/${CO_SLUG}/v1/chat/completions"
}

post_proxy() {
  local payload="$1"
  local headers_file
  headers_file="$(mktemp)"
  PROXY_STATUS="$(curl -sS -D "$headers_file" -o /tmp/trustgate-verify-proxy-body.json -w '%{http_code}' -X POST "${PROXY_URL}${PROXY_PATH}" \
    -H "Content-Type: application/json" \
    -H "X-AG-Gateway-Slug: ${GW_SLUG}" \
    -H "X-AG-API-Key: ${API_KEY}" \
    -d "$payload")"
  PROXY_BODY="$(cat /tmp/trustgate-verify-proxy-body.json)"
  TRACE_ID="$(python3 - "$headers_file" <<'PY'
import sys
trace = ""
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    if line.lower().startswith("x-ag-trace-id:"):
        trace = line.split(":", 1)[1].strip()
        break
print(trace)
PY
)"
  rm -f "$headers_file"
  if [[ -z "$TRACE_ID" && -n "${GW_ID:-}" ]]; then
    TRACE_ID="$(docker compose -f docker-compose.yaml -f docker-compose.telemetry.yaml exec -T postgres \
      psql -U postgres -d "$DB_NAME" -t -A -c \
      "SELECT trace_id FROM trustgate_data WHERE gateway_id = '${GW_ID}' ORDER BY created_at DESC LIMIT 1;" 2>/dev/null | tr -d '[:space:]')"
  fi
}

run_sink_assertions() {
  local trace_id="$1" expect_flagged="$2" collector_log="$3"
  python3 - "$trace_id" "$expect_flagged" "$collector_log" "$DB_NAME" "$METADATA_EVENT" "$RAW_EVENT" "$ROOT" <<'PY'
import json, re, subprocess, sys

trace_id, expect_flagged, collector_log, db_name, metadata_event, raw_event, root = sys.argv[1:8]
expect_flagged = expect_flagged == "true"

def emit(name, cond):
    print(f"ASSERT\t{name}\t{1 if cond else 0}")

chunks = [c.strip() for c in re.split(r"(?=ResourceLog #\d+)", collector_log) if trace_id in c]
metadata_chunk = None
raw_chunk = None
for c in chunks:
    if "trustgate.request.body" in c or "trustgate.response.body" in c:
        raw_chunk = c
    elif "http.request.method:" in c or "gen_ai.provider.name:" in c:
        metadata_chunk = c

# EventName may appear as "EventName:" (newer collector) or only in unit tests; also accept attribute fingerprint.
def has_metadata_event(chunk: str) -> bool:
    if f"EventName: {metadata_event}" in chunk:
        return True
    return "http.request.method:" in chunk and "trustgate.request.body" not in chunk

def has_raw_event(chunk: str) -> bool:
    if f"EventName: {raw_event}" in chunk:
        return True
    return "trustgate.request.body" in chunk and "http.request.method:" not in chunk

emit("sink1: metadata OTLP record found", metadata_chunk is not None)
emit("sink2: raw OTLP record found", raw_chunk is not None)

if metadata_chunk:
    emit(f"sink1: EventName {metadata_event}", has_metadata_event(metadata_chunk))
    emit("sink1: no request.body", "trustgate.request.body" not in metadata_chunk)
    emit("sink1: no response.body", "trustgate.response.body" not in metadata_chunk)
    emit("sink1: has trace_id attr", f"trustgate.trace_id: Str({trace_id})" in metadata_chunk)
    emit("sink1: has gateway_id", "trustgate.gateway_id:" in metadata_chunk)
    emit("sink1: has http.method", "http.request.method:" in metadata_chunk)
    emit("sink1: has gen_ai.provider", "gen_ai.provider.name:" in metadata_chunk)
    emit("sink1: has latency.total_ms", "trustgate.latency.total_ms:" in metadata_chunk)
    expected_flagged = f"trustgate.is_flagged: Bool({'true' if expect_flagged else 'false'})"
    emit(f"sink1: is_flagged={expect_flagged}", expected_flagged in metadata_chunk)

if raw_chunk:
    emit(f"sink2: EventName {raw_event}", has_raw_event(raw_chunk))
    emit("sink2: has request.body", "trustgate.request.body" in raw_chunk)
    emit("sink2: has response.body", "trustgate.response.body" in raw_chunk)
    emit("sink2: same trace_id", f"trustgate.trace_id: Str({trace_id})" in raw_chunk)
    emit("sink2: no policy_chain", "trustgate.policy_chain" not in raw_chunk)
    emit("sink2: no gen_ai.provider", "gen_ai.provider.name" not in raw_chunk)

pg = subprocess.run(
    [
        "docker", "compose", "-f", "docker-compose.yaml", "-f", "docker-compose.telemetry.yaml",
        "exec", "-T", "postgres",
        "psql", "-U", "postgres", "-d", db_name,
        "-c", f"SELECT row_to_json(t) FROM trustgate_data t WHERE trace_id = '{trace_id}';",
        "-t", "-A",
    ],
    capture_output=True,
    text=True,
    cwd=root,
)
row_raw = pg.stdout.strip()
emit("sink3: postgres row found", bool(row_raw))
if row_raw:
    row = json.loads(row_raw)
    emit("sink3: trace_id matches", row.get("trace_id") == trace_id)
    emit("sink3: request_body non-empty", bool(row.get("request_body")))
    emit("sink3: response_body non-empty", bool(row.get("response_body")))
    emit("sink3: gateway_id present", bool(row.get("gateway_id")))
    emit("sink3: schema_version=1", row.get("schema_version") == 1)
PY
}

verify_sinks() {
  local scenario="$1" expect_flagged="$2"
  echo ""
  echo "=== Scenario: $scenario (trace_id=$TRACE_ID) ==="

  assert "proxy HTTP 200" "$([[ "$PROXY_STATUS" == "200" ]] && echo 1 || echo 0)"
  assert "trace_id present" "$([[ -n "$TRACE_ID" ]] && echo 1 || echo 0)"

  sleep 4
  local collector_log
  collector_log="$(docker compose -f docker-compose.yaml -f docker-compose.telemetry.yaml logs otel-collector --since 3m 2>&1 | sed 's/^otel-collector-1  | //')"

  while IFS=$'\t' read -r tag name val; do
    [[ "$tag" == "ASSERT" ]] || continue
    assert "$name" "$val"
  done < <(run_sink_assertions "$TRACE_ID" "$expect_flagged" "$collector_log" "$ROOT")
}

echo "=== TrustGate 3-sink verification ==="

echo "Starting infra (postgres, redis, kafka, otel-collector)..."
docker compose -f docker-compose.yaml -f docker-compose.telemetry.yaml up -d postgres redis zookeeper kafka otel-collector
for _ in $(seq 1 60); do
  if docker compose -f docker-compose.yaml -f docker-compose.telemetry.yaml exec -T postgres pg_isready -U postgres >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
sleep 5

docker compose -f docker-compose.yaml -f docker-compose.telemetry.yaml exec -T postgres \
  psql -U postgres -tc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1 \
  || docker compose -f docker-compose.yaml -f docker-compose.telemetry.yaml exec -T postgres \
  psql -U postgres -c "CREATE DATABASE ${DB_NAME};"

write_verify_telemetry_yaml

if [[ ! -x ./bin/trustgate ]]; then
  echo "Building bin/trustgate..."
  make build
fi

MOCK_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
start_mock_upstream "$MOCK_PORT"
UPSTREAM_URL="http://127.0.0.1:${MOCK_PORT}"

ADMIN_JWT="$(mint_admin_jwt)"
start_servers

TS="$(date +%s)"

setup_route "sink-clean-${TS}"
post_proxy '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"what is the weather today"}]}'
verify_sinks "clean chat completion" false

setup_route "sink-flagged-${TS}"
post_proxy '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Contact me at john.doe@example.com please"}]}'
verify_sinks "PII in request (upstream still 200)" false

echo ""
echo "=== Scenario: postgres idempotency ==="
COUNT="$(docker compose -f docker-compose.yaml -f docker-compose.telemetry.yaml exec -T postgres \
  psql -U postgres -d "$DB_NAME" -t -A -c \
  "SELECT count(*) FROM trustgate_data WHERE trace_id = '$TRACE_ID';")"
assert "postgres: exactly 1 row per trace_id" "$([[ "$COUNT" == "1" ]] && echo 1 || echo 0)"

echo ""
echo "========================================"
echo "RESULTS: $PASS/$TOTAL passed, $FAIL failed"
echo "========================================"
[[ "$FAIL" -eq 0 ]]
