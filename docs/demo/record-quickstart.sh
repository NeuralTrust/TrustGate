#!/usr/bin/env bash
# Minimal demo for asciinema / GIF recording.
# Safe to run repeatedly. Does not print secrets.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

ADMIN="${ADMIN_URL:-http://localhost:8080}"
PROXY="${PROXY_URL:-http://localhost:8081}"
MCP="${MCP_URL:-http://localhost:8082}"

BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'
info() { echo -e "${BLUE}==>${NC} $*"; }
ok()   { echo -e "${GREEN}✓${NC} $*"; }

echo
echo "TrustGate — 60-second demo"
echo "Repo: https://github.com/NeuralTrust/TrustGate"
echo

info "Starting stack (make up) if health checks fail..."
if ! curl -sf "$ADMIN/healthz" >/dev/null 2>&1; then
  if [[ ! -f .env ]]; then
    cp .env.example .env
    ok "Seeded .env from .env.example"
  fi
  make up
  info "Waiting for Admin healthz..."
  for _ in $(seq 1 60); do
    curl -sf "$ADMIN/healthz" >/dev/null 2>&1 && break
    sleep 2
  done
fi

info "Health checks"
curl -sS "$ADMIN/healthz"  | tee /dev/stderr >/dev/null && ok "Admin  $ADMIN/healthz"
curl -sS "$PROXY/healthz"  | tee /dev/stderr >/dev/null && ok "Proxy  $PROXY/healthz"
curl -sS "$MCP/healthz"    | tee /dev/stderr >/dev/null && ok "MCP    $MCP/healthz"

echo
info "Chat completion through the proxy"
if [[ -n "${OPENAI_API_KEY:-}" ]]; then
  info "OPENAI_API_KEY is set — running examples/curl-first-request/first-request.sh"
  (cd examples/curl-first-request && ./first-request.sh)
else
  cat <<'TIP'
# Export a provider key, then run the first-request example:
export OPENAI_API_KEY="sk-..."
./examples/curl-first-request/first-request.sh

# Or a raw curl once gateway/consumer exist (see examples/curl-first-request/):
curl -X POST "http://localhost:8081/my-app/v1/chat/completions" \
  -H "X-AG-Gateway-Slug: demo" \
  -H "X-AG-API-Key: $CONSUMER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello!"}]}'
TIP
  ok "Skipped live completion (no OPENAI_API_KEY) — health checks already green"
fi

echo
ok "Done. Star the repo if this saved you a weekend: https://github.com/NeuralTrust/TrustGate"
echo
