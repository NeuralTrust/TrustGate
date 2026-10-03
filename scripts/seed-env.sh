#!/usr/bin/env bash
# Seeds .env from .env.example and fills in SERVER_SECRET_KEY when it is blank.
set -euo pipefail

cd "$(dirname "$0")/.."

ENV_FILE="${ENV_FILE:-.env}"
EXAMPLE_FILE="${EXAMPLE_FILE:-.env.example}"

if [[ ! -f "$ENV_FILE" ]]; then
  [[ -f "$EXAMPLE_FILE" ]] || { echo "seed-env: $EXAMPLE_FILE not found" >&2; exit 1; }
  cp "$EXAMPLE_FILE" "$ENV_FILE"
  echo "seed-env: created $ENV_FILE from $EXAMPLE_FILE"
fi

current="$(awk -F= '/^SERVER_SECRET_KEY=/{sub(/^[^=]*=/, ""); gsub(/[[:space:]]/, ""); print; exit}' "$ENV_FILE")"
if [[ -n "$current" ]]; then
  exit 0
fi

if command -v openssl >/dev/null 2>&1; then
  secret="$(openssl rand -base64 32 | tr -d '\n')"
else
  secret="$(head -c 32 /dev/urandom | base64 | tr -d '\n')"
fi

tmp="$(mktemp)"
if grep -q '^SERVER_SECRET_KEY=' "$ENV_FILE"; then
  awk -v secret="$secret" '
    /^SERVER_SECRET_KEY=/ && !seen { print "SERVER_SECRET_KEY=" secret; seen = 1; next }
    { print }
  ' "$ENV_FILE" > "$tmp"
else
  cp "$ENV_FILE" "$tmp"
  printf '\nSERVER_SECRET_KEY=%s\n' "$secret" >> "$tmp"
fi
mv "$tmp" "$ENV_FILE"
chmod 600 "$ENV_FILE" 2>/dev/null || true
echo "seed-env: generated SERVER_SECRET_KEY in $ENV_FILE"
