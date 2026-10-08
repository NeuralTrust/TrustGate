#!/bin/bash

tenant_id=${TENANT_ID:-""}
user_id=${USER_ID:-""}
ttl=${TTL_SECONDS:-3600}
secret=${SERVER_SECRET_KEY}

if ! [[ "$ttl" =~ ^[1-9][0-9]*$ ]]; then
    echo "TTL_SECONDS must be a positive integer" >&2
    exit 1
fi
if [ "$ttl" -gt 3600 ]; then
    echo "warning: TTL_SECONDS above 3600 is rejected unless ADMIN_TOKEN_MAX_TTL is raised" >&2
fi

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

now=$(date +%s)
claims="\"iat\":$now,\"exp\":$((now + ttl))"
if [ -n "$tenant_id" ]; then
    claims="$claims,\"tenant_id\":\"$tenant_id\""
else
    claims="$claims,\"platform_admin\":true"
fi
if [ -n "$user_id" ]; then
    claims="$claims,\"user_id\":\"$user_id\""
fi

header=$(echo -n '{"alg":"HS256","typ":"JWT"}' | b64url)
payload=$(echo -n "{$claims}" | b64url)
signature=$(echo -n "$header.$payload" | openssl dgst -binary -sha256 -hmac "$secret" | b64url)

echo "$header.$payload.$signature"
