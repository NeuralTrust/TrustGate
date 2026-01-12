#!/bin/bash

team_id=${TEAM_ID:-""}
user_id=${USER_ID:-""}
secret=${SERVER_SECRET_KEY}

header=$(echo -n '{"alg":"HS256","typ":"JWT"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')

if [ -n "$user_id" ]; then
    payload=$(echo -n "{\"team_id\":\"$team_id\",\"user_id\":\"$user_id\"}" | openssl base64 -A | tr '+/' '-_' | tr -d '=')
else
    payload=$(echo -n "{\"team_id\":\"$team_id\"}" | openssl base64 -A | tr '+/' '-_' | tr -d '=')
fi
signature=$(echo -n "$header.$payload" | openssl dgst -binary -sha256 -hmac "$secret" | openssl base64 -A | tr '+/' '-_' | tr -d '=')

echo "$header.$payload.$signature"