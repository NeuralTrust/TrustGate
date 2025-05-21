#!/bin/bash

header=$(echo -n '{"alg":"HS256","typ":"JWT"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
payload=$(echo -n '{}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
secret=${SERVER_SECRET_KEY}

signature=$(echo -n "$header.$payload" | openssl dgst -binary -sha256 -hmac "$secret" | openssl base64 -A | tr '+/' '-_' | tr -d '=')

echo "$header.$payload.$signature"
