# Create a TrustGate gateway from the Admin API

This guide shows how to create a TrustGate gateway directly through the Admin API Swagger at [https://admin.neuraltrust.ai/docs/index.html](https://admin.neuraltrust.ai/docs/index.html).

The API resources map to the gateway runtime like this:

1. Create the gateway in the target team.
2. Create an upstream for the backend integration.
3. Create a route/rule that points to the upstream and attach plugins as policies.
4. Optionally create a gateway API key for clients that will call the data plane.

## 0. Get an admin API token

Ask the NeuralTrust team for the `SERVER_SECRET_KEY` of your admin server. The team is selected by the JWT claims, so set `TEAM_ID` before generating the token.

```bash
export ADMIN_API_URL="https://admin.neuraltrust.ai"
export TEAM_ID="<team-id>"
export USER_ID="<optional-user-id>"
export SERVER_SECRET_KEY="<server-secret-key-from-neuraltrust>"

export ADMIN_TOKEN="$(scripts/generate_jwt_token.sh)"
```

Every Admin API request below uses the same headers:

```bash
AUTH_HEADERS=(
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
  -H "Content-Type: application/json"
)
```

## 1. Create the gateway

Create the gateway inside the team carried by the admin JWT.

```bash
curl -sS -X POST "${ADMIN_API_URL}/api/v1/gateways" \
  "${AUTH_HEADERS[@]}" \
  -d '{
    "name": "AI Gateway",
    "status": "active",
    "security_config": {
      "browser_xss_filter": true,
      "content_type_nosniff": true,
      "frame_deny": true,
      "ssl_redirect": false,
      "sts_include_subdomains": true,
      "sts_seconds": 31536000,
      "is_development": false
    },
    "client_tls": {},
    "required_plugins": [],
    "telemetry": {
      "enable_plugin_traces": true,
      "enable_request_traces": true,
      "extra_params": {},
      "header_mapping": {
        "conversation_id": "X-CONV-ID"
      },
      "exporters": [
        {
          "name": "trustlens",
          "settings": {
            "host": "kafka-kafka-bootstrap.kafka.svc.cluster.local",
            "port": "9092",
            "topic": "metrics"
          }
        }
      ]
    }
  }'
```

Save the returned gateway id:

```bash
export GATEWAY_ID="<id-from-create-gateway-response>"
```

Notes:

- `name` is the main required field in the API model.
- `security_config`, `client_tls`, `required_plugins`, and `telemetry` can be adjusted per environment.
- The JWT `team_id` claim selects the team. Use the returned `GATEWAY_ID` in the following gateway-scoped requests.

## 2. Define the upstream integration

An upstream represents the backend integration targets that TrustGate will call.

```bash
curl -sS -X POST "${ADMIN_API_URL}/api/v1/gateways/${GATEWAY_ID}/upstreams" \
  "${AUTH_HEADERS[@]}" \
  -d '{
    "name": "banking-sample-upstream",
    "algorithm": "round-robin",
    "targets": [
      {
        "host": "aiapi.neuraltrust.ai",
        "port": 443,
        "protocol": "https",
        "path": "/chat/banking",
        "weight": 100,
        "stream": false,
        "models": [],
        "tags": []
      }
    ]
  }'
```

Save the returned upstream id:

```bash
export UPSTREAM_ID="<id-from-create-upstream-response>"
```

For authenticated upstreams, add `headers`, `credentials`, or `auth` to each target according to the integration requirements. Keep provider credentials in a secret manager or deployment secret.

## 3. Add plugins as policies on a route

Routes are Admin API rules. Attach policy plugins through the rule `plugin_chain`. The route below exposes `POST /chat`, strips `/chat`, sends traffic to the upstream created above, and applies a small plugin chain.

```bash
curl -sS -X POST "${ADMIN_API_URL}/api/v1/gateways/${GATEWAY_ID}/rules" \
  "${AUTH_HEADERS[@]}" \
  -d '{
    "name": "Sample chat route",
    "path": "/chat",
    "methods": ["POST"],
    "type": "endpoint",
    "upstream_id": "'"${UPSTREAM_ID}"'",
    "strip_path": true,
    "session_config": {
      "header_name": "X-Session-ID"
    },
    "plugin_chain": [
      {
        "name": "neuraltrust_moderation",
        "enabled": true,
        "stage": "pre_request",
        "priority": 0,
        "parallel": true,
        "settings": {
          "mode": "enforce",
          "mapping_field": "message",
          "retention_period": 3600
        }
      },
      {
        "name": "data_masking",
        "enabled": true,
        "stage": "pre_request",
        "priority": 10,
        "parallel": true,
        "settings": {
          "reversible_hashing": {
            "enabled": false,
            "secret": ""
          },
          "apply_all": false,
          "similarity_threshold": 0.8,
          "max_edit_distance": 1,
          "predefined_entities": [
            {
              "entity": "credit_card",
              "enabled": true,
              "mask": "[MASKED_CC]"
            }
          ]
        }
      },
      {
        "name": "rate_limiter",
        "enabled": true,
        "stage": "pre_request",
        "priority": 20,
        "parallel": true,
        "settings": {
          "limits": {
            "per_ip": {
              "limit": 100,
              "window": "1m"
            }
          },
          "actions": {
            "type": "reject",
            "retry_after": "60"
          }
        }
      }
    ],
    "trustlens": {
      "team_id": "'"${TEAM_ID}"'",
      "mapping": {
        "input": {
          "extract_fields": {}
        },
        "output": {
          "extract_fields": {}
        }
      }
    }
  }'
```

Save the returned rule id:

```bash
export RULE_ID="<id-from-create-rule-response>"
```

Valid plugin stages are `pre_request`, `post_request`, `pre_response`, and `post_response`.

To add plugins after the rule already exists, use the Swagger `POST /api/v1/plugins` endpoint:

```bash
curl -sS -X POST "${ADMIN_API_URL}/api/v1/plugins" \
  "${AUTH_HEADERS[@]}" \
  -d '{
    "type": "rule",
    "id": "'"${RULE_ID}"'",
    "plugins": [
      {
        "name": "request_size_limiter",
        "enabled": true,
        "stage": "pre_request",
        "priority": 30,
        "parallel": true,
        "settings": {
          "max_header_size": 8192,
          "max_body_size": 1048576,
          "max_url_length": 2048,
          "max_header_count": 100,
          "allowed_payload_size": 10
        }
      }
    ]
  }'
```

Use `type: "gateway"` instead of `type: "rule"` only when you want to add required plugins at the gateway level.

### NeuralTrust Firewall plugins

`neuraltrust_jailbreak` and `neuraltrust_toxicity` require a firewall token and base URL in their settings:

```json
{
  "name": "neuraltrust_jailbreak",
  "enabled": true,
  "stage": "pre_request",
  "priority": 0,
  "parallel": true,
  "settings": {
    "mode": "enforce",
    "jailbreak": {
      "threshold": 0.9
    },
    "mapping_field": "message",
    "credentials": {
      "token": "<firewall-jwt-token>",
      "base_url": "https://firewall.neuraltrust.ai"
    }
  }
}
```

Ask NeuralTrust for the firewall secret/token setup before enabling these plugins.

## 4. Optional: create a data-plane API key

If clients will authenticate to the gateway with a TrustGate API key, create one after the route exists and bind it to the route policy.

```bash
curl -sS -X POST "${ADMIN_API_URL}/api/v1/iam/api-keys" \
  "${AUTH_HEADERS[@]}" \
  -d '{
    "name": "Client API key",
    "subject_type": "gateway",
    "subject": "'"${GATEWAY_ID}"'",
    "policies": ["'"${RULE_ID}"'"],
    "expires_at": "2027-01-01T00:00:00Z"
  }'
```

Store the returned key securely. It is only shown at creation time in most API-key flows.

## Summary

The minimum API-only flow is:

```text
POST /api/v1/gateways
POST /api/v1/gateways/{gateway_id}/upstreams
POST /api/v1/gateways/{gateway_id}/rules
POST /api/v1/plugins                 # optional, for post-create plugin changes
POST /api/v1/iam/api-keys            # optional, for client data-plane auth
```

Use the IDs returned by each response in the next request. The Admin API owns gateway, upstream, rule, plugin,
and API-key creation.
