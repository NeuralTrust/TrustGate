# MCP registry creation API

How to register an MCP server as a registry (backend) on a gateway via the admin API.

MCP registries reuse the same endpoint as LLM registries; the `type: "MCP"` discriminator selects an `mcp_target` block instead of the LLM `provider`/`auth` fields. MCP registries are consumed through the **MCP plane** (default port 8082) by MCP-type consumers — they are not routable through the LLM chat proxy routes.

## Endpoint

```
POST /v1/gateways/{gateway_id}/registries
Authorization: Bearer <admin JWT>
Content-Type: application/json
```

- `gateway_id` (path) — UUID of the target gateway.
- Auth: admin JWT signed with `SERVER_SECRET_KEY` (no `purpose` claim).
- Success: `201 Created` with the registry response (includes the generated `id`).

## Request body

Top-level fields relevant to MCP (`CreateRegistryRequest`):

| Field | Type | Required | Notes |
|---|---|---|---|
| `name` | string | yes | Max 255 chars. |
| `type` | string | yes | Must be `"MCP"` (case-insensitive, normalized to upper). |
| `description` | string | no | Free text. |
| `weight` | int | no | Used by `weighted-round-robin` load balancing; must be `>= 0`. |
| `mcp_target` | object | yes | Required when `type` is `MCP`. See below. |

> For MCP registries the LLM-only fields (`provider`, `provider_options`, `auth`, `health_checks`) are not used.

### `mcp_target`

| Field | Type | Required | Notes |
|---|---|---|---|
| `url` | string | yes | Must be a valid `http`/`https` URL. |
| `transport` | string | no | Defaults to `streamable-http` (the only supported value). |
| `headers` | map[string]string | no | Static headers added to upstream requests. |
| `auth` | object | no | Defaults to `{ "mode": "none" }`. See below. |

### `mcp_target.auth`

The `mode` selects which other fields are required.

| Field | Type | Applies to mode(s) |
|---|---|---|
| `mode` | string | all — one of `none`, `static`, `passthrough`, `exchange`, `forwarded` |
| `header` | string | `static` |
| `value` | string | `static` |
| `expected_audience` | string | `passthrough` |
| `pattern` | string | `exchange` — one of `impersonation`, `delegation`, `obo`, `token_exchange` |
| `audience` | string | `exchange` (`impersonation`, `delegation`, `token_exchange`) |
| `actor` | string | `exchange` (`delegation`) |
| `scope` | string | `exchange` (`obo`) |
| `provider` | string | `forwarded` |
| `registration` | string | `forwarded` — `manual` (default) or `auto` |
| `client_id` | string | `forwarded` (manual) |
| `client_secret` | string | `forwarded` (manual, optional) |
| `authorize_url` | string | `forwarded` (manual) |
| `token_url` | string | `forwarded` (manual) |
| `scopes` | string[] | `forwarded` (optional) |
| `resource` | string | `forwarded` (optional) |

## Auth modes

### `none`
No upstream credential. Reject if `header` or `value` are set.

```json
{ "mode": "none" }
```

### `static`
Fixed header injected on every upstream call. Requires `header` and `value`.

```json
{ "mode": "static", "header": "Authorization", "value": "Bearer sk-..." }
```

### `passthrough`
Forwards the caller's token to the upstream. Requires `expected_audience` (unconstrained passthrough is forbidden).

```json
{ "mode": "passthrough", "expected_audience": "api://upstream" }
```

### `exchange`
Performs an STS token exchange. Requires `pattern`, plus pattern-specific fields:

| `pattern` | Required fields |
|---|---|
| `impersonation` | `audience` |
| `delegation` | `audience`, `actor` |
| `obo` | `scope` (e.g. `resource/.default`) |
| `token_exchange` | `audience` |

```json
{ "mode": "exchange", "pattern": "delegation", "audience": "https://up.example.com", "actor": "agent-1" }
```

### `forwarded`
OAuth flow against the upstream provider. Requires `provider` and a `registration` mode:

- `registration: "auto"` — dynamic client registration; must **not** include `client_id`/`client_secret`.
- `registration: "manual"` (or omitted) — requires `client_id`, `authorize_url`, `token_url`. `client_secret`, `scopes`, `resource` are optional.

```json
{
  "mode": "forwarded",
  "provider": "github",
  "registration": "manual",
  "client_id": "Iv1...",
  "client_secret": "s3cret",
  "authorize_url": "https://github.com/login/oauth/authorize",
  "token_url": "https://github.com/login/oauth/access_token",
  "scopes": ["repo"]
}
```

## Full example

```bash
curl -s "$ADMIN_API_URL/v1/gateways/$GATEWAY_ID/registries" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "github-mcp",
    "type": "MCP",
    "description": "GitHub MCP server",
    "weight": 1,
    "mcp_target": {
      "url": "https://mcp.example.com/mcp",
      "transport": "streamable-http",
      "headers": { "X-Env": "prod" },
      "auth": {
        "mode": "static",
        "header": "Authorization",
        "value": "Bearer ghp_..."
      }
    }
  }'
```

## Error responses

JSON `{ "error": "<code>", "message": "<detail>" }`.

| Status | Meaning |
|---|---|
| 400 | Validation error — missing/invalid `name`, missing `mcp_target`, non-http(s) `url`, unsupported `transport`, or an auth block missing its mode-required fields |
| 401 | Missing or invalid admin token |
| 404 | Unknown `gateway_id` |
| 409 | Conflict (duplicate registry) |

## Source references

| Concern | File |
|---|---|
| Request DTO | `pkg/api/handler/http/registry/request/create_registry_request.go` |
| Handler / route | `pkg/api/handler/http/registry/create_registry_handler.go`, `pkg/server/router/admin_router.go` |
| Domain model + validation | `pkg/domain/registry/mcp_target.go` |
| Admin auth | `pkg/api/middleware/admin_auth.go` |
