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
OAuth flow against the upstream provider. The registry only declares the connection; **the end user authenticates at runtime** (browser login + consent) and the gateway holds per-user tokens — no user credentials are stored on the registry. Requires `provider` and a `registration` mode:

- `registration: "auto"` — dynamic client registration; the gateway self-registers and the user logs in at runtime. Must **not** include `client_id`/`client_secret`.
- `registration: "manual"` (or omitted) — the provider has no DCR, so an operator pre-registers an app once and supplies `client_id`, `authorize_url`, `token_url`. `client_secret`, `scopes`, `resource` are optional. The end user still logs in at runtime.

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

## Configuring from the catalog (frontend flow)

The registry form is prefilled from the curated MCP catalog. The frontend lists the catalog, lets the user pick a server, collects only the values the catalog says are missing, then builds the `mcp_target` request from the catalog entry plus those inputs.

### Catalog endpoint

```
GET /v1/mcp-servers-catalog
Authorization: Bearer <admin JWT>
```

Returns `{ "mcp_servers": [ ... ] }`, sorted by `relevance` (desc). Each entry:

| Field | Type | Meaning for the form |
|---|---|---|
| `code` | string | Stable server id (e.g. `com.asana/mcp`). Use as the `provider` key for `forwarded` auth. |
| `display_name` / `vendor` / `category` / `description` | string | Display only. |
| `url` | string | Server URL; may contain `{placeholders}` (see `url_variables`). |
| `transport` | string | Always `streamable-http`. |
| `auth_hint` | string | `none` \| `static` \| `oauth` — selects the `auth.mode` (see mapping). |
| `requires_auth` | bool | Whether any credential is needed. |
| `requires_config` | bool | Whether the operator must supply input before connecting. `false` → **connect by default, no button/form**. `true` → show a configure/Connect step. (Derived; see below.) |
| `url_variables` | array | Templated URL segments the user must supply. Each has `name`, `description`, `required`, `secret`, `in` (`path` \| `query`). |
| `auth_headers` | array | Static credentials the upstream expects. Each has `name`, `description`, `required`, `secret`, `scheme` (`Bearer` \| `Token` \| `Basic` \| `ApiKey` \| `App` \| `raw`). |
| `oauth` | object | OAuth capability (when `auth_hint` is `oauth`). See below. |

> **OAuth is a runtime concern, not a registry secret.** A `forwarded` registry only *declares the connection* — it never stores user OAuth tokens or per-user credentials. Each end user authenticates at runtime: on first use the gateway runs the OAuth authorization-code flow against the upstream, the user logs in and consents in the browser, and the gateway holds that user's token. So for the common case the registry form collects **nothing** for OAuth.

`oauth` object:

| Field | Type | Meaning for the form |
|---|---|---|
| `registration` | string | `auto` → gateway self-registers via DCR; **create the registry with no credentials, the user logs in at runtime**. This is the default path (94 of 133 servers). `manual` → the provider has no DCR, so an operator pre-registers an OAuth app **once** and supplies `client_id` (+ optional `client_secret`) at registry creation; the end user still logs in at runtime. Absent → tenant-hosted, discovered per-instance: attempt `auto`, fall back to `manual`. |
| `dcr` | bool | Whether DCR is supported. Mirrors `registration`. May be absent (unknown). |
| `pkce` | bool | Informational; PKCE is always applied by the gateway when supported. |
| `authorize_url` / `token_url` | string | Pass straight through for `manual` registration; ignore for `auto`. |
| `scopes` | string[] | Default scopes; pass through (editable). |
| `resource` | string | RFC 8707 audience; pass through. |

### Connect by default vs. configure (`requires_config`)

The UI should **not** show a config/Connect button for servers that need no operator input — those can be connected by default. Only servers that need input get a setup step. Branch on the precomputed `requires_config`:

- **`requires_config: false` — connect by default** (~107 servers): public servers (`auth_hint: none`, no required URL variables) and OAuth servers whose client self-registers (`oauth.registration: "auto"`, no required URL variables). Nothing to fill — the registry can be created directly; for OAuth the user simply logs in at runtime.
- **`requires_config: true` — show the configure step** (~83 servers): any server with a required URL variable (e.g. a tenant host/subdomain), a `static` secret (API key/token), or OAuth that needs a `manual`/tenant client.

The flag is derived server-side so the frontend doesn't re-implement the rule: `requires_config = (any url_variable.required) OR (auth_hint == "static") OR (auth_hint == "oauth" AND oauth.registration != "auto")`.

### Catalog → `mcp_target` mapping

1. **URL** — start from `url`. For each `url_variables` entry, substitute the user value: `in: "path"` replaces the `{name}` placeholder in the path; `in: "query"` appends `name=<value>` to the query string. A `secret: true` variable is a credential (e.g. a token in the query) and must be collected as a password field.
2. **`auth.mode`** — derive from `auth_hint`:

| `auth_hint` | `auth.mode` | What the user provides |
|---|---|---|
| `none` | `none` | nothing |
| `static` | `static` (credential header) — or none, if the only secret is a query `url_variable` | the secret(s) named in `auth_headers` / secret `url_variables` |
| `oauth` | `forwarded` | nothing for `auto`; `client_id`/`client_secret` for `manual` |

3. **`static` credential** — for the primary secret `auth_headers` entry, build `auth: { mode: "static", header: <name>, value: "<scheme> <secret>" }`, prefixing the user's secret with `scheme` (omit the prefix when `scheme` is `raw`). Any additional **non-secret** required headers go in `mcp_target.headers`.
4. **`forwarded` (OAuth)** — set `provider` to the catalog `code`. The registry never carries user credentials; the user authenticates at runtime. If `registration` is `auto`, send `{ mode: "forwarded", provider, registration: "auto" }` and nothing else. If `manual`, the operator additionally supplies a one-time pre-registered app `client_id` (+ optional `client_secret`); pass the catalog's `authorize_url`, `token_url`, `scopes`, `resource` through. Either way, end-user login happens at runtime — not at registry creation.

### Worked examples

**No auth** (`auth_hint: none`):

```json
{ "url": "https://mcp.assemblyai.com/docs", "auth": { "mode": "none" } }
```

**Static header** (`auth_hint: static`, header `Authorization`, `scheme: Bearer`, `secret: true`):

```json
{
  "url": "https://api.example.com/mcp",
  "auth": { "mode": "static", "header": "Authorization", "value": "Bearer <user-secret>" }
}
```

**Secret in query var** (`url_variables: [{ name: "token", in: "query", secret: true }]`):

```json
{ "url": "https://api.tinybird.co/mcp?token=<user-secret>", "auth": { "mode": "none" } }
```

**OAuth, `registration: auto`** (e.g. Atlassian, Notion, Linear — no credentials at creation; user logs in at runtime):

```json
{
  "url": "https://mcp.atlassian.com/v1/mcp/authv2",
  "auth": { "mode": "forwarded", "provider": "com.atlassian/mcp", "registration": "auto" }
}
```

**OAuth, `registration: manual`** (e.g. Asana, GitHub — provider has no DCR, so an operator supplies a one-time pre-registered app; the end user still logs in at runtime):

```json
{
  "url": "https://mcp.asana.com/v2/mcp",
  "auth": {
    "mode": "forwarded",
    "provider": "com.asana/mcp",
    "registration": "manual",
    "client_id": "<operator app client id>",
    "client_secret": "<operator app client secret>",
    "authorize_url": "https://app.asana.com/-/oauth_authorize",
    "token_url": "https://app.asana.com/-/oauth_token",
    "scopes": ["default"],
    "resource": "https://mcp.asana.com/v2/mcp"
  }
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
| Catalog endpoint + entry schema | `pkg/api/handler/http/catalog/list_mcp_servers_handler.go`, `pkg/domain/catalog/mcp_server.go` |
| Catalog data | `seed/mcp-catalog/enterprise-servers.json` |
| Request DTO | `pkg/api/handler/http/registry/request/create_registry_request.go` |
| Handler / route | `pkg/api/handler/http/registry/create_registry_handler.go`, `pkg/server/router/admin_router.go` |
| Domain model + validation | `pkg/domain/registry/mcp_target.go` |
| Admin auth | `pkg/api/middleware/admin_auth.go` |
