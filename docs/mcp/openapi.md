# OpenAPI → MCP tools

This page is for engineers working on the integration: field names, limits,
and the reasons behind them. Users configuring an API from the console should
read https://docs.neuraltrust.ai/trustgate/mcp/openapi instead, which covers
the same limits without the payload shapes.

TrustGate can turn an **OpenAPI 3** document into an MCP registry
(`mcp_target.source: openapi`). Each HTTP operation becomes a tool. Agents
talk MCP to TrustGate; TrustGate calls the REST API.

This mapping is **lossy by design**. That is an industry-wide constraint, not
a TrustGate-only gap: MCP is a tool-calling protocol, OpenAPI is a REST
contract. The sections below state what the market typically cannot do, what
TrustGate supports today, and how to work around the rest.

Related:

- [MCP testing guide](testing-guide.md) (configure a registry and call tools)
- [OpenAPI tools](https://docs.neuraltrust.ai/trustgate/mcp/openapi) (the
  user-facing page; keep the two in step when behaviour changes)

---

## 1. Market constraint

| Area | What vendors generally do | Why |
|------|---------------------------|-----|
| **Auth** | Collapse OpenAPI `securitySchemes` to a **static header** or **client credentials** | An MCP client is an agent, not a browser. Authorization-code, cookies, and mTLS per user need a full OAuth/UI dance that REST specs do not drive. |
| **Pagination** | Expose `page` / `cursor` / `limit` as tool arguments; the model loops | `tools/call` is one HTTP round-trip. Auto-walking every page is unbounded and unsafe. |
| **Complex types** | JSON request/response bodies; skip files, multipart, XML, callbacks | MCP `inputSchema` is JSON Schema. OpenAPI also describes media types and flows that are not tools. |
| **Spec versions** | Require **OpenAPI 3.x**; reject or poorly convert Swagger 2.0 | Swagger 2 uses `definitions` / `parameters` in body, which 3.x compilers do not load. |

TrustGate follows that industry shape **and** adds gateway controls the
typical “paste a spec into FastMCP / Stainless / Cloudflare” path does not:
consumer auth in front of the tools, toolkit allowlists, policies on
`tools/call`, and a validate-before-connect preview.

---

## 2. OpenAPI versions

| Document | Result |
|----------|--------|
| OpenAPI **3.0.x** | Supported (compile + runtime). |
| OpenAPI **3.1.x** / **3.2.x** | Supported. Tool argument validation uses JSON Schema 2020-12. |
| Swagger **2.0** (`"swagger": "2.0"`) | **Rejected** at the `parse` stage. |

**How we cover Swagger 2 APIs**

1. Publish an OpenAPI 3 document next to the Swagger 2 UI. TrustGate Admin
   does this: Swagger UI stays at `/docs/*` (2.0); MCP and other OAS 3
   consumers use **`GET /docs/openapi.json`**.
2. Point `spec_url` at that OAS 3 URL. Do **not** point it at `/docs/doc.json`
   or `/docs/swagger.json`.
3. If you do not control the upstream spec, convert once (for example
   [swagger2openapi](https://github.com/swagger-api/swagger2openapi)) and host
   the 3.x file where the gateway can fetch it.

`POST /v1/gateways/{id}/registries/validate-openapi` always returns HTTP 200.
Inspect `ok`, `stage` (`fetch` \| `parse` \| `compile`), and `message`.

---

## 3. Authentication

Two independent layers:

```
Agent  --(consumer credential)-->  TrustGate MCP  --(registry credential)-->  REST API
```

### Inbound (agent → TrustGate)

Unchanged from native MCP registries: API key, OAuth/OIDC on the **consumer**.
See [API key auth and external credentials](api-key-auth-and-external-credentials.md).

### Outbound (TrustGate → REST)

OpenAPI `components.securitySchemes` are **not** executed as login flows.
The registry supplies one credential used on every tool call:

| `mcp_target.auth.mode` | When to use |
|------------------------|-------------|
| `none` | Public API, or auth is already in `mcp_target.headers`. |
| `static` | API key / bearer / custom header (service account). |
| `client_credentials` | OAuth2 machine-to-machine (`token_url` + client id/secret). |

**Not supported on OpenAPI sources** (they are for native MCP servers):
`forwarded`, `passthrough`, `exchange`. The UI hides them when Source is
“OpenAPI document”.

**How we cover typical REST auth**

| Upstream wants | TrustGate setting |
|----------------|-------------------|
| `Authorization: Bearer <token>` | `static`, header `Authorization`, value `Bearer …` |
| `X-API-Key` / `x-api-key` | `static` with that header |
| OAuth2 client credentials | `client_credentials` + token URL |
| Per-user OAuth (authorization code) | Not mapped from the spec. Use a **native MCP** server with `forwarded` auth, or a confidential **service account** if the product allows it. |
| mTLS | Not an OpenAPI-registry feature. Terminate TLS at the mesh / gateway client elsewhere. |

The compiler does not send the Admin JWT when it **fetches the spec**. Spec
URLs must be readable without that JWT (as Admin `/docs/openapi.json` is).
Tool calls **do** send the registry static / client-credentials header.

---

## 4. Pagination

List operations become **one tool** whose arguments are the spec’s query/path
parameters (`page`, `size`, `cursor`, `limit`, …). TrustGate does **not**:

- auto-follow `Link` headers or `next` URLs
- concatenate every page into one tool result
- invent cursor semantics that are missing from the spec

That matches FastMCP, Speakeasy, and similar converters: unbounded pagination
behind a single `tools/call` is a denial-of-service footgun.

**How we cover it**

1. Keep pagination parameters in the OpenAPI document (and descriptions).
   The model can call `list_widgets` with `page=2` itself.
2. Use the consumer **toolkit** to expose only the list/get tools you want,
   or to alias a safer “search” operation.
3. Cap blast radius with policies (rate limit, TrustGuard) on `tools/call`.
4. Responses over **10 MiB** fail the tool call; design list endpoints with
   page size, not “return the world”.

If a client needs “fetch all rows”, wrap that in **your** API (a single
export endpoint) rather than asking the gateway to spider the list.

---

## 5. Complex types

### Supported

- `application/json` request bodies
- Path, query, header, and cookie parameters
- Query styles: `form`, `spaceDelimited`, `pipeDelimited`, `deepObject`
- Path/header style: `simple`
- Nested JSON objects: fields are **flattened** into the tool when names do
  not collide with parameters; otherwise the body is a single `body` (or
  `requestBody`) argument
- JSON Schema passed through to the model (`oneOf` / `anyOf` / `allOf` as
  written). Quality then depends on the client model, not on TrustGate.

### Skipped or rejected

| Construct | Behaviour |
|-----------|-----------|
| `multipart/form-data`, `application/x-www-form-urlencoded`, file/`binary` bodies | Operation **skipped** (`unsupported_operation` warning): only JSON bodies. |
| XML / other media types | Same skip if there is no JSON body. |
| Path styles `matrix` / `label` | Operation skipped. |
| External `$ref` (other URLs) | **Parse error**. The document must be self-contained. |
| Callbacks, webhooks, links | Ignored (not tools). |
| Missing `operationId` | Tool still created, named from method and path with underscores (`GET /v1/models-catalog` → `get_v1_models_catalog`). One `synthetic_tool_name` warning reports the count for the whole document. |

**How we cover it**

- Prefer JSON APIs. Split file uploads to a dedicated MCP or a pre-signed URL
  flow instead of OpenAPI tools.
- Run **Validate OpenAPI** and read `warnings` before connecting. Warnings are
  aggregated per document (one line per kind with a count), so a long list
  means several distinct problems, not one repeated across operations.
- Give operations an `operationId` when you control the spec: it is the only
  way to choose the tool name the agent sees.
- Curate with toolkit / `expose_as` when flattened names are ugly.
- Keep the spec under **5 MiB** and **500** operations (hard compile limits).
  More than **80** tools emits `large_toolset` — trim with toolkit so the
  agent context stays usable.

---

## 6. Fetch and network

The gateway process GETs `spec_url` (10s timeout, `User-Agent:
TrustGate-OpenAPI/1.0`). It must reach that URL.

- **Allowed:** `http` / `https`.
- **Always blocked:** loopback, link-local (including `169.254.169.254`),
  documentation/benchmark ranges, and **literal** private IP hosts.
- **Cluster DNS:** names such as `agentgateway-admin.dev.neuraltrust.ai` often
  resolve to RFC1918 or CGNAT (`100.64/10`). Those destinations are allowed
  for FQDNs so in-cluster Admin/TrustGuard specs work.
- Redirects: max 3, same host only.
- Relative `servers[0].url` (for example `"/"`) resolves against the spec
  URL host. Leave **API base URL** empty in that case.

`validate-openapi` HTTP 200 with `bytes_out` of a few hundred bytes is almost
always `ok: false` (for example a fetch block), not a successful tool preview.

---

## 7. Runtime behaviour

OpenAPI registries expose **tools only**. Prompts and resources are empty
(`SupportsPrompts` / `SupportsResources` are false).

Each `tools/call`:

1. Validates arguments against the compiled JSON Schema.
2. Builds the HTTP request (path/query/header/cookie + JSON body).
3. Sends registry auth headers.
4. Returns text content; JSON bodies also appear as `structuredContent`.
5. HTTP status outside 2xx sets `isError: true` (the tool result, not an MCP
   transport failure).

Compiled documents are cached for 5 minutes (max 256 entries).

---

## 8. Checklist for a customer API

1. Serve **OpenAPI 3.x** JSON at a URL the gateway can GET without a user JWT.
2. JSON-only operations you want as tools; pagination params documented.
3. **Validate OpenAPI** in Admin (`ok`, `tool_count`, `warnings`).
4. Registry auth: `static` or `client_credentials` matching the API.
5. Consumer toolkit: keep well under ~80 tools when possible.
6. Agent authenticates to TrustGate as usual; it never sees the upstream
   service secret.

TrustGate Admin itself is a supported target:

- Spec: `{admin}/docs/openapi.json`
- Base URL: omit
- Auth: Admin JWT as `static` `Authorization: Bearer …` if you need
  authenticated tools (healthz does not).
