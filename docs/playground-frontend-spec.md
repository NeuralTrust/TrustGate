# Playground integration spec

How to build a gateway playground in a frontend: let a user pick a consumer and chat through TrustGate **without that consumer's credentials**, while the consumer's policies (rate limits, guardrails, model policies) are enforced exactly as in production.

Audience: frontend teams integrating against TrustGate from another repository. A reference implementation lives in this repo under `frontend/` (see [Reference implementation](#reference-implementation)).

## How it works

The proxy plane accepts a **playground token**: a short-lived JWT minted by the frontend's server side (BFF), signed with the same `SERVER_SECRET_KEY` the gateway uses for admin API auth. The token is purpose-tagged and bound to a single consumer, then sent in a dedicated header on the normal proxy chat route. No new chat endpoint exists — the full proxy pipeline (auth, policies, streaming, sessions, metrics) runs unchanged.

```
Browser ──POST /api/playground/{consumer_slug}/v1/chat/completions──▶ Frontend BFF
Frontend BFF ──mint JWT, add X-AG-Playground-Token──▶ Gateway proxy plane (:8081)
Gateway ──validate token, run consumer policies──▶ LLM provider
                  ◀────────── SSE / JSON response streamed back ──────────
```

**Hard requirement:** the token (and `SERVER_SECRET_KEY`) must never reach the browser. All playground requests go through a server-side route in the frontend that mints the token per request.

## Token contract

| Property | Value |
|---|---|
| Format | JWT, `HS256` |
| Signing key | `SERVER_SECRET_KEY` (shared with the gateway deployment) |
| Header | `X-AG-Playground-Token: <jwt>` (raw token, no `Bearer` prefix) |
| Recommended TTL | 5 minutes (`exp` is enforced; expired tokens get 401) |

Required claims:

```json
{
  "purpose": "playground",
  "consumer_slug": "<slug of the consumer being tested>",
  "iat": 1750000000,
  "exp": 1750000300
}
```

Optional claims: `user_id` (dashboard user, useful for audit logs).

Validation performed by the gateway (`pkg/api/resolver/playground_resolver.go`):

- Signature and expiry against `SERVER_SECRET_KEY`. An empty server secret rejects all tokens.
- `purpose` must be exactly `"playground"`.
- `consumer_slug` must be non-empty and match the consumer slug in the request path. A token for consumer A used on consumer B's route returns **403**.
- The admin API **rejects** any token carrying a `purpose` claim ("Token not valid for admin API"), so a leaked playground token grants nothing beyond 5 minutes of chat as one consumer.

Minting example (TypeScript, [jose](https://github.com/panva/jose)):

```ts
import { SignJWT } from "jose";

const PLAYGROUND_TOKEN_TTL_SECONDS = 5 * 60;

export async function mintPlaygroundToken(consumerSlug: string): Promise<string> {
  const key = new TextEncoder().encode(process.env.SERVER_SECRET_KEY!);
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ purpose: "playground", consumer_slug: consumerSlug })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt(now)
    .setExpirationTime(now + PLAYGROUND_TOKEN_TTL_SECONDS)
    .sign(key);
}
```

## Gateway request

Send the chat request to the **proxy plane** (default port 8081), not the admin API:

```
POST {PROXY_API_URL}/{consumer_slug}/v1/chat/completions
Content-Type: application/json
X-AG-Playground-Token: <jwt>
X-AG-Gateway-Slug: <gateway_slug>        # see gateway discovery below
```

- The body is a standard OpenAI Chat Completions payload. `model` is optional when the consumer's registry defines a default. `"stream": true` returns SSE.
- Other fixed proxy routes work the same way with the same header: `/{slug}/v1/messages` (Anthropic), `/{slug}/v1/responses` (OpenAI Responses), `/{slug}/v1/models/{model}:generateContent` (Gemini).
- The consumer slug is the first path segment of the consumer's `path` field returned by the admin API.

### Gateway discovery

The proxy resolves which gateway a request targets in one of two ways (deployment config `GATEWAY_DISCOVERY_MODE`):

- **Header mode (default):** send `X-AG-Gateway-Slug: <gateway_slug>`. Recommended for BFF integrations.
- **Subdomain mode:** the Host must be `{gateway_slug}.{GATEWAY_BASE_DOMAIN}`; no header needed.

### Streaming

When `"stream": true`, the response is `text/event-stream` with OpenAI-style `data: {...}` lines ending in `data: [DONE]`. Relay the response body through the BFF without buffering so tokens render incrementally. If the upstream stream breaks mid-flight, the gateway emits a final explicit error event instead of silently truncating:

```
data: {"error":{"message":"upstream stream terminated unexpectedly","type":"upstream_error"}}
```

## Retrieving the trace (metrics) of a playground request

Every proxy response carries an `X-AG-Trace-Id` header (a gateway-specific name
to avoid colliding with the `X-Request-Id` some upstream providers emit). For
playground requests (those sent with `X-AG-Playground-Token`) the gateway also
stores the full metrics Event for that request in Redis, keyed by that same id,
with a short TTL (default 10 minutes). This lets the dashboard show what
happened: latency, token usage, cost, the policy chain, security flags,
attempts, etc.

1. Read `X-AG-Trace-Id` from the proxy response (it equals the trace id). It is
   already CORS-exposed, so the browser can read it; relay it through the BFF.
2. From the BFF (server-side, with the admin JWT), fetch the trace from the
   **admin API** (default port 8080):

```
GET {ADMIN_API_URL}/v1/playground/traces/{trace_id}
Authorization: Bearer <admin JWT>
```

- `200` returns the metrics Event as JSON (schema described in
  `pkg/infra/metrics/events/event.go`). Sensitive headers (including the
  playground token) are redacted.
- `404 not_found` means the trace is unknown or has expired — poll shortly after
  the response, since the Event is written asynchronously by the metrics worker.

The store is enabled by default and controlled by the deployment via
`PLAYGROUND_TRACE_STORE_ENABLED` and `PLAYGROUND_TRACE_STORE_TTL`. Non-playground
requests are never stored.

## Error contract

All errors are JSON `{ "error": "<code>", "message": "<detail>" }`. Surface `message` to the user where present.

| Status | `error` code | Meaning / UI treatment |
|---|---|---|
| 401 | `unauthenticated` | Missing/invalid/expired token — re-mint and retry once, then show error |
| 403 | `forbidden` | Token's `consumer_slug` doesn't match the route, or wrong purpose |
| 404 | `not_found` | Unknown consumer slug or inactive consumer |
| 400 | `invalid_request`, `invalid_model` | Bad payload or model reference |
| 403 | `model_not_allowed` | Consumer's model policy denies the requested model — show as a policy result |
| 4xx | `plugin_rejected` | A consumer policy fired (e.g. 429 rate limit) — this is the playground working as intended; show the policy message prominently |
| 502/503 | `backend_error`, `no_backend_available`, `provider_credential_error` | Upstream/provider problems |

## Listing consumers for the picker

Use the admin API (separate service, default port 8080, `Authorization: Bearer <admin JWT>` signed with the same secret but **without** a `purpose` claim):

```
GET {ADMIN_API_URL}/v1/gateways/{gateway_id}/consumers
```

Filter client-side to `type == "LLM" && active == true`. Each consumer exposes `slug` (for the token claim) and `path` (for the request URL). Both inline and role-based consumers work in the playground — no API key, OAuth, or IDP token is needed for either.

## BFF route checklist

1. Accept `POST /api/playground/{...path}` from the browser; reject if the first path segment (consumer slug) is missing.
2. Mint the playground token for that slug (server-side, per request — tokens are cheap and short-lived; do not cache across consumers).
3. Forward method, body, and query string to `{PROXY_API_URL}/{...path}`, adding `Content-Type: application/json`, `X-AG-Playground-Token`, and `X-AG-Gateway-Slug`.
4. Stream the upstream response body back with the upstream status and `Content-Type`.
5. Do not forward browser-supplied auth headers (`X-AG-API-Key`, `Authorization`) — the playground path is token-only.

Environment required by the BFF:

| Variable | Purpose |
|---|---|
| `SERVER_SECRET_KEY` | Signs playground (and admin) tokens; same value as the gateway |
| `PROXY_API_URL` | Base URL of the proxy plane, e.g. `http://trustgate-proxy:8081` |

## Verification checklist

- Chat succeeds with no consumer credential, for an inline consumer and a role-based consumer.
- Streaming renders token by token; non-streaming returns a complete JSON completion.
- A playground token replayed against the admin API returns 401.
- A token minted for consumer A used on consumer B's path returns 403.
- A rate-limit policy attached to the consumer produces a 429 `plugin_rejected` in the playground.
- Browser dev tools show no token, secret, or API key in any request leaving the browser.

## Reference implementation

In this repository:

| Concern | File |
|---|---|
| Token minting | `frontend/src/lib/jwt.ts` (`mintPlaygroundToken`) |
| BFF route with SSE relay | `frontend/src/app/api/playground/[...path]/route.ts` |
| Playground UI + SSE parsing | `frontend/src/components/entities/playground-view.tsx` |
| Gateway-side validation | `pkg/api/resolver/playground_resolver.go` |
| Header constant | `X-AG-Playground-Token` (`pkg/api/resolver/playground_resolver.go`) |
