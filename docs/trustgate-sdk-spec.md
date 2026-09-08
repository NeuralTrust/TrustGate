# TrustGate SDK — specification

Status: proposed, not implemented · Owner: victor.garcia@neuraltrust.ai · Date: 2026-09-08

Companion to `consumers-identity-model.md`. That memo defines the
**app-identified end user** consumer (`identity.source = app`) and the gateway
API it needs. This one specifies the **client library** an application actually
integrates against, so that integration is never a set of hand-built URLs.

## 1. Why

An application whose consumer identifies its own end users has to do two things
the MCP protocol does not cover:

1. **Get a person connected.** Before that person's first tool call, the app has
   to hand them a link where they sign in to the upstream (GitHub, Notion,
   Linear…) with their own account.
2. **Know where they stand.** Before acting for a person, the app has to know
   whether that person is connected, needs to reconnect, or has never connected.

Both are plain HTTP today (`POST /{slug}/connections/links`,
`GET /{slug}/connections?end_user=…`). Handing customers those URLs makes every
integration a copy of our routing: the endpoint shape, the header names, the
status vocabulary and the ticket lifetime all leak into their code, and we can
never change any of it. The SDK is the seam. Until it exists, the app hides the
*My app identifies its users* option in the consumer identity picker
(`APP_IDENTITY_SOURCE_ENABLED` in `features/consumers/lib/appIdentitySourceEnabled.ts`
in NeuralTrust/app) — shipping the SDK is what unhides it.

## 2. Scope

**v0.1 — in scope**

- The end-user **connections** API: mint a connect link, read connection state,
  wait for a connection to land.
- **Calling MCP for an end user**: the base URL and the headers an app-identified
  consumer must send (`X-AG-API-Key`, `X-NeuralTrust-End-User`), exposed so the
  app can hand them to any MCP client library it already uses.
- TypeScript / Node first (`@neuraltrust/trustgate-sdk`), Python second
  (`trustgate-sdk`, import `trustgate`) — same shape, idiomatic naming.

**Out of scope for v0.1**

- The admin API (gateways, consumers, registries, policies, auths). Different
  audience (platform admins, not applications), different credential (admin
  token), different base URL.
- The LLM proxy plane (`/v1/chat/completions` and friends) — apps already use
  the OpenAI/Anthropic SDKs against it, see `examples/`.
- An MCP protocol implementation. The SDK does **not** re-implement MCP: it
  produces the URL + headers, and the app keeps its own MCP client.
- Consumers whose users sign in with the platform (`identity.source = platform`).
  Those people authenticate in their MCP client; no application code is involved.

## 3. The model the SDK assumes

One SDK client is **one consumer**: an MCP consumer with
`identity.acts_for_users = true`, `identity.source = app`, and an API key (or a
client certificate) as its credential. Everything is scoped by that.

- The consumer authenticates as a machine, once, with its API key.
- Every request names the person it acts for with an opaque id (`end_user`,
  `X-NeuralTrust-End-User`), chosen by the application. The gateway namespaces
  it by consumer (`app:<consumer_id>:<end_user>`), so two applications naming
  `user_123` never share a connection.
- Access rules do not apply to those people — the application is the boundary.
  The consumer's registries are its whole surface.
- `end_user` constraints (gateway-enforced, `consumerdomain.ValidateEndUser`):
  non-empty after trim, ≤ 256 characters, no control characters. The SDK
  validates the same rules locally and fails fast with a typed error, so a bad
  id never costs a round trip.

## 4. Public surface (TypeScript)

```ts
import { TrustGate } from '@neuraltrust/trustgate-sdk'

const trustgate = new TrustGate({
  baseUrl: 'https://<mcp-host>/<consumer-slug>', // the consumer's MCP base
  apiKey: process.env.TRUSTGATE_API_KEY!,
  // optional
  fetch,                    // custom fetch (proxies, instrumentation)
  timeoutMs: 10_000,        // per request, default 10s
  retries: 2,               // GETs only (see §6)
  userAgent: 'acme-app/1.4',
})
```

`baseUrl` is exactly what the app's Connect tab shows for that consumer. The
SDK derives every path from it; the app never writes one.

### 4.1 Connections

```ts
// Mint a link for one person, for one provider or for whatever they still need.
const link = await trustgate.connections.createLink({
  endUser: 'user_123',
  provider: 'github',        // optional
})
// link: { connectUrl, ticket, provider?, expiresAt: Date }

// Where does that person stand?
const { endUser, connections } = await trustgate.connections.list({ endUser: 'user_123' })
// connections: [{ provider, code?, registry?, status, accountRef?, expiresAt? }]

// One provider, or undefined when the consumer has no such server.
const github = await trustgate.connections.get({ endUser: 'user_123', provider: 'github' })

// Block until a connection lands (Composio's wait_for_connection).
const settled = await trustgate.connections.waitForConnection({
  endUser: 'user_123',
  provider: 'github',
  timeoutMs: 120_000,        // default 2 min
  pollIntervalMs: 2_000,     // default 2s, capped by the SDK
  signal,                    // optional AbortSignal
})
// resolves on 'connected', throws ConnectionTimeoutError when the link is
// never used, and TicketExpiredError when expiresAt passes with no connection
```

`status` is the gateway's own vocabulary, not a boolean:
`'connected' | 'needs_reconnect' | 'not_connected'`. Exposed as a union type,
never widened to `string`.

### 4.2 Calling MCP for a person

```ts
const forUser = trustgate.forEndUser('user_123')

forUser.mcpUrl        // 'https://<mcp-host>/<consumer-slug>/mcp'
forUser.mcpHeaders()  // { 'X-AG-API-Key': '…', 'X-NeuralTrust-End-User': 'user_123' }

// The same connections calls, with the end user already bound.
await forUser.connections.list()
await forUser.connections.createLink({ provider: 'github' })
```

`forEndUser` is the shape most application code wants: resolve the person once
per request, pass the handle down. It validates the id immediately.

## 5. Wire contracts the SDK wraps

Both endpoints live on the MCP plane, next to the consumer, and authenticate
with the consumer's API key in `X-AG-API-Key`
(`pkg/api/handler/http/oauth/end_user_connections_handler.go`).

### `POST {baseUrl}/connections/links` → `201`

```jsonc
// request
{ "end_user": "user_123", "provider": "github" }   // provider optional
// response
{
  "connect_url": "https://…/oauth/connect/github?ticket=…",  // or /<slug>/mcp/connect?ticket=… without a provider
  "ticket": "…",
  "provider": "github",
  "expires_at": "2026-09-08T12:15:00Z"
}
```

The ticket is redeemable for **15 minutes** (`appoauth.ConnectTicketTTL`). The
SDK surfaces `expiresAt` as a `Date` and never caches a link past it.

### `GET {baseUrl}/connections?end_user=user_123` → `200`

```jsonc
{
  "end_user": "user_123",
  "connections": [
    {
      "provider": "app.github/mcp",
      "code": "github",
      "registry": "GitHub",
      "status": "connected",
      "account_ref": "octocat",
      "expires_at": "2026-10-01T00:00:00Z"
    }
  ]
}
```

The SDK camel-cases the payload (`account_ref` → `accountRef`) and parses
timestamps into `Date`. It does **not** invent fields the gateway does not send.

### `POST {baseUrl}/mcp`

Standard MCP, with `X-AG-API-Key` and `X-NeuralTrust-End-User`. The SDK only
supplies the URL and headers.

## 6. Errors and retries

The gateway answers with `{ "error": "<code>", "message": "<text>" }`. Each code
maps to one typed error, all extending `TrustGateError` (carrying `status`,
`code`, `message`, `requestId` when present):

| HTTP | `error` | SDK error | Means |
|---|---|---|---|
| 400 | `invalid_request` | `InvalidRequestError` | Bad body, bad `end_user`, unknown provider for this consumer |
| 401 | `unauthenticated` | `AuthenticationError` | Wrong API key, or a slug that is not an MCP consumer of this gateway |
| 409 | `end_users_not_identified` | `EndUsersNotIdentifiedError` | The consumer is not app-identified — the integration is pointed at the wrong consumer |
| 429 | — | `RateLimitedError` (with `retryAfterMs`) | Connect-attempt limiter, per consumer and per source |
| 503 | `unavailable` | `ServiceUnavailableError` | Rate limiter unavailable |
| 5xx | `internal_error` | `TrustGateServerError` | Gateway-side failure |

Retry policy: `GET /connections` retries on 429/503/5xx and on network errors
with exponential backoff plus jitter, honouring `Retry-After`.
`POST /connections/links` is **not** retried automatically — every call mints a
new ticket, and a silent retry would hand the app two live links.
`waitForConnection` polls the GET and inherits its retry behaviour.

Never log or serialise the API key: the client redacts it in error messages,
`toString`, and any debug hook.

## 7. Non-functional requirements

- **Zero runtime dependencies.** Node ≥ 18 (global `fetch`), ESM + CJS builds,
  first-class TypeScript types, `sideEffects: false`.
- **Browser-safe? No.** The client holds the consumer's API key, which is a
  machine credential — the SDK is server-side only and says so in its README
  and in a runtime warning if it detects a browser global.
- **Cancellation**: every call takes an optional `AbortSignal`.
- **No telemetry.** The SDK sends nothing anywhere except the configured
  `baseUrl`.
- **Versioning**: semver. The gateway contract it targets is stated in the
  README (`connections` API, gateway ≥ the release that ships it) and asserted
  by the integration suite, not by a runtime version check.

## 8. Python parity (v0.2)

Same objects, snake_case, sync and async clients:

```python
from trustgate import TrustGate

tg = TrustGate(base_url="https://<mcp-host>/<slug>", api_key=os.environ["TRUSTGATE_API_KEY"])
link = tg.connections.create_link(end_user="user_123", provider="github")
state = tg.connections.list(end_user="user_123")
```

## 9. Acceptance criteria

1. The snippet the app shows in the consumer identity section and in the
   Connect tab (`features/consumers/lib/mcpClientSnippets.ts`,
   `buildEndUserConnectionsSnippet`) compiles and runs unchanged against the
   published package.
2. An integration suite against a live gateway covers: link + connect + `list`
   reporting `connected`; a second `createLink` after a revoke reporting
   `needs_reconnect`; `list` for an unknown end user reporting
   `not_connected` for every connectable server; a wrong key raising
   `AuthenticationError`; a platform-identity consumer raising
   `EndUsersNotIdentifiedError`; an expired ticket raising `TicketExpiredError`.
3. Unit tests cover the `end_user` validation rules, the error mapping table in
   §6, `Retry-After` handling, and that `createLink` is never auto-retried.
4. No API key appears in any error, log line or stack the SDK produces.

## 10. Delivery

| Step | Deliverable |
|---|---|
| 1 | Package skeleton, client + config, error hierarchy, `end_user` validation |
| 2 | `connections.createLink` / `list` / `get` + unit tests |
| 3 | `forEndUser`, `mcpUrl`, `mcpHeaders` |
| 4 | `waitForConnection` + retry/backoff |
| 5 | README with the app's own snippet, integration suite, publish `0.1.0` |
| 6 | App: flip `APP_IDENTITY_SOURCE_ENABLED` to `true` |
| 7 | Python `0.1.0` |

## 11. Open questions

- **Webhooks instead of polling.** `waitForConnection` polls because the
  gateway has no callback when a connection lands. A per-consumer webhook would
  remove the poll; it is a gateway feature, not an SDK one.
- **Certificate-authenticated consumers.** An app-identified consumer may use
  mTLS instead of an API key. The connections endpoints read the API key today,
  so mTLS consumers cannot use them; either the endpoints learn to accept the
  client certificate, or the SDK documents API key as the credential for this
  pattern.
- **Disconnect.** There is `POST /oauth/disconnect/*` for the interactive flow;
  an app-identified equivalent (`connections.disconnect({ endUser, provider })`)
  needs a gateway endpoint before the SDK can offer it.
- **Listing end users.** Nothing exposes "every end user this consumer has
  connected". Worth having for support and for GDPR deletion, but it is a
  gateway endpoint first.
