# TrustGate SDK — specification

Status: proposed, not implemented · Owner: victor.garcia@neuraltrust.ai · Date: 2026-09-08
Revised: 2026-09-17 — the application actor (§3, §4.3, §5) after a survey of
Composio and Arcade; see §12.
Revised: 2026-09-22 — a consumer no longer declares who its callers are, and an
upstream account belongs to a server's instance rather than to a consumer. §3,
§4.3, §5 and §6 follow; `/whoami` grew the two things the SDK used to learn from
a failure (§4.0, §5).

Companion to `consumers-identity-model.md`. That memo settles **who a request
runs as** — read from the request, never declared on the consumer — and the
gateway API an application needs to connect the people it acts for. This one
specifies the **client library** an application actually integrates against, so
that integration is never a set of hand-built URLs.

## 1. Why

An application whose consumer identifies its own end users has to do two things
the MCP protocol does not cover:

1. **Get a person connected.** Before that person's first tool call, the app has
   to hand them a link where they sign in to the upstream (GitHub, Notion,
   Linear…) with their own account.
2. **Know where they stand.** Before acting for a person, the app has to know
   whether that person is connected, needs to reconnect, or has never connected.

And an application that acts for **nobody** — a nightly job, a pipeline, an
agent with no person behind it — has to do neither, which is the part that is
easy to get wrong. It must never be handed a link it cannot click.

The first two are plain HTTP today (`POST /{slug}/connections/links`,
`GET /{slug}/connections?end_user=…`). Handing customers those URLs makes every
integration a copy of our routing: the endpoint shape, the header names, the
status vocabulary and the ticket lifetime all leak into their code, and we can
never change any of it. The SDK is the seam.

Nothing in the console gates this any more. Naming an end user is a header an
application sends per call, not a mode somebody switches a consumer into, so the
pattern is available to every application that holds a key — which is exactly
why it wants a library rather than a page of URLs.

## 2. Scope

**v0.1 — in scope**

- The end-user **connections** API: mint a connect link, read connection state,
  wait for a connection to land.
- The **application actor**: calling MCP as the consumer itself, with no person
  involved and no link at runtime (§4.3). This is the batch case.
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
- Requests carrying a person's own verified token (a platform login, or a
  company IdP the consumer admits). Those people authenticate in their MCP
  client; no application code is involved.
- Connecting the account an MCP server's instance holds for every caller. An
  administrator does that once, on the instance, in the console (§5); the SDK
  deliberately offers no call for it, which is what makes `asApp()` unable to
  interrupt.

## 3. The model the SDK assumes

One SDK client is **one consumer**: an MCP consumer of type `mcp` holding an API
key (or a client certificate) as its credential. Everything is scoped by that.

### 3.1 Three actors, not one

Who a call is *attributed to* decides which credential the gateway reaches for,
and whether a person may have to be asked for consent. **The consumer declares
none of this.** It is read from the request, per request
(`pkg/api/handler/http/mcp/mcp_handler.go`), and the SDK's job is to make the
choice explicit in the caller's code rather than implicit in a header nobody
remembers to send.

| Actor | What the request carries | Gateway principal | Upstream credential | Can a call need a link? |
|---|---|---|---|---|
| **Application** | the machine credential, nothing else | `app:<consumer_id>` | the account the server's instance holds for everyone | **Never** |
| **Application for an end user** | the machine credential **+** `X-NeuralTrust-End-User` | `app:<consumer_id>:<end_user>` | per end user, via `connections/links` | Yes, first time |
| **Person** | a verified token (platform login, or a company IdP) | the person's own `sub` | their own connect page | Yes — and not through this SDK |

The middle row is what v0.1 was written for; the first is the batch case. The
third stays out of scope: those people authenticate in their own MCP client.

**One consumer is all three rows, one request at a time.** This is the change
from the previous revision, and it simplifies the SDK rather than complicating
it: `forEndUser()` and `asApp()` are two handles on the same client, both always
valid, and nothing has to be configured in the console to make either work. What
used to be a consumer-shaped refusal is now a per-request fact.

### 3.2 What naming an end user assumes

- The application authenticates as a machine, once, with its API key (or a
  client certificate).
- A request names the person it acts for with an opaque id (`end_user`,
  `X-NeuralTrust-End-User`), chosen by the application. The gateway namespaces
  it by consumer (`app:<consumer_id>:<end_user>`), because the name is
  *asserted* by the application and not verified — so two applications naming
  `user_123` never share a connection.
- Only a machine credential may assert one. A request carrying a person's own
  token is already that person; naming someone else from it would be
  impersonation, and the gateway refuses it.
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

### 4.0 One secret, resolved

`host` may be given in place of `baseUrl`, and the client resolves the rest from
the key itself:

```ts
const trustgate = new TrustGate({
  host: 'https://<mcp-host>',            // no slug
  apiKey: process.env.TRUSTGATE_API_KEY!,
})

const me = await trustgate.whoami()
// {
//   gateway: 'acme',
//   key: { name: 'prod', expiresAt: Date | undefined },
//   consumers: [
//     { slug: 'support-agent', type: 'MCP', active: true, url: '…/support-agent/mcp',
//       upstreams: [{ server: 'Notion', account: 'shared', connected: false,
//                     blocked: 'administrator' }] },
//     { slug: 'support-llm', type: 'LLM', active: true, url: 'https://…/support-llm/v1' },
//   ],
// }
```

Why it is in the SDK rather than left to the caller: the two planes do not share
a host, so a client configured with one base URL can never compose the other,
and the slugs were chosen by whoever created the consumers in the console. One
key resolves both.

Three things worth reading from it before anything else runs:

- `key.expiresAt` — `undefined` means never. A job that runs for six hours can
  refuse to start on a key with twenty minutes left, instead of discovering it
  as a `401` at hour one.
- `consumers[].url` — the MCP base for `forEndUser`/`asApp`, and the
  OpenAI-compatible base for the LLM plane.
- `consumers[].upstreams[].blocked` — who has to act before a server answers a
  call that runs as the application: `'administrator'` for an instance whose
  shared account nobody has connected, `'end_user'` for one that keeps an
  account per caller. Absent when the server is ready. Servers that carry their
  own credential are not listed, and `upstreams` is `undefined` — never `[]` —
  when the gateway could not read the accounts at all, so "no list" is
  distinguishable from "nothing to connect".

With `host`, the client picks the MCP consumer for `forEndUser`/`asApp` and
exposes the LLM one as `trustgate.llm.baseUrl`. When the key reaches more than
one consumer of a type, it raises `AmbiguousConsumerError` and the caller passes
`slug` — a library that guessed here would silently send a customer's traffic
through the wrong application.

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

### 4.3 Calling MCP as the application

```ts
const app = trustgate.asApp()

app.mcpUrl        // 'https://<mcp-host>/<consumer-slug>/mcp'
app.mcpHeaders()  // { 'X-AG-API-Key': '…' }   — no end-user header
```

`asApp()` is the batch handle: it sends the key and no end-user header, so every
call resolves to `app:<consumer_id>` and reads the account its servers' instances
hold for everyone — connected once, out of band, by an administrator (§5).

**It has no `connections.createLink`.** That is the point, and it is a type-level
guarantee, not a convention: a job that declares `asApp()` either fails at setup
or runs — it can never stop halfway holding a URL nobody will open. This is the
one thing an SDK can give a batch that a per-user API cannot, and it is why the
two handles are different types rather than one handle with a flag.

`asApp()` never refuses. Both handles are always available on the same client,
because which actor a request is comes from the request (§3.1) — so the guarantee
here is about what the *code* can do, not about what the consumer was configured
to be.

What it does have is the preflight:

```ts
const accounts = await app.connections.list()
// [{ provider: 'com.notion/mcp', registry: 'Notion', status: 'connected',
//    accountRef: 'ops@corp.com', expiresAt: Date },
//  { provider: 'app.linear/mcp', registry: 'Linear', status: 'not_connected' }]

const blocked = accounts.filter((a) => a.status !== 'connected')
if (blocked.length) throw new Error(`not connected: ${blocked.map((a) => a.registry)}`)
```

This is the half of the batch story the link cannot cover. A job that cannot be
handed a URL at runtime has to learn at startup that an account is missing or
has expired, while there is still a person around to fix it — otherwise the run
gets to the first call on that server and fails there, halfway through.

`status` is `connected`, `needs_reconnect` or `not_connected`, and `expiresAt`
is the credential's own expiry, so a job can refuse to start a six-hour run on
an account with twenty minutes left rather than discovering it at hour one.

`whoami().consumers[].upstreams` (§4.0) answers the same question in one call
across both planes and adds `blocked`, which names *who* fixes it. Prefer it for
a startup check; `app.connections.list()` remains the per-consumer form and the
one to poll between batches.

## 5. Wire contracts the SDK wraps

All of these live on the MCP plane, next to the consumer, and authenticate
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

### `GET {baseUrl}/connections` (no `end_user`) → `200`

The same endpoint asked about the other actor. Omitting `end_user` asks what the
application itself has connected — the principal `app:<consumer_id>` — which is
what `app.connections.list()` calls.

```jsonc
{
  "end_user": "",
  "actor": "application",
  "connections": [
    {
      "provider": "com.notion/mcp",
      "code": "notion",
      "registry": "Notion",
      "status": "connected",
      "account_ref": "ops@corp.com",
      "expires_at": "2026-10-01T00:00:00Z"
    }
  ]
}
```

`actor` is `end_user` or `application`, and it is there because an empty
`end_user` would otherwise read as an unnamed user rather than as the other
actor entirely.

Neither form is ever refused for being the wrong one. Both actors belong to
every MCP consumer, so asking about one says nothing about the other, and the
two `409`s this section used to document (`consumer_acts_for_users`,
`end_users_not_identified`) no longer exist.

### `POST {baseUrl}/mcp`

Standard MCP, with `X-AG-API-Key` and, for the end-user actor,
`X-NeuralTrust-End-User`. The SDK only supplies the URL and headers.

### `GET {host}/whoami` → `200`

Served at the MCP host with no slug, authenticated with the same key. It is what
`trustgate.whoami()` (§4.0) wraps.

```jsonc
{
  "gateway": "acme",
  "key": { "name": "prod", "expires_at": "2027-03-01T09:30:00Z" },
  "consumers": [
    {
      "slug": "support-agent", "name": "Support Agent", "type": "MCP",
      "active": true, "url": "https://<mcp-host>/support-agent/mcp",
      "upstreams": [
        { "server": "Notion", "provider": "notion", "account": "shared",
          "connected": false, "blocked": "administrator" },
        { "server": "GitHub", "provider": "github", "account": "user",
          "connected": false, "blocked": "end_user" }
      ]
    },
    { "slug": "support-llm", "type": "LLM", "active": true,
      "url": "https://<proxy-host>/support-llm/v1" }
  ]
}
```

`expires_at` is absent when the key never expires; `blocked` is absent when a
server is ready; `upstreams` is absent when the consumer binds no server that
reads a stored account — and also on a plane that cannot read them, which is why
a client reads `blocked` rather than counting a length. An unknown, disabled,
expired or foreign key gets one `401` that says nothing about which.

### The account an MCP server's instance holds — not an SDK call

Not a JSON API and not something the SDK calls. Whose account a server uses is a
property of **that server's instance**, not of a consumer: an administrator sets
the instance to a shared account and connects it once, from the server's page in
the console, and the gateway stores the credential under `instance:<registry_id>`.
Every application bound to that instance then rides on it.

That is what makes the batch case work and what makes it survive: the person who
clicked can leave the company without the job breaking, and no caller is ever
handed a link that would let them bind the account every other caller uses. It
also means the SDK has nothing to offer here — which is the point of §4.3.

An instance left on per-caller accounts has nothing for an application at all.
The gateway says so on the first call, naming both remedies (name the end user,
or switch the instance to a shared account), and `whoami` says it before the call
as `blocked: "end_user"`.

## 6. Errors and retries

The gateway answers with `{ "error": "<code>", "message": "<text>" }`. Each code
maps to one typed error, all extending `TrustGateError` (carrying `status`,
`code`, `message`, `requestId` when present):

| HTTP | `error` | SDK error | Means |
|---|---|---|---|
| 400 | `invalid_request` | `InvalidRequestError` | Bad body, bad `end_user`, unknown provider for this consumer |
| 401 | `unauthenticated` | `AuthenticationError` | Wrong API key, or a slug that is not an MCP consumer of this gateway |
| — | — | `AmbiguousConsumerError` | `host` was given and the key reaches more than one consumer of the requested type. Raised locally from `whoami`; the caller passes `slug` rather than letting a library guess whose traffic this is |
| 429 | — | `RateLimitedError` (with `retryAfterMs`) | Connect-attempt limiter, per consumer and per source |
| 503 | `unavailable` | `ServiceUnavailableError` | Rate limiter unavailable |
| 5xx | `internal_error` | `TrustGateServerError` | Gateway-side failure |

Retry policy: `GET /connections` — both actors — and `GET /whoami` retry on
429/503/5xx and on network errors with exponential backoff plus jitter,
honouring `Retry-After`.
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
   `AuthenticationError`; an expired ticket raising `TicketExpiredError`.
3. Unit tests cover the `end_user` validation rules, the error mapping table in
   §6, `Retry-After` handling, and that `createLink` is never auto-retried.
4. The application actor: `asApp()` produces the MCP URL and an `X-AG-API-Key`
   header with no end-user header, and a tool call against a server whose
   instance holds a connected shared account succeeds with no link anywhere in
   the flow. A compile-time test asserts the app handle exposes no link-minting
   call — the guarantee is the type, so a type that loses it is the regression.
5. Both handles on one client: `forEndUser('user_123')` and `asApp()` built from
   the same `TrustGate` both work, against the same consumer, in the same
   process. The previous revision's two `409`s must not come back as errors the
   SDK can raise.
6. The application actor's preflight: `app.connections.list()` on a consumer
   with one connected and one unconnected upstream reports `connected` and
   `not_connected` for the right servers and carries the connected one's
   `expiresAt`.
7. Resolution from one secret: with `host` and a key reaching an MCP and an LLM
   consumer, `whoami()` returns both URLs, the key's `expiresAt` (and
   `undefined` for a key with no expiry), and `blocked: 'administrator'` for a
   shared instance nobody has connected; a key reaching two MCP consumers raises
   `AmbiguousConsumerError` before any other call.
8. No API key appears in any error, log line or stack the SDK produces.

## 10. Delivery

| Step | Deliverable |
|---|---|
| 1 | Package skeleton, client + config, error hierarchy, `end_user` validation |
| 2 | `connections.createLink` / `list` / `get` + unit tests |
| 3 | `forEndUser`, `mcpUrl`, `mcpHeaders` |
| 4 | `waitForConnection` + retry/backoff |
| 4b | `asApp()` and the compile-time guarantee |
| 4c | `app.connections.list()` — the batch preflight, over `GET /connections` with no `end_user` |
| 4d | `whoami()` and `host`-only construction, over `GET /whoami` |
| 5 | README with the app's own snippet, integration suite, publish `0.1.0` |
| 6 | Python `0.1.0` |

## 11. Open questions

- **Webhooks instead of polling.** `waitForConnection` polls because the
  gateway has no callback when a connection lands. A per-consumer webhook would
  remove the poll; it is a gateway feature, not an SDK one.
- **Certificate-authenticated consumers.** An application may authenticate with
  a client certificate instead of an API key — the MCP plane accepts both, and
  both are machine credentials that may name an end user. The connections
  endpoints and `/whoami` read the API key today, so a certificate-only
  application cannot use them; either they learn to accept the client
  certificate, or the SDK documents the API key as the credential for this
  pattern.
- **Disconnect.** There is `POST /oauth/disconnect/*` for the interactive flow;
  an app-identified equivalent (`connections.disconnect({ endUser, provider })`)
  needs a gateway endpoint before the SDK can offer it.
- **Listing end users.** Nothing exposes "every end user this consumer has
  connected". Worth having for support and for GDPR deletion, but it is a
  gateway endpoint first.
- **Pushing a credential's death to a running job.** A run that starts with
  every account connected can still have one revoked under it an hour later,
  and it learns from the failure. `app.connections.list()` (§4.3) closes the
  "before it starts" half; the "while it runs" half is the webhook question
  above with a different subject, and a job that wants it today polls that same
  call between batches.

## 12. What the survey changed

A read of Composio and Arcade (September 2026, from their public documentation)
to check the shape of this spec against the field.

Both key every call on a `user_id`. Composio pairs an `auth_config` (the
developer's credentials for an app, reused across users) with a
`connected_account` per user; Arcade's `tools.authorize(user_id=…)` answers
`completed` when that person already authorised, and returns a URL when they
have not. So in both, the link is a **setup** step, not a per-call one — the
first draft of this spec had that right.

What neither appears to offer is an actor that is not a person. A batch job on
those platforms borrows some user's connection, which makes the job's access
depend on that user's employment and consent. TrustGate already has the other
thing — the application as a principal with its own upstream accounts
(`app:<consumer_id>`, §3.1) — and the spec simply did not name it. §4.3 is that
omission fixed, not a new capability.

The one piece of design this survey does add is the non-interruptible
guarantee: because the two actors are different handles, a job that declares
itself an application cannot be handed a link at runtime. On a platform where
the actor is a parameter rather than a type, that is a runtime surprise.

That guarantee survived the model changing under it. When this was written the
two handles were also two *kinds of consumer*, and half the argument for them was
that the gateway enforced the split. It no longer does — both actors belong to
every consumer, decided per request — and the handles are worth having anyway,
for the same reason they were: the code that cannot be interrupted is the code
that never had the method.
