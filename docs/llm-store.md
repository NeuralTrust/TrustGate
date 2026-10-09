# LLM Store

The LLM Store lets the people of a tenant call models through one URL,
`/store/v1/*`, with a **personal key**. The key leads to every **personal
consumer** its owner was granted on that gateway, and for each request the data
plane picks one of them. The picked consumer then serves the request exactly as
its own route would: its registries, model policies, load balancer, fallback and
policies.

TrustGate does not know who is granted what. The app owns the grants (users,
groups, everyone) and keeps TrustGate in sync by attaching the user's key to the
granted consumers. A key attached to a consumer *is* the authorisation.

## Concepts

| Concept | What it is |
|---|---|
| Personal consumer | An LLM consumer created with `"audience": "personal"`. It is configured like any LLM consumer, but it is never reachable at `/<slug>/v1`, it takes no bulk `auths`, and it needs a concrete (non-glob) default model on at least one primary registry. The audience is set at create and never changes. |
| Personal key | An `api_key` auth with an `owner_id` (the platform user id). One per user per gateway, valid for at most 90 days. It works on `/store/v1` and on the MCP Store (`/store/mcp`, see The MCP Store), nowhere else. `GET /auths` hides it. |
| Link | The attachment of a personal key to a personal consumer, with three attributes: `level` (`user`, `group` or `all`), `priority` (an integer, lower first, default 1) and `granted_at` (when the grant was made, the stable tie-break). A key has N ≥ 0 links. |

## Admin setup

Create a personal consumer. The request is the usual consumer create plus the
audience:

```json
POST /v1/gateways/{gateway_id}/consumers
{
  "name": "anthropic-for-engineering",
  "audience": "personal",
  "registries": [
    {"id": "<anthropic registry>", "model_policies": {"allowed": ["opus-5.5"], "default": "opus-5.5"}}
  ]
}
```

Attach a key with the link attributes. Sending the same call again with other
values updates that one link; the key's other links are untouched.

```json
POST /v1/gateways/{gateway_id}/consumers/{consumer_id}/auths/{auth_id}
{"level": "group", "priority": 1, "granted_at": "2026-10-01T09:00:00Z"}
```

`DELETE` on the same path removes the link. `GET /v1/gateways/{gateway_id}/auths?owner_id=<user id>`
finds a user's key, and `GET …/auths?owned=true` lists every personal key of
the gateway with the list's usual pagination (`owned=false` and no parameter
list application keys only). Each personal key in a response carries
`owner_id` and, when it has one, `budget`.

Give a user a spending limit by setting a budget on their key:

```json
PUT /v1/gateways/{gateway_id}/auths/{auth_id}/budget
{"max": 50, "unit": "dollars", "time_window": "calendar_month"}
```

The answer is 200 with the auth, `budget` included. A body of `null` clears the
budget. `max` is a finite number above zero, a whole number when `unit` is
`tokens`; `unit` is `tokens` or `dollars`, and only a `key_budgets` policy
counting in that unit holds the key to it (Budgets, below); `time_window` is
`calendar_month` or `calendar_day` (UTC). The call never changes the secret,
the expiry or the links, a rotation keeps the budget, and a revoke drops it
with the key, so set it again on the re-created key. An unknown key, or one of
another gateway, answers 404.

These calls answer 422:

- `personal` on an MCP consumer, a personal consumer without a primary default,
  a personal consumer on a hybrid gateway, or a change of `audience`;
- `auths` in the update body of a personal consumer (create never takes
  `auths`, for any audience: keys arrive only through attach);
- detaching from a personal consumer, or deleting, the registry that holds its
  last primary default model;
- an owned key attached to an application consumer, an application key attached
  to a personal consumer, link attributes on an application consumer, or a link
  without `level` or `granted_at`;
- `PUT` or `POST …/rotate` on an owned key (`owned_key`);
- `PUT …/budget` on an application key (`application_key`), or with a body
  other than `null` or a valid budget (`validation_failed`);
- `GET …/auths` with both `owned` and `owner_id` (`invalid_filter`).

Deleting a personal consumer removes its links and keeps the keys. Admin
`DELETE /auths/{auth_id}` revokes a key and all of its links.

Record the owner's directory groups on their key, so the MCP Store applies
grants and policies made to a group (The MCP Store, below), and their email, so
the key's requests are shown under the person and not their user id. Send the
whole membership again whenever it changes; an empty list clears it:

```json
PUT /v1/gateways/{gateway_id}/auths/{auth_id}/groups
{"groups": ["engineering", "sre"], "email": "alice@example.com"}
```

The answer is 200 with the auth, `owner_groups` and `owner_email` included.
Names are trimmed, deduplicated and sorted; at most 512 groups of at most 256
characters each (422 `validation_failed`). `email` is optional: absent leaves
the recorded one, empty clears it, and one that is not an address answers 422
`validation_failed`. A key created from the Portal records the email its
sign-in carries, so `email` is for keys made before that, or an owner whose
address changed. An application key answers 422 `application_key`, an unknown
key or one of another gateway 404. The secret, the expiry, the budget and the
links never change, and a rotation keeps the groups and the email. The change
reaches the proxies as a budget change does.

## Key lifecycle

The owner manages the key through self-only routes. They need a signed-in
tenant user: service credentials and platform tokens get 403. A body never
names another owner.

| Call | Result |
|---|---|
| `GET /v1/gateways/{gateway_id}/store/principal/llm-key` | 200 with `id`, `consumer_ids`, prefix, suffix and expiry, never the secret. 404 without a key. |
| `POST …/llm-key` `{"expires_at": "<RFC 3339>"}` | 201 with the secret in `api_key` (the field the admin auth responses use), shown once, linked to nothing. 409 if the user already has a key, 422 for an expiry not in (now, now + 90 days] or a hybrid gateway. |
| `POST …/llm-key/rotate` `{"expires_at"?}` | 200 with a new secret. Same id, same links. Without `expires_at` the current expiry stays, unless it has passed (422). Two rotations racing each other: the first wins and the second answers 409 `conflict` without changing anything, so the secret shown is always the live one. |
| `DELETE …/llm-key` | 204. The key and its links are gone in one transaction; a new create starts with no links. |

A rotation or revocation reaches every full-plane replica at the next
`InvalidateGatewayDataEvent` for the gateway and every DB-less proxy at the next
snapshot apply. A key lookup that was already reading when the caches were
cleared does not put the old answer back: the old secret is not served from a
cache refilled after the clear, and a key created during a lookup that missed
is not remembered as unknown.

## Request routing

Send the key in `X-AG-API-Key`, `x-api-key`, `x-goog-api-key` or
`Authorization: Bearer ag_…`, to any route of `/store/v1` (`chat/completions`,
`responses`, `messages`, `models`, `embeddings`, …). The Files API is refused in
v1: with a valid key, `/store/v1/files` and `/store/v1/files/{id}` answer the
404 of an unknown route, because file operations would run on the registry's
shared credential for every user it serves.

1. **404 before any key lookup** when the gateway is served by a hybrid data
   plane or has no active personal consumer. The answer is the one an unknown
   consumer slug gets.
2. **401** for no key, an unknown, disabled, expired or revoked key, an
   application key, or another gateway's key. An unknown key's digest is
   remembered for 30 s (and forgotten on the next `InvalidateGatewayDataEvent`),
   so the same random key sent again does not reach the database.
3. **Substitution.** Let S be the providers of the primary registries of the
   key's `user`-level consumers. Every registry of a `group` or `all` consumer
   whose provider is in S is ignored, fallback included. A consumer left with no
   primary registry takes no part. Fallback registries of `user` consumers never
   add to S.
4. **Admission.** A consumer admits the request when the normal routing of that
   consumer (model policies, capability of the route, files id) leaves a
   primary candidate. A fallback registry never admits. For a short model, a
   registry without an allow-list is dropped when the provider's catalog listing
   does not list the model, and nothing restores it. A provider with no
   authoritative listing (none loaded, Azure, OpenAI-compatible) lets such a
   registry admit any short model: give those registries an allow-list.
5. **Order.** Among the consumers that admit, the first by level (`user`,
   `group`, `all`), then priority, then specificity (a literal allow-list entry,
   then a glob, then no allow-list), then the oldest `granted_at`, then the
   consumer id. None → 403 `model_not_allowed`, before any upstream call and
   before the gateway's plan rate limit is charged. When every consumer refused
   the request for the same reason other than the model (a capability no linked
   provider supports, no backend left), the answer is that reason, as on
   `/<slug>/v1`: 400 for an unsupported capability, 503 for no backend.

| Model in the request | A consumer admits it when |
|---|---|
| none | a primary registry has a default model |
| `auto` | routing resolves with a primary candidate |
| `pool:<alias>` | its pool has that alias and a member survives substitution. No consumer defines it → 400; one defines it but nothing survives → 403 |
| `@provider/model` | a primary registry of that provider allows the model |
| short model | a primary candidate survives the catalog check |

The selected consumer then serves the request with its registries minus the
substituted ones, its model policies, its load balancer (`gateway:consumer`,
shared by every user it serves), its fallback, and its own policies plus the
gateway's global ones. MCP-wide policies never apply.

A session id (`X-Session-Id` or a known client header) names a conversation of
the key's owner. Two owners sending the same session id never continue each
other's conversation, and a `previous_response_id` recorded for another owner
starts a new session. On `/<slug>/v1` sessions stay per gateway.

`/store/v1/models` lists the union, deduplicated and sorted, of what each
remaining consumer lists through its surviving primary registries. A key with no
links lists `[]`, and its chat calls get 403.

### Worked example

Ana's key is linked to A (`group`, OpenAI without allow-list, default `gpt-4.1`,
fallback DeepSeek), B (`group`, Anthropic without allow-list), C (`group`,
Anthropic `["opus-5.5"]`) and D (`user`, OpenAI `["gpt6"]`, default `gpt6`), all
at priority 1 and granted in that order. D puts OpenAI in S, so A has nothing
left.

| Request | Served by | Why |
|---|---|---|
| `gpt-4.1` | 403 | D does not allow it, A is substituted, Anthropic's listing lacks it |
| `gpt6` | D | the only `user` link, literal entry |
| `opus-5.5` | C | literal entry beats B's open registry at equal level and priority |
| `opus-4.8` | B | only B admits it |
| no model | D | first link with a default |
| `/store/v1/models` | `gpt6` plus B's Anthropic listing | A's OpenAI and DeepSeek never list |

Without D, `gpt-4.1` goes to A, and when OpenAI fails A's fallback serves it as
A's own route would: a fallback registry without an allow-list is skipped for a
short model its provider's catalog does not list. `deepseek-chat` is still
refused, because a fallback never admits. A's open OpenAI registry now lists
the OpenAI catalog, so `/store/v1/models` gains it.

## The MCP Store

The same key opens its owner's MCP Store, `https://<gateway>.<MCP_BASE_DOMAIN>/store/mcp`,
sent in any of the key headers above. It is the Store a signed-in session gets:
what the owner installed, narrowed by the Store grants and access policies that
name them or one of their groups, with the `trustgate_store_*` and
`trustgate_list_tools` tools, and every call made with the owner's own
upstream accounts.

- The principal is the key's owner (`subject` = `owner_id`), method
  `personal_key`, with the groups recorded by `PUT …/auths/{auth_id}/groups` as
  its `groups` claim and the owner's email as its `email` claim. Unlike an application key's, nothing renames it to an
  application subject, and MCP policies scoped to groups apply to it.
- A personal key on any other MCP path, or an application key on
  `/store/mcp`, answers 401 like an unknown key. A disabled or expired key, a key
  whose owner spells a subject only the gateway mints (`app:…`, `instance:…`),
  and a key sent to another gateway's host answer the same.
- A connect link the Store hands out (a consent error, or
  `trustgate_store_install` called again for an installed server that is not
  connected) connects the owner's account, as it does for a session. The Store
  lists no `trustgate_connect_*` tool: installing is its one way in, and
  `trustgate_list_tools` names it (`connect_tool`) with the server's `code`.
- A person revokes an account they linked from the Portal:
  `DELETE /v1/gateways/{gateway_id}/store/principal/connections/{registry_id}`
  (the instance's `registry_id`, as `GET …/store/principal` lists it under
  `connections`). It acts on the signed-in user only (403 for a service
  credential), deletes their credential from the vault and answers 204, also
  when nothing was linked. An instance with one shared account answers 409: an
  administrator disconnects it in Registry. The install stays; the next call to
  the server is refused with the link to connect again, and that refusal drops
  the server's cached tool list, so `trustgate_list_tools` reports it as
  `needs_connect` from then on.
- `GET /whoami` describes a personal key with `"key": {"personal": true, …}`
  and the Store on each plane, slug `store`: the MCP Store, and `/store/v1` when
  the gateway has an active personal consumer.
- `trustgate_store_models` lists what the caller's personal key reaches,
  grouped by provider, with the key's `base_url` (`…/store/v1`): the same list
  the key's own `GET /store/v1/models` answers, found by owner, so a signed-in
  session gets it too. No key, an expired one, or one with no links says so
  (and names `trustgate_store_personal_key`); the key itself is never in the
  answer.

### The personal key page

A person can get the key from the Store itself, without the console:
`trustgate_store_personal_key` returns a link to
`/store/mcp/personal-key?ticket=…`, a page like the connect page where they
create, rotate or revoke it, with what the Portal's Personal key offers (90 days,
the secret shown once, the SDK / OpenAI / MCP usage). The key is never shown to
the model.

- **Who opens it.** The tool's caller is already signed in to the Store, so the
  ticket (15 minutes) names them. The link went through a model, though, and
  the page will show a secret, so the link alone opens nothing: the browser
  signs in through the default identity provider (instant for a person signed
  in to the console) and must come back as the ticket's owner on the same
  gateway. Another account is told who it is signed in as. The return is a
  one-time proof the token endpoint refuses (`BrowserSignIn`).
- **The page.** A cookie per link binds the browser; every form carries a CSRF
  token and a cross-site post is refused (`Sec-Fetch-Site`). Showing a secret,
  or revoking, spends the link. Changes count against the Portal's budget, 10
  an hour per person and gateway. Hybrid gateways have no personal keys.
- **Writes.** The MCP plane has no database in production: it writes the key
  through the control plane over config sync (`PersonalKeys` gRPC service,
  scoped like the Store's installs). A new key gets the groups and the email
  the browser's sign-in carried as its owner's.
- **The console.** With `CONSOLE_EVENTS_URL` set, the control plane posts each
  change to the console (`POST /api/internal/trustgate/personal-key-events`),
  signed with `SERVER_SECRET_KEY` (the console's `AGENTGATEWAY_JWT_SECRET`):
  `X-TrustGate-Timestamp` and `X-TrustGate-Signature: v1=hex(HMAC-SHA256(secret,
  "trustgate.console-events.v1." + timestamp + "." + body))`. The console audits
  it as the Portal does and reconciles the gateway, which links a new key to
  its models. Unset, a new key opens the MCP Store at once and reaches its
  models on the console's next reconcile.

## Errors

| Status | When |
|---|---|
| 404 `not_found` | hybrid gateway, no active personal consumer, or the Files API |
| 401 `unauthenticated` | the key is missing or not a valid personal key of this gateway |
| 403 `model_not_allowed` | no consumer admits the request, including a key with no links |
| 400 / 503 | every consumer refused it for the same capability or backend reason (Request routing, step 5) |
| 400 `invalid_model` | malformed model reference, or a pool alias no consumer defines |
| 429 / 503 / 403 `model_unpriced` | `partition: key` budgets, below |

## Budgets

A `token_rate_limiter` policy with `"partition": "key"` counts per owner: the
counter is `owner:<owner_id>`, so a rotation or a revoke and re-create keeps the
spend, and one owner shares one counter across every consumer that serves her.
A key without an owner counts as `auth:<auth_id>`. A request that no API key
authenticated (OAuth2, OIDC, mTLS, the playground) has no key and is not
counted by `partition: key`. Make it a global policy to cap a user across all
of her consumers.

```json
{"slug": "token_rate_limiter", "settings": {"partition": "key", "aggregate": {"max": 500000, "time_window": "calendar_month"}}}
```

A policy with `"key_budgets": true` (it needs `partition: key`) holds a key
with a `budget` (Admin setup) to it instead of `aggregate`: its `max`, in the
policy's `unit`, over its `time_window`. A budget in the other unit leaves the
key under the policy's own limit. With `key_budgets` the `aggregate` is
optional, so a policy without it caps only the keys that carry a budget, and a
key without one is not counted by that policy. Only a policy that sets
`key_budgets` reads key budgets: any other `partition: key` policy keeps its
own limit and unit for every key. This is the policy the app uses for per-user
limits, with every budget in dollars, attached to the consumers it manages:

```json
{"slug": "token_rate_limiter", "settings": {"partition": "key", "key_budgets": true, "unit": "dollars"}}
```

A budget counts on the owner's counter for its window,
`trl:<policy>:key:owner:<owner_id>:p:<2006-01 | 2006-01-02>`, the counter an
aggregate with the same window uses, so clearing a monthly budget under a
`calendar_month` aggregate keeps the month's spend. Per-model `rules` still
apply, and the answers below and the rate-limit headers report a budget as they
report an aggregate. A budget change reaches the proxies as a rotation does: on
the next `InvalidateGatewayDataEvent` on the full plane, and with the config
snapshot on a DB-less proxy.

`calendar_month` and `calendar_day` (UTC) are valid only with `partition: key`;
`custom_pricing`, `group_by_header` and `behavior_on_exceeded: downgrade_model`
are refused with it: a hard limit never serves past the budget. In a blocking
mode, over budget answers 429, a Redis read error 503 `budget_unavailable` with
`Retry-After: 5` (the default partition stays fail-open), and a dollar budget on
a model without a price 403 `model_unpriced`. A `partition: key` policy counts
the model that will be served: for a request with no model, `auto` or
`pool:<alias>` that is the selected route's default model, so such a request is
served and charged, and 403 `model_unpriced` answers only when that model has no
catalog or registry price. A policy without `partition` keeps counting such a
request under the model it names, as before.

A request is charged to the calendar period it was admitted in: a stream that
starts on the last second of a month and ends in the next one counts in the
month that admitted it.

## Telemetry

A store request's usage event carries `trustgate.auth.id` (the key),
`trustgate.principal.subject` (the owner), `trustgate.principal.email` (the
owner's email, when the key records one) and `trustgate.consumer.id` (the
selected consumer). An MCP Store request made with the key carries the same
subject and email, as a signed-in session's does. A request refused after authentication (403, 400, 405, 429)
carries the key and the owner and no consumer, and so does `/store/v1/models`.
A 401 carries neither the key nor the owner: nothing authenticated it. The end
user (`trustgate.end_user.id`) is always the key's owner:
`X-NeuralTrust-End-User`, the `X-TG-User-*` and Open WebUI headers and the
body's `user` field are ignored on `/store/v1`. Each snapshot publish records
`trustgate.configsnapshot.encoded_bytes`, `trustgate.configsnapshot.scopes` and
`trustgate.configsnapshot.entities` (`auths`, `owned_auths`,
`personal_consumers`, `personal_links`).

A warm store request on a DB-less proxy makes no database or config-sync call.
An attach, detach, priority change, rotation or revocation takes effect on the
next snapshot apply there, and on the next `InvalidateGatewayDataEvent` on the
full plane.

## Rollout and rollback

Every plane (admin, proxy, MCP, DB-less) must run a build with the LLM Store
before the app creates the first personal consumer: an older data plane ignores
`audience`, `owner_id` and the links, and would serve a personal consumer at its
slug. Create `partition: key` policies only once every plane understands them.
Set key budgets, and create `key_budgets` policies, only once every plane runs a
build with key budgets: an older plane ignores `budget` and `key_budgets` and
refuses a policy with no limit of its own.

To roll back: disable the `partition: key` policies (budgets can stay: nothing
reads them without such a policy), then
`UPDATE consumers SET active = false WHERE audience = 'personal';` before an
older binary serves, and optionally delete the owned keys and their links. The
columns can stay.

## Out of scope

- Hybrid gateways: `/store/v1` answers 404 and personal consumers are refused.
- The Files API on `/store/v1` (404, see Request routing).
- Personal keys on `/<slug>/v1` and on MCP paths other than `/store/mcp`: they
  answer as unknown keys.
- Traffic labeling of `/store/v1` requests, and the playground on personal
  consumers.
- The grants, the reconcile and the UI, which live in the app.
- Admin consumer responses keep listing every linked key in `auth_ids`; the link
  attributes are not exposed.

## Release notes

What changes for a deployment that never creates a personal consumer or a
personal key, OSS included. Everything else in this document is inert until
the first personal consumer exists.

| # | Change | Before |
|---|---|---|
| a | An application key whose `expires_at` has passed gets 401 on `/<slug>/v1/*`. An expired key attached to another consumer also gets 401. | The key kept working; on another consumer it got 403. |
| b | `InvalidateGatewayDataEvent` clears the whole `auth_key` cache and the new unknown-key cache (30 s) on every full-plane replica, so a rotation or a revocation stops the old secret on every replica at once. | Other replicas kept resolving the old secret for up to 5 minutes. |
| c | Usage events carry `auth_id`, and OTLP records `trustgate.auth.id`, on LLM proxy requests authenticated by an API key. | No auth id. |
| d | Admin consumer responses always carry `audience` (`application` for every existing consumer). | No `audience` field. |
| e | `whoami` on the fixed host resolves a gateway only from an enabled, unexpired application or personal key. A disabled or expired key answers like an unknown key. | Any key the key finder returned resolved its gateway, including a disabled one still in its cache. |
| f | `POST /v1/gateways/{gateway_id}/consumers/{consumer_id}/auths/{auth_id}` parses a non-empty body as link attributes: malformed JSON answers 422, and link attributes on an application consumer answer 422. No body behaves as before. | The body was ignored. |
| g | Deleting a registry that holds a personal consumer's last primary default model answers 422 `validation_failed`, like detaching it. | Personal consumers are new; an earlier build of this change answered 409 `has_dependents`. |
| h | The MCP connect ticket re-check refuses an expired or personal key. | Only enabled, type and gateway were checked. |
| i | `token_rate_limiter` gains `partition: key`, the `calendar_month` and `calendar_day` windows and the hard limits (503 `budget_unavailable`, 403 `model_unpriced`). All are opt-in: a policy without `partition` counts, fails open and prices exactly as before. | — |
| j | `GET /v1/gateways/{gateway_id}/auths` reads `owned`: `true` lists personal keys only, `owned` together with `owner_id` answers 422 `invalid_filter`, and a value that is not a boolean answers 422 `invalid_filter`. Admin auth responses carry `budget` on a personal key that has one. `PUT …/auths/{auth_id}/budget` is new, and `auths` gains a nullable `budget` column. `token_rate_limiter` gains `key_budgets` (needs `partition: key`): such a policy holds each key to its budget and may have no `aggregate`, `rules`, `window` or `cost_cap`; every other policy still needs one, and no other policy reads key budgets. | `owned` was ignored, and a policy had no way to read a key's budget. |
| k | `POST …/auths/{auth_id}/rotate` writes the new secret only while the stored one is the secret it read: of two rotations of the same key racing each other, the second answers 409 `conflict` and changes nothing. | Both answered 200; the secret the first one returned was already dead. |
| l | The LLM Store migrations wait at most 5 s for a table lock (`lock_timeout`); one that cannot get it fails and the rollout retries it, instead of queueing every later read and write on `consumers`, `auths` or `consumer_auth` behind it. | — |
| m | `auths` gains a nullable `owner_groups` column and `PUT …/auths/{auth_id}/groups` is new. A personal key is accepted on `/store/mcp` as its owner, and `whoami` describes one (`key.personal`) instead of refusing it. Application keys and every other MCP path are unchanged. | A personal key answered 401 on every MCP path and on `whoami`. |
| n | The MCP Store offers `trustgate_store_personal_key` and serves `/store/mcp/personal-key` (and `/return`) where a key can be issued. The config-sync listener gains the `PersonalKeys` service; `CONSOLE_EVENTS_URL` is new and optional. Deploy the control plane first: against an older one a DB-less data plane's page answers 500, since the control plane does not know the `PersonalKeys` service yet. | — |
| o | `auths` gains a nullable `owner_email` column. A personal key records its owner's email when the Portal or the Store's personal key page creates it, and `PUT …/auths/{auth_id}/groups` takes an optional `email`; admin auth responses carry `owner_email`. Requests made with the key carry it as the principal's email. `CreatePersonalKeyRequest` gains `email` (config sync), which an older control plane ignores. | A personal key's requests showed its owner's user id. |
| p | `DELETE …/store/principal/connections/{registry_id}` is new. A tool call refused because the caller's account is missing drops that server's cached tools, prompts and resources lists for the caller. | A revoked account's server kept being listed as ready, its tools refused, until the 5-minute discovery cache expired. |
| q | The MCP Store offers `trustgate_store_models`. The personal key page's "Use it" is one code card (tabs, Copy, numbered and coloured lines), and its MCP config no longer escapes `<your-api-key>`. | The snippets were three `<details>` whose lines each drew their own box. |
| r | Store session tokens carry `mcp_client` (the OAuth client they were issued to; not `client_id`, which auth bindings read), and a connect link minted from one names that app: the connected page offers "Close and go back to <app>", and says to switch back when the browser keeps the tab. TrustGuard evaluates carry `attributes.consumer {id, name}`. | The page said "go back to your assistant"; TrustGuard got the consumer id only. |

Roll back (a) by reverting it; the rest needs no action.

