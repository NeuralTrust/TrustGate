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
| Personal key | An `api_key` auth with an `owner_id` (the platform user id). One per user per gateway, valid for at most 90 days. It works only on `/store/v1`. `GET /auths` hides it. |
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
{"max": 50, "time_window": "calendar_month"}
```

The answer is 200 with the auth, `budget` included. A body of `null` clears the
budget. `max` is a finite number above zero, counted in the unit of the
`key_budgets` policy that enforces it (Budgets, below); `time_window` is
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

## Key lifecycle

The owner manages the key through self-only routes. They need a signed-in
tenant user: service credentials and platform tokens get 403. A body never
names another owner.

| Call | Result |
|---|---|
| `GET /v1/gateways/{gateway_id}/store/principal/llm-key` | 200 with `id`, `consumer_ids`, prefix, suffix and expiry, never the secret. 404 without a key. |
| `POST …/llm-key` `{"expires_at": "<RFC 3339>"}` | 201 with the secret in `key`, shown once, linked to nothing. 409 if the user already has a key, 422 for an expiry not in (now, now + 90 days] or a hybrid gateway. |
| `POST …/llm-key/rotate` `{"expires_at"?}` | 200 with a new secret. Same id, same links. Without `expires_at` the current expiry stays, unless it has passed (422). |
| `DELETE …/llm-key` | 204. The key and its links are gone; a new create starts with no links. |

A rotation or revocation reaches every full-plane replica at the next
`InvalidateGatewayDataEvent` for the gateway and every DB-less proxy at the next
snapshot apply.

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
   consumer id. None → 403 `model_not_allowed`, before any upstream call.

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

## Errors

| Status | When |
|---|---|
| 404 `not_found` | hybrid gateway, no active personal consumer, or the Files API |
| 401 `unauthenticated` | the key is missing or not a valid personal key of this gateway |
| 403 `model_not_allowed` | no consumer admits the request, including a key with no links |
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
policy's `unit`, over its `time_window`. With `key_budgets` the `aggregate` is
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
`custom_pricing` and `group_by_header` are refused with it. In a blocking mode,
over budget answers 429, a Redis read error 503 `budget_unavailable` (the
default partition stays fail-open), and a dollar budget on a model without a
price 403 `model_unpriced`. A dollar budget prices the model that will be
served: for a request with no model, `auto` or `pool:<alias>` that is the
selected route's default model, so such a request is served and charged, and
403 `model_unpriced` answers only when that model has no catalog or registry
price.

## Telemetry

A store request's usage event carries `trustgate.auth.id` (the key),
`trustgate.principal.subject` (the owner) and `trustgate.consumer.id` (the
selected consumer). A request refused after authentication (403, 400, 405, 429)
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
- Personal keys on MCP and on `/<slug>/v1`: they answer as unknown keys.
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
| e | `whoami` on the fixed host resolves a gateway only from an enabled, unexpired application key. A disabled, expired or personal key answers like an unknown key. | Any key the key finder returned resolved its gateway, including a disabled one still in its cache. |
| f | `POST /v1/gateways/{gateway_id}/consumers/{consumer_id}/auths/{auth_id}` parses a non-empty body as link attributes: malformed JSON answers 422, and link attributes on an application consumer answer 422. No body behaves as before. | The body was ignored. |
| g | Deleting a registry that holds a personal consumer's last primary default model answers 422 `validation_failed`, like detaching it. | Personal consumers are new; an earlier build of this change answered 409 `has_dependents`. |
| h | The MCP connect ticket re-check refuses an expired or personal key. | Only enabled, type and gateway were checked. |
| i | `token_rate_limiter` gains `partition: key`, the `calendar_month` and `calendar_day` windows and the hard limits (503 `budget_unavailable`, 403 `model_unpriced`). All are opt-in: a policy without `partition` counts, fails open and prices exactly as before. | — |
| j | `GET /v1/gateways/{gateway_id}/auths` reads `owned`: `true` lists personal keys only, `owned` together with `owner_id` answers 422 `invalid_filter`, and a value that is not a boolean answers 422 `invalid_filter`. Admin auth responses carry `budget` on a personal key that has one. `PUT …/auths/{auth_id}/budget` is new, and `auths` gains a nullable `budget` column. `token_rate_limiter` gains `key_budgets` (needs `partition: key`): such a policy holds each key to its budget and may have no `aggregate`, `rules`, `window` or `cost_cap`; every other policy still needs one, and no other policy reads key budgets. | `owned` was ignored, and a policy had no way to read a key's budget. |

Roll back (a) by reverting it; the rest needs no action.

