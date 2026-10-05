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
finds a user's key. These calls answer 422:

- `personal` on an MCP consumer, a personal consumer without a primary default,
  a personal consumer on a hybrid gateway, or a change of `audience`;
- `auths` in the update body of a personal consumer (create ignores `auths`);
- an owned key attached to an application consumer, an application key attached
  to a personal consumer, link attributes on an application consumer, or a link
  without `level` or `granted_at`;
- `PUT` or `POST …/rotate` on an owned key (`owned_key`).

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
`models`, `embeddings`, `files`, …).

1. **404 before any key lookup** when the gateway is served by a hybrid data
   plane or has no active personal consumer. The answer is the one an unknown
   consumer slug gets.
2. **401** for no key, an unknown, disabled, expired or revoked key, an
   application key, or another gateway's key.
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
| none | a primary registry has a default model (not needed on a route that takes no model, such as `GET /files/{id}`) |
| `auto` | routing resolves with a primary candidate |
| `pool:<alias>` | its pool has that alias and a member survives substitution. No consumer defines it → 400; one defines it but nothing survives → 403 |
| `@provider/model` | a primary registry of that provider allows the model |
| short model | a primary candidate survives the catalog check |

The selected consumer then serves the request with its registries minus the
substituted ones, its model policies, its load balancer (`gateway:consumer`,
shared by every user it serves), its fallback, and its own policies plus the
gateway's global ones. MCP-wide policies never apply.

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
refused, because a fallback never admits.

## Errors

| Status | When |
|---|---|
| 404 `not_found` | hybrid gateway, or no active personal consumer |
| 401 `unauthenticated` | the key is missing or not a valid personal key of this gateway |
| 403 `model_not_allowed` | no consumer admits the request, including a key with no links |
| 400 `invalid_model` | malformed model reference, or a pool alias no consumer defines |
| 429 / 503 / 403 `model_unpriced` | `partition: key` budgets, below |

## Budgets

A `token_rate_limiter` policy with `"partition": "key"` counts per owner: the
counter is `owner:<owner_id>`, so a rotation or a revoke and re-create keeps the
spend, and one owner shares one counter across every consumer that serves her.
A key without an owner counts as `auth:<auth_id>`; a request without a key (the
playground) is not counted. Make it a global policy to cap a user across all of
her consumers.

```json
{"slug": "token_rate_limiter", "settings": {"partition": "key", "aggregate": {"max": 500000, "time_window": "calendar_month"}}}
```

`calendar_month` and `calendar_day` (UTC) are valid only with `partition: key`;
`custom_pricing` and `group_by_header` are refused with it. In a blocking mode,
over budget answers 429, a Redis read error 503 `budget_unavailable` (the
default partition stays fail-open), and a dollar budget on a model without a
price 403 `model_unpriced`.

## Telemetry

A store request's usage event carries `trustgate.auth.id` (the key),
`trustgate.principal.subject` (the owner) and `trustgate.consumer.id` (the
selected consumer). A denied request carries the key and the owner and no
consumer, and so does `/store/v1/models`. Each snapshot publish records
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

To roll back: disable the `partition: key` policies, then
`UPDATE consumers SET active = false WHERE audience = 'personal';` before an
older binary serves, and optionally delete the owned keys and their links. The
columns can stay.

## Out of scope

- Hybrid gateways: `/store/v1` answers 404 and personal consumers are refused.
- Personal keys on MCP and on `/<slug>/v1`: they answer as unknown keys.
- Traffic labeling of `/store/v1` requests, and the playground on personal
  consumers.
- The grants, the reconcile and the UI, which live in the app.
- Admin consumer responses keep listing every linked key in `auth_ids`; the link
  attributes are not exposed.
