# Applications — one thing a team builds, across both planes

Status: design, nothing implemented · Owner: victor.garcia@neuraltrust.ai · Date: 2026-09-21

Companion to `consumers-identity-model.md`, which established that *a consumer is
an application*. That held while an application did one thing. It stops holding
the moment an application calls tools **and** models, because a consumer has one
type and an agent does not. This memo says what to put in its place.

## 1. What went wrong, concretely

The SDK resolves a key into what it reaches and hands back both planes:

```python
tg = TrustGate()          # one URL, one key
agent = tg.connect()      # the MCP consumer
llm  = tg.llm()           # the LLM consumer, on another host
```

That is the shape `GET /whoami` already returns, and the shape the SDK spec was
written to. **The console cannot produce it.** Keys are created inside a consumer
and never leave it, so an admin who builds "sdk" (MCP) and "sdk-llm" (LLM) walks
away with two keys, and `TrustGate` takes one. Every SDK example that sends its
model calls through the gateway falls back to a provider key of the caller's own,
which is the case the gateway exists to remove.

This is not a missing screen. It is the seam between what a team builds (one
agent) and what the system stores (two consumers) showing through.

## 2. What exists today (verified in code)

**A key already reaches many consumers.** An `Auth` belongs to a gateway;
consumers carry `AuthIDs`. `apiKeyConsumers.ForAPIKey` walks every consumer of
the gateway and keeps the ones holding that auth (`pkg/app/consumer/api_key_consumers.go:104-117`).
The admin API is complete:

```
POST   /v1/gateways/:gateway_id/auths        create a key, no consumer involved
GET    /v1/gateways/:gateway_id/auths        list them
POST   /v1/consumers/:id/auths/:auth_id      attach an existing key
DELETE /v1/consumers/:id/auths/:auth_id      detach
```

`AuthResponse` carries `key_prefix` / `key_suffix`, so a key can be listed and
recognised without the secret. **There is no reverse lookup**: nothing answers
"which consumers hold this auth" without scanning consumers.

**Slugs are globally unique**, not per gateway and not per type:
`CREATE UNIQUE INDEX consumers_slug_unique_idx ON consumers (slug)`
(`pkg/infra/database/migrations/20260611120000_consumer_slug_replaces_path.go:35`).
Two consumers of one application cannot share one.

**Routing is two different objects.** A `Registry` is either an `MCPTarget` or an
`LLMTarget` (`pkg/domain/registry/registry.go:31-32`) and they share no fields
worth a column:

| MCP row | LLM row |
|---|---|
| server, catalog code, auth mode (forwarded/shared), connection state, tool scope, per-instance config | provider, credentials, provider options, health checks, pricing |

**Identity is already split by plane, by validation.** `acts_for_users` is MCP
only and `end_user_header` is LLM only (`pkg/domain/consumer/identity.go:94-108`)
— two fields for one question a team answers once.

**Policies are consumer-scoped** among other levels (`policy.Level.WithConsumer`),
and an MCP scope names registries while an LLM scope names models.

**Connect is MCP only.** Per-user upstream credentials come from forwarded auth on
MCP registries; LLM credentials live on the registry itself and are not per
person.

**There is no application concept anywhere** — no `applications` table, no
`application_id`, nothing in the app's own store either.

## 3. The model

> An **Application** is what a team builds. It holds **at least one** consumer and
> **at most one per plane**: an MCP consumer, an LLM consumer, or both. It holds
> one keyring, and every key on it reaches every consumer it has.

Everything else follows from asking, of each thing the console shows today,
whether a team answers it once or once per plane.

## 4. What belongs to the Application, and what to the plane

| | Level | Why |
|---|---|---|
| Name | Application | The thing a team says out loud |
| Keys | Application | The reason for this memo: one secret, both planes |
| Identity — who it acts for | **Application** | One answer, written as `acts_for_users` on the MCP consumer and `end_user_header` on the LLM one. Asking twice in two vocabularies is the bug, not the feature |
| Active / paused | Application, cascading | Pausing half an agent is not a state anyone wants |
| Routing | **Plane** | Two different objects; see §2 |
| Policies | **Plane**, for now | An MCP scope names registries, an LLM scope names models. An Application-level policy may be real, but nothing demands it yet — do not invent the level before a case for it |
| Connect / upstream accounts | **Plane** (MCP only) | It has no meaning on the LLM side |
| Auth binding (client ids, cert subjects) | **Plane** | It constrains a credential against an endpoint, and the endpoints differ |
| Slug and URL | **Plane** | Decided: each consumer keeps its own (§6) |

## 5. The screens

**General** — name, identity ("who does this application act for?", asked once),
active state, and a line per plane saying which exist.

**Routing** — one tab, two sections, each present only when that plane is. Each
section carries its own endpoint in the header, because that is what differs per
plane and what people copy:

```
Routing

  Tools                          gw-….mcp.dev.neuraltrust.ai/1AxuXSNi/mcp   ⧉
  ┌──────────────────────────────────────────────────────────────────┐
  │ ⬤ Notion      Connected    45 tools                         ⋯    │
  │ ⬤ Linear      Connected    80 tools                         ⋯    │
  └──────────────────────────────────────────────────────────────────┘
  + Add server

  Models                         gw-….llm.dev.neuraltrust.ai/sdk-llm/v1     ⧉
  ┌──────────────────────────────────────────────────────────────────┐
  │ ⬤ OpenAI      Healthy      gpt-5.2, gpt-5-mini              ⋯    │
  │ ⬤ Anthropic   Healthy      claude-opus-5                    ⋯    │
  └──────────────────────────────────────────────────────────────────┘
  + Add provider
```

Two properties this has that a merged table does not:

- **A single-plane Application shows one section**, which is today's screen. No
  migration is visible to anyone who never wanted the second plane.
- **The empty state is how a plane is added.** With no LLM consumer, Models is one
  line — *"This application calls no models through the gateway."* — and a button.
  Pressing it creates the consumer and attaches the Application's keys. This is
  where the model earns its keep: nobody learns the word "consumer".

**Policies** — same two sections, same rule.

**Connect** — unchanged, MCP only, hidden when there is no MCP consumer.

**Auth** — the Application's keyring. Creating a key attaches it to every consumer
the Application has; adding a plane later attaches the existing keys to it.
Revoking says what it kills, which needs §7.

## 6. The slug (decided)

Each consumer keeps its own slug. The alternative — an Application slug that both
consumers derive from, giving sibling URLs `…/sdk/mcp` and `…/sdk/v1` — reads
better but needs the unique index to become `(slug, type)` plus a migration, and
the URLs live on different hosts anyway.

The consequence is a UI obligation: **never make someone read two unrelated slugs
and infer they are one application.** The endpoint belongs in the section header
of the plane it serves, next to a copy button, and nowhere else. The Application
is identified by its name.

## 7. Where the Application lives — the decision this memo needs

Three places it could exist, and they are not equivalent.

**(a) A thin entity in the gateway.** An `applications` table (id, gateway_id,
name) and a nullable `application_id` on consumers. Nothing else moves: routing,
policies, identity and connect stay exactly where they are. The gateway can then
name the application in `/whoami`, in traces and in audit, and the SDK can say
"this key reaches your application on both planes" rather than "two consumers".
Cost: one migration, one CRUD, and the config snapshot carries one more field.

**(b) A grouping in the console's own database.** Zero gateway change. But the
gateway never learns it, so `/whoami` keeps returning two consumers with nothing
relating them, telemetry cannot group by application, and the grouping is lost to
anyone using the admin API directly.

**(c) Derived from the keyring** — an Application is the set of consumers sharing
a key. No storage anywhere. It makes an identity out of a credential: detach a key
and the application splits in two; attach one key to two real applications and
they merge. Rejected.

**Recommendation: (a), kept thin.** The Application is a grouping and a name, not
a new configuration surface — the moment it starts owning routing or policies it
has become a second consumer and we are back here. Migration is trivial: every
existing consumer gets an Application named after it, and single-plane
Applications are what everyone has on day one.

## 8. What the backend needs

Small, and two of the three are worth doing whichever way §7 goes.

1. **Reverse lookup, auth → consumers.** Either a field on `AuthResponse` or
   `GET /v1/gateways/:id/auths/:auth_id/consumers`. Without it the console cannot
   warn that revoking a key kills two planes, which is true today and unwarned.
2. **`application_id` on the consumer** plus the `applications` CRUD, if (a).
3. **`application` in `/whoami`** (name and id per consumer), so the SDK and the
   examples can name the thing the user named. Not required for the console;
   required for the story to be true end to end.

Nothing in the data plane changes. Routing, policy resolution, the connect flow
and the MCP handler all keep working on consumers, because that is still what a
request resolves to.

## 9. Still open

- **Policies at Application level.** Left per plane on purpose (§4). Revisit when
  a rule appears that genuinely spans both — a spend cap might be the first.
- **Identity written twice.** The console asks once and writes two fields. Worth
  asking later whether `acts_for_users` and `end_user_header` should converge in
  the domain rather than in the UI.
- **A2A.** The model says "at most one per plane" and A2A is a plane. Nothing here
  assumes two, but the screens above name only Tools and Models.
- **Store consumer.** It is synthetic (`BuildStoreConsumer`) and belongs to no
  application. It must stay out of these lists.

## 10. Slicing, once §7 is decided

1. Backend: applications CRUD + `application_id`, and the auth reverse lookup.
2. Console: Applications list and detail replacing the consumers list; General
   with identity asked once; Routing and Policies as two sections; the keyring in
   Auth.
3. Adding a plane from the Routing empty state, keys attached automatically.
4. `/whoami` carries the application; SDK and examples stop explaining the split.
