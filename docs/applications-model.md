# Applications — one thing a team builds, across both planes

Status: design agreed · §8, §9.1 and §7.1 implemented; the screens are not · Owner: victor.garcia@neuraltrust.ai · Date: 2026-09-21

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

> An **Application** is what a team builds. It holds **at most one consumer per
> plane** — an MCP consumer, an LLM consumer, both, or neither yet. It holds one
> keyring, and every key on it reaches every consumer it has.

Everything else follows from asking, of each thing the console shows today,
whether a team answers it once or once per plane.

## 4. What belongs to the Application, and what to the plane

| | Level | Why |
|---|---|---|
| Name | Application | The thing a team says out loud |
| Keys | Application | The reason for this memo: one secret, both planes |
| Who the tools are used as | **Plane** (MCP) | Corrected — see §5.3. It decides where upstream accounts live, which is a property of the tool plane and has no meaning without one |
| Forwarding an end-user id for attribution | **Plane** (LLM) | `end_user_header`. Named like the above and unrelated to it |
| Active / paused | Application, cascading | Pausing half an agent is not a state anyone wants |
| Routing | **Plane** | Two different objects; see §2 |
| Policies | **Plane**, for now | An MCP scope names registries, an LLM scope names models. An Application-level policy may be real, but nothing demands it yet — do not invent the level before a case for it |
| Connect / upstream accounts | **Plane** (MCP only) | It has no meaning on the LLM side |
| Auth binding (client ids, cert subjects) | **Plane** | It constrains a credential against an endpoint, and the endpoints differ |
| Slug and URL | **Plane** | Decided: each consumer keeps its own (§6) |

## 5. The screens

### 5.1 Creating one asks for a name

Nothing else. Not "MCP or LLM?" — a team knows what it is building, not which of
our planes it lands on, and it is a question we can stop asking because the
answer is visible the moment they route something.

**A plane is born when the first thing is added to it.** Add a server under Tools
and the MCP consumer comes into existence; add a provider under Models and the
LLM one does. The console does it in one call — `CreateConsumerRequest` takes
`registries`, and the slug is generated — then attaches the Application's keys.

The keyring does not wait for either. An `Auth` belongs to the gateway, not to a
consumer (`POST /v1/gateways/:id/auths`), so an Application can hold keys with no
consumer under it at all, and each plane inherits them as it is born. A key
issued on day one keeps working when the model plane appears in month three.

**Birth is inferred; death is deliberate.** Removing the last server does not
delete the MCP consumer: its slug is in somebody's configuration, its URL is in
somebody's client, and its keys are attached. An empty plane is a plane with
nothing routed, which is a state the gateway has always allowed. Removing a plane
is its own action, and it says what it breaks.

An Application with no consumers at all is a draft. It has a name and maybe keys,
serves nothing, and says so in the list.

### 5.2 The tabs

**General** — name, active state, and a line per plane saying which exist. No
identity question: it moved to where its consequence is (§5.3).

**Routing** — one tab, **both sections always**, because an absent plane is now an
empty section with an invitation rather than something hidden. Each section
carries its own endpoint in the header once it has one, since that is what
differs per plane and what people copy:

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

- **The empty state is how a plane is added.** With no LLM consumer, Models is one
  line — *"This application calls no models through the gateway."* — and a button.
  Pressing it is what creates the consumer (§5.1). This is where the model earns
  its keep: nobody learns the word "consumer", and nobody was asked to predict
  which planes they would need.
- **Every existing Application gains an empty second section.** That is a change
  to a screen that works today, made on purpose: it is the only place someone
  finds out that their tool application could route its models here too.

Adding is **one button and one modal with two tabs** — *MCP servers* and *LLM
providers* — rather than a button per section. The tabs are how the catalog is
organised, not a question being asked: you go looking for what you want to add,
and the plane follows from what you pick. It is the same principle as §5.1, one
level down, and it is what makes "we never ask MCP or LLM" true in the only place
it could have leaked.

### 5.3 "Acts as", which is a property of the tools

§4 first put identity at the Application level, on the grounds that a team
answers it once. That was wrong, and worth saying plainly: the two fields it
would have written are not one question.

- `acts_for_users` (MCP) decides **where upstream accounts live** — once for the
  application, or one set per end user. It changes the connect flow, the
  principal a call runs as, and the shape the SDK hands back. It is consequential.
- `end_user_header` (LLM) lets an application **forward an opaque id for
  attribution** in traces, audit and rate limiting. It is a checkbox.

They share a vocabulary and nothing else. So there is no Application-level
identity, and the console never has to hold an answer before a consumer exists —
which keeps §7's promise that the row is a grouping and a name.

**It lives in the Tools section of Routing**, above the servers, because that is
what it is about: the same list of servers, connected once or connected per
person. One control, three states, mapping onto the two fields the gateway has:

```
  Accounts for these servers
  ( ) The application's own           acts_for_users = false
  ( ) Each end user, named by the     acts_for_users = true, source = app
      application in a header
  ( ) Each end user, signed in        acts_for_users = true, source = platform
      through the platform
```

It defaults to the first, which is the common case and the one that holds no
per-person credentials. An Application with no MCP plane never sees it.

Changing it later is not a toggle, and the UI has to say so: moving from the
application's own accounts to per-user ones strands whatever the application had
connected, and moving back leaves every user's credentials unreachable. The
gateway keys them by different principals (`app:<consumer_id>` versus
`EndUserSubject(consumer, user)`), so nothing is lost — it is simply no longer
what the application reads.

On the Models side the LLM checkbox sits with the providers and says what it
does: *forward an end-user id for attribution*. Nothing about accounts.

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

## 7. Where the Application lives (decided)

**In the console's own database, not in the gateway.** An `Application` row owns a
name and the ids of the one or two consumers it groups; the gateway keeps
knowing only about consumers, and nothing in the data plane learns a new word.

The alternative was a thin `applications` table in the gateway with an
`application_id` on the consumer. It buys one thing — the gateway could name the
application in `/whoami`, in traces and in audit — at the price of a schema
change, a CRUD, a field in the config snapshot and a migration for every existing
consumer. That is a lot of moving parts for a grouping that only the console
draws. Rejected on cost, not on principle; §7.3 says what it would have bought.

A third option, deriving the Application from the keyring, was rejected outright:
it makes an identity out of a credential, so detaching a key splits an
application in two and attaching one key to two real applications merges them.

### 7.1 An Application of one, derived

The console does not need a row for every application. A consumer that belongs to
no `Application` row **is** an Application — of one, named after itself. Grouping
is what creates a row.

This is what makes the decision cheap:

- **No migration.** The table starts empty. Every consumer that exists today
  keeps working and reads as a single-plane Application on day one.
- **No orphans by construction.** A consumer created through the admin API, by a
  script or by another tool, appears in the console immediately as an Application
  of one rather than disappearing from a list that only knows about rows.
- **Grouping is reversible.** Deleting the row ungroups; it does not delete
  anything the gateway holds.

### 7.2 The invariants, and who holds them

The gateway cannot enforce "at most one consumer per plane" because it does not
know the grouping exists. The console must, and it can: **the console is the only
writer of groupings**, so nothing behind its back can produce a second MCP
consumer inside one Application. The rules it owns:

- At most one consumer per plane in an Application. Zero is allowed: a draft
  (§5.1).
- Every consumer of an Application belongs to the same gateway and the same team.
- A consumer belongs to at most one Application.

Two states it has to tolerate rather than prevent, because the gateway is free to
change underneath:

- **A consumer named by a row is gone.** Deleted through the admin API. The
  Application shows the plane as missing and offers to forget it; it must not
  fail the page.
- **A consumer belongs to no row.** The normal case (§7.1), not an error state.

Deleting an Application in the console deletes its consumers in the gateway —
otherwise the "remove this application" a person expects leaves the endpoints
serving. That is the one place the console's delete is not just a row.

### 7.3 What this costs, stated plainly

- **`/whoami` cannot name the application.** It answers with the gateway and the
  consumers a key reaches, which is all the SDK needs to resolve both planes —
  the one-secret story works untouched. What it cannot say is *which application
  those two consumers are*. The SDK talks about consumers, and that stays true.
- **Telemetry cannot group by application at the gateway.** Traces carry the
  consumer, so a per-application view is a join the console does from its own
  rows. Fine for a dashboard, unavailable to anyone querying the gateway
  directly.
- **The admin API does not show the grouping.** A team automating against the
  gateway sees consumers, as it does today.

None of these blocks the work. If one of them starts to hurt — most likely the
telemetry one — the gateway-side entity from §7 is still there to be added, and
`application_id` can be backfilled from the console's rows.

## 8. What the backend needs

Almost nothing, which is the point of §7.

1. **Reverse lookup, auth → consumers.** Either a field on `AuthResponse` or
   `GET /v1/gateways/:id/auths/:auth_id/consumers`. Without it the console cannot
   warn that revoking a key kills two planes, which is true today and unwarned.
   Worth doing on its own merits.
2. **`include_synthetic` on the consumer list** (§9.1.1), so the analytics filter
   can offer the Store without a second copy of its id.

That is the whole change *in this repository*. Analytics needs one more,
elsewhere: the metrics service's dashboard endpoints take a single `consumerId`
and have to take a list (§9.1). Everything else is the console: an
`Application` model (id, teamId, gatewayId, name, consumer ids), its CRUD, and
the screens in §5. Routing, policy resolution, the connect flow and the MCP
handler keep working on consumers, because that is still what a request resolves
to.

## 9. Analytics

Nothing breaks, and that is worth saying first: every product event already
carries `trustgate.consumer.id` and `trustgate.consumer.name` alongside the
gateway and tenant (`docs/telemetry/otlp-metadata-contract.md`). Every chart that
exists keeps working, because a request still resolves to a consumer.

### 9.0 The console already says "application" here

Analytics has an **All applications** filter and tabs for Overview, Policy, Cost,
LLM and MCP. Both are ahead of the model:

- The label is `toolbar.allConsumers` rendered as *"All applications"*
  (`messages/en/v2Analytics.json`). The word is already in front of people; the
  thing behind it is a consumer.
- The tabs already separate what §9.3 says must stay separate — Cost and LLM on
  one side, MCP on the other, with Overview holding only what legitimately sums.

So this is not a new page. It is the same page with the filter finally meaning
what its label says.

### 9.1 An Application is at most two consumers

So "group by application" is not a join, it is a filter expansion:
`consumer_id IN (<mcp>, <llm>)`. The console builds its own queries and holds the
mapping, so its pages need no new data anywhere.

In code that means one thing threaded through one path. `AnalyticsContext`
carries `consumerId: string | null`; every tab hook passes it to its action; each
action puts it on the query string; `fetchTrustGateDashboard` sends it to the
metrics service. Making it `consumerIds` is mechanical — and it does not stop at
the console, because the last hop is another service's API
(`/v1/residency/trustgate/dashboard/*`, or `/v1/gateway-metrics/dashboard/*`).
That is a third repository, and §8 does not cover it.

One thing to know before promising this on wide date ranges: filtering by
consumer already takes the slow path. The console's own comment says why — *"the
data plane recomputes from the flat per-request view (the hourly MV has no
consumer dimension)"*. An application filter scans both of its consumers, so it
is that path twice over. If the rollup ever gains a consumer dimension it should
gain this one too, which is where §7.3's "if one of them starts to hurt" is most
likely to land first.

### 9.1.1 The unfiltered view, and the traffic that is not an application

The obvious worry is that the default view becomes a list of every application's
consumers. It does not. `useAnalyticsScreen` maps the sentinel to null
(`url.consumer === ALL_CONSUMERS_VALUE ? null : url.consumer`) and each action
omits the parameter entirely when it is null, so the unfiltered view is a
gateway-wide aggregate served by the hourly rollup. Nothing enumerates anything,
and the fast path stays fast. An id list only exists when someone picks one
application, and it is one or two values.

**Decided: the unfiltered total keeps counting everything, the Store included.**
It is the whole picture of what the gateway served and it is the cheap query;
carving the Store out would make the most-used view stop matching the rollup to
fix a label.

So the label is what gives. Unfiltered includes the **Store consumer** — the
synthetic one carrying people through the Portal, which belongs to no
application — so the default entry cannot go on saying *All applications*. It
becomes *All traffic*, and the dropdown groups what is under it:

```
  All traffic
  ── Applications ─────────
     sdk
     support-agent
  ── Portal ───────────────
     MCP Store
```

Which closes the real gap: today the Store is **in the total but not in the
list**, so a number includes traffic nobody can isolate. You can see that the
Portal is busy and never ask how busy.

The selector cannot offer it on its own. It is built from `listConsumersAction`,
which lists persisted consumers, and the Store consumer is never persisted —
`dataFinder` hangs it off `data.StoreConsumer`, deliberately outside
`data.Consumers`, which is also why `ForAPIKey` never resolves a key to it. Two
ways to give the console the entry:

1. **The console holds the id.** `StoreConsumerID()` is a well-known constant, so
   a fixed option appended to the list costs nothing. It also copies a UUID into a
   second repository, and a third if the metrics service ever needs it.
2. **The consumer list endpoint offers it.** An opt-in — `include_synthetic=true`
   — appending the Store consumer with a flag saying what it is. One more small
   change in this repository (§8), and the constant stays in one place.

Recommend the second, for the same reason §7 kept the application out of the
gateway: put each fact in the one place that owns it.

### 9.2 Outside the console, a dimension synced from the rows

Grafana and anything querying the event store directly do not have the console's
database. They need a small dimension table — `consumer_id → application_id,
application_name` — synced from it. Applied at read time, which has two
properties worth having: **history works** without a backfill, and **regrouping
is retroactive** — pair two consumers today and last month's events read as that
application too.

The alternative, stamping the application onto each event, would mean the gateway
knowing about applications, which is the thing §7 decided against. It also freezes
the grouping at write time, so a rename or a regroup leaves the past reading
wrong.

### 9.3 The two planes do not measure the same thing

This is the part that is design rather than plumbing. An MCP event is a tool call
— latency, policy outcome, no tokens and no cost. An LLM event is a model call —
tokens, cost, model label. Summing them into one number is wrong more often than
it is right:

| Measure | Sums across the application? |
|---|---|
| Requests, errors, latency | Yes |
| Tokens, cost, model mix | LLM only |
| Tool calls, policy blocks, consent prompts, upstream connections | MCP only |

So an Application analytics page is not one chart with a wider filter. It is two
halves with a shared header, mirroring §5's Routing: *this application served N
requests, E of them failed*, then a Tools half and a Models half. What the
application level genuinely adds over today is attribution — "this agent's model
spend" instead of "the consumer sdk-llm's model spend", which is the same number
under a name nobody chose.

## 10. Still open

- **Policies at Application level.** Left per plane on purpose (§4). Revisit when
  a rule appears that genuinely spans both — a spend cap might be the first.
- **Identity written twice.** The console asks once and writes two fields. Worth
  asking later whether `acts_for_users` and `end_user_header` should converge in
  the domain rather than in the UI.
- **A2A.** The model says "at most one per plane" and A2A is a plane. Nothing here
  assumes two, but the screens above name only Tools and Models.
- **Store consumer.** It is synthetic (`BuildStoreConsumer`) and belongs to no
  application. It must stay out of these lists — and note that §7.1 would
  otherwise show it as an Application of one.
- **Who syncs the analytics dimension** (§9.2), and how often. A rename should
  reach the dashboards without anyone rebuilding anything.

## 11. Slicing

Done, on `claude/applications-gateway-api` (this repo) and
`claude/applications-model` (the console):

- **Gateway (§8).** Auth responses carry the consumers holding each key;
  `include_synthetic` lists the consumers the gateway serves without storing.
- **Console model (§7.1).** The `Application` row, its migration, the grouping
  read with an application-of-one derived for every consumer nobody grouped, and
  the create / rename / group / delete actions.
- **Analytics (§9).** The filter narrows to applications and offers the Portal;
  the wire format is unchanged for one consumer, which is every application in
  production today, so no number moves.

Left: the screens (§5). They are the rest of this list, and they are one piece —
a grouped list whose detail panel is still per-consumer is not half a feature,
it is an incoherent one.



0. Analytics: `consumerId` → `consumerIds` through the console and the metrics
   service (§9.1), and the dimension for everything outside the console (§9.2).
   Both can start before the rest and neither changes what a chart shows until
   an Application groups two consumers.
1. Gateway: the auth → consumers reverse lookup (§8), which stands alone.
2. Console: the `Application` model and the derived Application-of-one read, with
   the consumers list becoming an Applications list. Nothing else changes yet.
3. Console: General with identity asked once; Routing and Policies as two
   sections; the keyring in Auth, attaching each key to every consumer.
4. Console: creating an Application from a name alone, and a plane coming into
   existence when the first server or provider is added to it (§5.1). This is the
   step the whole memo is for.
