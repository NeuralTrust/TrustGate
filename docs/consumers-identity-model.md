# Consumers & identity — target model

Status: design (pre-implementation) · Owner: victor.garcia@neuraltrust.ai · Date: 2026-09-07

Companion to `plan-b-mcp-store-and-identity.md`, which built the Store. This memo
answers the question that memo left open: now that people are served by the
Portal + Store + Access, **what is a consumer for, and what does identity mean
inside it?** It starts from first principles and only then maps the result onto
what exists today.

## 1. Two kinds of callers

Everything the gateway serves is called by one of two things:

| Caller | Example | Identity | Governance |
|---|---|---|---|
| **A person through an AI tool** | Cursor, Claude Desktop, VS Code, ChatGPT connectors | The person (SSO through the platform IdP) | Portal + Store + Access: what each user or group may see, request, install, connect |
| **An application built by a team** | An internal assistant, a backend agent, a batch job, a customer-facing chatbot | The application (API key / OAuth client), and *sometimes* the end user it acts for | Consumers: what upstreams and models/tools the app may reach, how traffic flows, which policies apply |

People are already solved end to end. **Consumers are for applications.** A
consumer *is* an application: its credentials, its upstreams, its policies.
Everything below follows from that.

## 2. What exists today (verified in code)

- **Two routing modes on every consumer** — `inline` (registries bound to the
  consumer) and `role_based` (no registries; at request time the caller's OIDC
  claims are matched against gateway **Roles**, each with `oidc_mapping` rules,
  `registry_ids`, `model_policies` (LLM) and `mcp_policies` (MCP toolkit); the
  effective view is the union of the matched roles ∩ the consumer's `role_ids`).
  `pkg/domain/role`, `pkg/app/role/oidc_resolver.go`, `pkg/app/mcp/role_scope.go`,
  `pkg/app/routing/resolver.go` (`resolveRoleBased`), admin routes
  `/v1/gateways/{id}/roles*`, `consumers/{id}/roles/{role_id}`.
- **Roles UI** in the app under Identity → Roles (`features/identity`: RolesDataTable,
  RoleCreateSidePanel, RoleDetailSidePanel, pickers), and an "Identity-based"
  toggle on consumer create plus a roles multiselect on the Routing tab whose banner
  reads *"Identity-based routing is managed in Roles (coming soon)"*. Half built.
- **The Store**: a synthetic MCP consumer (`consumerdomain.BuildStoreConsumer`,
  sentinel id) with no registries of its own. `pkg/app/store/scoper.go` builds the
  per-principal surface at request time: the principal's active **installs** ∩ the
  gateway's **Access** grants (users / groups keyed by IdP group id or name) under
  the principal's live **access level** (open / curated / none), resolved from
  per-user and per-group policies with the gateway default as fallback. Per-user
  upstream credentials (forwarded auth, connect page, vault), approvals with
  email, Portal, and `tools/list_changed` on revocation all hang off this.
- **Access page** (app): users, groups, applications, approvals; the single place
  an admin decides who may use which MCP server. Groups come from the unified
  directory (SCIM, Google Workspace pull, login claims).

So for MCP we have **two identity models in parallel** — Roles (claim rules →
registries) and Access (users/groups → servers) — with two stores and two UIs. The
only thing Roles can do that Access cannot is restrict *tools* per group. Access
does everything else and is what the product now leads with.

## 3. Target model

### 3.1 LLM consumer — the application is the identity

What an LLM application needs to configure:

- **Upstreams**: registries (providers), allowed models per registry, default model.
- **Traffic**: single target, fallback chain, load balancing (weighted / round
  robin), smart routing tiers. Unchanged.
- **Policies & limits**: guardrails, rate limits, budgets. Unchanged.
- **Authentication**: API key (the norm) or OAuth client credentials
  (service-to-service).

The person behind the application does **not** change routing. "Marketing may only
use the mini model, engineering may use GPT-4" is two applications: two consumers,
two keys. What the person is useful for is **attribution**: an optional end-user
identifier the app forwards (`X-NeuralTrust-End-User: <opaque id>`) that lands in
audit, traces and telemetry and can drive per-user rate limits. It never selects a
registry.

**Decision:** LLM consumers are always inline. No identity-based routing, no Roles.

### 3.2 MCP consumer — an application with tools, acting one of two ways

**(a) Acts as the application.** A backend agent, an automation, a scheduled job.
It reaches upstream servers with shared credentials (a static API key on the
registry, or client credentials). The admin configures which servers and which
tools (the consumer toolkit). Consumer auth: API key. No person involved. This is
the simple case and must stay simple.

**(b) Acts on behalf of end users.** An internal assistant where each person talks
to *their* Notion, *their* Linear. Identity is central here, but not to pick a
different set of registries. It is needed for exactly two things:

1. **Per-user connections.** Each person links their own account and the gateway
   forwards *their* credentials (forwarded auth). This exists: consent-required
   error → connect page → vault.
2. **Who may use what inside the app.** Which users or groups may reach each of
   the app's servers. That is precisely what Access governs for the Store — the
   same scoper applied to the *consumer's* registries instead of the whole catalog.

So an MCP consumer is: **servers + tools, authentication, and one identity switch**
— *"Acts on behalf of end users"* — which requires OAuth and turns on per-user
connections and Access rules. No Roles, no claim rules, no per-role registries.
Groups arrive from the directory exactly as they do for the Store.

### 3.3 One engine, two entry points

The Store stops being a special case: it is a **built-in MCP consumer** that acts
on behalf of end users, authenticates with the NeuralTrust IdP, has the whole
catalog as its server set (materialised lazily), and is governed by Access.
Custom MCP consumers are the same engine with a narrower, admin-chosen server set,
their own slug, their own IdP and their own policies.

| | LLM | MCP as the app | MCP on behalf of users | Store (built-in) |
|---|---|---|---|---|
| Consumer auth | API key / client credentials | API key | OAuth (NeuralTrust IdP or customer IdP) | OAuth (NeuralTrust IdP) |
| Server set | registries + models | registries + toolkit | registries + toolkit | catalog (lazy materialisation) + user installs |
| Traffic | fallback, LB, smart routing | n/a | n/a | n/a |
| Person | attribution header (optional) | none | per-user connections + Access rules | per-user connections + Access rules + self-service install / approvals |
| Who decides the set | admin | admin | admin (servers) + Access (who) | catalog + user (installs) + Access (who) |

## 4. Behaviour specification

### 4.1 Consumer fields

```
Consumer
  type: LLM | MCP
  auth: api_key | oauth
  registry_ids, model_policies, lb_config, fallback   (LLM)
  registry_ids, mcp.toolkit, mcp.fail_mode           (MCP)
  identity:
    acts_for_users: bool          # MCP only; requires auth = oauth
    end_user_header: bool         # LLM only; accept X-NeuralTrust-End-User for attribution
```

Removed: `routing_mode`, `role_ids`. Every consumer is what `inline` is today.

### 4.2 Request-time algorithm for `acts_for_users` MCP consumers

Given the authenticated principal `p` (sub, groups from token claims) and the
consumer `c` with registries `R`:

1. **Level.** `level = ModeResolver(p, gateway)` — the same live resolution the
   Store uses: p's own policy → any of p's groups' policies (most permissive wins)
   → gateway default. Values: `open`, `curated`, `none`.
2. **Surface.**
   - `none` → empty surface (tools/prompts/resources lists are empty, calls fail
     with the Access-denied error).
   - `open` → `R`.
   - `curated` → `{ r ∈ R : grant(r.code) ∪ grant(r.id) names p or one of p's groups }`.
3. **Credentials.** For each exposed registry with forwarded auth, the vault is
   consulted for p; a missing or undecryptable credential yields the existing
   consent-required error with the connect URL. Unconnected registries are skipped
   from list results exactly as today (partial consent).
4. **Change detection.** The stream watcher's surface fingerprint (already in
   `SurfaceWatcher`) covers this scoper too, so a revocation pushes
   `tools/list_changed` to the user's clients.

The Store is the same algorithm with `R = materialised registries of p's active
installs` and one extra rule: a server not yet installed is not in `R` (the Store
meta-tools cover discovery, request and install).

Consumers with `acts_for_users = false` skip steps 1–2 entirely (today's inline
behaviour) and never consult the vault per user.

### 4.3 LLM attribution

When `end_user_header` is on, the proxy reads `X-NeuralTrust-End-User`, validates
it as an opaque string (≤ 256 chars), stamps it into the request trace and
telemetry as `end_user`, and exposes it to the rate limiter as an optional key.
Nothing else reads it. Off by default.

## 5. Gateway changes

**Domain (`pkg/domain/consumer`)**
- Add `Identity{ActsForUsers bool, EndUserHeader bool}`; validate `ActsForUsers`
  only on `TypeMCP` and only with an OAuth auth attached (validated at the
  association layer, where auths are known).
- Remove `RoutingMode`, `RoleIDs`, `validateRoleBased`. `BuildStoreConsumer` sets
  `ActsForUsers = true`.
- Delete `pkg/domain/role` (Role, OIDCMapping, model policies per role).

**Application layer**
- Generalise `pkg/app/store/scoper.go` into an **AccessScoper** with a source
  strategy: `storeSource` (installs → materialised registries) and
  `consumerSource` (the consumer's own registries). `Scope` runs when
  `IsStoreConsumer(c) || c.Identity.ActsForUsers`.
- `pkg/app/mcp/rpc_dispatcher.go`: the store scoper already wraps every method;
  no change beyond the generalised predicate. `emptySurfaceInsteadOfError`
  applies to any `ActsForUsers` consumer, not only the Store.
- `pkg/app/mcp/credentials.go`: forwarded-auth resolution is already per
  principal; drop any Store-only guard so custom `ActsForUsers` consumers get the
  connect flow.
- `pkg/app/mcp/surface_watcher.go`: `WithSurfaceScoper` unchanged; it now fires
  for custom consumers too.
- Delete `pkg/app/mcp/role_scope.go`, `pkg/app/role/*`, `resolveRoleBased` in
  `pkg/app/routing/resolver.go`, `scopeByRoles` in the MCP handler.
- Proxy: read `X-NeuralTrust-End-User` when enabled (attribution only).

**Admin API**
- Consumer create/update bodies: drop `routing_mode`, `role_ids`; add
  `identity: {acts_for_users, end_user_header}`. Responses likewise.
- Remove `/v1/gateways/{id}/roles*` and `/consumers/{id}/roles/{role_id}`.
- Access endpoints unchanged; Access grants already key on catalog code and
  registry id, both of which custom consumers' registries carry.

**Persistence & sync**
- Migration: add `identity` JSON to `consumers`; drop `routing_mode`, `role_ids`;
  drop `roles` and `consumer_roles` tables after the data-plane snapshot no longer
  references them.
- Config snapshot compiler: stop emitting roles; emit `identity`.

## 6. App changes

**Consumers**
- Create panel and Routing tab: remove the Routing mode switch and the roles
  multiselect. For MCP, add an **Identity** section with the single switch *Acts on
  behalf of end users* (disabled with a hint when auth is API key) and a line
  linking to Access: *"Who may use each server is managed in Access."* For LLM,
  add *Accept end-user attribution header* with the header name shown.
- Connection details: an `acts_for_users` consumer shows the self-service connect
  page link (it already does for API-key MCP consumers) and notes that users sign in
  with their own account.
- Registry picker: unchanged (real registries + unmaterialised built-ins).

**Identity**
- Remove the Roles tab and everything under `features/identity` that is role
  specific (RolesDataTable, RoleCreateSidePanel, RoleDetailSidePanel,
  RoleFormFields, RoleResourcesSection, Role*PickerModal, listRoles/persistRole/
  deleteRole actions, useIdentityRoles). Auths stay; the tab is renamed to just
  *Identity providers* if it ends up alone.

**Access**
- Applications tab lists every `acts_for_users` consumer (plus the Store) so the
  admin sees which apps Access rules affect. Grants, policies, approvals: no change.

## 7. Migration and rollout

1. **Inventory.** Count `role_based` consumers per gateway in prod
   (`GET /v1/gateways/{id}/consumers`, filter `routing_mode`). If zero, skip step 3.
2. **Ship the switch.** Gateway: `Identity.ActsForUsers` + generalised scoper,
   additive, roles untouched. App: hide the Routing mode toggle (everything
   inline), add the Identity section. Existing `role_based` consumers keep working.
3. **Convert.** For each `role_based` MCP consumer: registries = union of its roles'
   registries; `acts_for_users = true`; each role's `oidc_mapping`
   `groups contains_any [...]` becomes group grants in Access on those servers.
   Toolkit = union of the roles' toolkits. LLM `role_based` consumers become one
   inline consumer per role (separate keys), which is what they modelled anyway.
4. **Remove.** Roles domain, routes, UI, tables. One release after step 3.

## 8. Inventory of what goes away

Gateway: `pkg/domain/role/**`, `pkg/app/role/**`, `pkg/app/mcp/role_scope*.go`,
`pkg/api/handler/http/role/**`, role routes in `admin_router.go`, `resolveRoleBased`
and helpers in `pkg/app/routing`, `Consumer.RoutingMode/RoleIDs`, `scopeByRoles`,
roles in the config snapshot, roles tables.

App: `features/identity` role components/actions/hooks, `routingMode`/`roleIds` in
`features/consumers` (types, mappers, contract, panels, tests), the
"Identity-based" copy in `v2Consumers.json`, roles auxiliary data in
`useConsumersAuxiliaryData`.

## 9. Open questions

- **Per-group tool restrictions.** Roles could restrict tools per group; Access
  cannot. Proposed: leave it out; if a customer asks, add an optional `tools`
  allow-list on an Access grant (server-level grant → tool subset), which is a
  small additive change to the scoper.
- **Customer IdP on custom consumers.** An `acts_for_users` consumer authenticating
  against the customer's own OIDC provider gets groups from that token's claims,
  not from the platform directory. Access keys groups by IdP id or name, so it
  works when the claim carries the same ids the directory synced; document this
  and surface a warning in the consumer panel when the auth is not the
  NeuralTrust IdP.
- **Attribution header name.** `X-NeuralTrust-End-User` proposed; confirm against
  the existing header conventions in the proxy before shipping.
