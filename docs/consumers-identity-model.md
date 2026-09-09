# Consumers & identity — target model

Status: gateway and app implemented (see §10) · Owner: victor.garcia@neuraltrust.ai · Date: 2026-09-07

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
- **Authentication**: API key (the norm), or a bearer JWT issued by the customer's
  IdP. The gateway does not implement any OAuth grant for machines: how the app
  obtains its token (client credentials, certificate credentials…) is the IdP's
  business; the gateway only validates what it receives (§4.4).

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
2. **Who may use what inside the app.** ~~Which users or groups may reach each of
   the app's servers.~~ **Decided against** (see §15): the consumer's servers are
   what an admin bound to it, the same for everyone it admits. Access governs the
   Store, where the person picks from a catalog; a consumer is already the
   decision, and two places deciding one surface would let an admin bind a server
   its own users cannot see.

So an MCP consumer is: **servers + tools, authentication, and one identity switch**
— *"Acts on behalf of end users"* — which turns on per-user connections. No Roles, no claim rules, no
per-role registries. Groups arrive from the directory exactly as they do for the
Store.

The end user can be known in two ways, and the switch has a *source*:

- **`platform`** — the consumer authenticates with OAuth (NeuralTrust IdP, or the
  customer's IdP). The person logs in; `sub` and `groups` come from the token;
  Access rules apply. This is what the Store does.
- **`app`** — the consumer authenticates with an **API key** and the application
  tells the gateway who its end user is on every request
  (`X-NeuralTrust-End-User: <opaque id>`). This is the Composio model
  (`user_id`): the app owns the user directory, the gateway owns the per-user
  upstream connections. Access rules do not apply — the app is the boundary —
  unless the app-supplied id is a platform user id, in which case they do.
  See §4.5.

### 3.3 One engine, two entry points

The Store stops being a special case: it is a **built-in MCP consumer** that acts
on behalf of end users, authenticates with the NeuralTrust IdP, has the whole
catalog as its server set (materialised lazily), and is governed by Access.
Custom MCP consumers are the same engine with a narrower, admin-chosen server set,
their own slug, their own IdP and their own policies.

| | LLM | MCP as the app | MCP on behalf of users | Store (built-in) |
|---|---|---|---|---|
| Consumer auth | API key (default) · bearer JWT from the customer's IdP (incl. tokens the app obtained by client credentials) | API key (default) · bearer JWT from the customer's IdP | OAuth (NeuralTrust IdP default, customer IdP advanced) · API key + end-user id | OAuth (NeuralTrust IdP) |
| Server set | registries + models | registries + toolkit | registries + toolkit | catalog (lazy materialisation) + user installs |
| Traffic | fallback, LB, smart routing | n/a | n/a | n/a |
| Person | attribution header (optional) | none | per-user connections; Access rules when the identity is a platform user | per-user connections + Access rules + self-service install / approvals |
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
    acts_for_users: bool          # MCP only
    source: platform | app        # platform ⇒ auth must be OAuth; app ⇒ API key + X-NeuralTrust-End-User
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

### 4.4 Authentication: what a bearer JWT from an external IdP must satisfy

The gateway is a plain OAuth resource server. For any consumer whose auth is
"External IdP (JWT)" — LLM, MCP-as-the-app, or MCP-for-users with the customer's
IdP — a request is accepted when the token passes all of:

1. signature against the issuer's JWKS, with an allowed algorithm;
2. `iss` equals the configured issuer;
3. `exp` / `nbf`;
4. `aud` contains the configured audience;
5. `scope` includes `required_scopes`, when any are configured;
6. **`azp` (or `client_id`) is in `allowed_client_ids`**, when configured. *New.*
   Without it, the only isolation between two applications of the same tenant is
   the audience, and customers routinely register one audience for the whole
   gateway; a token minted for app A would then open app B's consumer.

No other claim is read for LLM or MCP-as-the-app: `groups`, `roles` and the like
never select a registry or a model — that is the consumer's job. `sub` and `azp`
are kept on the principal for audit, traces and (optionally) rate-limit keys.
Only the MCP-for-users flavour reads `sub` and the groups claim, and there for
Access, not routing.

**Configuration, field by field** (what the auth form should ask):

| Field | Recommendation |
|---|---|
| Issuer | Required; the only thing the customer types. JWKS, algorithms and endpoints come from `/.well-known/openid-configuration`. |
| Audience | Required, one value, **proposed by us**: a fixed identifier per gateway (e.g. `https://<slug>.mcp.neuraltrust.ai`, or the default IdP's). Shown pre-filled and copyable: "register this as an API / app registration in your IdP and request tokens for it". |
| Allowed client IDs | New; list of `azp` / `client_id` values. Required when one auth is shared by several consumers, optional for one-to-one. |
| Required scopes | Optional, empty by default. A coarse scope only lets the IdP deny; fine-grained scopes would duplicate the consumer config. Note Entra client-credentials tokens for `api://<app>/.default` carry no `scp`, so requiring scopes would break them. |
| Subject claim | Machines: `azp` / `client_id` when present, else `sub`. Automatic; Advanced only. |
| Allowed algorithms | From discovery (RS256, ES256). Advanced. |
| JWKS URL | Override for IdPs without discovery. Advanced. |
| Session mode, userinfo URL, authorize / token URL, introspection | Interactive-flow fields. Hidden for LLM and MCP-as-the-app; shown only on the "External IdP (users)" flavour used by MCP-for-users, where userinfo and the groups claim mapping feed Access. |

Auth types offered in the UI: **API key** (no config), **External IdP (JWT)**
(Issuer, Audience, Allowed client IDs; Advanced as above), **External IdP (users)**
(the same plus userinfo and groups claim; selectable only on MCP consumers with
`acts_for_users` and `source = platform`), **mTLS** where it exists today. The
current `oauth2` and `oidc` types are merged behind the first two; they may stay
as two storage types until the cleanup.

### 4.5 API-key consumers acting for end users (the Composio pattern)

An application that authenticates with an API key can still let *its* users
connect their own upstream accounts. Composio's quickstart is the reference:
the developer's app holds one API key, identifies each end user by an opaque
`user_id`, calls `authorize(user_id, "github")` to get a `redirect_url` it shows
to that user, waits for the connection, and from then on tool calls made with
that `user_id` run against that user's connected account.

Mapping onto the gateway:

- **Identity.** `identity.acts_for_users = true, source = app`. Every request
  carries `X-NeuralTrust-End-User: <id>` (an opaque string, ≤ 256 chars). The
  principal becomes `sub = app:<consumer_id>:<id>` — namespaced so it can never
  collide with a platform user's `sub`. A request without the header on such a
  consumer is rejected with a clear error; without the flag the header is ignored.
- **Per-user connections.** Nothing new: the vault keys credentials by
  `(gateway, sub, provider)`, the credential resolver already raises the
  consent-required error with a connect URL when `sub` has no credential for a
  forwarded-auth registry, and the connect page completes the upstream OAuth and
  stores the token under that `sub`. The app forwards the connect URL to its user
  exactly as Composio's `redirect_url`.
- **Proactive link, Composio's `authorize()`.** So the app can offer "Connect
  GitHub" before the first tool call: `POST /v1/gateways/{id}/consumers/{cid}/
  connections/links {end_user, provider}` → `{connect_url, expires_at}`; and
  `GET .../connections?end_user=` → per-provider status (`connected`,
  `needs_reconnect`, `not_connected`), the equivalent of
  `wait_for_connection()`. Both are authenticated with the consumer's API key.
  They reuse `CreateServerTicket` / `Statuses` in `pkg/app/oauth/connect.go`.
- **Access.** Not applied for `source = app`: the gateway cannot know who
  `user_123` is. The set of servers is the consumer's set; who may use the app is
  the app's problem. If an app supplies platform user ids (or emails), a later
  option can map them and turn Access on; not in scope.
- **Today's API-key MCP consumers.** An API key currently *is* the principal
  (`sub = auth name`), so "connect" links one shared account per key. That stays
  the behaviour when `acts_for_users` is off: it is the MCP-as-the-app case.

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
- Proxy: read `X-NeuralTrust-End-User` when enabled (attribution only on LLM;
  principal namespace on MCP `source = app` consumers, §4.5).
- Auth (`pkg/domain/auth`, `pkg/app/auth/oauth2_verifier.go` + OIDC verifier):
  add `allowed_client_ids` to the OAuth2/OIDC config and check `azp` /
  `client_id` against it (§4.4). Default subject for machine tokens: `azp` /
  `client_id` when present.
- Connections API for API-key consumers: `POST …/consumers/{cid}/connections/links`
  and `GET …/consumers/{cid}/connections?end_user=` (§4.5), authenticated with the
  consumer's API key on the MCP plane.

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
  multiselect. For MCP, add an **Identity** section with the switch *Acts on
  behalf of end users* and, when on, the source: *Users sign in* (OAuth; line
  linking to Access: *"Who may use each server is managed in Access."*) or *My
  app identifies its users* (API key; shows the header name and the connections
  endpoints with a snippet). For LLM, add *Accept end-user attribution header*
  with the header name shown.
- Auth forms (`features/identity`): collapse `oauth2` / `oidc` into "External IdP
  (JWT)" and "External IdP (users)" per §4.4; Issuer with discovery, Audience
  pre-filled with the gateway convention, Allowed client IDs; the rest under
  Advanced. Interactive-flow fields only on the users flavour.
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
- **Audience convention.** One fixed audience per gateway is proposed; confirm
  whether the default IdP's audience can be reused so customers register a single
  value for both the Store and their own consumers.
- **App-supplied users and Access.** Left out on purpose; revisit if a customer
  wants to map its `user_id`s to platform users.

## 10. Implementation status (gateway)

Shipped on `claude/composio-mcp-gateway-auth-tyd2z1`, in this order:

1. **Roles removed** (§8). `routing_mode`, `role_ids`, the roles admin API, the
   role scoper, the roles snapshot slice and the `roles` / `role_registry` /
   `consumer_role` tables are gone (migration `20260909120000`). Every consumer
   routes inline. Bearer tokens resolve through OIDC only when the consumer
   carries OIDC auths and no OAuth2 auth.
2. **Consumer identity** (§4.1, §4.2). `identity: {acts_for_users, source,
   end_user_header}` on the consumer (migration `20260909130000`). The Store
   scoper scopes the Store only; a custom consumer is returned untouched
   whatever its identity (§15). `ValidateAuth` enforces the credential shape
   per identity (platform users → oauth2 or the built-in IdP; app users → api_key
   or mtls). The Store consumer is `acts_for_users = true, source = platform`.
3. **Auth binding** (§4.4 item 6, generalised). `auth_binding:
   {allowed_client_ids, allowed_certificate_subjects}` on the consumer
   (migration `20260909140000`), enforced after consumer resolution on the proxy
   plane (oauth2 / oidc: `azp` else `client_id`) and the MCP plane (JWT,
   introspection, mTLS common name or SAN). This is the per-consumer half of
   "trust anchors live in gateway Settings, keys stay per consumer": the anchor
   verifies, the binding says which application may enter.
4. **App-identified end users** (§4.5) and **LLM attribution** (§4.3). On an
   MCP consumer with `source = app`, `X-NeuralTrust-End-User` is required; the
   request runs as `app:<consumer_id>:<end_user>`, so the vault, the connect
   flow and the surface watcher are per end user without touching Access. The
   connections API lives on the MCP plane next to the consumer, authenticated
   with its API key: `POST /{slug}/connections/links {end_user, provider?}` →
   `{connect_url, ticket, expires_at}` and `GET /{slug}/connections?end_user=`
   → per-server `connected | needs_reconnect | not_connected`. An LLM consumer
   with `end_user_header` records the header as `end_user` in traces and
   telemetry (`trustgate.end_user`).

Not done on the gateway: merging the `oauth2` / `oidc` storage types behind the
two UI flavours (§4.4), and moving the trust-anchor forms to gateway Settings —
that is presentation; the gateway already keeps auths at gateway level and
binds them per consumer. Resolved open questions: the attribution header is
`X-NeuralTrust-End-User`; app-supplied users stay outside Access.

### App (NeuralTrust/app, branch `claude/access-page`)

- **Consumers.** Routing mode and roles are gone from types, mappers, actions,
  the create panel and the Routing tab. General gains the *Identity* section:
  MCP → *Acts on behalf of end users* with the source choice *Users sign in* /
  *My app identifies its users* (the latter shows `X-NeuralTrust-End-User` and a
  curl snippet of the connections endpoints for that consumer); LLM → *Accept
  end-user attribution header*. The Auth tab is *API key | OAuth*: an API-keys
  list with *Issue key*, masked keys, created date, *Rotate* and *Revoke*; under
  OAuth the trusted-IdP picker plus *Allowed client IDs* (or *Allowed
  certificate subjects* for mTLS) bound to `auth_binding`. The gateway's
  identity ↔ credential rule is mirrored in the UI (the disallowed method is
  disabled with a hint).
- **Identity → Settings.** The Roles UI is deleted. Gateway trust anchors live
  in Settings → Agent Gateway → *Machine identity*: only `oauth2` / `oidc` /
  `mtls` auths are listed (API keys are per consumer), and the create form
  offers *External IdP (JWT)* (Issuer, Audience; Advanced: JWKS, algorithms,
  subject claim, scopes), *External IdP (users)* (plus client, endpoints,
  session, userinfo) and *mTLS*. The old `/gateway/identity` route redirects to
  that tab.
- Not done: the Access *Applications* tab listing acts-for-users consumers, and a
  per-user note on the Connect tab for acts-for-users consumers.

## 11. MCP flow matrix (audit)

Every MCP consumer is one row of identity × credential. What the gateway does at
each step, and where it is enforced:

| Identity | Credential | Who is the principal | Upstream connections | Access rules | Enforced |
|---|---|---|---|---|---|
| Acts as the application | API key | the key (`sub` = auth name) | one shared account per key; linked on the API-key connect page `/{slug}/connect` or via the consent error | no | `resolveMCPConsumer`, `apiKeyConnectService` |
| Acts as the application | Trusted IdP (JWT) or mTLS | the token's `azp`/`sub` or the certificate CN | shared per principal, same page | no | `consumerAdmitsPrincipal` applies the auth binding |
| Users sign in (platform) | none → NeuralTrust login | the person (`sub`, `groups` from the platform token) | per person; consent error → connect page | no — the consumer's servers are what the admin bound (§15) | `emptySurfaceInsteadOfError` |
| Users sign in (platform) | Company IdP (oauth2 with a registered client) | the person, groups from that token's claims | per person | no | `ValidateAuthConfig` refuses a validation-only IdP (it cannot broker the login) and refuses api_key / mtls |
| My app identifies its users (app) | API key or mTLS + `X-NeuralTrust-End-User` | `app:<consumer_id>:<end_user>` | per end user; the app mints links and reads states through `/{slug}/connections/links` and `/{slug}/connections` | no (the app is the boundary) | header required (400), user login refused (403), API-key connect page refused (409), oauth2 auths refused at attach |

Invariants checked in this audit:

- The credential shape follows the identity at attach time and on every
  identity change (`ValidateAuth` / `ValidateAuthConfig`, 409), and the UI only
  offers what the gateway accepts.
- A per-user surface is never computed without a principal: the scoper and the
  surface watcher skip when the subject is empty.
- The end-user swap only happens after the caller proved it is the application
  (API key or certificate); a platform session cannot impersonate an end user.
- Per-user credentials are keyed by the principal subject everywhere (vault,
  consent tickets, connect page, statuses, stream fingerprint), so the three
  subjects (`auth name`, platform `sub`, `app:…`) never share an account.
- The Store is the platform-users row with the catalog as its server set.
- Client certificates authenticate on both planes: the MCP plane through the
  auth chain, the LLM proxy plane through `MTLSIdentityResolver` (TLS handshake
  or `X-Forwarded-Client-Cert` from a peer in `TRUST_XFCC_FROM`); the binding's
  allowed subjects apply on both.
- Product decision: consumers whose users sign in use the NeuralTrust login
  only. The gateway still accepts an interactive company IdP through the API,
  but the app does not offer one.
- Product decision: the *My app identifies its users* source is not offered in
  the app until the client library exists — the pattern is only fit to hand out
  through an SDK, not as raw connections URLs. The gateway keeps serving it, and
  a consumer already set to it stays editable. Spec:
  `trustgate-sdk-spec.md`; flag: `APP_IDENTITY_SOURCE_ENABLED` in the app.

## 12. Upstream MCP authentication for a machine consumer

The open question this section closes: an **MCP consumer that acts as the
application itself** — called with an API key, a client certificate, or a
bearer token validated against an IdP — reaches upstream MCP servers that want
credentials of their own. **How, and where, do we authenticate against those
upstreams?**

### 12.1 Where: on the server, never on the consumer

The upstream credential belongs to the **registry** (the MCP server entry),
`mcp_target.auth` (`pkg/domain/registry/mcp_target.go`), and is applied per
request by `credentialResolver.Apply` (`pkg/app/mcp/credentials.go`). The
consumer's own credential never travels upstream; it only decides **which
upstream modes are usable** and **whose identity the upstream sees**.

Six modes exist, and what each needs from the caller is what makes it usable or
not for a machine consumer:

| Upstream mode | What the upstream receives | What it needs from the caller |
|---|---|---|
| `none` | nothing | nothing |
| `static` | a header + secret the admin configured | nothing |
| `client_credentials` | a token the gateway mints as an OAuth client | nothing |
| `forwarded` | the access token of an account linked per principal (vault) | a principal **subject**, plus one linking step |
| `passthrough` | the caller's own token, audience-checked | the caller's **raw bearer token** |
| `exchange` · impersonation / delegation | a token the gateway mints asserting the caller's subject | a principal **subject** |
| `exchange` · OBO / token_exchange | a token the IdP mints from the caller's token | the caller's **raw bearer token** |

### 12.2 How each consumer credential fares

The machine principal is built by the auth chain
(`pkg/api/middleware/auth_chain.go`): an API key resolves to
`Principal{Subject: auth.Name, Method: api_key}` with **no raw token**; an IdP
JWT resolves to the token's own subject **with** the raw token. On the MCP
plane, a consumer that acts as the application then runs as
`app:<consumer_id>` instead, whenever the credential was an api key or a
certificate (§14.3) — the rows below say "the application's principal" for
that reason.

| Consumer credential | `none` / `static` / `client_credentials` | `forwarded` | `exchange` impersonation / delegation | `passthrough`, `exchange` OBO / token_exchange |
|---|---|---|---|---|
| **API key** | works | works — one shared account, linked to the application's principal | works (minted from the application's principal) | **impossible**: no token to reuse |
| **Client certificate (mTLS)** | works | works — the same account as its api keys reach | works | **impossible** |
| **IdP JWT (validated)** | works | works — keyed by the token's `sub` | works | works |

So the answer is: **a machine consumer authenticates upstream either with a
credential the server owns (`static`, `client_credentials`), with one shared
account linked once (`forwarded`), or with a gateway-minted assertion
(`exchange` impersonation/delegation). Reusing the caller's token is only
available behind an identity provider.**

### 12.3 The linking step for `forwarded`, without a person in the loop

A machine consumer has no browser, but `forwarded` needs an account. Two paths
already exist and both link to the *application's* principal, so the account is
shared by every call the application makes:

1. **The connect page** — `GET/POST /{slug}/connect`
   (`pkg/app/oauth/api_key_connect.go`): a human pastes the consumer's API key
   and the gateway mints a ticket for the application's principal, covering
   every forwarded provider of that consumer. One-time, out of band.
   Since §14.3, an admin can mint the same ticket from the console without
   holding a key at all (`POST .../upstream-accounts/link`).
2. **The `trustgate_connect_<provider>` tool** (`pkg/app/mcp/connection_tool.go`),
   exposed on the consumer's own tool list: calling it returns a connect URL for
   the current principal. This is also what the first tool call answers with —
   `ConsentRequiredError` carries a `connect_url` — so the failure is
   self-describing.

For a consumer whose *application* identifies its end users the same linking is
per end user and goes through the connections API instead; the connect page
refuses it with 409 (`ErrAPIKeyConnectEndUsers`), see §11.

### 12.4 What was actually missing (and the decisions)

- **The impossible pair failed at request time with a misleading message.** An
  API-key consumer reaching a `passthrough` upstream got
  `ErrNoPrincipal` — "requires an authenticated user identity" — when it *was*
  authenticated. Fixed: `MCPAuth.NeedsCallerToken()` names the two modes that
  reuse the caller's token, and the resolver answers with
  `ErrUpstreamNeedsCallerToken`, which states the fix (give the upstream its own
  credential, link an account, or call the consumer with an IdP token).
- **Still open — config-time enforcement.** The pair is a configuration error,
  so it should be refused when the consumer is bound to the server (or when the
  server's mode changes), not on the first tool call. The invariant: a
  `NeedsCallerToken` upstream requires the consumer to hold at least one
  oauth2/oidc auth. Not implemented: it needs a decision on whether to reject
  (409, and existing setups may break) or to surface it as a warning.
- **Still open — `passthrough` and `exchange` are invisible in the app.** The
  registry panels offer `none | static | forwarded` for a custom MCP server and
  `none | static | client_credentials` for an OpenAPI source
  (`features/registry/components/CustomMcpSidePanel.tsx`). The two modes that
  make an IdP-JWT consumer worth having are API-only.
- **Still open — nothing shows the admin the upstream state of a machine
  consumer.** The Connect tab explains the consumer's own credential but never
  says which of its bound servers still need an upstream account, nor points at
  the connect page. The data exists (`ProviderStatus`, `/{slug}/connect`).
- **Operational wart.** The machine principal's subject is the API key's
  **name** (unique per gateway), so renaming that auth orphans its vault
  credentials and silently forces a reconnect. Keying on the auth id would be
  stable; changing it needs a migration of existing vault rows.

## 13. One principal, two credential stores (the Portal's "Not connected")

Reported: Linear connected and working from Cursor, while the Portal's *My
access* showed it **Not connected** — and Airtable and Notion with it, all three
listed as installed.

The cause is topological, not per-provider. A deployed gateway runs three
processes (`k8s/base/deployment/*`): `admin` (control plane, Postgres) and
`mcp` / `proxy`, which are DB-less data planes
(`CONFIG_SYNC_DATA_PLANE_ENABLED`). The two planes were wired to **different
credential stores** (`pkg/container/modules/modules.go`):

- the control plane got the **Postgres** vault (`MCPVaultPostgres`),
- each data plane got the **Redis** vault (`MCPVaultRedis`).

The connect flow — the thing that stores a person's upstream account — runs on
the MCP plane, so every account linked from an MCP client lands in **Redis**.
The Portal preview is an admin-API read (`/v1/gateways/{id}/store/principal` →
`store.principalPreview.fillConnection`) served by the control plane, which
looked only in **Postgres** and therefore reported every user as never
connected. Installs did not have the same fate because the DB-less plane
forwards them to the control plane over the config-sync gRPC bridge
(`configsyncgrpc.NewInstallationsClient`), so they land in Postgres — which is
exactly why the Portal could show a server installed and unconnected at once.

Fixed by composing the control-plane vault: Postgres for what that plane writes,
with the shared Redis vault behind it for reads
(`vault.NewFallbackRepository`). Both planes take their Redis coordinates from
the same ConfigMap, so it is the same store the data plane wrote to. A delete
removes the credential from **both** stores — revoking from the control plane
must not leave a live copy on the data plane — and writes stay on Postgres.

Still open, and worth doing properly: **credentials should live in one durable
store.** Today, in a deployed topology, the Postgres vault holds nothing and
Redis is the real store — which is why `vault.WarnIfVolatile` exists. The
precedent to follow is installs: let the data plane write through the
control plane over the config-sync bridge, keeping Redis as a read cache on the
request path (the credential resolver reads on every tool call, so the hot path
cannot become a synchronous round trip).

## 14. An MCP consumer with an API key, reframed

§12 answered "which upstream modes work". It did not answer the question underneath,
which is what actually confuses everyone: **for a machine consumer, who is the
identity that owns the upstream account?** This section replaces the
machine-consumer parts of §12.4 and is grounded in a full trace of the code
(22 agents, every claim adversarially reviewed; the specific facts below were
re-verified by hand).

### 14.1 Three things we have been treating as one

| Concept | What it is for | What it is today |
|---|---|---|
| **Call credential** | proves "I am this application" on each request | an `auths` row of type `api_key`; a consumer may hold several, and rotation issues a new one |
| **Application identity** | the stable thing an upstream account should belong to | `app:<consumer_id>` (§14.3); until this branch, *nothing* |
| **Upstream account** | what the third-party MCP server authorizes | a vault row keyed by `(gateway_id, principal_sub, provider)` |

The whole difficulty came from the middle row being missing. `resolveAPIKey`
sets `Principal{Subject: auth.Name}` (`pkg/api/middleware/auth_chain.go`), so
the **display label of a credential** was the durable identity — on the MCP
plane it is now replaced by the application's own subject (§14.3), and what
follows is the reason. That string keys: the credential vault (`pkg/app/mcp/credentials.go:195`), connect tickets
and provider statuses (`pkg/app/oauth/api_key_connect.go:124`), per-user URL
variables, Store installs and grants, the per-principal discovery cache
(`pkg/app/mcp/discovery.go:260`), the upstream session pin
(`pkg/app/mcp/target.go:92`), the `sub` of any JWT we mint for an upstream
(`pkg/app/identity/sts/exchanger.go:149`), and the principal in traces/OTLP.

That has consequences nobody chose:

- **Names are no longer unique.** Migration `20260729110000` dropped
  `auths_gateway_name_unique`, so two enabled API keys on one gateway can share
  a name — and therefore one set of upstream accounts, *across different
  consumers*, since the vault key has no consumer column. The migration's own
  description justifies the drop with "credentials resolve by id/key_hash",
  which is true for inbound auth and false for the upstream vault.
- **And it is load-bearing, not an oversight.** The app's rotate flow
  deliberately issues the replacement key under the *same name* so the linked
  upstream account survives
  (`features/consumers/lib/consumerApiKeys.ts:167-199`). Keying the vault on the
  auth id — §12.4's proposed fix — would break rotation as designed.
- **Renaming orphans; deleting strands.** Nothing rewrites `principal_sub` on
  rename, and deleting an auth touches no vault row
  (`pkg/app/auth/deleter.go:64-86`). The upstream OAuth grant stays live and,
  with no gateway-wide vault listing and a ticket-gated `Delete`, becomes
  unrevokable through TrustGate — until someone creates a key with the same
  name, which re-adopts it, refresh token included.

### 14.2 What is actually broken today (verified)

1. **Revoking the last API key opens the consumer up.** Disabling the only
   credential of an MCP consumer is refused with 409
   (`pkg/app/auth/guard.go:63-80`), but `associator.DetachAuth`
   (`pkg/app/consumer/associator.go:130-139`) has no such guard, and the app's
   Revoke is detach-then-delete
   (`features/consumers/lib/consumerApiKeys.ts:140-163`). A zero-auth MCP
   consumer then satisfies `defaultIdPUsable = defaultIdPEnabled && !hasOAuth2
   && !hasEnabledAuth` (`auth_chain.go:164`), so the built-in provider is added
   to its scope and **any platform login on the gateway can enter it** — the
   exact outcome the comment three lines above says must not happen.
   `MCP_DEFAULT_IDP_ISSUER` is set in both the dev and prod overlays, so this is
   live. The reversible operation is blocked and the destructive one is not.
2. **A valid key gets a 401 on the connect page when the consumer has no
   `forwarded` registry.** `forwardedProviderIDs` returns an empty non-nil
   slice; `append([]string(nil), providers...)` makes it nil; the `*[]string`
   field marshals as `"providers":null`, decodes back as a nil pointer, and
   `routable()` rejects the ticket (`pkg/app/oauth/connect.go:116,386-392,458`).
   The console shows that authorize step for *every* API-key MCP consumer, so
   this is the default experience for anyone whose upstreams are `static`/`none`.
3. **The guarded path and the cheap path are inverted.** The human connect page
   is rate-limited twice, pins its ticket to consumer+auth+provider snapshot,
   and is audited. The `trustgate_connect_*` tool and the `ConsentRequiredError`
   both mint an **unpinned, unrate-limited, unaudited** ticket
   (`connection_tool.go:136`, `credentials.go:451`; audit needs ConsumerID+AuthID,
   `connect_auditor.go:86`). Tickets are not single-use, last 15 minutes, and
   also authorize `POST /oauth/disconnect/*` — and the `connect_url` is built
   from the request's `Host`.
4. **`Authorization: Bearer ag_...` does not authenticate on the MCP plane.**
   `Resolve` returns from the bearer branch without falling through to the
   API-key branch (`auth_chain.go:120-123`), and the key header is read
   untrimmed. The proxy plane accepts both forms and trims
   (`pkg/api/resolver/api_key_source.go:29-48`). Two planes, two notions of
   where an API key lives.
5. **Fail-open discards the actionable error.** With the default fail-open
   policy, a machine caller against a `passthrough`/OBO upstream never sees
   `ErrUpstreamNeedsCallerToken`: the registry is skipped and, if it is the only
   one, the caller gets "upstream MCP server unreachable"
   (`composer.go:206-239`). The better diagnostic only appears fail-closed.
6. **Machine traffic is attributed to a person.** With no principal email, every
   MCP request resolves one from the linked upstream account's `AccountRef`
   (`mcp_handler.go:200-206` → `request_identity.go:26-58`), so
   `principal_email` in traces becomes whichever human walked the connect page.
7. **The product barely mentions any of this.** Nothing before Create names
   upstream credentials; the only mention is the post-create screen and the
   Connect tab. `connect.apiKeyNote` points at "the General tab", which the UI
   labels "Auth". `passthrough`/`exchange` instances render as "No
   authentication", and saving such a registry from the custom panel degrades
   its mode to `none` (`mcpCatalog.ts:96-99,617-627` +
   `pkg/app/registry/updater.go:159-161`).

### 14.2b What is fixed now, and what is not

Fixed in this branch (gateway + app):

1. **The promotion is closed.** The built-in provider now also requires a
   matched consumer whose users sign in, so a machine application with no
   credential is unreachable rather than open to any platform login
   (`pathScope`, `wantsSignIn`). Existing credential-less MCP consumers are
   backfilled as sign-in consumers by
   `20260909150000_backfill_signin_identity_for_credentialless_mcp`, so their
   behaviour is unchanged. `DetachAuth` is deliberately *not* guarded: the app's
   own credential-swap edits detach before they attach, so a guard there would
   break them, and the promotion is closed at the source instead.
2. **The dead ticket.** An empty provider snapshot stays empty rather than
   degrading into absent, and the test fixture round-trips tickets through JSON
   so this class of bug fails in a unit test.
3. **Bearer-form api keys.** The MCP plane accepts `Authorization: Bearer ag_…`
   and `x-api-key`, trimmed, through the same helper the proxy plane uses.
4. **Fail-open no longer swallows the cause** when nothing was reachable, so
   `ErrUpstreamNeedsCallerToken` reaches the caller with the registry named.
5. **The product says it.** `GET`/`POST
   /v1/gateways/{gid}/consumers/{id}/upstream-accounts[/link]` report which
   bound servers want the application's own account and mint the pinned, audited
   connect ticket for it; the console's Connect tab lists them, shows each
   account's state, and authorizes them in one click — no api key needed, which
   is what made this unreachable from the console before.
6. **`passthrough`/`exchange` in the UI** read as "caller's own token" instead
   of "no authentication", and saving such a registry no longer strips its
   credential (the payload omits `auth` while the mode is one the panel cannot
   express).

Deliberately still open:

- **The in-band ticket paths** (`trustgate_connect_*` and the consent error)
  remain unpinned, unrate-limited and unaudited, and tickets stay reusable for
  their 15 minutes and also authorise disconnect. Pinning them is easy; the rest
  touches the tool-call hot path, where a limiter outage would turn a consent
  prompt into a failed call, so it wants its own change.
- **The in-band ticket hardening** above is the whole of what is left here.

Also fixed, and the reason the rest of §14 reads as history: **the machine
principal is now `app:<consumer_id>`** (§14.3). The email on machine traces
stays intentional (`TestHandler_StampsVaultEmailOnAPIKeyTrace`) — it answers
whose account the upstream saw — and the trace's principal subject still shows
the credential that called, from the `credential_subject` claim, so the change
did not cost attribution.

### 14.3 The model, implemented

**The upstream account belongs to the application, not to one of its
credentials.** A consumer that acts as the application now *runs as* the
application: `consumerdomain.AppSubject(consumerID)` = `app:<consumer_id>`,
namespaced exactly like the end users an application names
(`app:<consumer_id>:<end_user>`).

Where the swap happens, and why there: `resolveMCPConsumer`
(`pkg/api/handler/http/mcp/mcp_handler.go`), right after the consumer's auth
binding has been applied to the real caller. It cannot happen in
`resolveAPIKey`, where the old subject was set, because `consumer_auth` is a
**many-to-many** table: one api key can serve several consumers, so the
credential alone cannot say whose application this is. Only the request path
knows, which is the same reason the app-identified end-user swap already lives
there.

What it is limited to, deliberately: a caller that presented an **api key or a
client certificate** (`machineCredential`). A bearer token keeps its own
subject. On a consumer that admits tokens from an external IdP the token may
well be one person's, and collapsing those onto one subject would hand every
holder the account the first of them linked — sharing is the direction that
cannot be undone. A client-credentials token needs nothing from this anyway:
its subject is the application's client id already.

Everything but the subject carries over (`appPrincipal`): issuer, scopes,
claims and the raw token, because a `passthrough` or `exchange` upstream
forwards the caller's own token and dropping it would break those modes on a
machine consumer. The credential's own subject is kept as the
`credential_subject` claim, and the trace's principal subject prefers it, so
"which key called" survives while "whose account is this" is the application.

By construction, then:

- Rotating, renaming, adding or removing a credential never touches a linked
  account. The app's rotate-under-the-same-name trick
  (`consumerApiKeys.ts:167-199`) is no longer load-bearing — it is just a name.
- Two credentials of one application share the account **by design**; the
  dropped `auths_gateway_name_unique` (`20260729110000`) stops mattering,
  because a name is no longer an identity.
- Two applications never cross, even holding a key with the same name, since
  the subject carries the consumer id.
- An application's accounts are enumerable by prefix, so deleting the consumer
  can revoke them.
- The admin API needed no `auth_id` and no api key at all: an application that
  authenticates only with a client certificate still has accounts to link, and
  `GET /upstream-accounts` answers for the consumer. The
  `ErrUpstreamAccountsAmbiguousKey` 409 ("pass auth_id") is gone — the question
  it asked no longer exists.

Ticket authority changed with it. An application connect ticket is pinned to
the consumer; the api key is now an *optional* pin, present on the in-band
self-service ticket (so revoking a leaked key kills the tickets it spawned) and
absent on one an admin minted, whose authority was the admin API
(`currentAppIdentity`). Redemption revalidates that the consumer is still that
same active machine MCP consumer. Audit no longer requires a key to be present
(`connectAuditIdentity`), which is what would otherwise have made the admin path
the one path that went unaudited.

No migration was needed: none of this had shipped.

What stays unchanged: an upstream whose credential the server owns (`static`,
`client_credentials`) needs none of this, and remains the right default for a
machine consumer. What `forwarded` buys is *one shared service account per
application*, and the product now says exactly that.

## 15. Access governs the Store, not a consumer

Product decision, replacing what §4, §10 and §11 first said: **no access mode and
no grant narrows a consumer's surface.** A consumer's servers are the ones an
admin bound to it, identical for every caller it admits, whatever its identity.
`scoper.Scope` now returns any non-Store consumer untouched
(`pkg/app/store/scoper.go`), and the grant store is not even read on that path,
so an Access outage cannot affect an application.

The reasoning: Access exists for the **self-service catalog**, where a person
picks servers themselves and there is no per-application configuration to read —
mode (All / Selected / None) plus grants are how an admin bounds that choice. A
consumer is the opposite: someone already decided, deliberately, which servers
this application routes to. Layering Access on top puts two places in charge of
one surface, and the failure it produces is silent and confusing — an admin
binds a server to a consumer and the consumer's own users do not see it, because
a grant elsewhere does not name them.

What this means in practice:

- **Governance of a login consumer is admission, not scoping.** Who can enter it
  at all is the question — its credential, and for the built-in NeuralTrust login
  the auth binding. Everyone admitted sees the whole set. If per-person subsets
  of one application are ever wanted, the answer is more consumers (each with its
  own server set), not Access inside one.
- **The Store keeps everything.** Live mode resolution (own policy → most
  permissive group → gateway default), grants by catalog code or instance,
  install approvals, and the re-check at request time rather than only at install
  time. §7 and §8 stand as written.
- **The Portal is unaffected**: it previews the Store, and the app's Access page
  only ever granted catalog servers and instances — never consumers. The
  Applications tab there is a directory of consumers, not a place they are
  governed.

## 16. `trustgate_list_tools`: the surface a caller cannot otherwise see

`tools/list` can only carry the tools of servers that answered discovery. A
server the user has but has not connected contributes nothing to it — the
composer skips it on `ConsentRequiredError` so the connected ones still federate
(§12.3) — and neither does one that is down, or one whose tools the consumer's
toolkit turns away. The result is a list that is silent about exactly the servers
someone needs to act on: an agent asked "can you query Notion?" sees no Notion
tool and answers no, when the truth is "you have Notion, it needs one click".

`trustgate_list_tools` (`pkg/app/mcp/inventory_tool.go`) is the view that is not
silent. It answers server by server, each with a state:

| State | Meaning | What fixes it |
| --- | --- | --- |
| `ready` | the server answered; its tools are callable now | — |
| `needs_connect` | bound, but waiting for this principal's upstream account | the `trustgate_connect_*` tool named in the entry, or the connect page |
| `unavailable` | the gateway could not reach it | operational |
| `no_tools` | it answered but offers this consumer nothing | the consumer's toolkit |

Three decisions worth keeping:

- **One discovery pass feeds both views.** `compose` and the inventory read the
  same `serverSurface` list (`pkg/app/mcp/composer.go`), and the inventory runs
  the same `resolveNames` over the reachable bindings, so a name it advertises is
  a name `tools/call` accepts. Two passes would eventually disagree, and a caller
  told a name the gateway does not answer to is worse off than one told nothing.
- **A server that is not serving is described from the catalog.** Its tools come
  from `catalogdomain.MCPServer.Tools` — the unauthenticated snapshot the catalog
  already carries — and are returned with `callable: false`. That is what turns
  "Notion is not connected" into "Notion is not connected, and these are the
  fifteen tools you would get". The names are the server's own; qualification
  happens when it starts serving, which is why they are never marked callable.
- **The upstream's failure text stays in the log.** An `unavailable` entry says
  the gateway could not reach the server, not which host refused the connection.
  The caller cannot act on the latter, and it is not theirs to read.

One more thing it has to do, found the first time someone asked a client "what
do I have in TrustGate?": the client read `tools/list`, found the gateway's own
four tools in it — they have to be listed to be callable — and reported them to
the user as tools they have, under a heading of their own. They are not: they
are how the user's surface is managed. MCP has no way to mark a tool as plumbing
rather than capability, so the only lever is prose, and it is used in three
places: every gateway tool's description disowns itself
(`GatewayToolDisclaimer`) and points at this tool for the real answer, this
tool's description says what its answer excludes, and the answer itself ends by
saying it is the whole list. The text body carries it, not only
`structuredContent`, because the text is the part many clients hand the model.

It is offered to every consumer with an MCP server bound, and withheld from a
deny-all toolkit — a consumer meant to expose nothing gets no gateway tools
either, the rule the connect tool already followed (`metaToolsPermitted`).
Descriptions are truncated per entry: a caller wanting a tool's full schema gets
it from `tools/list` once the tool is callable.

## 17. How many instances a server can hold

Instances exist so one catalog server can be shelved twice with **different
configuration**: two Snowflake schemas, two Aha! domains, two API keys for two
accounts of the same SaaS. That is the whole point of them, and it decides which
servers should have them.

A server that is one URL behind per-user OAuth has no such configuration. The
gateway registers its client itself (`registration: auto`) or the platform holds
one, and each user signs in with their own account — so a second registry would
be a byte-for-byte copy of the first, and would buy nothing but ambiguity: an
instance to pick on every install and uninstall, every one of its tools renamed
with an instance prefix (`resolveNames`' `perInstance`), and two Access rows
granting the same thing.

**Every catalog entry declares the answer**, next to `self_service`, in
`seed/mcp-catalog/enterprise-servers.json`:

```json
{
  "name": "com.notion/mcp",
  "requires_auth": true,
  "self_service": true,
  "multi_instance": false,
  ...
}
```

It was derived at load time first (`SupportsInstances()`, next to
`IsSelfService()`), and the derivation is gone: reading an entry now answers the
question, adding a server means answering it, and there is no rule to trace
through auth hints and registration modes to find out what the catalog thinks.
The loader **requires** both on every entry — a pointer in the raw struct tells a
declared `false` from a forgotten field, and a missing one fails the whole
catalog load rather than defaulting to something plausible.

The rule the declarations follow, which is what a new entry should be measured
against:

| The entry has | Instances | Because |
| --- | --- | --- |
| any URL variable | yes | the URL itself differs |
| static auth headers, or a secret URL variable | yes | two credentials are two accounts |
| an OAuth client the operator registers (`manual`) | yes | the client id and secret are theirs |
| a `client_credentials` grant | yes | same |
| a fixed URL behind OAuth the gateway registers itself | **no** | only the user differs, and one instance serves them all |
| no auth at all | **no** | one URL, no credential, nothing to vary |

Across the 198 curated entries that is 96 multi-instance and 102 single; for
`self_service`, 114 and 84. The two are not the same question and do not answer
alike: 12 entries are both (Stripe, GitLab, Linear, Atlassian, Supabase and the
tenant-templated OAuth servers — a user can install them alone, and an operator
can still shelve two with different credentials), and 84 are neither
self-service nor single.

Nothing re-derives them, so nothing would notice a wrong one. Two things guard
the data instead: the loader's requirement above, and a test over the real
catalog (`TestCuratedCatalogFlagsAgreeWithTheEntry`) that checks each declared
value against that entry's own facts — a `multi_instance: false` entry may not
carry a URL variable, an auth header, a static method, a `client_credentials`
grant or a manual client; a `self_service: false` entry must have something an
admin would actually supply. An entry that breaks one is either mislabelled or a
shape the catalog has not seen, and either way it wants a human.

One deployment fact stays in code, because the seed cannot know it:
`applyPlatformOAuth` raises `self_service` for the three Google Workspace
entries when NeuralTrust's own OAuth client is configured, since the blocker the
seed declared — an operator must register a client first — is then gone. It
leaves `multi_instance` alone: the install form still offers an operator their
own client id and secret for such a server, so two instances can still differ.
That last part is the one behaviour that changed when the flags became data.

Two places enforce it, both reading the entry's declaration.
`appregistry.creator` refuses a second registry for a single-instance code with
`ErrSingleInstanceServer` (a conflict — the request is
well formed, the shelf already holds the only instance the server can have), and
the console hides *Add instance* for those servers and says why instead. Only
*new* duplicates are refused: a gateway that already holds two keeps them, since
the pair is real and something is routing to it. The self-service paths are
unaffected — `RegistryEnsurer.Ensure` and `from-catalog` both look for an
existing registry first, so they only ever create the first one.
