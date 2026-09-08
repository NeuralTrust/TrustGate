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
2. **Who may use what inside the app.** Which users or groups may reach each of
   the app's servers. That is precisely what Access governs for the Store — the
   same scoper applied to the *consumer's* registries instead of the whole catalog.

So an MCP consumer is: **servers + tools, authentication, and one identity switch**
— *"Acts on behalf of end users"* — which turns on per-user connections and, when
the user is a platform identity, Access rules. No Roles, no claim rules, no
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
   scoper scopes any `acts_for_users` + `source = platform` consumer over its own
   registries with the live Access mode (All / Selected / None); a
   hand-configured server without a catalog code stays exposed under Selected
   since grants key on the code. `ValidateAuth` enforces the credential shape
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
| Users sign in (platform) | none → NeuralTrust login | the person (`sub`, `groups` from the platform token) | per person; consent error → connect page | yes: mode All / Selected / None over the consumer's registries | `scoper.scopeConsumerRegistries`, `emptySurfaceInsteadOfError` |
| Users sign in (platform) | Company IdP (oauth2 with a registered client) | the person, groups from that token's claims | per person | yes | same; `ValidateAuthConfig` refuses a validation-only IdP (it cannot broker the login) and refuses api_key / mtls |
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
JWT resolves to the token's own subject **with** the raw token.

| Consumer credential | `none` / `static` / `client_credentials` | `forwarded` | `exchange` impersonation / delegation | `passthrough`, `exchange` OBO / token_exchange |
|---|---|---|---|---|
| **API key** | works | works — one shared account linked to the key's principal | works (minted from `auth.Name`) | **impossible**: no token to reuse |
| **Client certificate (mTLS)** | works | works — same, keyed by the certificate principal | works | **impossible** |
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
   and the gateway mints a ticket for `auth.Name` covering every forwarded
   provider of that consumer. One-time, out of band.
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
