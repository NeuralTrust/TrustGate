# Plan B — MCP Store & Platform-Gateway Identity Bridge

Status: design (pre-implementation) · Owner: victor.garcia@neuraltrust.ai · Date: 2026-08-29

## 1. Goal

Give TrustGate a Composio-style self-service experience — a fixed catalog URL where a
user installs the MCP they need or triggers an approval flow — with the enterprise
governance layer TrustGate already has, and **without** Composio's opaque tool-router.
Tool selection stays in the model/API layer (tool_search / defer_loading), so per-tool
governance is preserved.

Hard constraint from product: **connect the identity (SSO) once.** A user who logged into
the platform via the org's SSO must be the same principal the gateway governs — no second
IdP configuration.

## 2. What already exists (verified in code)

The authentication half of "connect once" is already built:

- **Built-in default IdP** — `pkg/app/auth/default_idp.go`. A synthetic, in-memory,
  non-persisted oauth2 auth (`SessionMode: true`, sentinel ID `de1de1de-…`), configured by
  env (`config.MCPDefaultIdPConfig`). It brokers interactive login for any consumer that has
  no auth of its own. Recognised via `IsDefaultIdP()`.
- **Platform MCP OAuth AS** (repo `app`) — `/api/mcp/oauth/{authorize,token,jwks,discovery}`.
  `authorize` reuses the platform NextAuth session (`await auth()`); an unauthenticated caller
  is bounced to `/login`, which runs the org's SSO (Entra/Google/OIDC) or magic-link/password.
  RS256-signed, PKCE S256, short TTLs, confidential client.
- **RoleScoper** — `pkg/app/mcp/role_scope.go` + `pkg/domain/role/oidc_mapping.go`. For
  `role_based` consumers, resolves the principal's OIDC claims against each role's
  `oidc_mapping` (claim path/op/values), then unions the matched roles' `mcp_policies.toolkit`
  and `model_policies`. This is the governance core the Store builds on.

Login chain today:

```
MCP client → gateway default IdP → platform /api/mcp/oauth/authorize
   → (no session) → platform /login → org SSO (whatever SSO Beta configured)
   → auth code → gateway proxy callback → gateway mints mcp_session (bound to gwid)
```

So there is **no second SSO connect** for authentication. The gateway "Identity" screen stays
(its Roles tab is the RoleScoper); its Auths tab keeps manual entries (mTLS / api_key /
third-party OIDC) while the platform SSO is served by the built-in default IdP — no per-gateway
IdP re-configuration.

## 3. The two real gaps

### Gap A — governance claims are not propagated (feature)

The platform token the gateway receives carries only `sub / email / org / scope / aud`
(`app` `mcpOAuth/tokens.ts`). It does **not** carry the SSO group/role claims. But the gateway's
role `oidc_mapping` matches on exactly those claims. So `role_based` governance cannot key off
corporate groups today.

**Decision (product):** propagate the **raw IdP group claims** (Option 2), because Identity roles
are authored against Enterprise groups. Example claim: `groups: ["Okta-Engineering", …]`. The
platform already extracts these at login (`app` `server/lib/sso/idpGroupSource/*`,
`extractGroupIdsFromClaims`) — today it consumes them for provisioning and drops them from the
session. We re-surface them into the MCP token.

Consequence to make explicit in UX: **group-based governance requires SSO.** Without SSO there are
no groups → a `role_based` consumer fails closed (`ErrNoRoleAccess`). Such a consumer must be
`inline` or carry a default/fallback role. (Propagating the mapped platform role as an *additional*
claim is a future option; not excluded.)

### Gap B — no tenant binding on default-IdP sessions (security, cross-tenant)

The gateway binds a default-IdP session to the **addressed gateway** (`gwid`), never to the
authenticated user's org:

- `pkg/app/oauth/proxy.go:207-230` builds the `CodeGrant` with `Subject` + `GatewayID`, and never
  reads the token's `org`.
- `pkg/api/handler/http/mcp/mcp_handler.go:541` (`resolveMCPConsumer`) accepts the default-IdP
  session on any inline path with **no org check**.
- The platform issuer is deliberately cross-tenant (one host for all orgs).

**Effect:** an `inline` consumer reachable via the default IdP is accessible by *any* platform user
with a valid session — including a user from a different customer org. `role_based` consumers are
safe (fail-closed). Precondition: default IdP enabled (env set; opt-in cloud feature). This is a
pre-existing gap, not introduced here.

**Fix (folded into Slice 1 as a hard requirement):** the `org` already travels in the platform
token — the gateway just drops it. Read `org` → `CodeGrant` → `mcp_session` claim → **enforce**
`principal.org == owning tenant of the gateway` when resolving a default-IdP consumer. Requires the
gateway to know its owning tenant (stamp `teamId` into the per-gateway config snapshot). After the
fix, `inline` + default IdP means "any user *in your org*", which is what an enterprise expects.

## 4. Slice 1 — identity bridge (first to build)

Platform (`app`, branch `claude/sso-auth-hardening`):
1. Persist the SSO group claims at login so they survive to the MCP OAuth `authorize`.
2. Include `groups` (Option 2) and `org` in `mintAuthCode` / `mintAccessToken`.

Gateway (`TrustGate`, branch `claude/composio-mcp-gateway-auth-tyd2z1`):
3. Read `org` from the platform token in the proxy callback; carry it in `CodeGrant` and the
   `mcp_session` claims.
4. Stamp the owning `teamId` into the per-gateway config snapshot.
5. Enforce `principal.org == gateway tenant` for default-IdP sessions (`resolveMCPConsumer` /
   session mint). Deny on mismatch.
6. Ensure `groups` claims reach the principal so `oidc_mapping` can match.

Security preconditions to assert for prod (both have PoC-friendly insecure defaults today):
- `MCP_OAUTH_CLIENT_SECRET` set (else `/token` skips secret check → public client).
- `MCP_OAUTH_ALLOWED_REDIRECT_HOSTS` set (else any https redirect_uri accepted).

## 5. The Store (later slices, unchanged in intent)

- **Fixed catalog URL** via idempotent bootstrap of a "store" consumer (stable URL, like Composio).
- **`SEARCH` over the whole catalog** (198 entries), not only installed.
- **`installation`** — durable per-principal entity, stored outside the config-snapshot (like the
  vault).
- **CatalogScoper** — per-principal surface filter layered on `mcp_policies` / RoleScoper.
- **4 meta-tools** — search / install / manage-connections / approvals.
- Policy, auto-approve and "required" live in the **consumer**, not the gateway. Top-down and
  bottom-up coexist via bootstrap defaults; `role_based` and `inline` both supported.

## 6. Phasing

1. Slice 1 — identity bridge (Gap A + Gap B together). ← next
2. Store bootstrap + fixed URL.
3. `installation` entity + CatalogScoper.
4. Meta-tools + approvals.
