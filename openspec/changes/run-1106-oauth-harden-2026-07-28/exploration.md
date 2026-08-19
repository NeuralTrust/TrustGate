# Exploration: RUN-1106 OAuth harden for MCP 2026-07-28

## Current State

TrustGate plays **two** OAuth roles. Neither implements RFC 9207 `iss` mix-up protection, issuer-bound DCR credentials, or `application_type`.

### Northbound (TrustGate is the AS / broker)

MCP clients discover `/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server`, register at `/oauth/register` (DCR), authorize at `/oauth/authorize`. TrustGate parks state, redirects to the configured IdP, then `/oauth/callback` redeems the IdP code and issues a gateway code back to the MCP client.

- AS metadata (`AuthorizationServer`) advertises `issuer = baseURL`, endpoints, PKCE S256, `token_endpoint_auth_methods_supported: ["none"]`. **Missing:** `authorization_response_iss_parameter_supported`, `jwks_uri` (no JWT issuance), `application_type` hints.
- Protected-resource metadata advertises the gateway as the only AS, `bearer_methods_supported: ["header"]`, path-scoped scopes. Adequate for RFC 9728 basics; no extra modern fields required for this ticket.
- `clientRedirect` returns `code`/`error` + `state` only — **no `iss`**.
- `CallbackHandler` / `AuthProxy.Callback` ignore the `iss` query param. `PendingAuthorization` does not store the expected IdP issuer.
- Northbound DCR (`RegisterRequest`) accepts `redirect_uris` + `client_name` only. Redirect URI policy already distinguishes https / loopback / private-use (`IsAcceptableRedirectURI`). No `application_type`. Clients stored as `oauth:gwclient:{clientID}` with no issuer field (`RegisteredGatewayClient`).
- IdP metadata fetch (`fetchASMetadata`) caches by configured issuer URL but **does not** check that the document's `issuer` matches.

### Southbound / connect (TrustGate is the client)

`registration: auto` discovers upstream PRM + AS metadata, then DCR-registers a public client (`token_endpoint_auth_method: none`). Manual providers (Google Workspace) skip DCR.

- Cache key is `gatewayID|registryID` (`clientKey`). Redis key `oauth:dcr:client:{key}`.
- `RegisteredClient` = `{client_id, client_secret, redirect_uri}` — **no issuer**.
- `EnsureClient` reuses a cached client when `RedirectURI` matches; it does **not** compare the discovered AS issuer. An upstream that changes AS (or a poisoned discovery cache) can reuse another AS's `client_id`/`client_secret`.
- DCR body has no `application_type`. TrustGate's callback is HTTPS → should be `web`.
- `ConnectState` has ticket/provider/verifier only — no expected issuer. `ConnectHandler.Callback` does not read `iss`.
- Discovery does not validate AS document `issuer` against the authorization-server URL from PRM.
- Vault user grants (`Credential`) are keyed by `(gateway, principal, provider)` with no issuer. Ticket wording is **client** credentials (DCR), not user tokens — leave vault shape unchanged.

### Audit / logging

No dedicated audit package. Connect already uses structured `slog` (`oauth connect: provider grant stored` with `has_refresh_token`, never the token). Product `events.Event.Security` is request-scoped MCP telemetry, not auth-flow audit. Issuer-mismatch / invalid-metadata events do not exist.

### Docs and tests

- Worktree docs: `docs/mcp/google-workspace-oauth.md` (manual, no DCR), `docs/mcp/testing-guide.md`, `docs/mcp/dual-era-rollout.md`. No CIMD / RFC 9207 / `application_type` guidance.
- `docs/mcp/api-key-auth-and-external-credentials.md` lives in the main TrustGate checkout (untracked), **not** this worktree. It covers principal vs forwarded vault ownership — complementary, not a substitute for OAuth harden docs.
- Tests cover DCR race (`SaveClientIfAbsent`), redirect-URI replacement, northbound register/PKCE/redirect policy, connect consent + auto-registration. **No** mix-up / cross-issuer / `application_type` / `iss` cases.

### Constraints (resolved from code)

| Question | Answer from code |
|---|---|
| Where to validate `iss`? | Both callbacks: IdP→gateway (`proxy.Callback`) and upstream AS→gateway (`connect.Callback`), **before** `ExchangeCode` / `tokenCall`. Also emit `iss` on gateway→MCP-client redirects. |
| Can cache keys bind issuer? | Yes without a Redis key migration: keep `gateway\|registry`, add `Issuer` on `RegisteredClient`, reject/re-register on mismatch. Optional key suffix is stricter but strands existing entries. |
| Require `iss` always? | **No.** Google/GitHub-style IdPs and many manual providers do not send RFC 9207 `iss`. Requiring it would break Workspace connect. Follow RFC 9207: require when AS metadata advertises `authorization_response_iss_parameter_supported`, always reject a **present but wrong** `iss`. |
| CIMD now? | Out of scope. No CIMD types, routes, or catalog flags exist. Preserve DCR. |
| Audit sink? | New structured slog events (same family as connect). Do not extend product MCP events or invent a new audit bus. Never log tokens, codes, or secrets. |

## Affected Areas

- `pkg/app/oauth/proxy.go` + `proxy_types.go` + `tokens.go` — park expected IdP issuer; validate `iss` before redeem; emit `iss` on client redirect
- `pkg/api/handler/http/oauth/callback_handler.go` + `connect_handler.go` — pass `iss` query into app layer
- `pkg/app/oauth/connect.go` + `connect_types.go` + `connect_registration.go` — park expected upstream issuer; validate before exchange
- `pkg/app/oauth/ports.go` — `RegisteredClient.Issuer`; registrar contract
- `pkg/infra/oauth/dcr_registrar.go` — send `application_type=web`; bind/reject cached client by issuer; validate AS metadata `issuer`
- `pkg/infra/oauth/connect_store.go` — persist new `Issuer` field (JSON-compatible; old rows lack it)
- `pkg/app/oauth/metadata.go` — advertise `authorization_response_iss_parameter_supported`; accept/validate/echo `application_type` on DCR
- `pkg/api/handler/http/oauth/register_handler.go` — pass through `application_type`
- `pkg/app/oauth/idp_transport.go` — validate fetched IdP metadata `issuer`
- Tests: `proxy_test.go`, `connect_test.go`, `metadata_test.go`, `dcr_registrar_test.go`, `handlers_test.go`, `connect_handler_test.go`
- Docs: new OAuth harden / CIMD-prep note under `docs/mcp/`; update `google-workspace-oauth.md` (legacy IdPs omit `iss`); optionally copy/link `api-key-auth-and-external-credentials.md` into the worktree
- Out of scope files: vault credential schema, Enterprise Managed Auth (RUN-1112), DCR removal

## Approaches

1. **In-place harden at existing seams (RFC 9207-compatible)** — Add issuer fields and checks on current types/handlers; emit `iss` as AS; validate as client per RFC 9207; DCR `application_type`; slog audit; docs + CIMD migration note. Legacy cached clients without `Issuer` get bound on next successful discover (stamp) or re-register if discover issuer ≠ empty-and-unbound after first stamp.
   - Pros: Smallest diff; matches hexagonal ports already in place; keeps Google/manual providers working; no Redis key rewrite; DCR stays.
   - Cons: Two callback signatures grow; must be careful not to log secrets; unbound legacy cache needs an explicit one-time stamp rule.
   - Effort: Medium

2. **New `oauth/security` package + always-require `iss`** — Extract validator/binder; fail closed if `iss` is missing.
   - Pros: Cleaner unit surface; strongest mix-up story for MCP-native ASes.
   - Cons: Extra package for ~one function; **breaks Google Workspace and other manual IdPs** that never send `iss`; larger PR vs 400-line budget.
   - Effort: High

3. **Feature-flagged observe-then-enforce** — Log mismatches first; enforce behind a gateway/env flag.
   - Pros: Safest rollout if production IdP behavior is unknown.
   - Cons: Mix-up stays exploitable until the flag flips; two behaviors to test; ticket QA wants mix-up **rejected**. Flag is unnecessary if RFC 9207 presence rules already protect legacy IdPs.
   - Effort: Medium–High

## Recommendation

**Approach 1.** Harden the existing northbound broker and southbound DCR/connect paths. Do not add a new package or a kill-switch.

Concrete policy for propose/design:

1. **As AS (northbound):** always set `iss` on authorization redirects to `baseURL` (same value as metadata `issuer`); advertise `authorization_response_iss_parameter_supported: true`.
2. **As client (IdP + upstream):** validate `iss` before code redeem. Reject mismatch always. Reject missing `iss` only when the expected AS metadata advertised the parameter (or we are the ones who discovered an MCP-modern AS that did). Google/manual static endpoints → allow missing `iss`.
3. **Credential binding:** add `Issuer` to `RegisteredClient`. On cache hit, if stored issuer is set and ≠ discovered issuer → reject, slog audit, re-register (same as redirect-URI change). If stored issuer is empty (pre-1106) → stamp current issuer, do not force users through consent.
4. **`application_type`:** southbound DCR sends `web`. Northbound DCR accepts `web`\|`native`, defaults by redirect URI (https → web, loopback/private-use → native), rejects inconsistent pairs (e.g. `web` + `cursor://`).
5. **Metadata:** validate discovered/fetched AS `issuer` equals the identifier used to fetch it (RFC 8414 / OIDC). Invalid metadata → error + audit, no redeem/register.
6. **Audit:** slog events `oauth.issuer_mismatch` and `oauth.invalid_metadata` with issuer URLs, gateway/registry/provider ids — never tokens, codes, secrets, or raw registration bodies.
7. **CIMD:** document only — DCR remains the runtime path; CIMD is a future client_id-as-URL option when hosts and clients support it. Do not add routes or remove `/oauth/register`.
8. **Rollout:** existing vault grants and DCR clients keep working; first discover after deploy stamps issuer. Operators reconnect only if an upstream actually changed AS.

## Risks

- **Legacy IdP break** if someone later tightens “missing `iss`” to always-reject (Google Workspace).
- **Pre-1106 DCR rows** without `Issuer` are briefly unbound; stamp-on-read closes the window without consent churn. Do not treat empty issuer as mismatch.
- **Issuer string normalization** (trailing slash, http/https, path) — must use one compare helper or false mismatches will re-register and invalidate refresh tokens.
- **Discovery cache TTL (1h)** can delay seeing a real AS change; issuer check on cached client still fires when discovery eventually updates.
- **PR size:** metadata + two callbacks + DCR + tests + docs can exceed 400 lines — split tests/docs if needed.
- **CIMD confusion:** docs must say DCR is not going away in this change.

## Ready for Proposal

Yes. Orchestrator should run **sdd-propose** for `run-1106-oauth-harden-2026-07-28` using Approach 1. No blocking product questions remain; RFC 9207 presence rules resolve the Google/`iss` tension from the codebase.
