# Exploration: RUN-1112 Enterprise-Managed Authorization

## Current State

TrustGate is already the MCP Authorization Server. An MCP client discovers `/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server`, registers at `/oauth/register` (public DCR, `token_endpoint_auth_method: none`), authorizes at `/oauth/authorize` (PKCE S256 → configured IdP), and redeems at `/oauth/token` (`authorization_code` | `refresh_token` only).

When `session_mode` is on, `/oauth/token` mints a TrustGate session JWT (`sub`, `scope`, `authid`, `gwid`, `aud`, `token_use=mcp_session`, 1h) plus a `gwrt_` refresh token. `MCPAuthMiddleware` → `chainIdentityResolver` verifies that session (`token_use` must be `mcp_session`) and attaches `AuthID` + `identity.Principal`. `RoleScoper` then evaluates `principal.Claims` via `OIDCResolver`. Consumer, toolkit, plugins, and composer stay downstream of that principal.

There is **no** ID-JAG / RFC 7523 path. `TokenRequest` has no `assertion`. AS metadata advertises only `authorization_code` and `refresh_token`. Auth types remain `api_key | oauth2 | oidc | mtls`. MCP consumers **cannot** attach `TypeOIDC` — interactive MCP requires `oauth2` so the gateway can broker login (`auth_rules.go`).

JWT validation already exists and is reusable: `pkg/infra/auth/oidc` (JWKS cache 5m, HMAC/`none` rejected, `iss`/`aud`/`exp`/`nbf`/scopes). RUN-1106 just added `IssuersEqual`, RFC 9207 `iss` (Google/manual IdPs may omit), DCR issuer bind, and slog `oauth.issuer_mismatch` / `oauth.invalid_metadata`. Invalid AS metadata is not cached.

ID-JAG (IETF `draft-ietf-oauth-identity-assertion-authz-grant-04`, pinned by MCP EMA): client obtains the grant at the **enterprise IdP** (RFC 8693 — out of TG scope), then POSTs to TG `/oauth/token`:

```
grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
assertion=<ID-JAG JWT>
```

Required JWT: `typ=oauth-id-jag+jwt`, `iss`, `sub`, `aud` = **Resource AS issuer** (TG `baseURL`), `client_id`, `jti`, `exp`, `iat`. Optional: `resource`, `scope`, `email`, `nbf`, `act`. Email is linking only. `act` is dual-identity (RUN-1117) — do not implement.

Cursor does not publicly document EMA/ID-JAG as of 2026-08. Mode must stay optional; default remains interactive OIDC.

### Constraints from code

| Question | Answer |
|---|---|
| New Auth type? | **No.** MCP already forbids `TypeOIDC`. Add a mode on `OAuth2Config`. |
| What token to mint? | Always the existing session JWT via `mintSession`. Never return the ID-JAG; never propagate it southbound. |
| ID-JAG `aud` vs `oauth2.audiences`? | Different. ID-JAG `aud` = TG AS issuer (`baseURL`). `oauth2.audiences` stay the inbound/session `aud` minted onto the TG token. |
| Public DCR clients? | TG advertises `token_endpoint_auth_methods_supported: ["none"]`. Bind `client_id` claim to form `client_id`; do **not** require a client secret. |
| `both` fallback? | Interactive OIDC stays. A **failed** jwt-bearer must return `invalid_grant`, never fall through to code/OIDC. |
| `ema` and `/oauth/authorize`? | Reject new interactive starts. Keep `refresh_token` for already-minted sessions. |
| Replay? | `jti` is required. No jti store exists — add a TTL store (`exp`). Fail closed if the store is down. |
| Audit sink? | slog, same family as RUN-1106. No product MCP event bus. Never log grants/tokens/secrets/claims/email. |
| RUN-1106 Google omit-`iss`? | Do not touch `Callback` / `validateResponseISS`. EMA is a different hop. |
| RUN-1117? | Note the seam only. Do not add `Principal.Actor` or map ID-JAG `act`. |

## Affected Areas

- `pkg/domain/auth/config.go` + `config_test.go` — `northbound_mode` (`oidc` default / `ema` / `both`) and optional EMA fields on `OAuth2Config` (expected resources, claim map). No new `Type`.
- `pkg/app/oauth/metadata.go` — advertise `urn:ietf:params:oauth:grant-type:jwt-bearer` and `io.modelcontextprotocol/enterprise-managed-authorization` **only** when mode is `ema` or `both`.
- `pkg/app/oauth/proxy.go` + `proxy_types.go` — `TokenRequest.Assertion`; `Exchange` jwt-bearer branch; `Authorize` reject when mode is `ema`.
- `pkg/api/handler/http/oauth/token_handler.go` — read `assertion`.
- New `pkg/app/oauth` ID-JAG validator (keep in oauth; do not invent a parallel Auth stack) — typ, sig via existing OIDC verifier/JWKS, trusted issuer, aud=`baseURL`, resource, scopes, exp/nbf, `client_id`, jti replay. Reuse `IssuersEqual`.
- `pkg/app/oauth/ports.go` / FlowStore (or sibling) — jti consume-once with TTL=`exp`.
- `pkg/infra/auth/oidc/{verifier,jwks_cache,discovery}.go` — reuse; pin JWKS to **configured** issuer/JWKS URL only (no assertion-driven discovery). Fail closed on refresh errors.
- Identity mapping into existing `identity.Principal` + `mintSession` (`authid`, `gwid`, `aud`, `token_use=mcp_session`). Primary id = `iss`+`sub` (or configured `subject_claim`). Email = optional link only.
- Unchanged after mint: `MCPAuthMiddleware`, `auth_chain.go` session path, `RoleScoper`, consumer AuthID, toolkit, plugins, composer.
- Tests: `proxy_test.go`, `metadata_test.go`, `handlers_test.go`, `config_test.go`, new ID-JAG table tests, functional MCP auth.
- Docs: `docs/mcp/enterprise-managed-authorization.md` (IdP registers TG as approved MCP resource; client support matrix — Cursor unconfirmed). Update `oauth-harden.md` (EMA is this change, not 1106).
- Out of scope files: southbound connect/DCR, vault schema, `Principal.Actor`, TypeOIDC, upstream MCP servers.

## Approaches

1. **In-place jwt-bearer on existing `oauth2` Auth (mode field)** — Add `northbound_mode` to `OAuth2Config`. Extend `/oauth/token` and AS metadata. Validate ID-JAG with existing OIDC verifier + RUN-1106 issuer helpers. Always `mintSession`. slog audit + jti store.
   - Pros: No Auth-model fork; MCP consumers already use `oauth2`; session/middleware/RoleScoper reused; OIDC path untouched when mode is `oidc`; `both` is a grant-type switch, not a second IdP.
   - Cons: `OAuth2Config` grows; ID-JAG `aud` (AS issuer) must not be confused with `oauth2.audiences`; public-client `client_id` bind needs care; jti store is new infra.
   - Effort: Medium (implementation) / High if tests+docs stay in one PR (400-line risk).

2. **New `TypeEMA` Auth** — Second identity-provider type beside `oauth2`/`oidc`.
   - Pros: Clean config isolation.
   - Cons: Duplicates the Auth model (ticket forbids); MCP attach rules and RoleScoper would need a third IdP type; operators would split OIDC vs EMA across two auths.
   - Effort: High

3. **New `oauth/ema` package + observe-then-enforce flag** — Extract validator; advertise extension behind a kill-switch; log mismatches first.
   - Pros: Smaller blast radius if IdP JWT shapes are unknown.
   - Cons: Extra package for one grant; observe mode leaves mix-up/replay open; ticket QA wants fail-closed. Optional **mode** already covers rollout (`oidc` → `both` → `ema`).
   - Effort: Medium–High

## Recommendation

**Approach 1.** Keep one `oauth2` Auth. Default `northbound_mode=oidc` (empty = oidc). EMA is an additional token grant, not a new identity system.

Concrete policy for propose/design:

1. **Mode**
   - `oidc`: current behavior. jwt-bearer → `unsupported_grant_type`. No EMA advertisement.
   - `both`: advertise EMA; accept jwt-bearer **and** interactive OIDC. Failed jwt-bearer is `invalid_grant` (no silent OIDC downgrade). Optional slog `oauth.ema.fallback` only when the client **chose** authorize/code, never after a failed assertion.
   - `ema`: advertise EMA; reject `/oauth/authorize`; accept jwt-bearer; keep `refresh_token` for minted sessions.

2. **Validation (fail closed)** — configured issuer + JWKS only; `typ=oauth-id-jag+jwt`; reject `none`/HMAC/alg confusion (reuse `validateAlgorithm`); `iss` via `IssuersEqual`; `aud` is exactly TG `baseURL` (single string or one-element array per draft-04); `resource` must match the requested TG MCP resource (RFC 8707); scopes ⊆ configured allowed; `exp`/`nbf`/`iat`; `client_id` matches form `client_id` of a registered gateway client; consume `jti` until `exp`. Metadata/JWKS refresh errors deny the grant and are not cached as success.

3. **Mint** — always `mintSession` with IdP `sub` (stable `iss`+`sub`, or `subject_claim`; Entra `oid` only if explicitly configured — do not silently prefer `oid` over `sub` for EMA). Copy approved claims into session claims so `RoleScoper` still works. Bind `authid` + `gwid` + session `aud` from the accepting oauth2 Auth. Short expiry stays 1h.

4. **Email** — never `Principal.Subject`. Optional controlled link to a pre-EMA account; if link fails, still accept on `iss`+`sub` (JIT). Do not log email.

5. **RUN-1117 seam** — EMA fills the **end-user** `Principal.Subject`. `AuthID` remains the consumer-attached oauth2 auth. Leave `act` unmapped. Do not add `Principal.Actor`.

6. **RUN-1106** — reuse issuer compare + slog shape. Do not change Google omit-`iss` on the interactive callback.

7. **SSRF** — JWKS/discovery only from configured https issuer/JWKS URL. Do not follow `iss` from the assertion to a new host.

8. **Docs** — IdP-side: register TG AS issuer + MCP resource URI; group/policy at the IdP. Client matrix: no confirmed Cursor EMA support as of 2026-08; treat as optional.

9. **Delivery** — expect >400 lines. Default split: (1) config+metadata, (2) validator+jti+token grant+mint, (3) tests+docs+slog. Stack on `feat/run-1112-enterprise-managed-authorization` (base 1103; retarget develop after #400).

## Risks

- **Client support gap** — Cursor/other MCP clients may not send ID-JAG yet. Default `oidc` and `both` are mandatory; do not require EMA globally.
- **ID-JAG `aud` vs session `aud` confusion** — mixing them accepts foreign grants or mints wrong-audience sessions.
- **Public-client `client_id` spoofing** — DCR is `none`; bind assertion `client_id` to the registered gateway client and to the requested resource/consumer.
- **jti store availability** — fail closed (deny) if Redis/store is down; do not accept without replay protection.
- **JWKS SSRF / cross-issuer reuse** — assertion-driven discovery would fetch attacker URLs; pin to configured issuer/JWKS.
- **Entra `oid` vs `sub`** — existing `subjectOf` prefers `oid` for vault keys. Silent reuse on EMA would diverge from the spec’s `iss`+`sub` primary id. Make it an explicit `subject_claim`.
- **`both` misuse** — operators may think `both` means “try EMA then OIDC on the same request.” It does not.
- **RUN-1117 collision** — mapping `act` or growing `Principal` here would pre-empt the dual-identity spike.
- **PR size** — validator + tests + docs will exceed the 400-line review budget unless chained.
- **IETF draft churn** — ID-JAG is draft-04 (expires 2026-11). Pin draft-04 + MCP extension name; do not chase later drafts in this change.

## Ready for Proposal

Yes. Orchestrator should run **sdd-propose** for `run-1112-enterprise-managed-authorization` using Approach 1. No blocking product questions remain: mode lives on `OAuth2Config`, EMA always mints the existing session token, OIDC stays default, RUN-1117 is a documented seam only.
