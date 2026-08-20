# Proposal: Enterprise-Managed Authorization (RUN-1112)

## Intent

Enterprise MCP clients exchange an IdP ID-JAG at `/oauth/token` for the existing TG session JWT. OIDC stays default. No Auth-model fork. RoleScoper, AuthID, toolkit, plugins stay.

## Scope

### In Scope
- `northbound_mode` on `OAuth2Config`: `oidc` (default) | `ema` | `both`
- jwt-bearer + ID-JAG (draft-04) vs configured issuer/JWKS; `jti` until `exp`
- Always `mintSession`
- Advertise `jwt-bearer` + `io.modelcontextprotocol/enterprise-managed-authorization` only when `ema`|`both`
- slog accept/deny — never grants/tokens/secrets/claims
- Docs: IdP registers TG as MCP resource; client matrix (Cursor unconfirmed)

### Out of Scope
- `TypeEMA`; `Principal.Actor` / `act` (RUN-1117)
- Google omit-`iss` (RUN-1106); global EMA; Cursor allowlists
- Southbound EMA; ID-JAG propagation; assertion-driven JWKS

## Capabilities

### New Capabilities
- `mcp-enterprise-managed-authorization`: mode, jwt-bearer/ID-JAG, mint, metadata, jti, slog, fail-closed JWKS.

### Modified Capabilities
- None (`mcp-dual-era-northbound` era-only; `mcp-oauth-harden` reused, unchanged).

## Approach

**Approach 1** (locked): in-place jwt-bearer on existing `oauth2` Auth.

- `oidc`: jwt-bearer → `unsupported_grant_type`; no EMA ad
- `both`: advertise EMA; jwt-bearer **and** OIDC; failed assertion → `invalid_grant` (no silent downgrade)
- `ema`: advertise EMA; reject `/oauth/authorize`; keep `refresh_token`
- Validate: `typ=oauth-id-jag+jwt`; configured issuer/JWKS; `IssuersEqual`; `aud=baseURL`; resource; scopes ⊆ allowed; exp/nbf/iat; bind `client_id`; consume `jti`; reject `none`/HMAC
- Mint: session JWT; id `iss`+`sub` (or explicit `subject_claim`); email linking only
- Pin draft-04. Chain: (1) config+metadata (2) validator+jti+grant+mint (3) tests+docs+slog

## Affected Areas

- `pkg/domain/auth/config.go` — `northbound_mode` + EMA fields; no new Type
- `pkg/app/oauth/metadata.go` — jwt-bearer + EMA extension when `ema`|`both`
- `pkg/app/oauth/proxy.go`, `proxy_types.go`, `token_handler.go` — `Assertion`; jwt-bearer Exchange; ema Authorize reject
- `pkg/app/oauth` validator + jti port — new ID-JAG validate; jti TTL store
- `pkg/infra/auth/oidc/*` — reuse; configured JWKS only; fail closed
- `docs/mcp/enterprise-managed-authorization.md` — IdP + client matrix

## Risks

- Clients lack EMA (High) — default `oidc`; `both` optional
- `aud` mix-up / `client_id` spoof (Med) — `aud=baseURL`; bind registered client + resource
- jti down / JWKS SSRF (Med) — fail closed; configured https JWKS only
- Entra `oid` vs `sub` (Med) — explicit `subject_claim`
- RUN-1117 / PR size / draft (Med) — no `act`; 3 slices; pin draft-04

## Rollback Plan

Set `northbound_mode=oidc`. Revert slices reverse-order. jti additive; no Redis rewrite.

## Dependencies

- RUN-1106 (blocks; reuse `IssuersEqual`, slog)
- Stacked on RUN-1103 tip; retarget `develop` after #400
- RUN-1117 seam only

## Success Criteria

- [ ] Valid ID-JAG → TG session JWT; invalid typ/sig/iss/aud/resource/scope/exp/nbf/jti → `invalid_grant`
- [ ] `oidc` unchanged; `both` no silent downgrade; `ema` rejects authorize, keeps refresh
- [ ] EMA advertised only when `ema`|`both`
- [ ] Principal is `iss`+`sub`; email linking only; RoleScoper works
- [ ] No grants/tokens/secrets/claims in logs; JWKS from configured URLs only
- [ ] Docs list confirmed clients (Cursor unconfirmed)
