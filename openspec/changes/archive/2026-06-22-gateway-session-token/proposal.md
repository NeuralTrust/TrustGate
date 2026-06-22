# Proposal: Gateway-minted session token for opaque-token IdPs (RUN-712, Option C)

## Intent

The MCP OAuth facade brokers login to an upstream IdP and **passes the IdP access token
through** as the gateway's own token (`exchangeCode` returns `grant.Token`,
`pkg/app/oauth/proxy.go:252`). Every MCP request re-validates that foreign token as a JWT
(JWKS) or via RFC 7662 introspection and derives `principal.Subject`, which keys the
per-user forwarded-auth vault.

This works for **JWT IdPs (Okta)** but breaks for **opaque-token IdPs (GitHub)**:
- Consent chaining is skipped — `subjectFromToken` (`proxy.go:205`) can't parse an opaque
  access token → *"no subject in IdP access token"* (`proxy.go:191`); the vault is never linked.
- MCP request auth can't validate the opaque token (`resolveOpaque` requires
  `IntrospectionURL`, `auth_chain.go:199`) nor derive a stable subject.

**Goal (Option C):** decouple the gateway session from the IdP token format. Mint a
gateway-owned session token at login, capture the subject **once** at callback, validate the
gateway token **locally** on MCP requests (no per-request IdP round-trip), and resolve the
subject from the session. Works for any OAuth2 IdP, JWT or opaque.

## Scope

### In Scope
- `OAuth2Config` additions: opt-in session switch + `UserInfoURL` + `SubjectClaim`.
- Callback subject capture (id_token → userinfo precedence) feeding both consent and minting.
- Mint a gateway RS256 session JWT via the existing STS signer; return it from `exchangeCode`.
- Opaque gateway refresh_token persisted in `FlowStore`; refresh re-mints from the session.
- Inbound local-validation branch for gateway-issued tokens in `auth_chain.go`.
- DI wiring; unit + functional tests (opaque login, subject derivation, validation, parity).

### Out of Scope
- Changing downstream `exchange`/`passthrough` vault mechanics beyond the subject source.
- Token revocation lists / denylists (TTL-bound only unless trivially free via refresh store).
- New key infrastructure — reuse `STS_SIGNING_KEY` / `STS_ISSUER`.
- Altering the Okta (JWT pass-through) path behavior.

## Capabilities

### New Capabilities
- `mcp-oauth-session-token`: gateway mints, validates locally, and refreshes its own session
  token for the MCP OAuth plane, decoupled from the upstream IdP token format.

### Modified Capabilities
- None (no existing OAuth spec; only `openspec/specs/budget` exists today).

## Approach

Stateless **RS256 JWT** minted by the existing `sts.TokenSigner.MintClaims`
(`pkg/infra/identity/sts/signer.go`), served by the gateway JWKS already exposed at
`/.well-known/jwks.json` (`oauth/jwks_handler.go`). Minted claims: `iss = STS_ISSUER`,
`aud = MCP resource/gateway`, `sub = captured subject`, `scopes`. Only an opaque gateway
**refresh_token** is persisted in `FlowStore` (`proxy_types.go`) → `{subject, scopes,
gatewayID, authID}`; the raw IdP token is discarded after subject capture.

**Subject capture (at `Callback`, `proxy.go:126`):** precedence `id_token` (when OIDC/openid
scope) → `UserInfoURL` (single GET with the IdP access token, e.g. GitHub
`https://api.github.com/user`), reading `SubjectClaim` (default `sub`; GitHub `id`/`login`).
The same captured subject feeds `consentDetour` (vault **write**) and the minted JWT `sub`
(vault **read**) → **subject parity by construction**.

**Inbound validation (`auth_chain.go`):** add a local-validation branch in `resolveBearer`
that recognizes tokens whose issuer == the gateway STS issuer, validates them **in-process**
against the signer's public key (no HTTP), and maps to the candidate auth by **audience + path
scope** — *without* touching the IdP-brokering fields. The critical reconciliation:
`resolveJWT` today selects the candidate auth by `cfg.Issuer == unverifiedIssuer(token)`, but
`OAuth2Config.Issuer` is also the upstream IdP issuer used by `Authorize`/refresh. In session
mode these **diverge**, so gateway tokens must be disambiguated by the STS issuer and never
matched against the IdP issuer field. The Okta JWT path (issuer == IdP) stays exactly as-is.

**Backward-compat:** an explicit per-auth opt-in flag on `OAuth2Config`. OFF (Okta + all
existing auths) = current pass-through, zero regression. ON = gateway mints its own session
token. **Refresh:** gateway issues its own refresh_token; `grant_type=refresh_token` re-mints
the short-TTL session JWT from the stored session (longer refresh TTL); no IdP re-touch.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `pkg/domain/auth/config.go` | Modified | Add session opt-in flag, `UserInfoURL`, `SubjectClaim` to `OAuth2Config`; extend `validate()` (mirror `OIDCConfig.SubjectClaim`). |
| `pkg/app/oauth/proxy.go` | Modified | `Callback`: capture subject once (id_token→userinfo); `exchangeCode` returns minted token; refresh re-mints. |
| `pkg/app/oauth/proxy_types.go` / `store.go` | Modified | `FlowStore` persists opaque refresh_token → `{subject, scopes, gatewayID, authID}`. |
| `pkg/app/oauth/*` (new port) | New | `SessionMinter`/subject-capture port + adapter (reuse `sts.TokenSigner`); userinfo fetch. |
| `pkg/api/middleware/auth_chain.go` | Modified | New STS-issuer-aware local-validation branch in `resolveBearer`; map by aud + path scope. |
| `pkg/container/modules/{api,mcp}.go` | Modified | Inject signer / session port into `NewAuthProxy` and chain resolver. |
| `*_test.go` + functional | New/Modified | Opaque login, subject derivation, local validation, consent/vault parity. |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Token disambiguation: gateway-JWT vs Okta-JWT | Med | Discriminate strictly by `iss == STS_ISSUER`; keep IdP-issuer match path untouched; tests assert no Okta regression. |
| Key management in prod / multi-replica | Med | Require stable `STS_SIGNING_KEY` (already enforced in prod, `mcp.go:60-65`); ephemeral key dev-only. |
| Wrong audience → wrong candidate auth | Med | Mint `aud` = MCP resource/gateway; map candidate by audience + path scope; validate `RequiredScopes`. |
| Refresh-token storage TTL / leakage | Low | Opaque refresh_token in Redis `FlowStore` with bounded TTL; session JWT short TTL. |
| Subject mismatch with existing vault rows | Med | `SubjectClaim` configurable; document GitHub `id` vs `login`; parity-by-construction for new links. |
| Downstream `exchange`/`passthrough` lose IdP token | Low | Out of scope here; session mode targets vault-keyed forwarded-auth (`Find` by subject), not passthrough. |

## Rollback Plan

Behavior is gated behind the per-auth opt-in flag. Rollback = set the flag OFF on affected
auths (config-only, no redeploy needed if config is hot-reloaded) → instant return to IdP
pass-through. Full revert = drop the `auth_chain.go` branch and config fields; no schema
migration is introduced (refresh_token lives in ephemeral Redis with TTL).

## Dependencies

- Existing STS signer + JWKS (`STS_SIGNING_KEY`, `STS_ISSUER`) — already wired.
- Redis `FlowStore` for refresh-token persistence — already present.

## Success Criteria

- [ ] GitHub (opaque) completes full MCP flow: login + consent detour to link Linear + authenticated MCP requests.
- [ ] Vault credential written at consent is found on later MCP requests for the same user (subject parity).
- [ ] Existing Okta (JWT) gateways keep working unchanged.
- [ ] No per-request call to IdP userinfo/introspection on the MCP hot path.
- [ ] Unit + functional tests cover opaque-IdP login, subject derivation, session-token validation, consent/vault parity.

## Impact / Size Estimate

**Medium.** ~6 source files touched + 1 small new port/adapter; no new key infra, no schema
migration. Test surface is the larger share (new opaque-IdP functional flow + parity assertions).
