# Exploration: Gateway-minted session token (RUN-712, Option C)

Worktree: `TrustGate-gateway-session-token` (branch `feat/gateway-session-token`, base `origin/develop`).
All file:line anchors are from this worktree.

## Problem restated

The MCP OAuth facade brokers login to an upstream IdP and then **passes the IdP
access token straight through** to the MCP client as the gateway's own token.
Every MCP request re-validates that foreign token (JWKS/JWT or RFC 7662
introspection) and derives `principal.Subject` from it; the same subject keys
the forwarded-auth vault. This only works for JWT-issuing IdPs (Okta). Opaque
IdPs (GitHub) break: consent chaining is skipped (no subject), and per-request
auth cannot validate the opaque token nor derive a stable subject.

Option C: the gateway mints **its own** session token at login, captures the
subject once during callback (id_token / userinfo), persists it gateway-side,
and validates the gateway token **locally** on each MCP request.

---

## Current State — end-to-end flow (code-anchored)

### A. Login & token handback (MCP client ↔ gateway facade) — `pkg/app/oauth/proxy.go`

1. **`Authorize`** (`proxy.go:67`): validates `response_type=code` + PKCE S256,
   resolves the IdP auth record via `authForResource`, generates `state` +
   gateway↔IdP PKCE `verifier`, parks a `PendingAuthorization` (`proxy_types.go:39`)
   keyed by `state` in the Redis `FlowStore` (`SavePending`, `store.go:47`,
   TTL 10m), and redirects the user-agent to the IdP authorize endpoint.
2. **`Callback`** (`proxy.go:126`) on `/oauth/callback`:
   - `TakePending` consumes the parked state.
   - `idpTokenCall` (`proxy.go:299`) exchanges the code at the IdP token endpoint
     → `token map[string]any` (the **raw IdP token response**; `decodeTokenResponse`
     at `proxy.go:334` also handles GitHub's form-encoded bodies).
   - mints a gateway authz `code = randomToken()` (`proxy.go:165`) and stores a
     `CodeGrant{ClientID, RedirectURI, CodeChallenge, Token: token}`
     (`proxy_types.go:51`) keyed by `gwCode` in Redis (`SaveCode`, `store.go:60`,
     TTL 5m). **The stored token IS the IdP token map.**
   - **`consentDetour`** (`proxy.go:185`): `sub := subjectFromToken(token)`
     (`proxy.go:205`) JWT-parses the IdP **access_token** for `oid`/`sub`. For an
     opaque token this returns `""` → logs *"consent chaining skipped: no subject
     in IdP access token"* (`proxy.go:191`) → **downstream never links** (bug #1).
   - redirects to client `?code=gwCode` (or to the consent detour URL).
3. **`Exchange` → `exchangeCode`** (`proxy.go:221`, `:232`) via `TokenHandler.Handle`
   (`token_handler.go:37`): `TakeCode` consumes `gwCode`, checks redirect_uri /
   client_id / PKCE (`s256(verifier) == grant.CodeChallenge`), then **returns
   `grant.Token` verbatim** (`proxy.go:252`) — the IdP token map is handed to the
   MCP client as the gateway token (the pass-through).

### B. MCP request auth (per request) — `pkg/api/middleware/`

1. **`MCPAuthMiddleware.Middleware`** (`mcp_auth.go:61`) → `chainIdentityResolver.Resolve`
   (`auth_chain.go:106`): mTLS → bearer → API key.
2. Bearer: **`resolveBearer`** (`auth_chain.go:163`) loads OAuth2 auth candidates,
   branches on `isJWT(token)` (3 dot-separated segments, `auth_chain.go:281`):
   - **`resolveJWT`** (`auth_chain.go:174`): match candidate by unverified issuer
     (`unverifiedIssuer`); validate via `jwt.Validate` (JWKS / OIDC discovery,
     `oidc/oauth2_validator.go:43`) when `JWKSURL != "" || IntrospectionURL == ""`,
     else `intro.Validate` (`introspection/validator.go:74`). Produces
     `identity.Principal{Subject: subjectOf(verified) (oid→sub, oauth2_validator.go:81),
     Method: MethodJWT, RawToken: raw}`.
   - **`resolveOpaque`** (`auth_chain.go:199`): **requires `cfg.IntrospectionURL`**;
     with none → `ErrUnauthenticated`. GitHub opaque tokens with no introspection
     die here (bug #2).
3. **`MCPAuthMiddleware.attach`** (`mcp_auth.go:80`): puts the `Principal` into ctx
   via `identitydomain.WithPrincipal` (`mcp_auth.go:89`). `Principal` shape:
   `principal.go:31` (`Subject, Method, Issuer, Claims, Scopes, RawToken`).

### C. Principal → vault (forwarded auth read side) — `pkg/app/mcp/credentials.go`

- **`credentialResolver.forwarded`** (`credentials.go:118`):
  `principal := identity.PrincipalFromContext(ctx)`;
  `r.vault.Find(ctx, gatewayID, principal.Subject, cfg.Provider)` (`credentials.go:125`).
  **Vault read key = `(gatewayID, principal.Subject, provider)`.**
- on `ErrNotFound` → `consentRequired` (`credentials.go:194`) mints a connect ticket
  carrying `principalSub`.
- (Other modes for context: `passthrough` at `credentials.go:92` forwards
  `principal.RawToken` + checks `HasAudience`; `exchange` at `credentials.go:104`
  keys an STS cache on `principal.Subject`.)

### D. Consent chain (vault write side) — `pkg/app/oauth/connect_chain.go` + `connect.go`

- **`ChainURL`** (`connect_chain.go:27`) / `hasUnlinked` (`connect_chain.go:72`):
  `principalSub` is the vault key probed against each forwarded-auth provider; an
  unlinked provider mints a `ConnectTicket{PrincipalSub, ...}` (`connect_types.go:31`).
- **`connectService.Callback`** (`connect.go:125`) after the downstream OAuth dance:
  `vaultdomain.NewCredential(gatewayID, st.Ticket.PrincipalSub, provider, ...)` then
  `vault.Upsert` (`connect.go:152-159`). **Vault write key = `ticket.PrincipalSub`.**

**Subject parity invariant:** the `sub` captured at callback (→ `consentDetour` →
`ChainURL` → `ticket.PrincipalSub` → vault **write**) must equal `principal.Subject`
derived on each MCP request (vault **read**). Today both derive from the IdP access
token; for opaque IdPs both are empty → the whole chain breaks.

### E. Auth config domain — `pkg/domain/auth/config.go`

- `OAuth2Config` (`config.go:34`): `Issuer, Audiences, JWKSURL, IntrospectionURL,
  ClientID, ClientSecret, RequiredScopes, Algorithms`. **No `userinfo_url`, no
  `subject_claim`, no session-mode switch.**
- `OIDCConfig` (`config.go:45`) **already has `SubjectClaim`** (`config.go:52`) —
  precedent for a configurable subject claim.

### F. Reusable minting / signing infra (KEY FINDING — already exists)

- **`pkg/infra/identity/sts/signer.go`** `Signer`: mints **RS256 JWTs** with
  `iss/iat/exp/jti` + `kid` header (`MintClaims`, `signer.go:68`) and exposes a
  **JWKS** (`signer.go:90`). Keyed off `STS_SIGNING_KEY` (RSA PEM) / `STS_ISSUER`
  (default `"trustgate"`) — `config.go:130-131`, DI at `mcp.go:60`. Falls back to an
  ephemeral key in dev (not shared across replicas).
- App port: `pkg/app/identity/sts/ports.go:26` `TokenSigner{ Issuer(); MintClaims(...);
  JWKS() }`.
- The gateway **already serves** `/.well-known/jwks.json` from this signer
  (`oauth/jwks_handler.go:32`, `JWKSPath = "/.well-known/jwks.json"`).
- The STS `exchanger.mint` (`sts/exchanger.go:147`) is a working example of minting a
  gateway JWT with `sub/aud/scope` claims via this signer.
- The OIDC verifier (`pkg/infra/auth/oidc`, via `OAuth2TokenValidator`,
  `oauth2_validator.go`) can verify a JWT against a JWKS URL — usable to validate the
  gateway's own session JWT, though in-process public-key validation avoids an HTTP hop.
- Secondary, **not** the right tool: `pkg/infra/auth/jwt/jwt_manager.go` mints HS256
  admin/playground tokens off `SERVER_SECRET_KEY` (no `kid`, no JWKS).

### G. DI wiring

- Chain resolver: `api.go:89` `NewChainIdentityResolver(apiKeys, credentials, paths,
  NewOAuth2TokenValidator, NewValidator(introspection), mtls, xfcc, TrustXFCCFrom)`.
- AuthProxy: `api.go:144-150` `NewAuthProxy(credentials, paths, nil, store, connect)`.
- MetadataService / FlowStore: `api.go:134-143`.
- STS signer + exchanger: `mcp.go:60`, `:74`. ConnectService / CredentialResolver:
  `mcp.go:101-117`.
- Layering (per `.agents/AGENT.md` §3): `domain` (stdlib only) ← `app` (ports + use
  cases, one interface/file, `//go:generate mockery`) ← `infra` (adapters) ← `modules`
  (dig). **No code comments anywhere** (§11, enforced by pre-commit hook).

---

## Affected Areas (insertion points for Option C)

- `pkg/domain/auth/config.go` — add `OAuth2Config` fields: `UserInfoURL`,
  `SubjectClaim`, and a session switch (e.g. `SessionMode`/`MintSession`); extend
  `validate()`. Mirror existing `OIDCConfig.SubjectClaim`.
- `pkg/app/oauth/proxy.go` — `Callback` (`:160-182`): after `idpTokenCall`, **capture
  subject once** from `id_token` (decode JWT in the token map) or a **userinfo** call
  (new); feed that subject to both `consentDetour` and session minting. Replace/augment
  `subjectFromToken` (`:205`). `exchangeCode` (`:252`) must return the **gateway** token,
  not `grant.Token`.
- New app port + infra adapter for the session token (e.g. `pkg/app/oauth/session.go`
  `SessionMinter`/`SessionValidator`, or reuse `sts.TokenSigner`) + optional
  `SessionStore` (extend `FlowStore`/`store.go` or a new Redis store) to persist
  `subject` (+ maybe IdP refresh token).
- `pkg/app/oauth/proxy_types.go` — extend `CodeGrant` to carry the captured subject /
  gateway session material instead of (or beside) the IdP token map.
- `pkg/api/middleware/auth_chain.go` — add a branch in `resolveBearer`/`resolveJWT`/
  `resolveOpaque` that recognizes the gateway-minted token (issuer == gateway STS
  issuer, or opaque-token prefix + session-store lookup) and validates it **locally**
  (no IdP round-trip), producing a `Principal{Subject: sessionSubject}`. Keep Okta JWT
  pass-through untouched (backward compat).
- `pkg/container/modules/api.go` (+ `mcp.go`) — inject the signer / new session port
  into `NewAuthProxy` and the chain resolver.
- Tests: `proxy_test.go`, `auth_chain_test.go`, `mcp_auth_test.go`, `credentials_test.go`,
  plus functional coverage for opaque-IdP login + consent/vault subject parity.

---

## Approaches

1. **Stateless signed JWT, reuse the STS signer** — mint the session token via the
   existing `sts.TokenSigner` (RS256, `sub = capturedSubject`, gateway `iss`/`aud`),
   validate per-request **in-process** against the signer's public key / JWKS.
   - Pros: reuses minting + JWKS + `/.well-known/jwks.json` that already ship; no new
     persistence; no IdP round-trip on the hot path; subject embedded → parity is free.
   - Cons: revocation is hard (TTL-bound only); if downstream `passthrough`/`exchange`
     modes still need the **IdP** token, it must be stored somewhere anyway; ephemeral
     dev key already warned about (multi-replica needs a shared key).
   - Effort: **Medium**.

2. **Opaque gateway token + Redis session store** — issue a random token, persist
   `token → {subject, idp_tokens, scopes, exp}` (extend `FlowStore` or a new store),
   look it up per-request.
   - Pros: revocable; natural home for the IdP access/refresh token (keeps
     passthrough/exchange working); explicit session lifecycle.
   - Cons: a Redis read on the MCP hot path (still no IdP call, so satisfies the AC);
     more new infra (store, TTL, refresh).
   - Effort: **Medium-High**.

3. **Hybrid** — signed JWT for identity (subject/parity, local validation) **plus** a
   session store keyed by `jti`/subject holding the IdP refresh token for downstream
   modes and revocation.
   - Pros: best of both — local validation + revocation + IdP-token availability.
   - Cons: most moving parts; two artifacts to keep consistent.
   - Effort: **High**.

## Recommendation

Lead with **Approach 1 (stateless signed JWT via the existing STS signer)** because
the minting, JWKS, and `/.well-known/jwks.json` plumbing already exist and it directly
satisfies the "no per-request IdP round-trip" AC with subject parity for free. Add a
**minimal session store only if** an open question forces it — specifically if
downstream `passthrough`/`exchange` modes must keep receiving the **IdP** token (then
store the IdP token, Approach 3-lite), or if revocation is a hard requirement. Gate the
whole behavior behind a per-auth/per-gateway switch so Okta JWT gateways keep their
current pass-through path unchanged.

## Risks

- **Backward compatibility / token disambiguation**: the chain resolver must reliably
  tell a gateway-minted token from a pass-through IdP token without regressing Okta.
  Issuer match against the gateway STS issuer is the natural discriminator but must be
  airtight.
- **Downstream auth-mode coupling**: `passthrough` forwards `principal.RawToken` and
  checks audience; `exchange` (OBO/token-exchange) needs the **IdP** token and
  `Method == MethodJWT`. Minting our own token changes `RawToken`/`Method` — these modes
  may break unless the IdP token is preserved and the validation branch sets compatible
  `Method`/audience.
- **Key management in prod/multi-replica**: ephemeral signer key is dev-only; a shared
  `STS_SIGNING_KEY` is required, and reusing the STS issuer for session tokens conflates
  two roles.
- **Subject stability across IdPs**: GitHub userinfo returns numeric `id` + `login`;
  the chosen subject must be deterministic and match what already-linked vault rows
  used (migration/parity concern for existing data).
- **Refresh semantics**: whether the gateway session token has its own refresh, and
  whether refresh re-touches the IdP, is unresolved (see open questions).

## Open Questions (resolve before design)

1. **Token format** — stateless signed JWT (reuse STS signer, in-process validation)
   vs opaque token + Redis session store? Drives persistence + revocation.
2. **Session persistence** — none (JWT-embedded) vs a new `SessionStore`/extended
   `FlowStore`? Must we store the **IdP** access/refresh token for downstream
   `passthrough`/`exchange` modes?
3. **Key management** — reuse `STS_SIGNING_KEY`/`STS_ISSUER` and the existing JWKS, or a
   dedicated session-signing key + issuer? Confirm shared-key requirement for replicas.
4. **Backward-compat switch** — global default vs per-gateway/per-auth flag
   (`session_mode: minted|passthrough`)? How does `auth_chain.go` discriminate the
   gateway token from an Okta JWT (issuer? audience? prefix?) without regression?
5. **Subject source & precedence** — `id_token.sub/oid` vs userinfo (`sub`/`id`/`login`)
   vs configurable `subject_claim`. Which is authoritative, and does it match existing
   vault rows?
6. **Subject capture mechanism** — request `openid` scope to get an `id_token`, or call
   a configured `userinfo_url` (GitHub `https://api.github.com/user`)? Userinfo endpoint
   discovery (extend `fetchASMetadata`, `metadata.go:252`) vs explicit config field?
7. **Refresh semantics** — does the gateway session token get a refresh_token? On refresh
   do we re-validate/refresh the upstream IdP token, or just re-issue from the stored
   session? Session TTL vs IdP token lifetime.
8. **Audience/scope enforcement** — what `aud` does the gateway session token carry (the
   MCP resource?) so `passthrough` `HasAudience` and `RequiredScopes`/`HasScopes` checks
   still hold for minted tokens?

## Ready for Proposal

**Yes.** The flow is fully mapped and the insertion points are concrete. The proposal
should pick a token format (Approach 1 vs 3-lite) and resolve open questions #2, #4, and
#7 (persistence, the backward-compat switch, and refresh semantics) before design.
