# Design: Gateway-minted session token for opaque-token IdPs (RUN-712, Option C)

> Worktree `TrustGate-gateway-session-token` (`feat/gateway-session-token`). All anchors verified in-tree.
> Binding conventions: `.agents/AGENT.md` (hexagonal domain/app/infra/api, DI in `pkg/container/modules`, one
> interface/file + `//go:generate mockery`, **NO comments**) and `golang-pro` (error `%w`, ctx propagation,
> `go vet`/`golangci-lint` clean, `-race`). No deviation.

## Technical Approach

Mint a **stateless RS256 session JWT** at login via the existing `appsts.TokenSigner`
(`pkg/infra/identity/sts/signer.go`, already serving `/.well-known/jwks.json` through
`oauthhttp.JWKSHandler`). The subject is captured **once** at `Callback` (id_token → userinfo
precedence) and feeds both the consent vault-write (`consentDetour`→`ChainURL`→`ticket.PrincipalSub`)
and the minted `sub` (vault-read key on MCP requests) → **parity by construction**. Inbound MCP
requests validate the session JWT **in-process** against the signer's public key (no HTTP, no IdP
hop) in a new `auth_chain.go` branch keyed off `iss == signer.Issuer()`. An opaque gateway
**refresh_token** persists a session record in the existing Redis `FlowStore`; `grant_type=refresh_token`
re-mints locally. Everything is gated by a per-auth `session_mode` flag; OFF = today's pass-through
(Okta untouched).

## Architecture Decisions

| Decision | Choice | Rejected | Rationale |
|---|---|---|---|
| Token format | Stateless RS256 JWT via existing STS signer | Opaque token + mandatory Redis lookup on hot path | Minting + JWKS already ship; satisfies "no per-request IdP/Redis read for access validation"; subject embedded → parity free. |
| Inbound validation layering | New **app port** `appauth.SessionTokenVerifier` + infra adapter `pkg/infra/auth/session` built from the signer's public key, injected into `chainIdentityResolver` | Extend `r.jwt` (OIDC `JWTValidator`) | Hexagonal: `r.jwt` resolves IdP JWKS by config/discovery; gateway-key in-process verification is a different concern. A discrete port keeps Okta path byte-for-byte unchanged and avoids teaching the OIDC adapter the STS issuer. |
| Candidate disambiguation | `iss == signer.Issuer()` routes to `resolveSession`; candidate picked by private `authid` claim, defended by `aud ∈ cfg.Audiences` + `scope.allows` + `HasScopes` | Match gateway token against `cfg.Issuer` (IdP issuer) | In session mode IdP issuer and STS issuer diverge; matching on STS issuer is airtight and never collides with `resolveJWT`'s `cfg.Issuer==issuer` loop. |
| Token-confusion guard | Mint private claim `token_use:"mcp_session"`; `resolveSession` requires it | None | STS exchange tokens share the same key+iss; the `token_use` + `authid` claims prevent an exchange token being replayed as a session token. |
| Refresh persistence | New `FlowStore` session methods on concrete `pkg/infra/oauth/store.go` `Store` (Redis); raw IdP token discarded after capture | New standalone store | Reuse the wired Redis `Store`; rotation on each refresh. |
| Subject capture | Port `appoauth.UserInfoClient` (infra HTTP adapter) + unexported `captureSubject` precedence on `authProxy` | Bake HTTP into `proxy.go` | Keeps `app` free of concrete HTTP; mockable. |

## Data Flow

```
LOGIN (capture once)
  Callback ─ idpTokenCall ─→ token{access_token,id_token?}
     └─ captureSubject(cfg, token):  id_token[SubjectClaim] → UserInfoClient.Fetch(UserInfoURL)[SubjectClaim]
     └─ CodeGrant{Subject,AuthID,Audience,Scopes,SessionMode,Token}  ─ SaveCode
     └─ consentDetour(sub)  ─→ ChainURL ─→ vault WRITE key = sub

EXCHANGE (mint)                                INBOUND MCP (verify, no IdP hop)
  exchangeCode: if grant.SessionMode            resolveBearer:
    signer.MintClaims{sub,aud,scope,             if iss==signer.Issuer() → resolveSession
      authid,token_use} → access_token            SessionTokenVerifier.Verify (RS256, kid, exp, iss)
    SaveSession(refresh→record)                   pick auth by authid (+aud,scope,HasScopes)
    → {access_token,refresh_token,...}            Principal{Subject:sub} → vault READ key = sub  ✔ parity
  else → grant.Token (pass-through, Okta)
```

## File Changes

| File | Action | Description |
|---|---|---|
| `pkg/domain/auth/config.go` | Modify | `OAuth2Config` += `SessionMode bool` (`json:"session_mode"`), `UserInfoURL string`, `SubjectClaim string`; `validate()` checks `UserInfoURL` is http(s) when set. |
| `pkg/app/auth/session_verifier.go` | Create | Port `SessionTokenVerifier{Verify(ctx,raw)(*identity.Principal,error); Issuer() string}` + `//go:generate mockery`. |
| `pkg/infra/auth/session/verifier.go` | Create | Adapter: parses RSA public key + kid + issuer from `signer.JWKS()`/`Issuer()` at construction; RS256 in-process verify, no HTTP. |
| `pkg/app/oauth/userinfo.go` | Create | Port `UserInfoClient{Fetch(ctx,url,accessToken)(map[string]any,error)}` + `//go:generate mockery`. |
| `pkg/infra/oauth/userinfo_client.go` | Create | HTTP GET adapter (Bearer access token, JSON decode, `io.LimitReader`). |
| `pkg/app/oauth/proxy.go` | Modify | `authProxy` += `signer appsts.TokenSigner`, `userinfo UserInfoClient`; `Callback` captures subject + fills `CodeGrant`; `exchangeCode` mints when `SessionMode`; `refresh` branches on session record; add `captureSubject`/`mintSession`. |
| `pkg/app/oauth/proxy_types.go` | Modify | `CodeGrant` += `Subject,AuthID,Audience string`, `Scopes []string`, `SessionMode bool`; new `SessionRecord` struct; `FlowStore` += `SaveSession/GetSession/DeleteSession`. |
| `pkg/infra/oauth/store.go` | Modify | Implement session methods (`oauth:session:` prefix, `sessionTTL=30d`); `Get` (no consume) + rotation `Delete`. |
| `pkg/api/middleware/auth_chain.go` | Modify | `chainIdentityResolver` += `session appauth.SessionTokenVerifier`; `NewChainIdentityResolver` gains the param; `resolveBearer` STS-issuer branch; new `resolveSession`. |
| `pkg/container/modules/api.go` | Modify | Providers for `UserInfoClient` + `SessionTokenVerifier`; pass `signer`/`userinfo` to `NewAuthProxy`, `session` to chain resolver. |
| `pkg/app/**/mocks/*`, `pkg/infra/auth/session/...` mocks | Create | `go generate ./...`. |

## Interfaces / Contracts

```go
// pkg/app/auth/session_verifier.go
//go:generate mockery --name=SessionTokenVerifier --dir=. --output=./mocks --filename=auth_session_token_verifier_mock.go --case=underscore --with-expecter
type SessionTokenVerifier interface {
	Verify(ctx context.Context, raw string) (*identity.Principal, error)
	Issuer() string
}

// pkg/app/oauth/userinfo.go
//go:generate mockery --name=UserInfoClient --dir=. --output=./mocks --filename=oauth_userinfo_client_mock.go --case=underscore --with-expecter
type UserInfoClient interface {
	Fetch(ctx context.Context, userInfoURL, accessToken string) (map[string]any, error)
}

// pkg/app/oauth/proxy_types.go
type SessionRecord struct {
	Subject   string   `json:"subject"`
	Scopes    []string `json:"scopes,omitempty"`
	GatewayID string   `json:"gateway_id"`
	AuthID    string   `json:"auth_id"`
	Audience  string   `json:"audience,omitempty"`
}
type FlowStore interface { // additions only
	SaveSession(ctx context.Context, refreshToken string, rec SessionRecord) error
	GetSession(ctx context.Context, refreshToken string) (*SessionRecord, error)
	DeleteSession(ctx context.Context, refreshToken string) error
}
```

**Minted claims (`mintSession`):** `iss`,`iat`,`exp`,`jti` (set by `MintClaims`), `sub`=captured subject,
`aud`=`cfg.Audiences` (string or array), `scope`=space-joined granted scopes, `authid`=`auth.ID.String()`,
`token_use`="mcp_session". Access TTL = `appsts.DefaultTokenTTL` (5m); refresh TTL = `sessionTTL` (30d).

**`resolveSession`** (no IdP/HTTP): `Verify` once → require `claims.token_use=="mcp_session"`; pick the
candidate `a` where `a.ID.String()==claims.authid && scope.allows(a.ID)`; defense-in-depth assert
`identity.AudienceMatches(principal aud, cfg.Audiences)` and `principal.HasScopes(cfg.RequiredScopes)`;
return `Identity{a.GatewayID, a.ID, Principal{Subject, Method:MethodJWT, Issuer:signerIssuer, Claims, Scopes, RawToken:raw}}`.

**`captureSubject` precedence:** (1) `id_token` in token map → `ParseUnverified`, read `SubjectClaim`
(default `sub`, fallback `oid`); (2) else `cfg.UserInfoURL!=""` → `UserInfoClient.Fetch`, read `SubjectClaim`
(GitHub `id`); (3) else legacy `subjectFromToken`. Non-string claims coerced via `fmt.Sprintf("%v", v)`
(GitHub numeric `id`). Empty subject in session mode → `oauthErr("access_denied","could not determine subject")`.

## Testing Strategy

| Layer | What | Approach |
|---|---|---|
| Unit | `OAuth2Config.validate()` session fields | table tests: `SessionMode` + bad/good `UserInfoURL`, default `SubjectClaim`. |
| Unit | `infra/auth/session.Verifier` | mint via real `sts.Signer`, assert Verify OK; reject wrong-kid, expired, wrong-iss, `alg=none`, missing `token_use`. **AC#4**: adapter has no `*http.Client`. |
| Unit | `proxy.captureSubject` | id_token path, userinfo path (mock `UserInfoClient`, GitHub numeric `id`→string), empty→error. |
| Unit | `proxy.exchangeCode` mint vs pass-through | `SessionMode=true`→minted `access_token` verifies + `refresh_token` present + `SaveSession` called; `SessionMode=false`→returns `grant.Token` verbatim (**AC#3** Okta). |
| Unit | `proxy.refresh` | session refresh re-mints from `GetSession` (no IdP call) + rotates; non-session refresh still proxies to IdP. |
| Unit | `resolveBearer`/`resolveSession` | session token (iss==signer issuer) resolves by `authid`; **AC#3** Okta JWT (iss==IdP) still hits `resolveJWT` unchanged; opaque non-introspection still 401; cross-`authid` rejected; bad `token_use` rejected. |
| Unit | `store` session methods | Save/Get/Delete round-trip + rotation against miniredis. |
| Functional | **AC#1** GitHub opaque end-to-end | stub IdP (form-encoded token + `https://api.github.com/user`-shaped userinfo): Authorize→Callback→Exchange yields minted session JWT; consent detour fires (subject non-empty). |
| Functional | **AC#2 / parity** | subject captured at Callback == `principal.Subject` on a follow-up MCP request → vault row written at consent is `Find`-able (same `(gatewayID, sub, provider)`). |
| Functional | **AC#3** no-regression | existing Okta JWT gateway: pass-through token returned, MCP request validates via `resolveJWT`, unchanged. |

`go test -race ./...`, `go vet`, `golangci-lint` clean; mocks via `go generate ./...`.

## Migration / Rollout

No schema migration. Per-auth `session_mode` (default false). Rollback = set flag OFF (config-only) →
instant IdP pass-through; full revert = drop the `auth_chain.go` branch + config fields (refresh records
are TTL-bound Redis keys, self-expiring).

## Security Considerations

- **Token confusion**: same signing key/iss as STS exchange tokens → mitigated by mandatory
  `token_use:"mcp_session"` + `authid` checks in `resolveSession`.
- **Audience binding**: mint `aud=cfg.Audiences`; inbound asserts `AudienceMatches` so a token for auth A
  can't authorize auth B even on a shared path.
- **Key rotation / kid**: verifier reads kid+key from the signer at construction (single source); rotating
  `STS_SIGNING_KEY` rotates JWKS + verifier together. Prod already requires a stable key (`mcp.go:60-65`).
- **Refresh entropy/TTL**: opaque refresh_token from `randomToken()` (CSPRNG); 30d TTL; rotated + old
  deleted on each refresh; short 5m access TTL bounds replay.
- **No token logging**: never log `access_token`/`refresh_token`/raw subject material; keep existing
  `slog` named-attr discipline (subject only at existing `consentDetour` info log).

## Open Questions

- [ ] **Downstream `exchange` (OBO / token-exchange)**: session mode discards the IdP token, but
  `exchanger.entraOBO`/`tokenExchange` require `principal.RawToken`=IdP token + `Method==MethodJWT`
  (`exchanger.go:169,187`). Confirm session mode is only supported with `forwarded` (and
  impersonation/delegation/passthrough-against-the-gateway-aud) downstream modes — or do we also persist
  the IdP token (Approach 3-lite) to keep OBO working? Should `validate()` reject `session_mode` +
  exchange-OBO config combos?
- [ ] **`aud` to mint**: emit all of `cfg.Audiences`, or only the resource-specific audience from the
  authorize `resource` param? (Design assumes all of `cfg.Audiences`.)
- [ ] **Refresh rotation**: rotate refresh_token each refresh (assumed) vs reuse; confirm 30d session TTL
  and 5m access TTL values.
- [ ] **GitHub subject claim**: default capture to `id` (stable, recommended) vs `login` (mutable)?
  Confirm `SubjectClaim` default (`sub`) and the GitHub-specific value documented for operators.
- [ ] **`Principal.Method` for session tokens**: keep `MethodJWT` (preserves `forwarded`/impersonation/
  `HasScopes`) vs introduce `MethodSession`? (Design keeps `MethodJWT`.)
```