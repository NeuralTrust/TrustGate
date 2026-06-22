# Tasks: Gateway-minted session token for opaque-token IdPs (RUN-712, Option C)

> Worktree `TrustGate-gateway-session-token` (`feat/gateway-session-token`). `design.md` is authoritative.
> Conventions are binding: `.agents/AGENT.md` (hexagonal `domain → app → infra → api`, DI in
> `pkg/container/modules`, one interface per file + `//go:generate mockery`, **NO comments**) and
> `golang-pro` (error `%w` wrapping, `context` propagation, `go vet` / `golangci-lint` clean, `-race`).
> Each phase is independently compilable and `go test`-able; constructor signature changes update their
> DI call sites in the same phase.

## Resolved decisions (FINAL — these override any hedging in `design.md`'s Open Questions)

1. **OBO / token-exchange is a non-goal in session mode.** Session mode discards the IdP token, so
   downstream `exchange` (entraOBO / token-exchange) is **incompatible by design**. Session mode targets
   `forwarded` / `passthrough` / `exchange-impersonation` / `exchange-delegation`. **No task adds
   `validate()` coupling** between the gateway auth `OAuth2Config` and the downstream registry `MCPAuth`
   (separate entities); no task cross-validates them. Document the non-goal only.
2. **Minted `aud` = ALL of `cfg.Audiences`** (the auth's configured audiences).
3. **TTLs:** session/access JWT TTL = **1h**; gateway `refresh_token` TTL = **30d**; **rotate** the gateway
   `refresh_token` on every refresh (delete old, save new). (Note: this 1h access TTL deliberately differs
   from `appsts.DefaultTokenTTL` (5m); pass an explicit `1*time.Hour` to `MintClaims`.)
4. **`SubjectClaim` default = `"sub"`**; GitHub is configured with `"id"`. Document only; **no migration task**.
5. **Reuse `identity.MethodJWT`** for session tokens (do NOT add `MethodSession`). Inbound session
   validation sets `Principal{Subject, Method: MethodJWT, Issuer: <gateway STS issuer>, Scopes,
   RawToken: <session JWT>, Claims}`.

---

## Phase 1 — Domain config + opt-in validation

Goal: add the opt-in session fields to `OAuth2Config` and validate them, keeping OFF == today (zero
regression). No DI change.

- [x] **1.1** `pkg/domain/auth/config.go`: add to `OAuth2Config` the fields `SessionMode bool`
  (`json:"session_mode,omitempty"`), `UserInfoURL string` (`json:"userinfo_url,omitempty"`),
  `SubjectClaim string` (`json:"subject_claim,omitempty"`). Mirror the existing `OIDCConfig.SubjectClaim`
  style. Backward compat: zero values == current pass-through behavior.
- [x] **1.2** `pkg/domain/auth/config.go`: extend `(*OAuth2Config).validate()` to require `UserInfoURL`,
  when non-empty, to be an http(s) URL with a host (reuse the `url.Parse` scheme/host pattern already used
  for issuer discovery). Do **not** require `JWKSURL`/`IntrospectionURL` when `SessionMode` is on (an
  opaque IdP has neither). **Guardrail (Resolution #1):** do NOT add any coupling to downstream registry
  `MCPAuth` / exchange modes here. The `SubjectClaim` default (`"sub"`) is applied at the capture call
  site, not stored.
- [x] **1.3** `pkg/domain/auth/config_test.go`: table tests for `validate()` covering `SessionMode=true`
  with good/bad `UserInfoURL`, `SessionMode=true` with no JWKS/introspection (must pass), default
  `SubjectClaim` empty (valid), and OFF-mode unchanged.

**Acceptance:** `go test ./pkg/domain/auth/... -race` green; `go vet` + lint clean.

---

## Phase 2 — Inbound session-token verifier (app port + infra adapter)

Goal: an in-process RS256 verifier for the gateway's own session JWT, built from the STS signer's public
key (no HTTP). New files only — no existing constructor changes.

- [x] **2.1** Create `pkg/app/auth/session_verifier.go`: port
  `SessionTokenVerifier interface { Verify(ctx context.Context, raw string) (*identity.Principal, error); Issuer() string }`
  with the `//go:generate mockery --name=SessionTokenVerifier --dir=. --output=./mocks --filename=auth_session_token_verifier_mock.go --case=underscore --with-expecter` directive.
- [x] **2.2** Create `pkg/infra/auth/session/verifier.go`: adapter implementing `SessionTokenVerifier`.
  Construct from `appsts.TokenSigner` — read `Issuer()` and parse the RSA public key + `kid` from `JWKS()`
  at construction (single source of truth; no `*http.Client` field — AC#4). `Verify` parses RS256 only
  (reject `alg=none`/non-RS256), validates signature against the stored key, enforces `exp` and
  `iss == Issuer()`, requires the `kid` header to match. Build and return
  `identity.Principal{Subject: claims["sub"], Method: identity.MethodJWT, Issuer: Issuer(),
  Claims: claims, Scopes: <space-split "scope">, RawToken: raw}`. The `token_use`/`authid`/`aud`/scope
  policy checks live in `resolveSession` (Phase 4), not here. Wrap errors with `%w`.
- [x] **2.3** `go generate ./pkg/app/auth/...` (or `mockery`) to emit
  `pkg/app/auth/mocks/auth_session_token_verifier_mock.go`.
- [x] **2.4** `pkg/infra/auth/session/verifier_test.go`: mint a token via a **real** `infra/identity/sts`
  signer and assert `Verify` succeeds and yields the expected `Subject`/`Issuer`/`Scopes`/`RawToken`.
  Reject: wrong `kid`, expired token, wrong issuer, `alg=none`, tampered signature. Assert the adapter
  type has **no** `*http.Client` field (AC#4 reflection or construction check).

**Acceptance:** `go test ./pkg/infra/auth/session/... -race` green; `go vet` + lint clean; package compiles
without touching wired code.

---

## Phase 3 — Callback subject capture + minting + session persistence

Goal: capture the subject once at `Callback`, mint the gateway session JWT at `exchangeCode` when
`SessionMode`, and persist a rotatable session record. Updates `NewAuthProxy` + its DI site in the same
phase.

- [x] **3.1** Create `pkg/app/oauth/userinfo.go`: port
  `UserInfoClient interface { Fetch(ctx context.Context, userInfoURL, accessToken string) (map[string]any, error) }`
  with `//go:generate mockery --name=UserInfoClient --dir=. --output=./mocks --filename=oauth_userinfo_client_mock.go --case=underscore --with-expecter`.
- [x] **3.2** Create `pkg/infra/oauth/userinfo_client.go`: HTTP `GET` adapter — `Authorization: Bearer
  <accessToken>`, `Accept: application/json`, JSON-decode under `io.LimitReader` (1<<20), non-2xx →
  wrapped error. Default `*http.Client` timeout like `NewAuthProxy` (15s).
- [x] **3.3** `pkg/app/oauth/proxy_types.go`: extend `CodeGrant` with `Subject string`, `AuthID string`,
  `Audience string` (or keep audiences from cfg), `Scopes []string`, `SessionMode bool` (json-tagged).
  Add `SessionRecord{Subject string; Scopes []string; GatewayID string; AuthID string; Audience string}`
  (json-tagged per `design.md`). Extend the `FlowStore` interface with `SaveSession(ctx, refreshToken
  string, rec SessionRecord) error`, `GetSession(ctx, refreshToken string) (*SessionRecord, error)`,
  `DeleteSession(ctx, refreshToken string) error`.
- [x] **3.4** `pkg/infra/oauth/store.go`: implement all three session methods to keep
  `var _ appoauth.FlowStore` satisfied. Add `sessionPrefix = "oauth:session:"` and
  `sessionTTL = 30 * 24 * time.Hour`. `SaveSession` = `save(...)`; `GetSession` = read **without** consume
  (plain `Get`, `redis.Nil`→`nil,nil`); `DeleteSession` = `Del`. (Rotation = caller deletes old + saves new.)
- [x] **3.5** `pkg/app/oauth/proxy.go`: add fields `signer appsts.TokenSigner` and `userinfo UserInfoClient`
  to `authProxy`; extend `NewAuthProxy(...)` with both params. Add `captureSubject(ctx, cfg, token)` with
  precedence: (1) `id_token` in token map → `jwt.ParseUnverified`, read `cfg.SubjectClaim` (default `sub`,
  fallback `oid`); (2) else `cfg.UserInfoURL != ""` → `userinfo.Fetch`, read `cfg.SubjectClaim`; (3) else
  legacy `subjectFromToken`. Coerce non-string claims via `fmt.Sprintf("%v", v)` (GitHub numeric `id`).
  In session mode an empty subject → `oauthErr("access_denied","could not determine subject")`.
- [x] **3.6** `pkg/app/oauth/proxy.go` `Callback`: when `cfg.SessionMode`, call `captureSubject`, store the
  captured subject + `AuthID` + `Audiences` + granted `Scopes` + `SessionMode` into `CodeGrant`, and pass
  the captured subject to `consentDetour` (so the vault **write** key == captured subject). Keep OFF path
  byte-for-byte (still `subjectFromToken`).
- [x] **3.7** `pkg/app/oauth/proxy.go`: add `mintSession(cfg, grant)` building claims `sub`=captured
  subject, `aud`=**all** `cfg.Audiences` (Resolution #2; string vs array shape per `AudiencesFromClaim`
  conventions), `scope`=space-joined granted scopes, `authid`=`grant.AuthID`, `token_use`="mcp_session";
  call `signer.MintClaims(claims, 1*time.Hour)` (Resolution #3). In `exchangeCode`, when
  `grant.SessionMode`: mint the access token, generate an opaque `refresh_token` via `randomToken()`,
  `SaveSession(refresh → SessionRecord)`, and return `{access_token, token_type:"Bearer",
  expires_in:3600, refresh_token, scope}`. When OFF: return `grant.Token` verbatim (Okta untouched).
- [x] **3.8** `pkg/container/modules/api.go`: add a `UserInfoClient` provider
  (`infraoauth.NewUserInfoClient(nil)`) and update the `NewAuthProxy` provider to inject
  `sts.TokenSigner` (cross-module from `mcp.go`) and `UserInfoClient`.
- [x] **3.9** `go generate ./pkg/app/oauth/...` to emit `pkg/app/oauth/mocks/oauth_userinfo_client_mock.go`.
- [x] **3.10** Tests:
  - `pkg/app/oauth/proxy_test.go`: `captureSubject` id_token path, userinfo path (mock `UserInfoClient`,
    GitHub numeric `id`→string), empty→`access_denied`.
  - `exchangeCode`: `SessionMode=true` → returned `access_token` verifies against a real signer +
    `refresh_token` present + `SaveSession` called with captured subject/scopes; `SessionMode=false` →
    returns `grant.Token` verbatim (AC#3 Okta).
  - `pkg/infra/oauth/store_test.go`: Save/Get/Delete round-trip + rotation against `miniredis`.

**Acceptance:** `go test ./pkg/app/oauth/... ./pkg/infra/oauth/... -race` green; `go vet` + lint clean;
whole module builds.

---

## Phase 4 — Inbound `resolveSession` branch + chain DI wiring

Goal: route gateway-issued tokens to a local-validation branch keyed off the STS issuer; Okta paths
untouched. Updates `NewChainIdentityResolver` + its DI site in the same phase.

- [x] **4.1** `pkg/api/middleware/auth_chain.go`: add `session appauth.SessionTokenVerifier` to
  `chainIdentityResolver`; add the param to `NewChainIdentityResolver` (and the struct literal).
- [x] **4.2** `pkg/api/middleware/auth_chain.go` `resolveBearer`: before the `isJWT` split, if the token is
  a JWT and `unverifiedIssuer(token) == r.session.Issuer()`, dispatch to `resolveSession`. The IdP-issuer
  `resolveJWT` / `resolveOpaque` paths stay exactly as-is (Okta no-regression).
- [x] **4.3** `pkg/api/middleware/auth_chain.go`: add `resolveSession(ctx, token, candidates, scope)`:
  `r.session.Verify` once; require `principal.Claims["token_use"] == "mcp_session"`; pick the candidate
  `a` where `a.ID.String() == claims["authid"] && scope.allows(a.ID)`; defense-in-depth assert
  `identity.AudienceMatches(identity.AudiencesFromClaim(claims["aud"]), cfg.Audiences)` and
  `principal.HasScopes(cfg.RequiredScopes)`; return `Identity{a.GatewayID, a.ID, principal}` (principal
  already carries `Method: MethodJWT`, `Issuer: signerIssuer`, `RawToken: token` — Resolution #5).
  Reject (→ `ErrUnauthenticated`) on missing/wrong `token_use`, unknown/cross `authid`, aud/scope mismatch.
- [x] **4.4** `pkg/container/modules/api.go`: provide `appauth.SessionTokenVerifier` from the infra
  adapter built on `sts.TokenSigner` (e.g. `authsession.NewVerifier(signer)`), and pass it into the
  `NewChainIdentityResolver` provider.
- [x] **4.5** `pkg/api/middleware/auth_chain_test.go`: session token (iss == signer issuer) resolves by
  `authid` and yields `Principal.Subject` == captured subject; **AC#3** an Okta JWT (iss == IdP) still hits
  `resolveJWT` unchanged; opaque non-introspection token still 401; cross-`authid` rejected; missing/bad
  `token_use` rejected; aud-mismatch rejected.

**Acceptance:** `go test ./pkg/api/middleware/... -race` green; `go vet` + lint clean; module builds; Okta
unit paths unchanged.

---

## Phase 5 — Gateway refresh (rotation) + end-to-end functional tests

Goal: `grant_type=refresh_token` re-mints locally from the stored session and rotates the refresh token;
full opaque-IdP flow + parity + Okta no-regression covered functionally.

- [ ] **5.1** `pkg/app/oauth/proxy.go` `refresh`: first try `GetSession(ctx, req.RefreshToken)`. If a
  `SessionRecord` exists → re-`mintSession` from it (no IdP call), rotate: generate a new `refresh_token`,
  `SaveSession(new → record)`, `DeleteSession(old)`, return `{access_token, token_type, expires_in:3600,
  refresh_token, scope}`. Preserve original subject + scopes (Resolution #3). If no session record →
  existing IdP `refresh_token` proxy path unchanged (Okta).
- [ ] **5.2** `pkg/app/oauth/proxy_test.go`: session refresh re-mints from `GetSession` with **no** IdP
  call, rotates (old refresh deleted, new returned, subject/scopes preserved); non-session refresh still
  proxies to the IdP token endpoint.
- [ ] **5.3** Functional **AC#1** (opaque GitHub e2e): stub IdP (form-encoded token endpoint + a
  `https://api.github.com/user`-shaped userinfo returning numeric `id`); `SubjectClaim="id"`,
  `SessionMode=true`. Drive Authorize → Callback → Exchange and assert a minted session JWT is returned
  (verifiable against the gateway JWKS) and the consent detour fires with a non-empty subject.
- [ ] **5.4** Functional **AC#2 / parity**: subject captured at `Callback` == `principal.Subject` on a
  follow-up MCP request through `resolveSession`; the vault row written at consent
  (`(gatewayID, subject, provider)`) is `Find`-able on the request path. Distinct subjects do not share
  credentials.
- [ ] **5.5** Functional **AC#3** no-regression: existing Okta JWT gateway (`SessionMode=false`) → exchange
  returns the IdP JWT verbatim; MCP request validates via `resolveJWT` against the IdP issuer; principal
  subject derives from the IdP token as today.
- [ ] **5.6** Repo-wide gates: `go generate ./...` (mocks current), `go build ./...`,
  `go test -race ./...`, `go vet ./...`, `golangci-lint run`.

**Acceptance:** all functional + unit suites green under `-race`; lint/vet clean; flag OFF reproduces
current behavior exactly.

---

## Non-goal note (Resolution #1 — document, do not implement)

OBO / token-exchange downstream with session mode is **out of scope and incompatible by design** (the IdP
token is discarded after subject capture). No task wires `validate()` cross-checks between the gateway
`OAuth2Config` and the downstream registry `MCPAuth`. If both are configured, behavior is undefined and
documented as unsupported; session mode is for `forwarded` / `passthrough` /
`exchange-impersonation` / `exchange-delegation` only.

---

## Review Workload Forecast

| Metric | Estimate |
|---|---|
| Source files created | 4 (`app/auth/session_verifier.go`, `infra/auth/session/verifier.go`, `app/oauth/userinfo.go`, `infra/oauth/userinfo_client.go`) |
| Source files modified | 6 (`domain/auth/config.go`, `app/oauth/proxy_types.go`, `app/oauth/proxy.go`, `infra/oauth/store.go`, `api/middleware/auth_chain.go`, `container/modules/api.go`) |
| Test files created/modified | ~7 (config, verifier, proxy, store, auth_chain unit + 1–2 functional suites) |
| Generated mock files | 2 (`SessionTokenVerifier`, `UserInfoClient`) |
| **Est. source LOC (non-generated, non-test)** | **~520 LOC** |
| **Est. test LOC** | **~1,150 LOC** |
| **Est. generated (mocks)** | **~100 LOC** |
| **Total new/changed (excl. generated)** | **~1,670 LOC across ~17 files** |

**Split recommendation — YES, chain the PRs.** The non-generated diff (~1,670 LOC) is well over the
400-line review threshold, and the phases form a clean dependency chain with independent compile/test
gates. Recommended chained PRs (one per phase), each reviewable in isolation:

1. **PR1 — Phase 1** (domain config + validation): ~75 LOC. Trivial, no behavior change when OFF.
2. **PR2 — Phase 2** (session verifier port + adapter): ~300 LOC. Pure new code, no wiring.
3. **PR3 — Phase 3** (callback capture + mint + persistence): ~600 LOC. **Largest; the review hotspot.**
   If it still exceeds ~400 reviewable LOC, sub-split: 3a = userinfo port/adapter + `proxy_types`/`store`
   session persistence; 3b = `proxy.go` capture/mint/exchange + DI + tests.
4. **PR4 — Phase 4** (inbound `resolveSession` + chain DI): ~330 LOC. Security-critical; review token
   disambiguation + Okta no-regression carefully.
5. **PR5 — Phase 5** (refresh rotation + functional e2e): ~360 LOC, mostly tests.

**Risks / hidden dependencies for review:**

- **Phase 3 is the heaviest and most coupled** (`proxy.go` touches Callback, exchange, capture, mint, plus
  `proxy_types` + `store` + DI). Strongest candidate to sub-split (3a/3b above).
- **Phase 4 token disambiguation** (gateway STS issuer vs IdP issuer) is the security crux; the `token_use`
  + `authid` + `aud` defenses must be reviewed together, and the Okta `resolveJWT`/`resolveOpaque` paths
  must be proven byte-for-byte unchanged.
- **Cross-module DI:** `sts.TokenSigner` is provided in `modules/mcp.go` but consumed by providers in
  `modules/api.go` (`NewAuthProxy`, `SessionTokenVerifier`). dig resolves cross-module, but verify the
  graph builds in the container wiring tests.
- **TTL divergence (Resolution #3):** access TTL is 1h, deliberately not `DefaultTokenTTL` (5m) — easy to
  regress; assert the exact `exp` in tests.
- **`aud` shape:** minting all `cfg.Audiences` must round-trip through `AudiencesFromClaim` /
  `AudienceMatches` (single string vs array) so inbound audience assertion holds.
