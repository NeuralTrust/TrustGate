# Explore: functional coverage for API-key forwarded authorization

RUN-1139 — `test(mcp-auth): cover API-key forwarded authorization end to end`
Parent epic RUN-1136. Base branch `feat/api-key-self-service-connect-endpoint`
(nothing merged into `develop`).

## Scope and baseline

Worktree: `/Users/edu/Neuraltrust/TrustGate-api-key-forwarded-coverage`,
branch `test/api-key-forwarded-coverage`, based on
`origin/feat/api-key-self-service-connect-endpoint` (HEAD `8c5cd730`).

Toolchain available: **Go 1.26.6** (matches `go.mod` and CI). Postgres 5432 and
Redis 6379 are reachable locally, so the functional suite can be run — but it was
**not** run during this phase because it requires creating `.env.functional`, and
writing `.env*` files is forbidden by the repo baseline rules. Suite duration is
therefore reported as a bound, not a measurement (see §8).

## Executive finding

The harness needed for this work already exists and is close to complete: a real
three-process boot, admin-API builders for every object the scenarios need, a
real in-process MCP upstream, and an OAuth IdP stub pattern. Three gaps must be
closed before any scenario can pass:

1. **The connect rate limiter is enabled by default and will break the suite.**
   `MCP_CONNECT_RATE_LIMIT_ENABLED` defaults to `true` with a **source limit of
   10 per minute**, and every functional request arrives from `127.0.0.1`, so all
   `POST /:slug/connect` calls in the entire suite share one bucket. Scenarios
   3, 7, 8 and 9 alone exceed it. This is the single highest-risk item.
2. **There is no fake OAuth *provider*.** The suite has an OAuth *IdP* stub
   (inbound identity, JWKS only) — it cannot serve `/authorize` redirects or
   `/token` exchanges. A new provider stub is required.
3. **There is no upstream Authorization capture.** `startMCPUpstream` mounts the
   MCP SDK handler directly, with no interception point.

Everything else — gateway/consumer/registry/auth seeding, MCP JSON-RPC calls,
host pinning, no-redirect client, secret-hygiene assertions — is reusable as is.

---

## 1. The existing functional suite

### Boot model

`tests/functional/setup_test.go` (`TestMain`) is the whole harness. It is not an
in-process server: it **builds and runs the real binary three times**.

| Step | Detail |
|---|---|
| Env | `godotenv.Overload("../../.env.functional")`, then `config.LoadConfig()` |
| Admin token | `jwt.NewJwtManager(&cfg.Server).CreateToken()` → global `AdminToken` |
| Isolation | Drops and recreates Postgres db `trustgate_functional`; flushes Redis **db 9** |
| Stubs | TrustGuard and Firewall-complexity HTTP stubs started before the binary is built, their URLs injected as env |
| Build | `go build -o <tmp>/trustgate ../../cmd/trustgate` once |
| Processes | `admin` (8090), `proxy` (8091), `mcp` (8092), each `exec.Cmd` with `Setpgid`, health-polled via `/healthz` |
| Teardown | SIGKILL each process group, flush Redis, drop the database |

Package is `functional_test` behind `//go:build functional`. Ports come from
`.env.functional`; `AdminURL` / `ProxyURL` / `MCPURL` / `BaseDomain` are globals.

### Builders (`common_test.go`)

All go through the admin REST API with the bearer token, and all `require` on
failure so the calling test aborts:

`CreateGateway`, `CreateRegistry`, `CreateRole`, `CreatePolicy`,
`CreateConsumer`, `CreateAuth`, `CreateAPIKeyAuth` (returns `(authID, plaintextKey)`),
`CreateConsumerWithRegistries`, `AttachRegistry`, `AttachAuth`, `AttachPolicy`,
`AttachRoleRegistry`, `UpdateConsumer`, `UpdateRole`, `SetPolicyGlobal`,
`ConsumerSlug`, `sendRequest`.

Side tables that make host pinning work:

- `gatewayHosts` (`sync.Map`): gatewayID → `{slug}.llm.neuraltrust.ai`
- `consumerSlugs`: consumerID → server-generated slug
- `uniqueName(prefix)`: `prefix-<8 hex>`, the isolation primitive — there is no
  per-test cleanup, tests coexist in one database and rely on unique names.

### MCP helpers (`mcp_e2e_test.go`)

| Helper | Purpose |
|---|---|
| `startMCPUpstream(t, configure)` | Real MCP server (`modelcontextprotocol/go-sdk`) behind `httptest.NewServer(sdk.NewStreamableHTTPHandler(...))`, auto-closed via `t.Cleanup` |
| `addTool` / `addGreetPrompt` / `addReadmeResource` | Upstream fixtures |
| `mcpPost` / `mcpRPC` | POST to `MCPURL + /{slug}/mcp`, pinning `req.Host` to the gateway host; no admin token |
| `apiKeyHeaders(key)` | `{"X-AG-API-Key": key}` |
| `bearerHeaders(token)` | `{"Authorization": "Bearer …"}` |
| `rpcResult` / `rpcErrorCode` / `listedNames` | Assertion helpers |
| `mcpRegistryPayload(name, url)` | `{"type":"mcp","mcp_target":{"url":…}}` — **no `auth` block**, so it normalizes to `mode: none` |
| `createMCPConsumer(...)` | Inline MCP consumer + fresh API key, returns `(consumerID, key)` |
| `newMCPIDPStub` | RSA JWKS + `sign(aud, groups)` for OAuth2 role-based tests |

### Shared-host helpers (`mcp_oauth_shared_host_test.go`)

This is where the new test belongs, and it contributes the pieces the connect
flow needs:

- `noRedirectClient()` — `http.Client` with
  `CheckRedirect: func(...) error { return http.ErrUseLastResponse }`.
- `mcpRequestWithHost(t, method, path, host, query, body)` — arbitrary method and
  path on the MCP plane with a pinned `Host`, **does not follow redirects**, JSON
  body only.
- `decodeBody`, `oauthIDPStub` (metadata + JWKS), `oauth2AuthPayload`,
  `authorizeQuery`, `sharedHost` const.
- The **cache-propagation idiom**: after attaching an auth via the admin plane,
  the MCP process only sees it once the Redis invalidation event lands, so the
  test wraps the first assertion in `require.Eventually(..., 5s, 100ms)`. Any new
  test that seeds through admin and then hits `/{slug}/connect` must do the same.

### Plugin-chain helpers (`mcp_plugin_chain_test.go`)

`addCountingEchoTool` / `addCountingFixedTool` use `atomic.AddInt64` to prove
upstream invocation counts — the closest existing pattern to "assert something
about the upstream call", but they count invocations, not headers.

### Reporter

`report_test.go` exposes `Track(t, "SuiteName") func()` (deferred), used by
`dbless_mcp_vault_test.go`. Optional; most MCP tests do not use it.

---

## 2. The fake OAuth provider — does not exist, must be built

The suite has two **inbound identity provider** stubs and no **upstream OAuth
provider**:

| Stub | File | Serves | Missing for this work |
|---|---|---|---|
| `oauthIDPStub` | `mcp_oauth_shared_host_test.go` | `/.well-known/oauth-authorization-server`, `/jwks` | no `/authorize` handler, no `/token` |
| `mcpIDPStub` | `mcp_e2e_test.go` | `/jwks` + JWT signing | same |

Neither can be extended cheaply into a provider: they model the identity that
authenticates *into* TrustGate, whereas `forwarded` needs the account TrustGate
authenticates *out to*. A new stub is required.

What it has to implement is small and fully determined by
`pkg/infra/oauth/provider_client.go`:

- **`GET /authorize`** — the gateway sends `response_type`, `client_id`,
  `redirect_uri`, `state`, optional `scope`, `code_challenge`,
  `code_challenge_method=S256`, `resource`. The stub must 302 to
  `redirect_uri?code=<code>&state=<state>`. Following that redirect lands on the
  MCP plane's `GET /oauth/callback/{provider}`.
- **`POST /token`** — form-encoded `grant_type=authorization_code`, `code`,
  `redirect_uri`, `client_id`, optional `client_secret`, `code_verifier`. Must
  return JSON `{access_token, refresh_token, expires_in, scope}`. `ExpiresAt` is
  derived from `expires_in`; when neither `expires_in` nor `refresh_token` is
  present the credential is born already expired, so the stub **must** set at
  least one, otherwise the runtime refresh path fires and scenario 6 fails.
- Refresh is the same endpoint with `grant_type=refresh_token`. Not needed for
  the 10 scenarios, but free once `/token` exists.

Registry wiring, from `registrydomain.MCPAuth.Validate()`: `mode: forwarded`
with `registration: manual` (the default when omitted) requires **`provider`,
`client_id`, `authorize_url`, `token_url`**, all http(s) URLs. `registration: auto`
would trigger dynamic client registration against the upstream and must be
avoided. So `mcpRegistryPayload` needs a forwarded variant that injects the
stub's URLs.

Note the callback base URL: `ConnectHandler.Start` passes `c.BaseURL()`, which in
the harness is `http://localhost:8092`, so the redirect URI the provider receives
is `http://localhost:8092/oauth/callback/{provider}` — reachable from the test
process.

---

## 3. The fake upstream MCP server and header capture

No existing functional test asserts on an outbound header to an MCP upstream.
Tests that capture headers do so on *LLM/plugin* stubs (`proxy_e2e_test.go`,
`trustguard_stub_test.go`, `firewall_complexity_stub_test.go`,
`plugin_azure_content_safety_test.go`) using `r.Header.Get(...)` inside a plain
`http.HandlerFunc`.

The injection point in production is unambiguous
(`pkg/app/mcp/credentials.go`, `forwarded` → `setAuthorization(target, "Bearer "+cred.AccessToken)`
→ `target.Headers["Authorization"]`), so the capture is a one-line wrapper around
the existing upstream constructor:

```go
handler := sdk.NewStreamableHTTPHandler(...)
srv := httptest.NewServer(http.HandlerFunc(func(w, r) {
    record(r.Header.Get("Authorization"))   // store, never log
    handler.ServeHTTP(w, r)
}))
```

Guard it with a mutex or `atomic.Value`: the MCP composer dials upstreams
concurrently, and CI runs with `-race`.

---

## 4. Vault assertions — and a backend trap

**The standard functional MCP plane uses the Postgres vault, not Redis.**

`modules.All(plane, dbless)` returns `dataPlaneModules()` only when `dbless &&
isDataPlane(plane)`. The harness boots plain `mcp` mode with `dbless=false`, so
it gets `fullModules()` → `MCPVaultPostgres` →
`vaultrepo.NewRepository(conn, cipher)`, table `vault_credentials`, unique on
`(gateway_id, principal_sub, provider)`.

`dbless_mcp_vault_test.go` therefore does **not** describe the backend the new
test will exercise: it constructs `vaultrepo.NewRedisRepository(redisDB, cipher)`
in-process against Redis db 9 and drives `Upsert/Find/ListByPrincipal/Delete`
directly. It is a repository test wearing a functional build tag. Its genuinely
reusable contribution is the **secret-hygiene idiom**:

```go
assert.NotContains(t, raw, "access-connect", "raw redis value must not leak plaintext access token")
```

plus the `crypto.NewCipher(<SERVER_SECRET_KEY>)` + decrypt round-trip.

For RUN-1139, the strong assertion is **behavioral**: after the connect flow, a
`tools/call` with `X-AG-API-Key` must reach the upstream carrying exactly the
bearer the stub minted. That proves persistence, key derivation and principal
identity in one step, with no direct database access. If the design wants an
explicit storage assertion, it needs a new pgx helper against
`trustgate_functional` (only `setup_test.go` uses pgx today, and only against the
`postgres` database) — recommend against it as redundant.

Shared/isolation scenarios (7 and 8) are also cleanest behaviorally: the vault
key is `(gateway_id, principal_sub, provider)` and `principal_sub = auth.Name`,
so "same key → same grant" is exactly "second client sees the first client's
bearer upstream without connecting".

---

## 5. Rate limiter interference — the top risk

### The numbers

`pkg/config/config.go`:

```
defaultMCPConnectRateLimitEnabled  = true
defaultMCPConnectRateLimitSource   = 10
defaultMCPConnectRateLimitConsumer = 100
defaultMCPConnectRateLimitWindow   = time.Minute
```

`.env.functional.example` does **not** set any `MCP_CONNECT_RATE_LIMIT_*`
variable, so the functional binary boots with the limiter **on**.

### Why it bites

`APIKeyConnectHandler.Post` applies the **source** limit first, before parsing
anything, keyed by `ResolveConnectSource(peer, XFF, trustedCIDRs)`. With
`MCP_CONNECT_TRUSTED_PROXY_CIDRS` unset, `X-Forwarded-For` is ignored and the
source is always the peer address — `127.0.0.1` for every test in the suite.

That is **10 POSTs per minute for the whole functional package**, shared across
tests, and the whole suite runs well inside one window. Scenario 3 (1 POST),
7 (2), 8 (2) and 9 (1+) already exceed it, before counting the happy-path POST
each other scenario needs. Failures would be non-deterministic 429s that shift
with test ordering — the worst possible failure mode.

The consumer limit (100/min, keyed by consumer ID) is not a practical concern
because each test mints a fresh consumer.

### The fix, and the precedent for it

`provideConnectAttemptLimiter` returns `appoauth.NewNoopConnectAttemptLimiter()`
when `Enabled` is false, so disabling is total and needs no Redis. The suite
already does exactly this for the plan limiter:

```
# Plan rate limit is on by default in the binary; keep it off in the functional
# harness so suite volume does not trip free-tier burst/quota.
RATE_LIMIT_ENABLED=false
```

**Recommendation:** add `MCP_CONNECT_RATE_LIMIT_ENABLED=false` to
`.env.functional.example` with a comment in the same voice. CI copies that file
verbatim (`cp .env.functional.example .env.functional`), so this one line fixes
local and CI at once. It cannot be done from Go: config is read once at process
boot, and the three servers boot in `TestMain` before any test runs.

Alternative if a scenario ever wants to *prove* the 429 (out of scope here):
raise the limits instead of disabling, e.g. `MCP_CONNECT_RATE_LIMIT_SOURCE=1000`.
Not recommended — limiter behavior is already covered exhaustively at unit level
in `pkg/infra/ratelimit/connect_test.go` (thresholds, concurrency, window expiry,
HMAC domain separation, opaque errors) and in the handler tests.

Redis availability is not a separate concern: with the limiter disabled the noop
never touches Redis, and Redis is a CI service anyway.

---

## 6. Following redirects and extracting the ticket

Two redirect hops, with opposite requirements.

**Hop 1 — `POST /{slug}/connect` → 303.** Must **not** be followed: the ticket is
in the `Location` header and the target is the connect page. `noRedirectClient()`
already does this. `mcpRequestWithHost` uses it, but only marshals JSON bodies —
the handler rejects anything that is not
`application/x-www-form-urlencoded` (`isFormURLEncoded`, else `415`), so a small
form-posting variant is needed.

Extraction, without ever logging the value:

```go
loc, err := resp.Location()
require.NoError(t, err)
require.Equal(t, "/"+slug+"/mcp/connect", loc.Path)
ticket := loc.Query().Get("ticket")
require.NotEmpty(t, ticket)   // assert non-empty, never print
```

`resp.Location()` resolves the relative `Location` against the request URL, so
`loc.Path` and `loc.Query()` both work. Do **not** put `ticket` in an assertion
message — `require`/`assert` print message arguments on failure.

**Hop 2 — the OAuth leg.** `GET /oauth/connect/{provider}?ticket=…` returns a
302 to the provider stub's `/authorize`, which 302s to
`/oauth/callback/{provider}?code=…&state=…`, which renders the connect page.
Here following redirects is desirable, and a default `http.Client` handles the
chain — but it does not preserve a pinned `Host` across hops. Since the MCP plane
resolves the consumer from the path for these routes and the provider stub is
addressed by its own `httptest` URL, driving the three hops explicitly with
`noRedirectClient()` and asserting each `Location` is both more precise and
easier to debug. Recommended.

Note the connect/callback routes are registered **before**
`installMiddlewares(app, r.authTransport)` in `mcp_router.go`, so they are
unauthenticated — no API key on the OAuth leg.

---

## 7. Gaps — what is genuinely new

Unit coverage on this branch is dense. Enumerated from
`pkg/app/oauth/api_key_connect_test.go` (8 tests),
`pkg/api/handler/http/oauth/api_key_connect_handler_test.go` (9),
`pkg/app/oauth/connect_test.go` (8),
`pkg/app/oauth/connect_lifecycle_audit_test.go` (21),
`pkg/app/mcp/credentials_test.go` (17 subtests),
`pkg/infra/ratelimit/connect_test.go` (9).

| # | Scenario | Existing coverage | Verdict |
|---|---|---|---|
| 1 | Consumer with API-key auth + `forwarded` registry | `TestAPIKeyConnectService_CreateTicketSnapshotsProviders` (mocked) | **New at functional level** — nothing seeds a forwarded registry through the admin API today; also proves the admin DTO accepts the payload |
| 2 | Open the self-service connect page | `TestAPIKeyConnectHandlerGet_RendersValidatedTarget`, `…Get_StatusMapping`, **and `TestMCPRouterDispatch` in `pkg/server/router/mcp_router_test.go`**, which already asserts route ordering against `/+/connect` on a real Fiber app | **Largely covered.** Reduce to a single "the page is reachable through the running MCP plane" status assertion — do not re-test routing or HTML |
| 3 | POST key → 303 with ticket | `TestAPIKeyConnectHandlerPost_*` (isolated Fiber app); `TestMCPRouterDispatch/"POST self-service route"` already asserts the exact `Location` shape `/tools/mcp/connect?ticket=…` | **New only where routing tests cannot reach**: real gateway host resolution, a real API key validated against a real consumer, and a real ticket persisted in Redis that the next hop can redeem |
| 4 | OAuth against a fake provider | `TestConnectService_FullConsentFlow` (mocked `ProviderClient`) | **New** — first exercise of the real `providerClient` over HTTP, including PKCE and form encoding |
| 5 | Credential persisted in the vault | `connect_test.go` (mock vault), `dbless_mcp_vault_test.go` (Redis repo direct) | **New for the Postgres vault reached through the flow.** Assert behaviorally (§4), not by reading the table |
| 6 | Tool call with `X-AG-API-Key` injects the token upstream | `TestCredentialResolver_Forwarded/"vaulted credential is injected"` (mock vault, synthetic principal) | **New and the point of the ticket** — the only place proving connect-time principal == runtime principal, since both derive `auth.Name` independently (`api_key_connect.go` vs `auth_chain.go:300`) |
| 7 | Two clients, same API key, same grant | **none** | **New. Genuinely uncovered anywhere.** Highest-value assertion in the set |
| 8 | Different API-key principals never cross grants | `TestCredentialResolver_Forwarded/"credentials never cross principals"` | **Partially covered.** Worth keeping end to end as the counterpart to 7 — cheap once 7 exists, and the unit test uses a hand-built principal rather than one derived from a real key |
| 9 | Key of another consumer rejected | `TestAPIKeyConnectService_CreateTicketConsumerBoundary`, `TestAPIKeyConnectHandlerPost_AuthorizationMissesAreIndistinguishable`, and `TestMCPServer_CredentialOfAnotherConsumerIsRejected` for the runtime path | **Thoroughly covered at unit level.** One functional 401 assertion, folded into another test — do not build a dedicated test |
| 10 | OAuth2 per-user behavior unchanged | `mcp_oauth_shared_host_test.go`, `TestMCPServer_RoleBasedConsumer*` | **Mostly covered.** The new bit is that a `role_based`/OAuth2 consumer still gets its own per-subject grant while an API-key consumer shares one. Only worth adding if it does not need a second IdP + JWT-minting setup — see open question Q4 |

**Net:** 1–7 are genuinely new; 8 is a cheap and worthwhile end-to-end
counterpart; 9 should be one assertion, not a test; 10 should be scoped down or
deferred to the design.

---

## 8. CI

`.github/workflows/ci.yml`, job **`functional-tests`** ("Functional Tests"):

| Aspect | Value |
|---|---|
| Runner | `ubuntu-latest` |
| Services | `redis` (6379), `postgres:13` (5432, user/password `postgres`, `pg_isready` health check) |
| Go | 1.26.6, `check-latest: true`, module cache on |
| Env setup | `cp .env.example .env` **and `cp .env.functional.example .env.functional`**, then appends `OPENAI_API_KEY` from secrets |
| Extra DBs | creates `trustgate_repo_test` and `sensible_pg_test` |
| Command | `go test -tags functional -v -race -count=1 -p 1 ./tests/functional/...` |
| Timeout | none passed → Go's default **10m per package** |
| Build tag | `functional` on every file, package `functional_test` |

Local equivalent (`make test-functional`) is
`go test -tags functional -v -count=1 -timeout=120s ./tests/functional/...` —
**no `-race`, and a 120s package timeout**. Two consequences:

- New tests must fit the 120s local budget, or `make test-functional` breaks for
  everyone even though CI passes. Budget: the harness itself spends ~10-20s on
  build plus three health-polled boots before the first test runs.
- CI runs with `-race`, so any shared state in the new upstream-header capture
  must be synchronized.

Suite wall time was not measured (see §Scope). The `-timeout=120s` in the
Makefile is the practical ceiling the team already accepts; treat it as the
budget rather than a measured figure.

`-p 1` serializes *packages*, not tests within a package: tests inside
`functional_test` still run sequentially by default (none call `t.Parallel()`),
which is what keeps the shared database usable.

The QA checklist's "race, vet and lint" map to: CI functional job (`-race`),
`unit-tests` reusable workflow (`golangci-lint`, `go vet` via the shared
workflow), and the `license-check` job — new files need the Apache header if
they are added under `pkg/`; **files under `tests/functional/` currently carry no
license header** (`make license-check` config should be confirmed, Q5).

---

## 9. Secret hygiene

Existing patterns to follow:

1. **Never print the secret, even in failure messages.** `require`/`assert`
   render `msgAndArgs` on failure. `CreateAPIKeyAuth` returns the plaintext key
   and no test ever formats it into a message.
2. **Assert absence, not presence, of plaintext at rest** —
   `dbless_mcp_vault_test.go`:
   `assert.NotContains(t, raw, "access-connect", "raw redis value must not leak…")`.
3. **Log level is `WARN`** in `.env.functional.example`, so gateway stdout
   (prefixed and streamed to the test output by `prefixWriter`) stays quiet. Do
   not lower it for debugging in committed code.
4. **`sendRequest` echoes response bodies into failure messages**
   (`"create auth failed: %v", body`). The create-auth response *contains*
   `api_key`. That is pre-existing and only triggers on failure, but the new test
   must not adopt that idiom for the connect POST — assert on status and
   `Location` only, and never `%v` a body that could carry the key or the ticket.
5. For the upstream capture, store the observed `Authorization` in a struct field
   and compare with `require.Equal(t, want, got)`; do not build a message that
   interpolates either side.

The ticket itself is secret-adjacent (design doc: "the ticket never appears in
access logs, including the 303 redirect"). Treat it like the API key.

---

## Affected-areas map

| File | Action | Why |
|---|---|---|
| `tests/functional/mcp_api_key_connect_test.go` | **add** | The new scenarios. Name mirrors the feature; sits next to `mcp_oauth_shared_host_test.go` as the issue asks |
| `.env.functional.example` | **modify** (1 line + comment) | `MCP_CONNECT_RATE_LIMIT_ENABLED=false`. Blocking — CI copies this file |
| `tests/functional/mcp_e2e_test.go` | **modify** (small) | Optional variant of `startMCPUpstream` that captures the inbound `Authorization`, and a forwarded variant of `mcpRegistryPayload`. Could live in the new file instead — see approaches |
| `docs/mcp/testing-guide.md` | **modify** | New rows in the §5 scenario table; operator + Cursor flow for the self-service connect URL (§4 "Real agent client") |
| `docs/mcp/api-key-auth-and-external-credentials.md` | **modify only if** implementation details change during delivery | Issue says "if"; nothing found so far requires it |
| `openspec/changes/api-key-forwarded-coverage/` | **add** | SDD artifacts |

No production code change is expected. If one becomes necessary it is a signal
the test found a real bug — escalate rather than adapting the test.

---

## Approaches comparison

### A. Test granularity

| Option | Pros | Cons | Effort |
|---|---|---|---|
| **A1** One table-driven test over all 10 scenarios | Single setup | Wrong shape: the scenarios do not share a signature (some need two keys, some two consumers, some no OAuth leg). Forces `any` payloads and conditional branches inside the loop — the anti-pattern the repo's table-driven convention exists to avoid. A 429 or a propagation flake kills all 10 | Low, misleading |
| **A2** One flow test with `t.Run` subtests over a shared fixture, plus 2-3 focused siblings | Mirrors `mcp_oauth_shared_host_test.go` exactly (one gateway/consumer, ordered subtests naming each guarantee). Minimizes admin-API seeding and connect POSTs, which is what the rate limiter and the 120s budget both reward. Subtest names become the coverage report | Subtests are order-dependent (the tool call needs the completed connect); acceptable and already the neighbour's shape | **Recommended** |
| **A3** One top-level `Test…` per scenario | Maximum isolation, clearest failures | 10× gateway/consumer/registry seeding, 10× `require.Eventually` propagation waits, 10+ connect POSTs. Slowest and most limiter-exposed | High |

**Recommendation: A2.** Concretely:

1. `TestMCPAPIKeyConnect_ForwardedFlowEndToEnd` — one gateway, one MCP consumer,
   one API key, one forwarded registry pointed at the provider stub, one
   capturing upstream. Subtests: connect page renders → POST returns 303 with a
   ticket → OAuth leg completes against the stub → `tools/call` reaches the
   upstream with the stub's bearer (scenarios 1-6).
2. `TestMCPAPIKeyConnect_SharedKeyReusesGrantAndIsolatesPrincipals` — a second
   client using the same key sees the same grant with no second connect
   (scenario 7); a second consumer with its own key gets consent-required rather
   than the first grant (scenario 8). Folds in scenario 9 as a single 401
   assertion on the cross-consumer POST.
3. Scenario 10 as an assertion appended to an existing OAuth2 test, or deferred
   (Q4).

### B. Harness reuse

| Option | Pros | Cons |
|---|---|---|
| **B1** Reuse the shared-host harness and helpers as is, add only a provider stub and a capturing upstream | Smallest diff, consistent with the file the issue points at, inherits host pinning / no-redirect / propagation idioms | Adds a form-post variant of `mcpRequestWithHost` |
| **B2** New self-contained harness | Full control | Duplicates boot assumptions, breaks the "one `TestMain`" model, reviewers will reject |

**Recommendation: B1.** Put the provider stub and the capturing upstream in the
new test file rather than editing `mcp_e2e_test.go`, so the diff stays in one
place and the shared files stay stable; promote them later if a second test
needs them.

---

## Size forecast (PR budget 400 lines)

| Item | Est. changed lines |
|---|---|
| Fake OAuth provider stub (`/authorize` + `/token`, code/state bookkeeping) | 55-70 |
| Capturing MCP upstream + forwarded registry payload helper | 30-40 |
| Form-POST helper + ticket extraction | 25-35 |
| Test 1 — end-to-end flow with subtests (scenarios 1-6) | 90-120 |
| Test 2 — shared key / isolation / cross-consumer (7-9) | 60-80 |
| Scenario 10 assertion, if in scope | 15-40 |
| `.env.functional.example` | 3 |
| `docs/mcp/testing-guide.md` | 20-35 |
| **Total** | **~300-420** |

**Verdict: fits the 400-line budget, with no slack.** Two levers if it drifts
over: drop scenario 10 to a follow-up (saves up to 40), and keep scenario 9 as a
single assertion rather than a test (already assumed). Splitting into chained PRs
is not worthwhile — the provider stub is useless without a test that drives it.

---

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| **Connect rate limiter trips a 429** | Non-deterministic failures that move with test ordering; the most likely way this PR lands red | `MCP_CONNECT_RATE_LIMIT_ENABLED=false` in `.env.functional.example`. Verify by grepping the booted config, not by assuming |
| **Admin→MCP cache propagation** | The consumer/auth/registry may not be visible to the MCP process when the first connect request lands | `require.Eventually(..., 5s, 100ms)` around the first MCP-plane assertion, exactly as `mcp_oauth_shared_host_test.go` does |
| **Credential born expired** | If the stub returns neither `expires_in` nor `refresh_token`, `ExpiresAt` is the zero time, `Expired(60s)` is true, and the tool call takes the refresh path instead of injecting | Stub returns `expires_in: 3600` **and** a refresh token |
| **`registration: auto`** | Triggers dynamic client registration and upstream metadata discovery against a stub that does not serve it | Always set `registration: manual` (or omit) with explicit `client_id` / `authorize_url` / `token_url` |
| **`-race` on the header capture** | CI-only failure | Mutex or `atomic.Value` around the recorded header |
| **120s local package timeout** | `make test-functional` breaks locally while CI (10m) passes | Keep to two new top-level tests; reuse one gateway per test |
| **Secret in a failure message** | Violates the QA checklist | Never pass key/ticket/token as `msgAndArgs`; assert status and `Location` shape only |
| **Vault backend confusion** | Writing assertions against Redis when the plane uses Postgres | Assert behaviorally through the tool call (§4) |
| **Base branch is unmerged** | Rebase churn if RUN-1136 moves | Draft PR against `feat/api-key-self-service-connect-endpoint`, rebase before review |

---

## Open questions (answerable from the repo)

**Q1 — Comments in functional tests.** `.agents/AGENT.md` §11.1 forbids *all*
comments including Go doc comments, with no stated exemption, yet every file in
`tests/functional/` carries substantial explanatory comments (see the header of
`mcp_oauth_shared_host_test.go`). Which convention governs a new file in
`tests/functional/`? *Resolve by:* checking whether the pre-commit comment-strip
hook (referenced in §11.1) excludes `tests/` or `_test.go`, and by reading
§9 alongside §11.1. **Default if unresolved: match the neighbours** — reviewers
compare against the adjacent file.

**Q2 — License headers under `tests/`. RESOLVED: not required.**
`make license-check` runs
`addlicense -check … -ignore '**/mocks/**' cmd pkg tools` — `tests/` is outside
the scanned paths entirely. New functional test files need no Apache header,
matching every existing file in `tests/functional/`.

**Q3 — Admin registry DTO for `forwarded`.** `registrydomain.MCPAuth` has the
fields, but the create-registry request DTO must actually accept and map
`mcp_target.auth.{provider,client_id,client_secret,authorize_url,token_url,scopes,registration}`,
and `client_secret` is secret-resolved on update. *Resolve by:* reading the
registry request DTO under `pkg/api/handler/http/request/` (or wherever
`CreateRegistry` binds) and confirming the JSON path a functional payload must
use.

**Q4 — Scenario 10 scope.** "Existing OAuth2 per-user behavior remaining
unchanged" is largely covered by `mcp_oauth_shared_host_test.go` and
`TestMCPServer_RoleBasedConsumer*`. Does RUN-1139 need a *new* assertion that an
OAuth2 principal gets a per-subject forwarded grant (requiring a JWT-minting IdP
stub **and** the provider stub in one test, ~40 lines and real budget pressure),
or is a regression note in the testing guide enough? *Resolve by:* the design
phase deciding against the 400-line budget; recommend deferring.

**Q5 — Route ordering. RESOLVED: already covered.**
`pkg/server/router/mcp_router_test.go` / `TestMCPRouterDispatch` builds the real
`mcpRouter` and asserts, with subtests: `GET /tools/connect` renders the
self-service form (`action="/tools/connect"`); a single-segment connect **with a
ticket query still stays self-service** rather than being captured by
`/+/connect`; `POST /tools/connect` returns the exact `Location`
`/tools/mcp/connect?ticket=self-service-ticket`; and the nested `/tools/mcp/connect`
and `/oauth/connect/{provider}` routes still resolve. Scenario 2 should therefore
shrink to one reachability assertion, and the functional value of scenario 3 is
the real identity/ticket plumbing, not the routing.

**Q6 — Provider key format.** `ConnectStartPath` is `/oauth/connect/*` because
"provider keys can contain slashes (e.g. `app.linear/mcp`)". Should the stub use
a simple provider id (`github`) or a slash-bearing one to also cover the wildcard
route? *Resolve by:* reading `providerParam` handling and picking a simple id
unless the design wants the extra edge covered.

---

## Reusable-asset summary

| Need | Reuse | Source |
|---|---|---|
| Boot admin/proxy/mcp | as is | `setup_test.go` |
| Seed gateway/consumer/registry/auth | as is | `common_test.go` |
| API key with plaintext | `CreateAPIKeyAuth` | `common_test.go` |
| MCP JSON-RPC with API key | `mcpRPC` + `apiKeyHeaders` | `mcp_e2e_test.go` |
| Real MCP upstream | `startMCPUpstream` + `addTool` | `mcp_e2e_test.go` |
| Non-redirect HTTP + host pinning | `noRedirectClient`, `mcpRequestWithHost` | `mcp_oauth_shared_host_test.go` |
| Cache-propagation wait | `require.Eventually` idiom | `mcp_oauth_shared_host_test.go` |
| Secret-absence assertions | `assert.NotContains` idiom | `dbless_mcp_vault_test.go` |
| Fake OAuth **provider** | **build** | — |
| Upstream `Authorization` capture | **build** (wrapper) | — |
| Form-encoded POST + ticket extraction | **build** (small) | — |
| Limiter disabled in harness | **add env line** | `.env.functional.example` |
