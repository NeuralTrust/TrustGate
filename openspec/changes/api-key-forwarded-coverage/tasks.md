---
linear: RUN-1139
change: api-key-forwarded-coverage
base: feat/api-key-self-service-connect-endpoint
---

# Tasks: API-key forwarded authorization coverage (RUN-1139)

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | 380 (363 test + 3 env + 14 docs) |
| 400-line budget risk | Medium |
| Chained PRs recommended | No |
| Suggested split | Single draft PR into `feat/api-key-self-service-connect-endpoint` |
| Delivery strategy | single-pr |
| Chain strategy | size-exception |

Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: size-exception
400-line budget risk: Medium

**Single-PR verdict — fits, with 20 lines of slack.** Splitting is not available: the provider stub is dead code without the test that drives it, and the tests do not compile without the stub. `openspec/changes/**` is SDD process output and is excluded from the count; if a reviewer counts it, request `size:exception` with the indivisibility rationale rather than shrinking coverage.

**Levers if the count drifts over 400**, in order: (1) trim `docs/mcp/testing-guide.md` to the §5 rows only, saves 8-10; (2) drop `scopes` + the `authorizeParams()` PKCE assertion, saves ~10; (3) collapse test 1's subtests into a linear body, saves ~8, least preferred; (4) `size:exception`.

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Phases 1-6 | Single draft PR | Base = `feat/api-key-self-service-connect-endpoint`. Never `develop` — Edu merges epic RUN-1136 manually |

## Verification constraints (read before Phase 1)

`.env.functional` cannot be created by an agent, so `make test-functional` is unavailable locally. The green-light gate is CI's Functional Tests job. Locally, per-phase verification is:

```bash
go vet -tags functional ./tests/functional/...
go test -tags functional -c -o /dev/null ./tests/functional/
```

`go test -c` compiles without running; `-run XXX` does **not** work as a compile check because `TestMain` boots the harness and needs `.env.functional`.

`golangci-lint run --build-tags functional ./tests/functional/...` reports `unused` (enabled in `.golangci.yml:13`) for every helper that has no caller yet — so run it from **Phase 4 onward only**. The pre-commit hook's `make lint` is untagged (`golangci-lint run ./...`), so it never sees these files and will not block Phases 2-3 commits.

## Phase 1: Deterministic execution conditions

Spec: *Deterministic execution conditions* → *Suite is order-independent*.

- [x] 1.1 `.env.functional.example`: after the `RATE_LIMIT_ENABLED=false` block (line 49), append a two-line comment in the same voice plus `MCP_CONNECT_RATE_LIMIT_ENABLED=false`. **3 lines**
- [x] 1.2 Confirm `MCP_CONNECT_RATE_LIMIT_ENABLED` binds to `GlobalConfig.MCPConnectRateLimit.Enabled` (`pkg/config/config.go:160`) and that the CI functional job copies the example file verbatim. **0 lines**

Verify: `rg -n MCP_CONNECT_RATE_LIMIT .env.functional.example`

## Phase 2: Provider stub and upstream capture

Spec: *End-to-end self-service connect proof* (enabler); *Forwarded injection proves principal identity* (enabler).

- [x] 2.1 Create `tests/functional/mcp_api_key_connect_test.go`: `//go:build functional`, `package functional_test`, import block. **No comments anywhere in this file** (`.agents/AGENT.md` §11.1). **20 lines**
- [x] 2.2 `oauthProviderStub` struct + `newOAuthProviderStub` (mint `accessToken`/`refreshToken` once, `httptest.NewServer` over a `ServeMux`, `t.Cleanup(Close)`) + `authorizeURL`/`tokenURL`/`host`/`bearer`/`tokenExchanges`/`authorizeParams`, every accessor mutex-guarded. **30 lines**
- [x] 2.3 `GET /authorize` handler: record `r.URL.Query()`, `400` on empty `state`/`redirect_uri`, mint a single-use code, `302` to `redirect_uri` with `code`+`state`. **No `require` in the handler** — `t.FailNow` off the test goroutine is undefined behavior (D6). **25 lines**
- [x] 2.4 `POST /token` handler: `ParseForm`, `authorization_code` consumes the code, `refresh_token` accepts any non-empty token, other grants `400`; increment `tokenCalls`; respond with `access_token`, `refresh_token`, `token_type`, **`expires_in: 3600`**, `scope`. Omitting `expires_in` *and* the refresh token makes the credential born expired and sends the runtime down the refresh path — scenario 6 then fails for a reason that looks nothing like its cause. **25 lines**
- [x] 2.5 `upstreamCapture` (`record`/`observed`/`reset`, one `sync.Mutex` over both fields) + `startCapturingMCPUpstream` wrapping the SDK handler. CI runs `-race` and the composer fans out concurrently, so value and counter must move together under the same lock. **28 lines**

Verify: `go vet -tags functional ./tests/functional/...` && `go test -tags functional -c -o /dev/null ./tests/functional/`

## Phase 3: Connect-flow helpers

Spec: *End-to-end self-service connect proof*; *Secret hygiene in verification*.

- [x] 3.1 `mcpForwardedRegistryPayload(name, upstreamURL, provider, idp)`: `mcp_target.auth` with `mode: forwarded`, `registration: manual`, `provider`, `client_id`, `authorize_url`, `token_url`, `scopes`. No `client_secret`; never `registration: auto` (triggers DCR against a stub that serves none). **20 lines**
- [x] 3.2 `mcpConnectFormPost` (form body, `Content-Type: application/x-www-form-urlencoded`, pinned `req.Host`, `noRedirectClient()`) + `doRedacted(t, req, stage)` (drops the `*url.Error`, which renders the full URL) + `connectTicketFrom` (assert `303`, `Location.Path == /{slug}/mcp/connect`, `require.NotEmpty(ticket)`, **body closed unread**). **30 lines**
- [x] 3.3 `driveProviderConsent`: three hops through `noRedirectClient()` with **no pinned Host** — `/oauth/connect/{provider}` and `/oauth/callback/{provider}` must be hit on plain `localhost:8092` because `ConnectHandler.Start` passes `c.BaseURL()` as the redirect-URI base. Hop 1 asserts `redirect_uri == MCPURL + "/oauth/callback/" + provider` explicitly so a reintroduced Host pin fails at the point of cause. Hop 3's body is **closed unread** — `renderConnectPage` embeds the live ticket in `href`/`action`. **26 lines**
- [x] 3.4 `requireBearerMatches` (prefix check + `require.True(got == want)` with `len()`-only message; `require.Equal` renders both operands and would print the token) + `requireConsentRequired` (assert HTTP `200` and `code == -32003` only; `mcp_handler.go:254` puts a live ticket in `data.connect_url`, so never `rpcResult` and never render the body). **16 lines**
- [x] 3.5 `requireRPCSucceeded` — redacted replacement for `rpcResult` at every success call site. `rpcResult` (`mcp_e2e_test.go:130-137`) renders `body` and `body["error"]` verbatim, so an unexpected consent-required answer prints a live ticket from both the message and `data.connect_url`. Asserts `200`, then presence-and-non-nil on `body["error"]` (never `require.Nil`, which renders the operand), and returns `body["result"]` for callers that need it. **8 lines**
- [x] 3.6 `echoToolCall` + `forwardedFixture`/`newForwardedFixture` — the stub/capturing-upstream/gateway/provider/registry seed is identical in both tests; extracting it removes the duplication that let the two fixtures drift. **14 lines**

Verify: same as Phase 2. Tagged `golangci-lint` still deferred.

## Phase 4: Flow test — scenarios 1-6

Spec: *End-to-end self-service connect proof* (all three scenarios); *Forwarded injection proves principal identity* → *Stored token injected upstream*.

- [x] 4.1 `TestMCPAPIKeyConnect_ForwardedFlowEndToEnd`: `require.False(GlobalConfig.MCPConnectRateLimit.Enabled)` on line one, then seed in order — stub, capturing upstream, gateway (`uniqueName`), forwarded registry, MCP consumer, API-key auth, `AttachAuth`. `slug := ConsumerSlug(t, consumerID)`, `provider := uniqueName("prov")`. No `t.Parallel()`. **25 lines**
- [x] 4.2 Subtest "connect page is reachable through the running MCP plane": `require.Eventually(5s, 100ms)` around `GET /{slug}/connect` with the gateway Host pinned. This is the **only** propagation gate in this test, and `GET` is the only admissible gate — `POST` mints a ticket per iteration. **12 lines**
- [x] 4.3 Subtest "api key is exchanged for a ticket": `mcpConnectFormPost` with `api_key`, Host pinned, then `connectTicketFrom`. Unwrapped. **12 lines**
- [x] 4.4 Subtest "consent completes against the fake provider": `driveProviderConsent`, then assert `code_challenge_method == "S256"` and `code_challenge != ""` from `authorizeParams()`. **10 lines**
- [x] 4.5 Subtest "stored credential is injected into the upstream call": `tools/call` with `X-AG-API-Key` and pinned Host; `rpcResult` (safe on success only); `requireBearerMatches(idp.bearer(), capture.observed())`; `require.Equal(t, 1, idp.tokenExchanges())` — `2` means a silent refresh, not a vault read. **26 lines**

Verify: `go vet -tags functional ./tests/functional/...`; `golangci-lint run --build-tags functional ./tests/functional/...`; `go test -tags functional -c -o /dev/null ./tests/functional/`; then CI.

## Phase 5: Shared-key and isolation test — scenarios 7-9

Spec: *Shared-key grant reuse asserted explicitly*; *Principal and consumer isolation* (both scenarios).

- [x] 5.1 `TestMCPAPIKeyConnect_SharedKeyReusesGrantAndIsolatesPrincipals`: limiter assertion, fresh gateway (D4 — the vault key starts with `gateway_id`, so a distinct gateway makes cross-test bleed structurally impossible), consumer A + key A, consumer B + key B on the **same** registry, then complete A's connect via Phases 3-4 helpers. Gate propagation once per consumer. **20 lines**
- [x] 5.2 Scenario 7: **two** `tools/call`s with key A. One call cannot prove reuse — each `mcpRPC` is a fresh MCP session, so the second is a genuinely distinct client sharing one key. `capture.reset()` between them, then `requireBearerMatches` and `require.Equal(t, 1, idp.tokenExchanges())`. The exchange count is the observable that separates "reused the stored grant" from "ran consent again", and it is meaningful precisely because consent failures are deliberately not cached (`rememberFailure` returns early on `ConsentRequiredError`, `discovery.go:246-252`). **12 lines**
- [x] 5.3 Scenario 8: **second API-key auth attached to consumer A**, called with that key — holds the consumer constant so the test proves *principal* isolation rather than consumer isolation. `principal.Subject` is `auth.Name` (`auth_chain.go:300-304`) and the vault is keyed `(gateway, subject, provider)` (`credentials.go:137`), so a second auth on the same consumer is a distinct principal. Assert `requireConsentRequired` + `require.Zero(seen)`: comparing bearers cannot fail, because `askUpstream` resolves the credential in `c.target(...)` before `c.dialer.Connect(...)` (`discovery.go:215-219`), so zero requests reach the upstream and the captured bearer is always `""`. Attach before the propagation gate so the `Eventually` GET covers the new binding. **6 lines**
- [x] 5.4 Scenario 9: a key owned by a **different** consumer posted to consumer A's `/{slug}/connect`, assert generic `401`, single assertion, no dedicated test. **3 lines**

Verify: as Phase 4.

## Phase 5b: Adversarial review fixes

- [x] 5b.1 Blocker — scenario 8's isolation assertion passed vacuously (`require.False(otherBearer == idp.bearer())` on an always-empty capture). Replaced with `require.Zero(seen)`; see 5.3.
- [x] 5b.2 Blocker — scenario 7 asserted "the second client's call must reach the upstream" with only one call in the block. Added the real second call plus the exchange-count close; see 5.2.
- [x] 5b.3 Warning — `rpcResult` could render a live ticket at two call sites. Added `requireRPCSucceeded` (3.5) and reused it at all three success sites. `mcp_e2e_test.go` untouched.
- [x] 5b.4 Warning — investigated whether the `GET /{slug}/connect` gate can pass while the gated `POST` returns `401`. **Not reachable; gate left as is.** The functional MCP plane is DB-backed (`setup_test.go:155`), so propagation runs through `dataFinder`'s per-gateway `consumer_data` TTL cache, not the config-sync snapshot. That unit is atomic per gateway *and* carries the auth binding: `consumerSelectColumns` (`repository.go:54-64`) selects `auth_ids` via a correlated `array_agg` over `consumer_auth` **in the same statement** as the consumer row, so one MVCC snapshot covers both; `load()` then installs the whole `Data` with a single `memoryCache.Set` behind `singleflight`. Both predicates read that same object — `validMCPConsumer(target)` and `validAPIKeyAuth(auth, target.Consumer, …)` both come from `findTarget`. Ordering closes the rest: `createMCPConsumer` returns only after `AttachAuth` committed and published `InvalidateGatewayDataEvent`, and the `Eventually` GET is the first MCP touch. `FindByAPIKey` has no negative caching (`key_finder.go:46-61`), so a fresh key cannot be cached absent.
- [x] 5b.5 Suggestions — hoisted `slugA` (was two admin round-trips), extracted the shared fixture (3.6), dropped consumer B's redundant propagation poll, and moved scenario 8 onto a second auth of consumer A.

Verify: as Phase 4.

## Phase 6: Docs and final verification

Spec: *OAuth2 per-user regression without new tests*; *Verification changes no production behavior*.

- [ ] 6.1 `docs/mcp/testing-guide.md` §5 (line 262): add rows for both new tests and the operator + Cursor self-service connect flow, plus the note that `TestMCPOAuth_SharedHostScopesChallengeAndResolvesConsumerIdP` and `TestMCPServer_RoleBasedConsumer*` passing unmodified **is** scenario 10. **14 lines**
- [ ] 6.2 Run `clean-comments` over the new file and confirm zero comments survive; confirm `git diff --stat` shows no `pkg/` change — a needed production change means the test found a defect, so escalate against RUN-1136 instead of adapting the test. **0 lines**
- [ ] 6.3 Audit `git diff --stat -- tests docs .env.functional.example` against 400; pull the levers above in order if it drifts. **0 lines**
- [ ] 6.4 Rebase onto `feat/api-key-self-service-connect-endpoint` (unmerged and moving), open the **draft** PR against it with `RUN-1139` in the body. **0 lines**

Verify: `go vet -tags functional ./tests/functional/...`; `golangci-lint run --build-tags functional ./tests/functional/...`; `make lint`; CI Functional Tests job green on the full package under `-race`.

## Line budget by phase

| Phase | Forecast | Actual |
|---|---|---|
| 1 — Deterministic conditions | 3 | 3 |
| 2 — Stub and capture | 128 | 219 |
| 3 — Connect helpers | 92 | 143 |
| 4 — Flow test | 85 | 40 |
| 5 — Isolation test | 58 | 38 |
| 6 — Docs | 14 | pending |
| **Total** | **380 / 400** | **443 + docs** |

Cumulative `git diff --stat 8c5cd730 -- tests docs .env.functional.example` is **443**
(3 in `.env.functional.example`, 440 in the test file), up 14 from the 429 that went into
review. The review fixes cost 14 net: the redacted `requireRPCSucceeded` guard (+8) and the
second `tools/call` that actually proves grant reuse (+5) are load-bearing and cannot be
compressed further; the shared fixture (+14 gross) buys back 10 at the two call sites, so it
funds only part of itself rather than the ~5 the review projected. The savings that did land
— flattening the seed into `newForwardedFixture`, dropping consumer B's redundant
propagation poll, hoisting `slugA`, and folding scenario 8 onto a second auth of consumer A —
took Phase 4 from 49 to 40 and Phase 5 from 41 to 38.

Reaching net zero from here would mean deleting Phase 4's four named subtests (~9 lines of
`t.Run` scaffolding), which the review did not ask for and which costs the per-scenario
failure attribution the whole test was structured around. Not taken. The 400-line budget
needs the recorded `size-exception`, or lever 1 (trim the guide to §5 rows) plus lever 2
(drop `scopes` and the PKCE assertion). `git diff --stat -- pkg` is empty and
`tests/functional/mcp_e2e_test.go` is untouched.
