---
linear: RUN-1139
type: test
changelog: "Functional coverage for the MCP API-key self-service connect flow and forwarded credential injection, end to end against a fake OAuth provider."
---

# Proposal: API-key forwarded authorization coverage (RUN-1139)

## Intent

Unit coverage on `feat/api-key-self-service-connect-endpoint` is dense but every layer is mocked. Nothing proves that the principal derived at **connect** time (`api_key_connect.go`, from `auth.Name`) is the same principal derived at **runtime** (`auth_chain.go:300`), because the two derive it independently. Only a functional test through the real three-process harness can prove that the vault grant created by the connect page is the bearer the upstream MCP server actually receives. Two further guarantees — one API key means one shared grant, and different principals never cross grants — are uncovered anywhere today.

## Scope

### In Scope

- New `tests/functional/mcp_api_key_connect_test.go`, build tag `functional`, package `functional_test`, **no comments** (AGENT.md §11.1; pre-commit hook strips them). Intent lives in subtest names and assertion messages.
- Two top-level tests: an ordered-subtest flow test (issue scenarios 1–6) and a shared-key/isolation test (7–9, with 9 as a single 401 assertion).
- Test-support: fake external OAuth **provider** stub (`/authorize` 302 with `code`+`state`, `/token` returning `expires_in` **and** a refresh token), a mutex-guarded capturing wrapper around `startMCPUpstream`, a form-encoded POST helper, and a `forwarded` variant of `mcpRegistryPayload`. All local to the new file.
- `.env.functional.example`: `MCP_CONNECT_RATE_LIMIT_ENABLED=false` with a comment matching the existing `RATE_LIMIT_ENABLED=false` voice.
- `docs/mcp/testing-guide.md`: new §5 scenario rows plus the operator and Cursor self-service connect flow.

### Out of Scope

- **Scenario 10 as new test code — deviation from the issue.** `TestMCPOAuth_SharedHostScopesChallengeAndResolvesConsumerIdP` plus `TestMCPServer_RoleBasedConsumer*` already guard inbound OAuth2 per-user behavior. A second IdP stub with JWT minting costs ~40 lines against a 400-line budget to re-prove existing coverage. Requirement becomes: those tests keep passing, and the guide records the regression note.
- Direct assertions against `vault_credentials` (Postgres). The behavioral tool-call assertion proves persistence, key derivation and principal identity in one step; a new pgx helper would be redundant.
- Slash-bearing provider ids. Providers use plain realistic strings; the wildcard route is a unit-test edge case.
- Proving the connect limiter's 429 — exhaustively covered in `pkg/infra/ratelimit/connect_test.go` and the handler tests.
- Any admin-API change. `MCPAuthRequest` already exposes `mode` and `provider` and maps to `domain.MCPAuth`.
- Any production code change. If one becomes necessary, the test found a real bug — escalate, do not adapt the test.

## Capabilities

### New Capabilities

- None. This change adds verification, not behavior.

### Modified Capabilities

- None. `api-key-self-service-connect` and `mcp-connect-security-observability` requirements are **verified end to end**, not altered.

## Approach

Reuse the shared-host harness as is (`setup_test.go` boot, `common_test.go` builders, `noRedirectClient`, host pinning, the `require.Eventually` admin→MCP cache-propagation idiom). Add only what does not exist: the provider stub and the header capture.

**Flow test** — one gateway, one MCP consumer, one API key, one `forwarded` registry (`registration: manual`, explicit `client_id`/`authorize_url`/`token_url` pointing at the stub), one capturing upstream. Ordered subtests: connect page reachable → `POST /{slug}/connect` returns 303 with a ticket in `Location` → the OAuth leg is driven hop by hop with `noRedirectClient` (`/oauth/connect/{provider}` → stub `/authorize` → `/oauth/callback/{provider}`) → `tools/call` with `X-AG-API-Key` reaches the upstream carrying exactly the bearer the stub minted.

**Isolation test** — a second client using the same key sees the same grant with no second connect; a second consumer with its own key gets consent-required, not the first grant; that consumer's key against the first slug returns the generic 401.

Secrets are never rendered: key, ticket and token are asserted on shape or equality only, never passed as `msgAndArgs`, never `%v`-ed from a response body.

## Chain / base strategy

| Item | Value |
|---|---|
| Worktree | `/Users/edu/Neuraltrust/TrustGate-api-key-forwarded-coverage` |
| Branch | `test/api-key-forwarded-coverage` |
| Base | `feat/api-key-self-service-connect-endpoint` (epic RUN-1136) — **not** `develop` |
| PR | Single **draft** PR into the integration branch, `RUN-1139` in the body |
| Merge to `develop` | **Never by an agent.** Edu merges the epic manually after end-to-end validation |
| Rebase | Rebase onto the integration branch before review; base is unmerged and moving |

Size forecast **~300–420 changed lines** against the 400-line budget — fits with no slack. Levers if it drifts: scenario 10 is already deferred (up to 40 lines), scenario 9 stays a single assertion (already assumed), and the guide edit can shrink to the §5 table rows. Chained PRs are not worthwhile: the provider stub is dead code without the test that drives it.

## Affected Areas

| Area | Impact | Description |
|---|---|---|
| `tests/functional/mcp_api_key_connect_test.go` | New | Both tests plus their local stubs and helpers |
| `.env.functional.example` | Modified | `MCP_CONNECT_RATE_LIMIT_ENABLED=false` (~3 lines) — blocking; CI copies this file verbatim |
| `docs/mcp/testing-guide.md` | Modified | §5 scenario rows, operator + Cursor connect flow |
| `docs/mcp/api-key-auth-and-external-credentials.md` | Modified only if | Nothing found so far requires it |
| `openspec/changes/api-key-forwarded-coverage/` | New | SDD artifacts |
| `tests/functional/mcp_e2e_test.go` | Unchanged | Helpers stay local to the new file; promote later only if a second test needs them |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Connect limiter trips a shared-bucket 429 (10/min per source, all traffic from `127.0.0.1`) | High if unaddressed | `MCP_CONNECT_RATE_LIMIT_ENABLED=false`; verify against the booted config, do not assume |
| Credential born expired → runtime takes the refresh path instead of injecting | Med | Stub returns `expires_in: 3600` **and** a refresh token |
| Admin→MCP cache propagation not yet landed at first connect | Med | `require.Eventually(5s, 100ms)` on the first MCP-plane assertion |
| `-race` failure on the shared header capture | Med | Mutex around the recorded `Authorization` |
| 120s local package timeout (`make test-functional`, no `-race`) | Med | Two top-level tests, one gateway each, minimal connect POSTs |
| `registration: auto` triggering dynamic client registration against the stub | Low | Always `manual` with explicit URLs |
| Secret leaking into a failure message or snapshot | Low | Never pass key/ticket/token as `msgAndArgs`; assert status and `Location` shape |
| Base branch moves under us | Med | Draft PR, rebase before review |

## Rollback Plan

Fully additive and test-only. Revert by deleting `tests/functional/mcp_api_key_connect_test.go`, reverting the one `.env.functional.example` line and the `docs/mcp/testing-guide.md` edit. No production code, no schema, no migration, no runtime behavior touched — reverting cannot regress the gateway. If the limiter env line ever needs to stay while the tests go, it is independently revertable.

## Dependencies

- Base branch `feat/api-key-self-service-connect-endpoint` (RUN-1136) must remain the PR target until Edu merges the epic.
- Go 1.26.6 (matches `go.mod` and CI); local Postgres 5432 and Redis 6379 for `make test-functional`.
- CI `functional-tests` job copies `.env.functional.example` → `.env.functional`, so the limiter line must land in the example file.
- `modelcontextprotocol/go-sdk` upstream server and the existing admin-API builders — no new module dependencies.

## Success Criteria

- [ ] Full flow passes against the fake OAuth provider: connect page → 303 with ticket → authorize → callback → credential stored.
- [ ] The upstream MCP server receives exactly the bearer minted by the provider stub on a `tools/call` authenticated with `X-AG-API-Key`.
- [ ] Shared-key behavior asserted explicitly: a second client with the same key reuses the grant without connecting again.
- [ ] A different API-key principal gets consent-required, not the first principal's grant.
- [ ] A key belonging to another consumer is rejected with the generic 401.
- [ ] `TestMCPOAuth_SharedHostScopesChallengeAndResolvesConsumerIdP` and `TestMCPServer_RoleBasedConsumer*` still pass unchanged (scenario 10).
- [ ] No secret (API key, ticket, access token) appears in any log, failure message or snapshot.
- [ ] `go test -tags functional -race -count=1 -p 1 ./tests/functional/...` green; `make test-functional` completes inside its 120s timeout.
- [ ] `go vet` and `golangci-lint` green; no comments in the new test file.
- [ ] `docs/mcp/testing-guide.md` documents the operator and Cursor self-service connect flow.
