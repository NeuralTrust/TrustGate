# Tasks: API-Key Self-Service Connect Endpoint

## Review Workload Forecast

| Phase | Expected additions + deletions |
|---|---:|
| Existing SDD artifacts | 340–390 |
| 1. Application authorization | 300–390 |
| 2. Secure form foundation | 200–280 |
| 3. HTTP adapter | 260–360 |
| 4. Routing and DI | 260–350 |
| 5. Final verification | 0–20 |
| **Total** | **1,360–1,790** |

| Field | Value |
|---|---|
| 400-line budget risk | High |
| Chained PRs recommended | No |
| Delivery strategy | exception-ok |
| Chain strategy | size-exception |

Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: size-exception
400-line budget risk: High

### Single-PR Work Units

| Commit | Scope |
|---|---|
| Planning | OpenSpec proposal, spec, design, and tasks |
| Phase 1 | App use case and unit tests |
| Phase 2 | DTO, generated mock, page, and tests |
| Phase 3 | Handler and tests |
| Phase 4 | Router, DI, and dispatch tests |
| Phase 5 | Final cleanup and verification |

Use one `feat/api-key-self-service-connect-endpoint` branch and one RUN-1141 PR to `develop`, with phase-aligned commits.

Size exception rationale: the security matrix, DI graph, and route precedence form one functional contract that is difficult to review safely in isolation; the SDD artifacts document that same change.

## Phase 1: Application Authorization (RUN-1141)

- [x] 1.1 Create `pkg/app/oauth/api_key_connect.go`: sentinel, mockery directive, single interface/implementation, constructor, and methods.
- [x] 1.2 Enforce target-first `DataFinder`/`MatchSlug`, MCP/API-key state, gateway/AuthID isolation, exact `auth.Name`, and `MCPPath(slug)`.
- [x] 1.3 Create `pkg/app/oauth/api_key_connect_test.go` for success, call order, target/auth matrix, dependency errors, and exact ticket arguments.
- [x] 1.4 Run focused tests, `goimports`/`gofmt`, and directive-only comment cleanup.

## Phase 2: Secure Form Foundation (RUN-1141)

- [ ] 2.1 Generate, never hand-edit, `pkg/app/oauth/mocks/oauth_api_key_connect_service_mock.go`.
- [ ] 2.2 Create `pkg/api/handler/http/oauth/request/api_key_connect_request.go` with the sole body-only `api_key` form DTO.
- [ ] 2.3 Update `pkg/api/handler/http/oauth/pages.go` for escaped action, blank password, `autocomplete="off"`, and no-store rendering.
- [ ] 2.4 Extend `pkg/api/handler/http/oauth/pages_test.go` for escaping, blank secret, field attributes, and cache headers; run focused checks.

## Phase 3: HTTP Adapter (RUN-1141)

- [ ] 3.1 Create `pkg/api/handler/http/oauth/api_key_connect_handler.go` with thin Host/slug GET and form-urlencoded POST methods.
- [ ] 3.2 Map GET misses to 404; POST authorization 401, malformed 400, media 415, dependencies 500, success no-store 303.
- [ ] 3.3 Create `pkg/api/handler/http/oauth/api_key_connect_handler_test.go` for body-only input, no-Origin acceptance, statuses, redirect, and secret absence.
- [ ] 3.4 Run focused tests, formatting/import checks, and comment cleanup.

## Phase 4: Routing and Dependency Injection (RUN-1141)

- [ ] 4.1 Update `pkg/container/modules/mcp.go` to provide the use case from exact-typed dependencies.
- [ ] 4.2 Update `pkg/container/modules/api.go` with a local `MCPBaseDomain` resolver factory, avoiding global resolver collision.
- [ ] 4.3 Update `pkg/container/modules/server_mcp.go` and `pkg/server/router/mcp_router.go`; register GET/POST before `/+/connect`.
- [ ] 4.4 Create `pkg/server/router/mcp_router_test.go` for real Fiber precedence and OAuth/existing-MCP regressions.
- [ ] 4.5 Run container/router tests and prove minimal DI resolution without collisions.

## Phase 5: Final Verification (RUN-1141)

- [ ] 5.1 Audit leakage, generic failures, unchanged runtime/vault/OAuth2, and exclusion of RUN-1142/RUN-1140.
- [ ] 5.2 Re-run generation; reject drift and remove non-directive/Swagger/license Go comments.
- [ ] 5.3 Run `goimports`, `gofmt`, `go vet ./...`, focused tests, `make lint`, and `go test -race ./...`.
