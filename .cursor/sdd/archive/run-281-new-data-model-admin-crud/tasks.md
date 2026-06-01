# Tasks: RUN-281 New data model + admin CRUD

Scope guard: no RUN-299 cache invalidation, no hot-path Policy matcher
(B.4), no plugin chain wiring (B.3), no `Auth` type implementations
(B.7), no audit log (B.9), no streaming / provider adapters / load
balancing / hot-path forwarding (B.4/B.5), no read-through caching, no
admin authentication, no multi-tenant filters, no soft delete.

Branch: stay on `feat/run-282-b0-project-setup-scaffolding` (user
override). Each phase below maps to one PR (or two for the Consumer-a
split). PR-size budget per `_base.mdc`: 400 lines soft cap; phases
flagged ⚠️ are expected to need a documented `size:exception` label.

Sub-issue mapping:

- RUN-295 + RUN-296 → all `<entity>-a` phases.
- RUN-297 → all `<entity>-b` phases.
- RUN-298 → all `<entity>-c` phases.
- RUN-299 → deferred outside B.2.

Entity order is **Gateway → Backend → Consumer → Policy → Auth**.
Within an entity, order is `a → b → c`.

## Phase 0: Cross-cutting prerequisites (one PR)

Lands before Gateway-a so the per-entity slices have a shared base.
Estimated 250–350 LOC.

- [x] 0.1 Add `github.com/vektra/mockery/v2` to `tools/tools.go` (build
      tag `tools`) pinning v2.53.6 in `go.mod`; add Makefile targets
      `tools` (install mockery) and `mocks` (verifies mockery is on PATH
      and runs `go generate ./...`).
- [x] 0.2 Created `pkg/api/handler/http/helpers/params.go` with
      `ParseUUIDParam`, `ParsePage`, `ParseSize` (clamp to ≤ 200) +
      `DefaultPage=1`, `DefaultSize=20`, `MaxSize=200` constants and
      sentinels (`ErrInvalidUUIDParam`, `ErrInvalidPage`,
      `ErrInvalidSize`).
- [x] 0.3 Created `pkg/api/handler/http/helpers/response.go` with
      `WriteCreated`, `WriteOK`, `WriteNoContent`, `WriteListEnvelope`
      and the `ListEnvelope { Items, Page, Size, Total }` JSON shape.
- [x] 0.4 Created `pkg/api/handler/http/helpers/errors.go` with the
      `MapDomainError(err) → (status, ErrorBody)` switch plus
      `WriteError`. Initial branches: 400 invalid uuid, 422 invalid
      pagination / validation / invalid config, 404 not_found, 409
      already_exists / has_dependents, 500 default. Extended
      `pkg/common/errors/errors.go` with `ErrAlreadyExists`,
      `ErrHasDependents`, `ErrValidation` so entity-specific sentinels
      can wrap them with `%w`.
- [x] 0.5 `pkg/domain/common/` skipped — YAGNI; no shared value object
      needed yet.
- [x] 0.6 Tests: `params_test.go` (14 sub-tests covering UUID happy /
      invalid / missing, page default / valid / zero / negative /
      non-int, size default / valid / clamp / max / zero / negative /
      non-int) and `errors_test.go` (11 sub-tests covering every
      MapDomainError branch and an `errors.Is`-wrapped case). All pass
      with `go test -race ./pkg/api/handler/http/helpers/...`.

## Phase 1: Gateway-a (RUN-295 + RUN-296 slice)

Domain + migration + pgx repository + repo integration tests. Estimated
380–450 LOC.

- [x] 1.1 Created `pkg/domain/gateway/gateway.go` (Gateway aggregate +
      `New` constructor with name/description validation +
      `Rehydrate`/`Rename`/`SetDescription` mutators),
      `repository.go` (Repository interface + `ListFilter`),
      `errors.go` (`ErrNotFound`/`ErrAlreadyExists`/`ErrHasDependents`/
      `ErrInvalidName`/`ErrInvalidDescription` all wrapping the
      matching `pkg/common/errors` sentinels with `%w`).
- [x] 1.2 Created
      `pkg/infra/database/migrations/20260528113134_create_gateways_table.go`
      with `Up` (CREATE TABLE + UNIQUE name + `lower(name)` index)
      and `Down` (DROP TABLE). Picked up automatically by the
      existing blank-import in `cmd/agentgateway/main.go`.
- [x] 1.3 Created `pkg/infra/repository/gateway/repository.go`
      implementing the domain Repository over `pgxpool` +
      `database.WithTx`. Includes `mapPgError` that translates
      `23505` (unique violation) → `ErrAlreadyExists` and `23503`
      (FK violation) → `ErrHasDependents`. Re-uses one `scanGateway`
      helper for `QueryRow` and `Query` results.
- [x] 1.4 No code change needed: gateway sentinels wrap the common
      ones with `%w`, so `MapDomainError` already routes them
      correctly via `errors.Is(err, commonerrors.Err…)`. Verified
      with `TestValidationErrorsWrapCommonSentinel`. Subsequent
      `<entity>-a` slices follow the same pattern.
- [x] 1.5 `pkg/domain/gateway/gateway_test.go` — 6 sub-tests for
      `New` (happy, trim, empty, whitespace-only, overlong name,
      overlong description), `TestRename` (3 cases),
      `TestSetDescription` (2 cases), `TestRehydrate`, and
      `TestValidationErrorsWrapCommonSentinel`. No DB; runs under
      `go test -race` in ~30 ms.
- [x] 1.6 `pkg/infra/repository/gateway/repository_test.go` (external
      test package) — `setupRepo` skips when `PG_TEST_URL` is unset
      (matches AGENT.md §9). Tests cover: Save + FindByID happy,
      FindByID missing → `ErrNotFound` (and wrapped `commonerrors.ErrNotFound`),
      Save duplicate → `ErrAlreadyExists`, Update happy + missing,
      Delete happy + double-delete idempotence, List with default
      pagination + page-2 + `NameContains` + case-insensitive
      filter. Cleanup is `TRUNCATE gateways CASCADE` between tests.

## Phase 2: Gateway-b (RUN-297 slice)

App services with mockery mocks + unit tests + a small shared cache
primitive adopted from TrustGate's finder pattern (cache-first, DB
fallback, cache populate). Estimated 700–800 LOC ⚠️ (PR will need a
`size:exception` label; future `-b` phases reuse the cache primitive
and stay within budget).

Scope addition vs original plan: the user mandated the canonical
TrustGate finder shape ("busca en cache local TTL, sino busca en BBDD
y persiste la entidad en el ttl map"). To honour that without
dragging in RUN-291 (Redis client + cross-process invalidation), Phase
2 ports **only** the in-process TTL primitive. RUN-291 will later
insert the Redis layer between memory and DB without touching the
finder contract.

- [x] 2.0 Ported the local TTL primitive from TrustGate:
      `pkg/infra/cache/ttlmap.go` (thread-safe TTLMap with lazy
      eviction on read) + `pkg/infra/cache/ttlmap_manager.go`
      (namespace manager with stable namespace constants
      `GatewayTTLName`, `BackendTTLName`, `ConsumerTTLName`,
      `PolicyTTLName`, `AuthTTLName`). Added `CacheConfig.LocalTTL`
      (env `CACHE_LOCAL_TTL`, default 5m) and wired
      `*cache.TTLMapManager` as a singleton through
      `pkg/container/modules/cache.go`. Covered by
      `ttlmap_test.go` (get/set/delete, TTL expiry + lazy sweep,
      Clear, concurrent reader/writer, namespace isolation,
      idempotent `GetTTLMap`). All pass under `-race`.
- [x] 2.1 Created `pkg/app/gateway/creator.go` (`Creator` interface +
      impl + `//go:generate mockery`). Takes an in-package
      `CreateInput { Name, Description }` so the app layer stays free
      of transport DTOs; the HTTP handler in Phase 3 maps onto it.
      Persists via `Repository.Save` then pre-warms the gateway TTL
      namespace so read-after-write hits memory.
- [x] 2.2 Created `pkg/app/gateway/updater.go` (`Updater` + impl +
      `mockery`). `FindByID → Rename → SetDescription →
      Repository.Update`, refreshes the cache entry on success;
      propagates `ErrNotFound` / `ErrValidation` unchanged.
- [x] 2.3 Created `pkg/app/gateway/deleter.go` (`Deleter` + impl +
      `mockery`). Invalidates the cache entry on successful delete;
      leaves the cache untouched on repo error (so a transient
      `ErrHasDependents` does not poison the cached entity).
- [x] 2.4 Created `pkg/app/gateway/finder.go` (`Finder` + impl +
      `mockery`). `FindByID` follows memory → DB → populate exactly
      like `TrustGate/pkg/app/gateway/data_finder.go`. Type-assertion
      failure on the cached value is treated as poisoning: the entry
      is dropped, the read falls through to the DB, and a warning is
      logged. `List` is intentionally uncached (variable filters and
      pages).
- [x] 2.5 Ran `go generate ./pkg/domain/gateway/... ./pkg/app/gateway/...`.
      Produced `pkg/domain/gateway/mocks/gateway_repository_mock.go`
      and `pkg/app/gateway/mocks/{creator,updater,deleter,finder}_mock.go`.
- [x] 2.6 Unit tests driven by the generated `domain.gateway`
      Repository mock and a real `TTLMapManager`: `creator_test.go`
      (success + pre-warm, invalid name short-circuit, repo error
      propagation incl. wrapped `commonerrors.ErrAlreadyExists`),
      `updater_test.go` (success + cache refresh, `ErrNotFound`,
      invalid name short-circuit before repo `Update`),
      `deleter_test.go` (success + cache invalidation, `ErrNotFound`
      leaves cache intact, `ErrHasDependents` propagation),
      `finder_test.go` (cache hit returns the same pointer, miss
      populates the cache, `ErrNotFound`, poisoned cache falls back
      to DB and is refreshed, `List` passthrough). All pass under
      `go test -race ./pkg/app/gateway/...`.

## Phase 3: Gateway-c (RUN-298 slice)

Admin handlers + DTOs + router + DI module fill-in. Estimated 380–450
LOC.

- [ ] 3.1 Create request DTOs in `pkg/api/handler/http/request/`:
      `create_gateway_request.go`, `update_gateway_request.go`,
      `list_gateway_request.go` (each one file, one struct, one
      `Validate()`).
- [ ] 3.2 Create response DTOs in `pkg/api/handler/http/response/`:
      `gateway_response.go`, `list_gateway_response.go`.
- [ ] 3.3 Create the five action handlers under
      `pkg/api/handler/http/`: `create_gateway_handler.go`,
      `get_gateway_handler.go`, `list_gateway_handler.go`,
      `update_gateway_handler.go`, `delete_gateway_handler.go`. Each
      depends on the relevant app-service interface from Phase 2.
- [ ] 3.4 Fill `pkg/container/modules/gateway.go`: replace
      `return nil` with concrete providers (repo, domain repo iface,
      4 app services, 5 handlers).
- [ ] 3.5 Extend `pkg/container/modules/api.go` to register the 5 new
      handler providers under the admin transport.
- [ ] 3.6 Extend `adminRouterParams` in
      `pkg/server/router/admin_router.go` with 5 handler fields and
      register the `POST/GET/GET/PUT/DELETE /v1/gateways[/:id]` routes
      after the existing health/version routes.
- [ ] 3.7 Handler tests using `fiber.New().Test(req)` against each
      handler driven by mockery mocks of the app-service interfaces.
      Cover Admin CRUD API spec scenarios: validation, status codes,
      domain-error mapping, pagination defaults, name filter.
- [ ] 3.8 Add a small DI test under `pkg/container/modules/` proving
      the gateway module resolves end-to-end (handlers receive their
      use cases through the interface).

## Phase 4: Backend-a — SUPERSEDED ✅

> **Superseded** by the LLM-only Backend slice landed in the
> `feat/run-282-b0-project-setup-scaffolding` branch. The original
> plan used a `Type` discriminator (`llm`/`a2a`/`mcp`) and a generic
> `Config JSONB`. The shipped design is LLM-only: every backend is an
> OpenAI-compatible pool with `Algorithm` + `Targets[]` +
> `EmbeddingConfig?`. Differentiation between LLM vendors happens via
> the free-form `Target.Provider` string (validated at runtime by a
> separate provider registry, out of scope here). A2A and MCP backends
> will land as separate aggregates if/when needed.

- [x] 4.1 Domain at `pkg/domain/backend/` (`backend.go`, `target.go`,
      `targets.go`, `embedding_config.go`, `builder.go`,
      `repository.go`, `errors.go`). Discriminated `TargetAuth` with
      `APIKey`/`Azure`/`AWS`/`OAuth2`/`GCPServiceAccount` variants.
- [x] 4.2 Migration `20260528142004_create_backends_table.go`:
      `(id, gateway_id REFERENCES gateways(id) ON DELETE RESTRICT,
      name, algorithm, targets JSONB, embedding_config JSONB,
      created_at, updated_at)` + `UNIQUE(gateway_id, name)` and indexes
      on `gateway_id` and `lower(name)`.
- [x] 4.3 `pkg/infra/repository/backend/repository.go`. Maps `23503`
      (FK violation) → `backend.ErrInvalidGatewayID`; `23505` (unique
      violation) → `backend.ErrAlreadyExists`.
- [x] 4.4 `helpers/errors.go` covers backend errors via the existing
      `commonerrors.ErrValidation` / `ErrNotFound` / `ErrAlreadyExists`
      wrap — no extra branches needed.
- [x] 4.5 Unit + repo integration tests covering targets JSONB
      round-trip, semantic algorithm validation, and FK rejection.

## Phase 5: Backend-b — SUPERSEDED ✅

> Superseded together with Phase 4. The Creator and Updater do not
> carry per-type JSON-config validators; instead validation lives in
> `Backend.Validate()` / `Target.Validate()` / `TargetAuth.Validate()`.
> `Algorithm` is mutable, `GatewayID` is immutable post-creation
> (`backend.ErrInvalidGatewayID` on attempted change).

- [x] 5.1 `pkg/app/backend/creator.go`.
- [x] 5.2 `pkg/app/backend/updater.go` (rejects `GatewayID` mutation).
- [x] 5.3 `pkg/app/backend/deleter.go`.
- [x] 5.4 `pkg/app/backend/finder.go` (cache-first, mirrors the
      gateway finder).
- [x] 5.5 `go generate ./...` (mocks committed under
      `pkg/app/backend/mocks/` and `pkg/domain/backend/mocks/`).
- [x] 5.6 Unit tests per use case driven by the generated mocks.

## Phase 6: Backend-c — SUPERSEDED ✅

> Superseded together with Phase 4. Routes are nested under
> `/v1/gateways/:gateway_id/backends` (not `/v1/backends`) so the
> parent gateway is part of the URL.

- [x] 6.1 Request DTOs: `create_backend_request.go`,
      `update_backend_request.go`, `list_backend_request.go`.
- [x] 6.2 Response DTOs: `backend_response.go`,
      `list_backend_response.go` (credentials redacted to `***`).
- [x] 6.3 Five handlers under `pkg/api/handler/http/`.
- [x] 6.4 `pkg/container/modules/backend.go` provides the repo, four
      use cases, and five handlers.
- [x] 6.5 Handlers exposed via `AdminRouterDeps` in
      `pkg/server/router/admin_router.go`.
- [x] 6.6 Routes mounted at `/v1/gateways/:gateway_id/backends[/:id]`.
- [x] 6.7 Handler-level coverage deferred to the functional suite —
      use-case + DTO unit tests already cover the wire/domain mapping.

## Phase 7: Consumer-a1 (split — RUN-295 slice)

Domain + migrations only. Estimated 350–400 LOC.

- [ ] 7.1 `pkg/domain/consumer/consumer.go` with the
      `AttachBackend/DetachBackend/AttachPolicy/DetachPolicy/AttachAuth/DetachAuth`
      idempotent mutators. `repository.go` + `errors.go`.
- [ ] 7.2 Migration `<unix_ts>_create_consumers_table.go`.
- [ ] 7.3 Migration `<unix_ts>_create_consumer_backend_join.go`
      (composite PK `(consumer_id, backend_id)`, both FKs CASCADE).
- [ ] 7.4 Migration `<unix_ts>_create_consumer_policy_join.go`
      (deferred FK to `policies` table — temporarily without the
      Policy FK if Policy-a hasn't merged; ensure timestamp prefix
      orders this **after** the policies-table migration once Phase 11
      lands).
- [ ] 7.5 Migration `<unix_ts>_create_consumer_auth_join.go` (same
      ordering caveat with respect to Phase 14).
- [ ] 7.6 Unit tests for the consumer aggregate's attach/detach
      idempotence.

> Ordering note: if Consumer-a1 lands before Policy-a / Auth-a, the
> join migrations referencing not-yet-existing tables will fail. Two
> options for the implementer: (a) park the `consumer_policy` and
> `consumer_auth` join migrations as draft files until their parents
> land, or (b) move Policy-a and Auth-a *before* Consumer-a1 in the
> entity order. Decision recorded in design.md §"Migration
> Conventions" Phase 2 ordering: prefer (b) — Policy-a and Auth-a land
> before Phase 7. Tasks below assume that re-ordering: in practice
> Phase 7 runs after Phase 11 (Policy-a) and Phase 14 (Auth-a) have
> merged. Mark Phase 7 blocked-by Phase 11 + 14.

## Phase 8: Consumer-a2 (split — RUN-296 slice)

Repository + diffing logic + integration tests. Estimated 400–500 LOC ⚠️.

- [ ] 8.1 `pkg/infra/repository/consumer/repository.go` implementing
      `Save` (insert consumer + insert all join rows in one
      `WithTx`).
- [ ] 8.2 `Update` diffs current persisted join sets against the
      updated aggregate's slices and applies adds + deletes inside a
      single `WithTx`.
- [ ] 8.3 `Delete` relies on FK CASCADE to remove join rows; assert
      the cascade via integration test.
- [ ] 8.4 `FindByID` + `List` load joins via a single query per join
      table (no N+1).
- [ ] 8.5 Extend `helpers/errors.go` with consumer-domain branches.
- [ ] 8.6 Repository integration tests covering Persistence Model
      "Consumer.Update diffs joins atomically" scenario (add C, remove
      B, leave A; failure rollback).

## Phase 9: Consumer-b (RUN-297 slice)

Estimated 550–650 LOC ⚠️. Bigger because Creator/Updater orchestrate
the attach/detach mutations from request slices.

- [ ] 9.1 `pkg/app/consumer/creator.go` (translates
      `CreateConsumerRequest.BackendIDs/PolicyIDs/AuthIDs` into
      attach calls before `Save`).
- [ ] 9.2 `pkg/app/consumer/updater.go` (loads existing, applies
      request diffs, then `Update`).
- [ ] 9.3 `pkg/app/consumer/deleter.go`.
- [ ] 9.4 `pkg/app/consumer/finder.go`.
- [ ] 9.5 `go generate ./...`; commit mocks.
- [ ] 9.6 Unit tests per use case covering happy paths and the
      idempotent attach/detach semantics surfaced from the
      domain.

## Phase 10: Consumer-c (RUN-298 slice)

Estimated 400–450 LOC.

- [ ] 10.1 Request DTOs (`create_consumer_request.go` with
      `BackendIDs []uuid.UUID`, `PolicyIDs []uuid.UUID`,
      `AuthIDs []uuid.UUID`; `update_consumer_request.go`;
      `list_consumer_request.go`).
- [ ] 10.2 Response DTOs (`consumer_response.go` includes the three
      ID slices; `list_consumer_response.go`).
- [ ] 10.3 Five handlers.
- [ ] 10.4 Fill `pkg/container/modules/consumer.go`.
- [ ] 10.5 Register handlers in `modules/api.go`.
- [ ] 10.6 Add `/v1/consumers[/:id]` routes to `admin_router.go`.
- [ ] 10.7 Handler tests, including a scenario asserting that a
      create with `BackendIDs=[A, B, A]` results in attached `{A, B}`
      (idempotence visible through the API).

## Phase 11: Policy-a (RUN-295 + RUN-296 slice)

Estimated 400–450 LOC.

- [ ] 11.1 `pkg/domain/policy/policy.go` with
      `type PolicyAction string` (consts `allow`, `log`, `mask`,
      `block`), aggregate, validation rejecting unknown `Action`.
      `repository.go`, `errors.go` (`ErrInvalidAction`).
- [ ] 11.2 Migration `<unix_ts>_create_policies_table.go` with `action
      TEXT NOT NULL CHECK (action IN ('allow','log','mask','block'))`,
      `where JSONB NOT NULL`, `when JSONB NOT NULL`.
- [ ] 11.3 `pkg/infra/repository/policy/repository.go`.
- [ ] 11.4 Extend `helpers/errors.go` with policy-domain branches.
- [ ] 11.5 Unit + integration tests covering the action CHECK
      constraint and JSONB round-tripping.

## Phase 12: Policy-b (RUN-297 slice)

Estimated 380–450 LOC.

- [ ] 12.1 `pkg/app/policy/{creator,updater,deleter,finder}.go`.
- [ ] 12.2 `go generate ./...`; commit mocks.
- [ ] 12.3 Unit tests.

## Phase 13: Policy-c (RUN-298 slice)

Estimated 380–450 LOC.

- [ ] 13.1 Request DTOs (`Where` and `When` accepted as
      `json.RawMessage`; validation limited to "is valid JSON").
- [ ] 13.2 Response DTOs.
- [ ] 13.3 Five handlers.
- [ ] 13.4 Fill `pkg/container/modules/policy.go`.
- [ ] 13.5 Register handlers in `modules/api.go`.
- [ ] 13.6 Add `/v1/policies[/:id]` routes to `admin_router.go`.
- [ ] 13.7 Handler tests.

## Phase 14: Auth-a (RUN-295 + RUN-296 slice)

Estimated 350–420 LOC.

- [ ] 14.1 `pkg/domain/auth/auth.go` with `Type string` (allow-list
      validated at construction time; B.7 owns the final list — for
      B.2 start with `{api_key, oidc, mtls}` and document the
      provisional nature in the file's package doc).
      `repository.go`, `errors.go`.
- [ ] 14.2 Migration `<unix_ts>_create_auths_table.go` with
      `type TEXT NOT NULL`, `config JSONB NOT NULL`. No CHECK
      constraint on `type` so adding strings later is migration-free.
- [ ] 14.3 `pkg/infra/repository/auth/repository.go`.
- [ ] 14.4 Extend `helpers/errors.go` with auth-domain branches.
- [ ] 14.5 Unit + integration tests.

## Phase 15: Auth-b (RUN-297 slice)

Estimated 380–450 LOC.

- [ ] 15.1 `pkg/app/auth/{creator,updater,deleter,finder}.go`. The
      Creator/Updater enforce the `type` allow-list defined in the
      domain package; `Config` is validated as "is valid JSON" only
      (B.7 will refine).
- [ ] 15.2 `go generate ./...`; commit mocks.
- [ ] 15.3 Unit tests.

## Phase 16: Auth-c (RUN-298 slice)

Estimated 380–450 LOC.

- [ ] 16.1 Request DTOs.
- [ ] 16.2 Response DTOs.
- [ ] 16.3 Five handlers.
- [ ] 16.4 Fill `pkg/container/modules/auth.go`.
- [ ] 16.5 Register handlers in `modules/api.go`.
- [ ] 16.6 Add `/v1/auths[/:id]` routes to `admin_router.go`.
- [ ] 16.7 Handler tests.

## Phase 17: B.2 verification & docs

One small PR closing the epic. Estimated 100–200 LOC.

- [ ] 17.1 Run `go generate ./...` then `go build ./...` then
      `go test -race ./...`; ensure CI is green.
- [ ] 17.2 Run `golangci-lint run` (config from B.0); fix any new
      warnings.
- [ ] 17.3 Spot-check `.agents/AGENT.md` §10/§11 compliance: no
      multi-interface files, no DTOs outside `request/` and
      `response/`, no hand-written mocks. Add a brief checklist to
      the PR description template.
- [ ] 17.4 Mark RUN-295 / RUN-296 / RUN-297 / RUN-298 as Done in
      Linear, attach the PR list, and confirm RUN-281 itself moves to
      Done. RUN-299 remains Backlog with a note linking back to
      RUN-291.
- [ ] 17.5 SDD archive: `sdd-archive` the
      `run-281-new-data-model-admin-crud` SDD once verified.

## Reordering note (operational, not specifications)

Because the consumer join tables FK to policies + auths, the
implementation order **departs** from the entity order stated in the
proposal (Gateway → Backend → Consumer → Policy → Auth). The effective
phase execution order is:

```
0  → 1, 2, 3 (Gateway -a, -b, -c)
   → 4, 5, 6 (Backend -a, -b, -c)
   → 11 (Policy -a)
   → 14 (Auth -a)
   → 7, 8, 9, 10 (Consumer -a1, -a2, -b, -c)
   → 12, 13 (Policy -b, -c)
   → 15, 16 (Auth -b, -c)
   → 17 (verification & archive)
```

The proposal's narrative ("Gateway → Backend → Consumer → Policy → Auth")
holds for the **logical** delivery story; the **physical** PR sequence
above interleaves Policy-a and Auth-a earlier so Consumer's join FKs
can compile. Reviewer note: this is intentional and documented here.

## PR-budget summary

| Phase | Slice | Est. LOC | size:exception? |
|---|---|---|---|
| 0 | Cross-cutting prereqs | 250–350 | no |
| 1 | Gateway-a | 380–450 | no |
| 2 | Gateway-b | 480–550 | ⚠️ likely |
| 3 | Gateway-c | 380–450 | no |
| 4 | Backend-a | 430–500 | ⚠️ likely |
| 5 | Backend-b | 500–550 | ⚠️ likely |
| 6 | Backend-c | 380–450 | no |
| 7 | Consumer-a1 | 350–400 | no |
| 8 | Consumer-a2 | 400–500 | ⚠️ possible |
| 9 | Consumer-b | 550–650 | ⚠️ likely |
| 10 | Consumer-c | 400–450 | no |
| 11 | Policy-a | 400–450 | no |
| 12 | Policy-b | 380–450 | no |
| 13 | Policy-c | 380–450 | no |
| 14 | Auth-a | 350–420 | no |
| 15 | Auth-b | 380–450 | no |
| 16 | Auth-c | 380–450 | no |
| 17 | Verification | 100–200 | no |

Total: ~6800–7700 LOC across **18 PRs**, average ~410 LOC. About 4–5
PRs flagged as likely `size:exception` candidates; the rest fit the
team budget.
