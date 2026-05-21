# Verification Report

**Change**: deprecate-service-entity
**Version**: v1 (single delta)
**Mode**: Standard (no Strict TDD configured)

---

## Completeness

| Metric            | Value                            |
|-------------------|----------------------------------|
| Tasks total       | 38                               |
| Tasks complete    | 38                               |
| Tasks incomplete  | 0                                |
| Tasks out of scope| 1 (Task 5.4 — per user decision) |

All 38 in-scope tasks marked `[x]`. Task 5.4 (Postgres testcontainer for migration) was explicitly waived by the user in favor of a manual staging smoke test, and is annotated as such in `tasks.md`.

---

## Build & Tests Execution

**Build**: ✅ Passed

```
$ go build -mod=mod ./...
BUILD_EXIT=0
```

**Vet**: ✅ Passed

```
$ go vet -mod=mod ./...
VET_EXIT=0
```

**Tests**: ✅ 45 packages passed / ❌ 0 failed / ⚠️ 0 skipped

```
$ go test -mod=mod -count=1 $(go list ./... | grep -v tests/functional)
TEST_EXIT=0
ok  github.com/NeuralTrust/TrustGate/pkg/app/gateway        0.034s
ok  github.com/NeuralTrust/TrustGate/pkg/app/plugin         0.010s
ok  github.com/NeuralTrust/TrustGate/pkg/app/rule           0.075s
ok  github.com/NeuralTrust/TrustGate/pkg/app/upstream       0.029s
ok  github.com/NeuralTrust/TrustGate/pkg/config             0.018s
ok  github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule  0.030s
ok  github.com/NeuralTrust/TrustGate/pkg/domain/iam/apikey  0.023s
ok  github.com/NeuralTrust/TrustGate/pkg/domain/upstream    0.028s
ok  github.com/NeuralTrust/TrustGate/pkg/handlers/http      0.121s
ok  github.com/NeuralTrust/TrustGate/pkg/handlers/http/request   0.034s
ok  github.com/NeuralTrust/TrustGate/pkg/infra/auditlogs    0.057s
... (full list: 45 packages)
```

The `tests/functional` package was excluded — it requires a live Postgres + Redis at runtime; static `go vet` against it passes (exit 0), confirming it compiles correctly.

**Coverage**: ➖ Not available (no coverage tool configured in the project; `openspec/config.yaml` absent).

---

## Spec Compliance Matrix

### Spec: `forwarding_rule` (delta — MODIFIED)

| Requirement                                                                | Scenario                              | Test                                                                                                       | Result          |
|----------------------------------------------------------------------------|---------------------------------------|------------------------------------------------------------------------------------------------------------|-----------------|
| REQ-FR-1: Forwarding rule MUST reference an upstream directly              | Create rule with valid upstream       | `pkg/app/rule/creator_test.go > TestCreator_Create_Success`                                                | ✅ COMPLIANT     |
| REQ-FR-1: Forwarding rule MUST reference an upstream directly              | Create rule with cross-gateway upstream | `pkg/app/rule/creator_test.go > TestCreator_Create_UpstreamFromOtherGateway`                              | ✅ COMPLIANT     |
| REQ-FR-1: Forwarding rule MUST reference an upstream directly              | Create rule omitting upstream_id      | `pkg/handlers/http/request/validators_test.go > TestCreateRuleRequest_Validate/missing_upstream_id` + `pkg/domain/forwarding_rule/forwarding_rule_test.go > TestValidate_UpstreamIDRequired` | ✅ COMPLIANT     |
| REQ-FR-2: Runtime forwarding MUST resolve upstream without Service lookup  | HTTP forward                          | (structural) `pkg/handlers/http/forwarded_handler.go` calls `helpers.GetUpstream(ctx, h.upstreamFinder, …)`; `serviceFinder` field gone — verified by `rg serviceFinder pkg/` → 0 hits | ⚠️ PARTIAL (no behavioral test; only static evidence) |
| REQ-FR-2: Runtime forwarding MUST resolve upstream without Service lookup  | Cache DTO shape                       | (structural) `types.ForwardingRuleDTO.UpstreamID` field exists, `ServiceID` field gone — verified by `rg 'ServiceID' pkg/types/` → 0 hits | ⚠️ PARTIAL (no behavioral test; only static evidence) |

### Spec: `services` (delta — REMOVED)

| Requirement                       | Scenario                  | Test                                                                                                        | Result          |
|-----------------------------------|---------------------------|-------------------------------------------------------------------------------------------------------------|-----------------|
| REQ-S-1: Service CRUD endpoints removed | Legacy endpoint        | (structural) `pkg/server/router/admin_router.go` — `services :=` group absent; verified by `rg 'services := gateways.Group' pkg/server/router/` → 0 hits | ⚠️ PARTIAL (no behavioral 404 test; only static evidence) |
| REQ-S-1: Service CRUD endpoints removed | Service package import | (structural) `rg 'pkg/domain/service\|pkg/app/service' --type go pkg/` → 0 hits; build succeeds              | ✅ COMPLIANT     |

### Spec: `data-migration`

| Requirement                                                            | Scenario                       | Test                                                                                       | Result                                |
|------------------------------------------------------------------------|--------------------------------|--------------------------------------------------------------------------------------------|---------------------------------------|
| REQ-DM-1: Migration MUST move every rule to an upstream without data loss | Endpoint service migrated   | (structural) `pkg/infra/migrations/20240007_*.go` — `INSERT INTO upstreams` with `svc-migrated-` synthesis | ⚠️ PARTIAL — manual staging smoke planned per user decision (5.4 OUT OF SCOPE) |
| REQ-DM-1: Migration MUST move every rule to an upstream without data loss | Upstream-type service relinked | (structural) `pkg/infra/migrations/20240007_*.go` — `UPDATE forwarding_rules SET upstream_id = s.upstream_id WHERE … type = 'upstream'` | ⚠️ PARTIAL — manual staging smoke planned |
| REQ-DM-1: Migration MUST move every rule to an upstream without data loss | Orphan rule blocks migration   | (structural) `pkg/infra/migrations/20240007_*.go:117` — `return fmt.Errorf("orphan rules detected: %d", orphans)` triggers Tx rollback | ⚠️ PARTIAL — manual staging smoke planned |
| REQ-DM-1: Migration MUST move every rule to an upstream without data loss | Idempotent re-run              | (structural) GORM `MigrationsManager.ApplyPending` records version in `public.migration_version` and skips already-applied migrations (unchanged behavior, inherited from existing pipeline) | ⚠️ PARTIAL — manual staging smoke planned |
| REQ-DM-2: Migration MUST complete within elevated startup timeout         | Large dataset                  | (structural) `pkg/infra/database/database.go:22-31` — `migrationTimeout()` reads `DB_MIGRATION_TIMEOUT` env (default 5m) | ✅ COMPLIANT (configurable, default 5m as specified) |
| REQ-DM-3: Down migration MUST restore service_id link (best-effort)       | Down after Up                  | (structural) `pkg/infra/migrations/20240007_*.go` `Down` recreates schema, restores `service_id`, reverse-maps from `upstream_id` | ⚠️ PARTIAL — manual staging smoke planned |

**Compliance summary**:
- ✅ COMPLIANT (passing tests prove behavior): 4 of 13 scenarios
- ⚠️ PARTIAL (structural evidence only, no behavioral test): 9 of 13 scenarios
- ❌ FAILING: 0
- ❌ UNTESTED: 0

The 9 PARTIAL scenarios all have structural evidence (the code is in place and verifiable by grep). Behavioral coverage gaps:
- HTTP/WS forwarded handlers have no unit test for the upstream-resolution path (these handlers have always been integration-tested via `tests/functional`).
- The 404 on legacy `/services` routes is implicitly true because the route group is deleted — only an integration test would prove it explicitly.
- Data-migration scenarios are not exercised by any automated test, by explicit user decision (5.4 out of scope → manual staging smoke).

---

## Correctness (Static — Structural Evidence)

| Requirement                                                              | Status            | Notes                                                                                                                       |
|--------------------------------------------------------------------------|-------------------|-----------------------------------------------------------------------------------------------------------------------------|
| Domain: `ForwardingRule.UpstreamID uuid.UUID gorm:"type:uuid;not null"`  | ✅ Implemented     | `pkg/domain/forwarding_rule/forwarding_rule.go:26` matches design spec exactly.                                             |
| Request DTO: `CreateRuleRequest.UpstreamID string binding:"required"`    | ✅ Implemented     | `pkg/handlers/http/request/create_rule_request.go`; `UpdateRuleRequest.UpstreamID` optional as designed.                    |
| `rule.Creator` validates upstream belongs to gateway                     | ✅ Implemented     | `pkg/app/rule/creator.go` — explicit `if ups.GatewayID != gatewayID` returning `ErrUpstreamNotFound`.                       |
| `helpers.GetUpstream` signature: `(ctx, upstreamFinder, rule)`           | ✅ Implemented     | `pkg/handlers/http/helpers/upstream.go` — drops `serviceFinder` param.                                                       |
| HTTP `ForwardedHandlerDeps` drops `ServiceFinder`                        | ✅ Implemented     | `pkg/handlers/http/forwarded_handler.go` — verified by `rg ServiceFinder pkg/handlers/http/` → 0 hits.                       |
| WebSocket forwarded handler drops `serviceFinder`                        | ✅ Implemented     | `pkg/handlers/websocket/forwarded_handler.go:183` — direct `upstreamFinder.Find(reqCtx.Context, gatewayUUID, upstreamUUID)`. |
| `pkg/domain/service` package deleted                                     | ✅ Implemented     | Filesystem check: directory absent.                                                                                          |
| `pkg/app/service` package deleted                                        | ✅ Implemented     | Filesystem check: directory absent.                                                                                          |
| `pkg/infra/repository/service_repository.go` deleted                     | ✅ Implemented     | Filesystem check: file absent.                                                                                               |
| All 5 `*_service_handler.go` files deleted                               | ✅ Implemented     | Filesystem check: files absent.                                                                                              |
| `cache.Client.{GetService,SaveService}` removed + key/TTL constants gone | ✅ Implemented     | `pkg/infra/cache/client.go` — verified no Service members.                                                                   |
| `DeleteServiceCacheEvent` + subscriber removed                           | ✅ Implemented     | `pkg/infra/cache/event/events.go` Registry has no `DeleteServiceCacheEventType`.                                             |
| Audit constants `EventTypeService*`, `TargetTypeService` removed          | ✅ Implemented     | `pkg/infra/auditlogs/constants.go` — verified.                                                                                |
| Admin router `services :=` group removed                                 | ✅ Implemented     | `pkg/server/router/admin_router.go` — `rg 'services := gateways.Group'` → 0 hits.                                            |
| DI container `service*` wiring removed                                   | ✅ Implemented     | `pkg/dependency_container/container.go` — Container struct exposes only `UpstreamRepository`/`UpstreamCreator`/`UpstreamUpdater`. |
| `gateway_repository.go::Delete` cascade fix                              | ✅ Implemented     | `service.Service` cascade removed from delete tx (unrelated to original task list but required for correctness).             |
| Prometheus label `service` → `upstream`                                  | ✅ Implemented     | `pkg/infra/prometheus/prometheus.go:18` — `routeLabels = []string{"upstream", "route"}`.                                     |
| Middleware constant `ServiceIDKey` → `UpstreamIDKey = "upstream_id"`     | ✅ Implemented     | `pkg/server/middleware/metrics.go:20` + `pkg/server/middleware/auth.go:165`.                                                  |
| Migration `20240007_drop_services_and_link_rules_to_upstreams.go`        | ✅ Implemented     | Up has 6 ordered steps per spec; orphan-rules abort at line 117; `svc-migrated-` synthesis at line 71; Down restores schema. |
| `DB_MIGRATION_TIMEOUT` env var with 5m default                           | ✅ Implemented     | `pkg/infra/database/database.go:22-31`.                                                                                       |
| `pkg/domain/errors.go` — `ErrServiceNotFound` removed, `ErrUpstreamNotFound` present | ✅ Implemented | Verified.                                                                                                                    |
| Swagger/OpenAPI regenerated                                              | ✅ Implemented     | `docs/swagger.yaml` has 0 hits for `service_id`/`/services` and 8 hits for `upstream_id`.                                    |
| Release notes + operator runbook                                         | ✅ Implemented     | `openspec/changes/deprecate-service-entity/RELEASE_NOTES.md`.                                                                |

---

## Coherence (Design Match)

| Decision                                                       | Followed?  | Notes                                                                                                                                |
|----------------------------------------------------------------|------------|--------------------------------------------------------------------------------------------------------------------------------------|
| D1: Single-PR breaking change, no dual-write                   | ✅ Yes      | No dual-write code present; clean cut.                                                                                                |
| D2: Synthesize one upstream per endpoint-service (1:1)         | ✅ Yes      | Migration `WITH synthesized AS (INSERT … FROM services s WHERE s.type='endpoint' …)`.                                                |
| D3: Run inside existing GORM migration registry (`20240007_…`) | ✅ Yes      | Migration file conforms to existing registry pattern.                                                                                 |
| D4: Migration timeout 30s → configurable 5m default            | ✅ Yes      | `migrationTimeout()` honors env var.                                                                                                  |
| D5: Drop `service_id` column same migration (no soft-deprec.)  | ✅ Yes      | `DROP COLUMN IF EXISTS service_id` at line 134.                                                                                       |
| D6: Down is best-effort, endpoint synthesis is one-way         | ✅ Yes      | Down recreates schema and reverse-maps `service_id` for type=upstream rows; synthesized upstreams remain.                            |
| D7: Synthesized upstream naming `svc-migrated-<service_uuid>`  | ✅ Yes      | Verified in migration SQL line 71.                                                                                                    |
| D8: Drop `services` table in same migration                    | ✅ Yes      | `DROP TABLE IF EXISTS services` at line 151.                                                                                          |
| D9: Prometheus label rename approved + called out in release notes | ✅ Yes  | Label renamed; `RELEASE_NOTES.md` documents the breaking change for dashboards.                                                       |
| D10: No pre-flight CLI for orphans; runbook documents recovery | ✅ Yes      | `RELEASE_NOTES.md` includes the pre-flight orphan-detection SQL and remediation guidance.                                             |

**Deviations from the original `File Changes` table**: none. All listed files were touched as planned. Two additions beyond the original list, both correct:
1. `pkg/handlers/http/{create,update}_upstream_handler.go` — `@Success` annotation type changed to `map[string]interface{}` (swag workaround, see Phase 6.1).
2. `pkg/infra/repository/gateway_repository.go` — removed dead `service.Service` cascade in `Delete()` (would have crashed once the model type was deleted).

---

## Issues Found

### CRITICAL (must fix before archive)

**None.**

### WARNING (should fix)

1. **`scripts/benchmark.sh` still calls the removed `/services` endpoint** (`scripts/benchmark.sh:114` POSTs to `$ADMIN_URL/gateways/$GATEWAY_ID/services` and line 141 sends `"service_id": "$SERVICE_ID"`). This script will return HTTP 404 on every run against a deployment with this change. **Action**: rewrite the benchmark to create an upstream and use `upstream_id` directly in the rule payload, mirroring the functional-test migration in Phase 5.

### SUGGESTION (nice to have)

1. **HTTP/WS forwarded handlers lack behavioral tests for the upstream-resolution path.** Currently only structural evidence (the `serviceFinder` field is gone, `upstreamFinder.Find` is invoked). Consider adding a handler-level test that exercises a matched rule end-to-end with a fake `upstreamFinder` to prove REQ-FR-2 scenarios at runtime.
2. **Cosmetic var-name churn in `tests/functional/*`**: many files still have `serviceID := CreateService(...)` where `CreateService` is now an identity shim returning the input `upstream_id`. Readers may be momentarily confused. Could be cleaned up by renaming `serviceID` → `upstreamID` and inlining away the shim call — non-blocking, purely aesthetic. (Earlier attempt during Phase 6 hit shadowing collisions; safer to do per file in a follow-up.)
3. **No automated test for the migration** (Task 5.4 deferred by explicit user decision). The risk is contained by transactional rollback + orphan-rule abort, and the user has committed to a manual staging smoke test. If a regression slips in later, consider adding a testcontainers-backed test then.

---

## Verdict

**PASS WITH WARNINGS**

Build, vet, and the entire unit test suite (45 packages) pass cleanly. All 38 in-scope tasks are complete. Every spec requirement has at least structural evidence in the codebase; 4 of 13 scenarios have explicit passing behavioral tests, the other 9 are validated by static structure (and, for migration scenarios, explicit manual smoke test planned). Coherence with `design.md` is full — all 10 decisions (D1–D10) implemented as designed, no unexpected deviations.

The one WARNING — `scripts/benchmark.sh` — does not block archive but should be addressed before anyone runs the benchmark against the new version. Suggestions are non-blocking improvements.
