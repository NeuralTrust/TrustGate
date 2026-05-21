# Tasks: Deprecate Service entity

## Phase 1: Foundation (schema + domain types) <!-- ENG-429 -->

- [x] 1.1 Bump migration startup timeout in `pkg/infra/database/database.go`: read `DB_MIGRATION_TIMEOUT` env (default `5m`), apply to `migCtx`.
- [x] 1.2 Create `pkg/infra/migrations/20240007_drop_services_and_link_rules_to_upstreams.go` with `Up` per spec data-migration §steps 1-6 and best-effort `Down` (D6).
- [x] 1.3 In the Up function, synthesize endpoint-service upstreams with name `svc-migrated-<service_uuid>` (D7), `algorithm='round-robin'`, single target from S.host/port/protocol/path/headers/credentials.
- [x] 1.4 In the Up function, after step 4 assert `COUNT(forwarding_rules WHERE upstream_id IS NULL) = 0`; on failure return `fmt.Errorf("orphan rules detected: %d", n)` to trigger Tx rollback.
- [x] 1.5 Rename `forwarding_rule.ForwardingRule.ServiceID` → `UpstreamID` in `pkg/domain/forwarding_rule/forwarding_rule.go`; update GORM tag to `gorm:"type:uuid;not null"`; update `Validate()` to require `UpstreamID != uuid.Nil`.
- [x] 1.6 Rename `CreateParams.ServiceID` → `UpstreamID` in `pkg/domain/forwarding_rule/builder.go`.
- [x] 1.7 Drop `ErrServiceNotFound` from `pkg/domain/errors.go`; add `ErrUpstreamNotFound` if missing.

## Phase 2: Core Implementation (app + handlers + runtime) <!-- ENG-430 -->

- [x] 2.1 Update `pkg/app/rule/creator.go`: replace `serviceRepo service.Repository` with `upstreamRepo upstream.Repository`; validate `upstream.GatewayID == gatewayID` else return `ErrUpstreamNotFound`.
- [x] 2.2 Update `pkg/app/rule/updater.go`: same swap; rename `parseAndUpdateServiceID` → `parseAndUpdateUpstreamID`.
- [x] 2.3 Update `pkg/handlers/http/request/{create,update}_rule_request.go`: rename `ServiceID` → `UpstreamID` (JSON tag `upstream_id`, binding `required` on create).
- [x] 2.4 Update `pkg/handlers/http/{create,update,list}_rule_handler.go`: drop `ErrServiceNotFound` branch, add `ErrUpstreamNotFound` → 400.
- [x] 2.5 Update `pkg/handlers/http/response/list_rules_output.go` and `pkg/types/dto.go` (`ForwardingRuleDTO.ServiceID` → `UpstreamID`, JSON tag `upstream_id`).
- [x] 2.6 Rewrite `pkg/handlers/http/helpers/upstream.go::GetUpstream` to call `upstreamFinder.Find(ctx, rule.GatewayID, rule.UpstreamID)` directly; drop `serviceFinder` param and `domainService` import.
- [x] 2.7 Update `pkg/handlers/http/forwarded_handler.go`: drop `serviceFinder` field, `ServiceFinder` from `ForwardedHandlerDeps`, and the `service.Finder` import; pass only upstream finder to helper.
- [x] 2.8 Update `pkg/handlers/websocket/forwarded_handler.go`: same removal; replace `service.Finder` block (lines ~179-186) with direct `upstreamFinder.Find(rule.GatewayID, rule.UpstreamID)`.
- [x] 2.9 Update `pkg/app/gateway/data_finder.go::convertModelToTypesRules` to emit `UpstreamID` instead of `ServiceID`.
- [x] 2.10 Update `pkg/infra/repository/forwarded_rule_repository.go::UpdateRulesCache` DTO mapping (ServiceID → UpstreamID).
- [x] 2.11 Update `pkg/infra/repository/upstream_repository.go::DeleteUpstream` to count `forwarding_rule` rows (not `service.Service`); drop the `service` import.

## Phase 3: Removal (delete the Service bounded context) <!-- ENG-431 -->

- [x] 3.1 Delete `pkg/domain/service/` (service.go, builder.go, builder_test.go, repository.go, mocks/).
- [x] 3.2 Delete `pkg/app/service/` (creator.go, creator_test.go, updater.go, updater_test.go, finder.go, mocks/).
- [x] 3.3 Delete `pkg/infra/repository/service_repository.go`.
- [x] 3.4 Delete `pkg/handlers/http/{create,get,list,update,delete}_service_handler.go`.
- [x] 3.5 Delete `pkg/infra/cache/event/delete_service_cache_event.go` and `pkg/infra/cache/subscriber/delete_service_cache_event_subscriber.go`; remove `DeleteServiceCacheEventType` constant.
- [x] 3.6 Remove from `pkg/infra/cache/client.go`: `GetService`, `SaveService`, `ServiceKeyPattern`, `ServicesKeyPattern`, `ServiceTTLName`, `ServiceCacheTTL`, the `service` import; regenerated `client_mock.go` via mockery.
- [x] 3.7 Remove from `pkg/infra/auditlogs/constants.go`: `EventTypeServiceCreated/Updated/Deleted`, `TargetTypeService`.
- [x] 3.8 Remove `services` route group in `pkg/server/router/admin_router.go`.
- [x] 3.9 Remove `ServiceFinder` and all `service*` wiring (repo, creator, updater, finder, handlers, subscriber) from `pkg/dependency_container/container.go`; also pruned `HandlerTransportDTO` `*ServiceHandler` fields and a stray `service.Service` cascade in `gateway_repository.go::Delete`.

## Phase 4: Observability + middleware <!-- ENG-432 -->

- [x] 4.1 Rename Prometheus labels `service_id` → `upstream_id` in `pkg/infra/prometheus/*` for `GatewayDetailedLatency` and `GatewayUpstreamLatency` (label name was `"service"` → `"upstream"`; help text updated).
- [x] 4.2 Update label emission sites in `pkg/handlers/http/forwarded_handler.go` (lines ~363, ~512) to pass `matchingRule.UpstreamID` instead of `matchingRule.ServiceID`. (Pulled forward in Phase 2.)
- [x] 4.3 Update `pkg/server/middleware/{auth,metrics}.go` if they reference `service_id`. (Constant `ServiceIDKey` → `UpstreamIDKey` = `"upstream_id"`. Pulled forward in Phase 2.)

## Phase 5: Testing <!-- ENG-434 -->

- [x] 5.1 Add `pkg/domain/forwarding_rule/forwarding_rule_test.go` case: `Validate()` returns error when `UpstreamID == uuid.Nil` (already added in Phase 1 as `TestValidate_UpstreamIDRequired`).
- [x] 5.2 Update `pkg/app/rule/creator_test.go`: replaced `serviceRepoMock` with `upstreamRepoMock`; added `TestCreator_Create_UpstreamFromOtherGateway` for cross-gateway upstream returns `ErrUpstreamNotFound`; renamed `TestCreator_Create_ServiceNotFound` → `TestCreator_Create_UpstreamNotFound`.
- [x] 5.3 Update `pkg/app/rule/updater_test.go`: renamed `ServiceID` field/var usages to `UpstreamID`; renamed `TestUpdater_Update_InvalidServiceID` → `TestUpdater_Update_InvalidUpstreamID`.
- [x] 5.4 (OUT OF SCOPE — manual smoke test in staging) Per user decision, no automated migration test will be added. Migration will be validated by a manual seed-and-deploy in staging (recreate (a) endpoint service + rule, (b) upstream service + rule, (c) orphan rule to verify the abort path) before production rollout.
- [x] 5.5 Functional tests (`tests/functional/`): turned `CreateService` into a backwards-compatible shim in `common_test.go` (extracts `upstream_id` from payload, returns it — no service is created since the endpoint no longer exists); ran a global `sed 's/"service_id"/"upstream_id"/g'` over the 22 affected files; renamed subtest names that referenced `service_id`/`service ID` in `create_rule_test.go`.
- [x] 5.6 Updated `pkg/handlers/http/{update,delete,add}_plugins_handler_test.go` (renamed struct field `ServiceID` → `UpstreamID`). `validators_test.go` was already done in Phase 2.
- [x] 5.7 `go build -mod=mod ./...` is green; `go test -mod=mod $(go list ./... | grep -v tests/functional)` exits 0 (all unit tests pass). Functional tests still require a live Postgres/Redis to run, not a code issue.

## Phase 6: Docs + cleanup <!-- ENG-435 -->

- [x] 6.1 Ran `swag init -g cmd/gateway/main.go --parseDependency` (PATH=$HOME/go/bin) → regenerated `docs/swagger.{yaml,json}` and `docs/docs.go`; then `npx swagger2openapi docs/swagger.json -o docs/openapi.json` → regenerated `docs/openapi.json`. Side fix: `@Success` annotations in `create_upstream_handler.go` and `update_upstream_handler.go` had to change `upstream.Upstream` → `map[string]interface{}` because swag can't resolve those types under `--parseDependency` (the same latent bug previously hid behind the `service.Service` annotation that got deleted in Phase 3). Verified: swagger.yaml has 0 hits for `service_id`/`/services` and 8 hits for `upstream_id`/`UpstreamID`.
- [x] 6.2 Operator runbook written inside `RELEASE_NOTES.md` (orphan-rule pre-flight SQL, migration time estimate, `DB_MIGRATION_TIMEOUT` guidance, post-deploy verification queries, rollback strategy).
- [x] 6.3 `RELEASE_NOTES.md` covers: removed `/services` routes, `service_id` → `upstream_id` JSON field, Prometheus label rename, audit event types removed, `DB_MIGRATION_TIMEOUT` env var, cross-gateway upstream validation behaviour.
- [x] 6.4 Final grep: `rg 'service_id|domainService|service\.(Finder|Creator|Updater|Repository|Service)' --type go` returns hits only inside the two migration files (`20240001_initial_schema.go` creates the historical schema; `20240007_drop_services_and_link_rules_to_upstreams.go` references the column it is removing). Zero hits in production code, zero in unit tests, zero in functional tests (apart from local `serviceID` variable names which are cosmetic and the `CreateService` deprecated shim).
- [x] 6.5 README updated: phase completion summary added, status table shows ✅ for Apply/Verify/Phases 1–6.

<!-- human-verification: ENG-436 -->
