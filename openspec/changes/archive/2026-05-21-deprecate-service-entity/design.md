# Design: Deprecate Service entity, wire forwarding_rule → upstream

## Technical Approach

Rewire `forwarding_rules.service_id` → `forwarding_rules.upstream_id` and delete the entire `Service` bounded context (domain, app, infra, handlers, cache, events, audit constants, router routes, swagger). Endpoint-type services are absorbed as single-target upstreams during a one-shot Postgres migration that runs inside the existing GORM migrations pipeline. The change is **breaking** at the admin HTTP API surface (clients must call `/upstreams` instead of `/services`); the data plane is fully backward-compatible because the runtime already only honors `TypeUpstream`.

## Architecture Decisions

| #  | Decision                                                               | Alternatives                                                                                                   | Rationale                                                                                                                                                                  |
|----|------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| D1 | Single-PR breaking change (no dual-write window)                       | (a) Two-phase: keep `service_id` nullable + dual-write for 1 release; (b) versioned API `/v2/rules`            | TrustGate self-hosts the admin clients and ships migrations on boot. Runtime already collapses service→upstream; dual-write code would be dead weight. Forces a clean cut. |
| D2 | Synthesize one upstream per endpoint-service (1:1)                     | (a) Refuse to migrate if any endpoint service exists; (b) Merge endpoint services by gateway into one upstream | 1:1 preserves rule-target affinity exactly. Refusing blocks customers using endpoint type. Merging changes load-balancing semantics.                                       |
| D3 | Run migration inside existing GORM migration registry (`20240007_...`) | (a) Out-of-band SQL script; (b) Standalone CLI command                                                         | Existing pipeline already runs on startup with advisory lock — reuses ordering, idempotency, and rollback machinery.                                                       |
| D4 | Bump startup migration timeout from 30s → 5min, gated by env           | Keep 30s                                                                                                       | Step (3) inserts up to N rows where N=count(endpoint services). Production could have hundreds. 30s is unsafe for tenants with large datasets.                             |
| D5 | Drop `service_id` column in same migration (no soft-deprecation)       | Keep nullable for 1 release                                                                                    | GORM `forwarding_rule.ForwardingRule` struct cannot have both `ServiceID` and `UpstreamID` cleanly; soft-deprecation needs feature flags we don't have.                    |
| D6 | Down migration is best-effort, endpoint synthesis is one-way           | Full reversible Down                                                                                           | Endpoint→upstream loses no data; the reverse needs to pick one target from a possibly-grown upstream — ambiguous. Document and accept.                                     |

## Data Flow (post-change)

```
Admin HTTP → CreateRuleHandler → rule.Creator
                                   │
                                   ├─ gatewayRepo.Get(gatewayID)
                                   ├─ upstreamRepo.Get(upstream_id, gatewayID)   ← was serviceRepo.Get
                                   └─ ruleRepo.Create(rule{upstream_id})

Data plane → AuthMiddleware → ruleMatcher → ForwardedHandler
                                               │
                                               └─ upstreamFinder.Find(gw, rule.UpstreamID)  ← was helpers.GetUpstream(serviceFinder,…)
```

## File Changes

| File                                                                                                         | Action     | Description                                                                                                      |
|--------------------------------------------------------------------------------------------------------------|------------|------------------------------------------------------------------------------------------------------------------|
| `pkg/infra/migrations/20240007_drop_services_and_link_rules_to_upstreams.go`                                 | Create     | The migration per spec, single Tx, orphan-rule assert, endpoint synthesis via raw SQL inserting into `upstreams` |
| `pkg/infra/database/database.go`                                                                             | Modify     | Bump migration timeout `30s` → configurable, default `5m`                                                        |
| `pkg/domain/forwarding_rule/forwarding_rule.go`                                                              | Modify     | `ServiceID uuid.UUID` → `UpstreamID uuid.UUID`; GORM tag `gorm:"type:uuid;not null"`; update `Validate()`        |
| `pkg/domain/forwarding_rule/builder.go` + `_test.go`                                                         | Modify     | `CreateParams.ServiceID` → `UpstreamID`                                                                          |
| `pkg/domain/service/**`                                                                                      | Delete     | Entire package incl. mocks, repository, builder, tests                                                           |
| `pkg/app/service/**`                                                                                         | Delete     | Creator/Updater/Finder + mocks + tests                                                                           |
| `pkg/infra/repository/service_repository.go`                                                                 | Delete     | —                                                                                                                |
| `pkg/infra/repository/upstream_repository.go`                                                                | Modify     | `DeleteUpstream` checks `forwarding_rule` count, not `service.Service`                                           |
| `pkg/handlers/http/{create,get,list,update,delete}_service_handler.go`                                       | Delete     | —                                                                                                                |
| `pkg/handlers/http/request/{create,update}_rule_request.go`                                                  | Modify     | `ServiceID string` → `UpstreamID string` + binding                                                               |
| `pkg/handlers/http/response/list_rules_output.go`                                                            | Modify     | Rename field                                                                                                     |
| `pkg/handlers/http/create_rule_handler.go`, `update_rule_handler.go`                                         | Modify     | Drop `ErrServiceNotFound` path, add `ErrUpstreamNotFound`                                                        |
| `pkg/handlers/http/helpers/upstream.go`                                                                      | Modify     | `GetUpstream` takes rule only, calls `upstreamFinder.Find(gw, rule.UpstreamID)`                                  |
| `pkg/handlers/http/forwarded_handler.go`, `pkg/handlers/websocket/forwarded_handler.go`                      | Modify     | Drop `serviceFinder`/`ServiceFinder` dep; switch to direct upstream lookup                                       |
| `pkg/app/rule/creator.go`, `updater.go`                                                                      | Modify     | Replace `serviceRepo` with `upstreamRepo`; validate upstream belongs to gateway                                  |
| `pkg/app/gateway/data_finder.go`                                                                             | Modify     | DTO field rename                                                                                                 |
| `pkg/types/dto.go`                                                                                           | Modify     | `ForwardingRuleDTO.ServiceID` → `UpstreamID`                                                                     |
| `pkg/infra/cache/client.go` + mocks                                                                          | Modify     | Drop `GetService`/`SaveService`, `Service*KeyPattern`, `ServiceTTLName`                                          |
| `pkg/infra/cache/event/delete_service_cache_event.go`, `subscriber/delete_service_cache_event_subscriber.go` | Delete     | —                                                                                                                |
| `pkg/infra/auditlogs/constants.go`                                                                           | Modify     | Drop `EventTypeService*`, `TargetTypeService`                                                                    |
| `pkg/server/router/admin_router.go`                                                                          | Modify     | Drop the `services :=` group                                                                                     |
| `pkg/server/middleware/{auth,metrics}.go`                                                                    | Modify     | Replace `service_id` labels with `upstream_id`                                                                   |
| `pkg/infra/prometheus/*`                                                                                     | Modify     | Histogram labels `service_id` → `upstream_id` (breaking metric label change)                                     |
| `pkg/dependency_container/container.go`                                                                      | Modify     | Remove all `service*` wiring; drop `ServiceFinder` from `ForwardedHandlerDeps`                                   |
| `docs/swagger.{yaml,json}`, `docs/openapi.json`, `docs/docs.go`                                              | Regenerate | Drop `/services` paths, rename DTO field                                                                         |
| `tests/functional/*_test.go` (~15 files)                                                                     | Modify     | Replace create-service-then-rule fixtures with create-upstream-then-rule                                         |
| `pkg/domain/errors.go`                                                                                       | Modify     | Drop `ErrServiceNotFound`                                                                                        |

## Interfaces / Contracts

```go
// pkg/domain/forwarding_rule/forwarding_rule.go
type ForwardingRule struct {
    ID         uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
    GatewayID  uuid.UUID `gorm:"type:uuid;not null"`
    UpstreamID uuid.UUID `gorm:"type:uuid;not null"`
    // … rest unchanged
}
```

```go
// pkg/handlers/http/request/create_rule_request.go
type CreateRuleRequest struct {
    UpstreamID string `json:"upstream_id" binding:"required"`
    // … rest unchanged
}
```

```go
// pkg/app/rule/creator.go — new dependency shape
type creator struct {
    repo         forwarding_rule.Repository
    gatewayRepo  gateway.Repository
    upstreamRepo upstream.Repository   // ← was serviceRepo
    // …
}
// On Create: upstream must exist AND upstream.GatewayID == gatewayID, else ErrUpstreamNotFound.
```

## Testing Strategy

| Layer       | What to Test                                                                               | Approach                                                                                                        |
|-------------|--------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| Unit        | `rule.Creator/Updater` reject cross-gateway upstream, accept valid                         | Update existing `creator_test.go`/`updater_test.go` with `upstreamRepoMock`                                     |
| Unit        | `forwarding_rule.Validate()` requires `UpstreamID != uuid.Nil`                             | Extend `forwarding_rule_test.go`                                                                                |
| Migration   | Endpoint service → synthesized upstream; upstream service straight relink; orphan rollback | New `pkg/infra/migrations/20240007_*_test.go` running against a Postgres testcontainer with seeded service rows |
| Integration | Admin POST /rules with `upstream_id` happy + cross-gateway 400                             | New handler test or existing functional `create_rule_test.go`                                                   |
| Functional  | Update ~15 `tests/functional/*` fixtures; full request → upstream flow green               | Replace `apiCreateService` helper with `apiCreateUpstream`                                                      |
| Smoke       | Boot with seeded pre-migration DB; verify all rules resolve                                | Manual + CI canary                                                                                              |

## Migration / Rollout

1. **Backup** production DB before deploy (DBA gate).
2. Deploy artifact → on startup, migration `20240007` runs under advisory lock and elevated timeout (D4).
3. Migration aborts cleanly on orphan rules — operators must clean DB before retry.
4. Post-migration smoke: `SELECT COUNT(*) FROM forwarding_rules WHERE upstream_id IS NULL` = 0; `\d services` returns not-exists.
5. Comms: announce admin API breaking change (`/services` gone, `service_id` → `upstream_id` on `/rules`) in release notes. Provide a one-page client-migration guide.
6. Rollback: previous binary + `Down` migration. Endpoint upstreams remain (documented one-way).

## Resolved Decisions (was Open Questions)

- [x] **D7 — Synthesized upstream naming**: `svc-migrated-<service_uuid>`. Deterministic, collision-free within a gateway, immediately recognizable as migration-origin. The original `service.name` is intentionally NOT reused (avoids collisions with existing upstreams that may share the name).
- [x] **D8 — Drop `services` table in this migration**: no safety-net release. Rationale: the `Down` migration recreates the table schema, the runtime no longer reads from it, and keeping it around encourages drift. Single clean cut.
- [x] **D9 — Prometheus label rename approved**: `GatewayDetailedLatency` and `GatewayUpstreamLatency` switch label `service_id` → `upstream_id`. Ops/dashboard update is part of rollout comms (release notes call this out).
- [x] **D10 — No pre-flight CLI for orphans**: rely on the migration's transactional orphan-assert. If orphans exist, the migration aborts cleanly and the operator fixes the DB manually before retry. The runbook MUST document the recovery SQL.
