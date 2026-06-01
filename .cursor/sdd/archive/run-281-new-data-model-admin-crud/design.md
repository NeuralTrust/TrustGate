# Design: RUN-281 New data model + admin CRUD (control plane)

## Technical Approach

Apply **Approach D** from `explore.md` §5: per-entity chained PRs. For
each of the five aggregates, ship three chained PRs (`-a` domain +
migration + repo, `-b` app services, `-c` admin handlers). Entity order
is **Gateway → Backend → Consumer → Policy → Auth**. All code respects
`.agents/AGENT.md` §10 to the letter:

- One use case per file in `pkg/app/<entity>/<usecase>.go` (interface +
  impl + `//go:generate mockery`).
- One request DTO per file in `pkg/api/handler/http/request/`.
- One response DTO per file in `pkg/api/handler/http/response/`.
- One action per file in `pkg/api/handler/http/` (e.g.
  `create_gateway_handler.go`).
- Repositories in subfolders (`pkg/infra/repository/<entity>/`),
  deviating from TrustGate's flat layout. AGENT.md §11 is the source of
  truth.

## Architecture Decisions

| Decision | Choice | Alternatives considered | Rationale |
|---|---|---|---|
| Domain layer purity | Aggregates contain no infra imports (`pgx`, `fiber`, `redis`, logging). Repositories are interfaces in the domain package. | Anaemic domain + repository in infra-only | Keeps `pkg/domain` portable and unit-testable in isolation; matches AGENT.md §3 dependency direction. |
| Aggregate file layout | `<entity>.go` (aggregate) + `repository.go` (interface) + `errors.go` (sentinels), one per file. | Single `<entity>.go` with everything | Smaller files, easier diffs, follows TrustGate `pkg/domain/gateway/` shape. |
| Backend polymorphism | Single `backends` table with `type` discriminator (`'llm'`, `'a2a'`, `'mcp'`) + `config JSONB`. | Table-per-type; three independent aggregates | Simpler schema, no joins on hot path, RUN-279 explicitly frames `Backend(LLM\|A2A\|MCP)` as one concept. Validation moves to app layer. |
| Backend config validation | Per-type validator in `pkg/app/backend/creator.go` + `updater.go`. Strict allow-list of fields per `type`; reject unknown fields. | Permissive JSONB; downstream consumers validate | Fail-fast at write-time, the only enforcement point we have until B.4/B.5 read the config. |
| Identifiers | UUID v4, **app-generated** (`uuid.NewRandom()`), stored as `UUID` in Postgres. | DB-generated UUIDs; serial integers | Matches AgentGuardian + TrustGate convention. App-generated IDs simplify event sourcing later and remove a DB round-trip on inserts. |
| Soft delete | None. FK `ON DELETE CASCADE` on the 3 join tables. | Soft delete with `deleted_at` everywhere | YAGNI for B.2. If audit/recoverable-delete becomes a product requirement, add `deleted_at` per aggregate in a follow-up. |
| M:N association ownership | `Consumer` aggregate owns the joins (`AttachBackend`/`DetachBackend`/etc.). `consumer.Repository.Save` and `Update` diff the join tables inside `database.WithTx`. | Separate linker use cases per join (3 new packages) | Single consistency boundary, smaller API surface, transactional guarantee per consumer update. |
| Listing pagination | Offset (`?page`, `?size`, default 1/20, max 200). Substring `?name=` filter only. | Cursor pagination | Admin console use case is small; cursor adds opaque tokens for no current benefit. Cursor can be retrofitted. |
| Error handling | Domain sentinel errors (`gateway.ErrNotFound`, `gateway.ErrAlreadyExists`, …). Handlers map them to HTTP via `pkg/api/handler/http/helpers/errors.go`. | HTTP-status-aware errors in domain; panic-based control flow | Keeps domain unaware of HTTP. Helper centralises mapping in one file. |
| Repository layout | Subfolder per entity (`pkg/infra/repository/gateway/repository.go`). | Flat (TrustGate's shape) | AGENT.md §11 says subfolder. Room for `mappers.go`, `queries.go`, `*_test.go` per entity. |
| Repository constructor signature stability | `New<Entity>Repository(conn *database.Connection) *Repository`. No `cache.Client` parameter today. | Inject cache stub now | RUN-299 will wrap with a cache decorator when RUN-291 lands. The constructor signature stays stable. |
| Mocks | `mockery v2` + `//go:generate` directives. `make mocks` regenerates everything; CI checks that committed mocks match source. | Hand-written mocks; `gomock` | AGENT.md §10.5 forbids hand-rolled mocks. `mockery` is the TrustGate standard. |
| Validation | Server-side: explicit `Validate()` on each request DTO; struct tags + custom logic. No reflection-based validators like `validator.v10` at this stage (decision deferred until we hit complex DTOs). | `go-playground/validator/v10` | Avoid adding a dependency until a request DTO actually needs cross-field validation TLAs. Keep current B.0 dependency list lean. |
| Listing response shape | `{ "items": [...], "page": 1, "size": 20, "total": N }`. | Bare array; `Link` headers | Easier admin console consumption. |
| Slog usage | Every app service and repository accepts `*slog.Logger`; logs use named attrs. | Package-level loggers; `fmt`-style messages | Matches AGENT.md §8 logging convention. |

## Data Flow

```text
admin client
  -> admin Fiber app
  -> admin middleware chain (request id, recover, access log, security, cors)
  -> /v1/<entity> route
  -> <action>_<entity>_handler.Handle()
     -> request.<Action><Entity>Request{}.Validate()
     -> pkg/app/<entity>.<UseCase>.<verb>(ctx, req)
        -> domain aggregate constructor / mutator (pure)
        -> pkg/infra/repository/<entity>.Repository.<Save|Update|Delete|FindByID|List>
           -> database.WithTx(ctx, conn, fn)
              -> pgx.Tx.Exec / QueryRow / Query
              -> for Consumer: diff M:N join tables in the same tx
  -> response.<Entity>Response{} JSON-marshalled
  -> 200 / 201 / 204 / 4xx / 5xx via helpers/errors.go mapping
```

## File Changes

Notation: `**` denotes "per entity, one file each" (5 entities for
domain/app/repo/handlers, except where noted).

| File | Action | Description |
|---|---|---|
| `pkg/domain/<entity>/<entity>.go` | Create | Aggregate root + constructors. No infra imports. |
| `pkg/domain/<entity>/repository.go` | Create | `Repository` interface (Save, Update, Delete, FindByID, List). |
| `pkg/domain/<entity>/errors.go` | Create | Sentinel errors. |
| `pkg/domain/backend/backend.go` | Create (special) | Adds `Type BackendType` + `Config json.RawMessage`. |
| `pkg/domain/consumer/consumer.go` | Create (special) | Exposes `AttachBackend`, `DetachBackend`, `AttachPolicy`, `DetachPolicy`, `AttachAuth`, `DetachAuth`. |
| `pkg/domain/common/` | Create (small) | Shared `Page`, `Sort` value objects + `IsNotFoundError` helper. Only if needed by ≥2 packages. |
| `pkg/infra/database/migrations/<unix_ts>_create_gateways_table.go` | Create | DDL + Down. |
| `pkg/infra/database/migrations/<unix_ts>_create_backends_table.go` | Create | DDL + Down. Includes `type` enum check + `config jsonb`. |
| `pkg/infra/database/migrations/<unix_ts>_create_consumers_table.go` | Create | DDL + Down. |
| `pkg/infra/database/migrations/<unix_ts>_create_policies_table.go` | Create | DDL + Down. Includes `action` enum check + `where jsonb` + `when jsonb`. |
| `pkg/infra/database/migrations/<unix_ts>_create_auths_table.go` | Create | DDL + Down. Includes `type` text + `config jsonb`. |
| `pkg/infra/database/migrations/<unix_ts>_create_consumer_backend_join.go` | Create | Composite PK, FK CASCADE. |
| `pkg/infra/database/migrations/<unix_ts>_create_consumer_policy_join.go` | Create | Composite PK, FK CASCADE. |
| `pkg/infra/database/migrations/<unix_ts>_create_consumer_auth_join.go` | Create | Composite PK, FK CASCADE. |
| `pkg/infra/repository/<entity>/repository.go` | Create | pgx implementation of `domain.Repository`. Uses `database.WithTx` for any multi-statement write. |
| `pkg/infra/repository/consumer/repository.go` | Create (special) | Diffs `consumer_backend` / `consumer_policy` / `consumer_auth` inside `WithTx`. |
| `pkg/app/<entity>/creator.go` | Create | Interface + impl + `//go:generate mockery`. |
| `pkg/app/<entity>/updater.go` | Create | Same shape. |
| `pkg/app/<entity>/deleter.go` | Create | Same shape. |
| `pkg/app/<entity>/finder.go` | Create | Same shape; exposes `FindByID` + `List`. |
| `pkg/app/<entity>/mocks/*` | Auto-generate | `make mocks` outputs. |
| `pkg/api/handler/http/create_<entity>_handler.go` | Create | One per entity. |
| `pkg/api/handler/http/get_<entity>_handler.go` | Create | One per entity. |
| `pkg/api/handler/http/list_<entity>_handler.go` | Create | One per entity. |
| `pkg/api/handler/http/update_<entity>_handler.go` | Create | One per entity. |
| `pkg/api/handler/http/delete_<entity>_handler.go` | Create | One per entity. |
| `pkg/api/handler/http/request/create_<entity>_request.go` | Create | One per entity. |
| `pkg/api/handler/http/request/update_<entity>_request.go` | Create | One per entity. |
| `pkg/api/handler/http/request/list_<entity>_request.go` | Create | Pagination + `?name=` filter; one per entity. |
| `pkg/api/handler/http/response/<entity>_response.go` | Create | Single-item response per entity. |
| `pkg/api/handler/http/response/list_<entity>_response.go` | Create | Listing envelope per entity. |
| `pkg/api/handler/http/helpers/params.go` | Create (one file) | `ParseUUIDParam`, `ParsePage`, `ParseSize`. |
| `pkg/api/handler/http/helpers/response.go` | Create (one file) | JSON writers: `WriteCreated`, `WriteOK`, `WriteNoContent`. |
| `pkg/api/handler/http/helpers/errors.go` | Create (one file) | Domain-error → HTTP-status mapping. |
| `pkg/container/modules/<entity>.go` | Modify | Replace `return nil` with concrete providers (domain repo iface, pgx repo, 4 app services, 5 handlers). |
| `pkg/container/modules/api.go` | Modify | Register the new handler providers under the admin transport. Proxy module untouched. |
| `pkg/server/router/admin_router.go` | Modify | Add `/v1/<entity>` routes per entity + new fields in `adminRouterParams`. |
| `Makefile` | Modify | Add `mocks` target running `go generate ./...`. Add `mockery` to the dev tool list. |
| `tools/tools.go` (or `go.mod` test-only block) | Create or modify | Pin `github.com/vektra/mockery/v2` so `go install` resolves a single version. |

Untouched in B.2:

| File | Reason |
|---|---|
| `pkg/config/config.go` | No new env vars. |
| `pkg/server/router/proxy_router.go` | Admin-only scope. |
| `pkg/api/middleware/**` | Admin auth/audit are B.7/B.9. |
| `pkg/infra/logger/**` | Done in B.0. |
| `pkg/infra/cache/**` | Doesn't exist yet; arrives with RUN-291. |
| `.cursor/sdd/run-280-port-reusable-components/**` | Paused; resumed post-B.2. |

## Interfaces / Contracts

Domain repository interface — one per entity, identical shape:

```go
// pkg/domain/gateway/repository.go
package gateway

import (
    "context"

    "github.com/google/uuid"
)

type Repository interface {
    Save(ctx context.Context, g *Gateway) error
    Update(ctx context.Context, g *Gateway) error
    Delete(ctx context.Context, id uuid.UUID) error
    FindByID(ctx context.Context, id uuid.UUID) (*Gateway, error)
    List(ctx context.Context, filter ListFilter) (items []*Gateway, total int, err error)
}

type ListFilter struct {
    NameContains string
    Page         int
    Size         int
}
```

App-service contracts (one per file, mockery-mocked):

```go
// pkg/app/gateway/creator.go
//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=gateway_creator_mock.go --case=underscore --with-expecter
type Creator interface {
    Create(ctx context.Context, req request.CreateGatewayRequest) (*gateway.Gateway, error)
}

// pkg/app/gateway/finder.go
//go:generate mockery --name=Finder ...
type Finder interface {
    FindByID(ctx context.Context, id uuid.UUID) (*gateway.Gateway, error)
    List(ctx context.Context, req request.ListGatewayRequest) ([]*gateway.Gateway, int, error)
}

// pkg/app/gateway/updater.go and deleter.go follow the same shape.
```

Polymorphic `Backend` aggregate:

```go
// pkg/domain/backend/backend.go
type BackendType string

const (
    BackendTypeLLM BackendType = "llm"
    BackendTypeA2A BackendType = "a2a"
    BackendTypeMCP BackendType = "mcp"
)

type Backend struct {
    ID        uuid.UUID
    GatewayID uuid.UUID
    Name      string
    Type      BackendType
    Config    json.RawMessage   // validated per Type by pkg/app/backend
    CreatedAt time.Time
    UpdatedAt time.Time
}
```

`Consumer` aggregate exposes join management explicitly:

```go
// pkg/domain/consumer/consumer.go
type Consumer struct {
    ID        uuid.UUID
    Name      string
    Backends  []uuid.UUID  // join: consumer_backend
    Policies  []uuid.UUID  // join: consumer_policy
    Auths     []uuid.UUID  // join: consumer_auth
    CreatedAt time.Time
    UpdatedAt time.Time
}

func (c *Consumer) AttachBackend(id uuid.UUID) { /* dedupe + append */ }
func (c *Consumer) DetachBackend(id uuid.UUID) { /* remove if present */ }
// AttachPolicy / DetachPolicy / AttachAuth / DetachAuth follow.
```

`consumer.Repository.Save` and `Update` are responsible for diffing the
three join slices against the persisted state in a single transaction.

`Policy` aggregate — persisted shape only; no plugin chain:

```go
// pkg/domain/policy/policy.go
type PolicyAction string

const (
    PolicyActionAllow PolicyAction = "allow"
    PolicyActionLog   PolicyAction = "log"
    PolicyActionMask  PolicyAction = "mask"
    PolicyActionBlock PolicyAction = "block"
)

type Policy struct {
    ID        uuid.UUID
    Name      string
    Action    PolicyAction
    Where     json.RawMessage  // matcher predicate; opaque in B.2
    When      json.RawMessage  // condition predicate; opaque in B.2
    CreatedAt time.Time
    UpdatedAt time.Time
}
```

`Auth` aggregate — generic descriptor; B.7 owns the type implementations:

```go
// pkg/domain/auth/auth.go
type Auth struct {
    ID        uuid.UUID
    Name      string
    Type      string           // e.g. "api_key", "oidc", "mtls" — list confirmed by B.7 owner
    Config    json.RawMessage  // opaque in B.2
    CreatedAt time.Time
    UpdatedAt time.Time
}
```

Domain-error to HTTP mapping (one place):

```go
// pkg/api/handler/http/helpers/errors.go
package helpers

import (
    "errors"

    "github.com/gofiber/fiber/v2"

    gatewaydomain  "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
    backenddomain  "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
    // … one import per entity
)

func MapDomainError(err error) (status int, payload fiber.Map) {
    switch {
    case errors.Is(err, gatewaydomain.ErrNotFound),
         errors.Is(err, backenddomain.ErrNotFound) /* … */ :
        return fiber.StatusNotFound, fiber.Map{"error": "not_found"}
    case errors.Is(err, gatewaydomain.ErrAlreadyExists) /* … */:
        return fiber.StatusConflict, fiber.Map{"error": "already_exists"}
    case errors.Is(err, gatewaydomain.ErrInvalidInput) /* … */:
        return fiber.StatusUnprocessableEntity, fiber.Map{"error": err.Error()}
    default:
        return fiber.StatusInternalServerError, fiber.Map{"error": "internal_error"}
    }
}
```

## Migration Conventions

- Filename: `<unix_ts>_<snake_action>.go`, where `<unix_ts>` is the exact
  unix epoch second at authoring time. Example:
  `20260528100000_create_gateways_table.go`.
- Each file holds one DDL change (one CREATE TABLE, one ALTER TABLE,
  etc.). No "kitchen-sink" migrations.
- `Up` and `Down` are pure DDL; no data backfill in B.2 (no existing
  data exists yet).
- Cross-entity ordering enforced by the unix-timestamp prefix:
  - Phase 1: `gateways`, `backends`, `consumers`, `policies`, `auths`.
  - Phase 2: `consumer_backend`, `consumer_policy`, `consumer_auth`.

## Testing Strategy

| Layer | Approach |
|---|---|
| Domain | Table-driven unit tests on constructors + mutators (`Attach*`, `Detach*`). No DB, no mocks. |
| App service | Unit tests against the use-case interface, driven by mockery mocks of `domain.Repository`. Each test asserts on `Repository` call shape and on the return value of the use case. |
| Repository | Integration tests behind `PG_TEST_URL` env var (per AGENT.md §9). Skip-cleanly when unset. Tests use a fresh schema-per-test via the in-code migrations. |
| Admin handler | `fiber.New().Test(req)` against the handler, driven by a mockery mock of the app-service interface. Asserts on status code + JSON body. |
| DI module | A small test under `pkg/container/modules/` resolves a hydrated entity module + asserts that all consumer providers can be invoked. |

No end-to-end test in B.2; covered later by the functional test harness
(B.10).

## Dependencies

- B.0 outputs (`pkg/infra/database/{connection, migrations_manager,
  tx}.go`, the DI `container` wrapper, the entity module stubs,
  `admin_router.go`, the Fiber middleware chain).
- New external module: `github.com/vektra/mockery/v2` (dev tool, pinned
  in `tools.go` + invoked via Makefile target).
- Existing external modules used: `github.com/google/uuid`,
  `github.com/jackc/pgx/v5`, `github.com/gofiber/fiber/v2`,
  `github.com/stretchr/testify`.

## Rollback Plan

Per-PR revert is the unit. Within an entity, revert order is `c → b →
a`. Across entities, revert order is `Auth → Policy → Consumer →
Backend → Gateway`. Each migration ships an explicit `Down`, so the
runner can roll back per-ID if it ever exposes that path (the manager
currently only applies forward; a one-off `migrate down` task is **not**
in B.2 scope).
