# Explore: RUN-281 — B.2 New data model + admin CRUD (control plane)

Status: investigation only. No code is written in this phase.
Repo: `AgentGateway` · Branch: `feat/run-282-b0-project-setup-scaffolding`
(branch override granted by user — we are not creating a new feature branch).

Parent issue: [RUN-281](https://linear.app/neuraltrust/issue/RUN-281) (Backlog).
Sub-issues: RUN-295 (entities + schema + migrations), RUN-296 (repositories),
RUN-297 (app services), RUN-298 (admin HTTP handlers), RUN-299 (cache
invalidation events — **deferred**, depends on RUN-291 which is paused).

## 1. Goal & scope summary

**Build the control plane** around AgentGateway's new data model:
`Gateway`, `Backend(type=LLM|A2A|MCP)`, `Consumer`, `Policy`, `Auth`, plus
the join tables for the many-to-many relationships.

Per `RUN-279` (epic):
> "*The new data model collapses today's `gateway / service / upstream /
> rule / consumer / plugin chain` into a tighter shape centered on
> `Backend` (LLM | A2A | MCP), `Consumer` and `Policy`.*"

Relationships from RUN-281:

```
gateway   1 <-> n  backend
consumer  n <-> n  backend
consumer  n <-> n  policy
consumer  n <-> n  auth
```

What B.2 delivers (5 layers per entity, mirroring TrustGate where the
shape carries over but **not** a literal 1:1 port):

1. Domain aggregates (`pkg/domain/<entity>/`) + repository interfaces.
2. Postgres schema + in-code migrations (`pkg/infra/database/migrations/`).
3. Repositories (`pkg/infra/repository/<entity>/`) on `pgx/v5` + `WithTx`.
4. App services (`pkg/app/<entity>/`): one file per use case
   (`creator.go`, `updater.go`, `deleter.go`, `finder.go`) **with
   interface + impl + `//go:generate mockery`** per `.agents/AGENT.md` §10.
5. Admin HTTP handlers (`pkg/api/handler/http/`) + request DTOs
   (`pkg/api/handler/http/request/`) + response DTOs
   (`pkg/api/handler/http/response/`), wired into `admin_router.go`.

What B.2 explicitly **does not** deliver (strict non-goals — propose/design
must reject anything in this list):

- Hot-path Policy matcher / resolver (B.4 / RUN-283).
- Plugin chain wiring, plugin manager, plugin catalog (B.3 / RUN-334 +
  RUN-293).
- Auth **type** implementations — only persist the `Auth` aggregate as a
  generic descriptor (`type`, `config`). Type-specific verification is
  B.7.
- Audit log integration (B.9).
- Cache invalidation events (RUN-299) — depends on B.1 cache subsystem
  (RUN-291) which is currently paused.
- Streaming, provider adapters, load balancing.
- Hot-path traffic forwarding (`forwarded_handler.go`) — that is B.4 / B.5.
- Read-through caching in repositories — B.2 repos are strictly DB.

## 2. State of the repository today

What is already on disk we can build on (B.0 deliverables + B.1 phase 1
runtime config):

| Path | Status | What we get for B.2 |
|---|---|---|
| `pkg/config/config.go` | done | DB config + env loader. No new env vars expected from B.2. |
| `pkg/infra/database/connection.go` | done | `Connection { Pool *pgxpool.Pool }` with ping fail-fast. |
| `pkg/infra/database/migrations_manager.go` | done | `RegisterMigration(...)` registry sorted by unix-timestamp prefix; `ApplyPending` commits each migration in its own tx alongside its `migration_version` row. B.2 migrations register via `init()`. |
| `pkg/infra/database/tx.go` | done | `WithTx(ctx, conn, fn func(pgx.Tx) error)` — every multi-statement write in B.2 repositories uses this. |
| `pkg/infra/database/migrations/doc.go` | placeholder | Only `package migrations`. B.2 lands the first real migrations here. |
| `pkg/container/modules/{gateway,backend,consumer,policy,auth}.go` | placeholders | Each is `func X(_ *container.Container) error { return nil }`. B.2 fills them with concrete providers. |
| `pkg/container/modules/api.go` | partial | Health + version handlers wired. B.2 extends it with admin handler providers + admin `*Middlewares` consumes the same chain. |
| `pkg/server/router/admin_router.go` | partial | Only health + version routes. B.2 registers `/v1/<entity>` routes here. |
| `pkg/api/handler/http/health_handler.go`, `version_handler.go` | done | Handler-shape reference — keep parity. |
| `pkg/domain/` | empty | Where every B.2 aggregate lives. |
| `pkg/app/` | empty | Where every B.2 use case lives. |
| `pkg/infra/repository/` | **does not exist** | Will be created by B.2 (one subfolder per entity per AGENT.md §11). |
| `pkg/api/handler/http/request/` | **does not exist** | Created by B.2. |
| `pkg/api/handler/http/response/` | **does not exist** | Created by B.2. |
| `.cursor/sdd/run-280-port-reusable-components/` | paused | RUN-280 SDD stays on disk; B.1 resumes after B.2 (and uses B.2 entities). |

Net: **the scaffolding is exactly the shape B.2 needs.** No B.0 retrofit
required; the entity modules are already placeholders waiting to be wired.

## 3. Affected-areas map

Legend: 🆕 create · ✏️ edit · ⏸️ leave alone in B.2.

### 3.1 Domain (`pkg/domain/`)

| Path | Action | Contents |
|---|---|---|
| `pkg/domain/gateway/gateway.go` | 🆕 | Aggregate root (`Gateway` struct, value objects). Pure Go, no infra. |
| `pkg/domain/gateway/repository.go` | 🆕 | `Repository` interface (Save, FindByID, ListByX, Delete). |
| `pkg/domain/gateway/errors.go` | 🆕 | Domain-level sentinel errors (`ErrGatewayNotFound`, `ErrGatewayExists`). |
| `pkg/domain/backend/backend.go` | 🆕 | `Backend` aggregate with `Type` enum (LLM, A2A, MCP). |
| `pkg/domain/backend/repository.go` | 🆕 | `Repository` interface. |
| `pkg/domain/backend/errors.go` | 🆕 | |
| `pkg/domain/consumer/consumer.go` | 🆕 | `Consumer` aggregate + join references. |
| `pkg/domain/consumer/repository.go` | 🆕 | |
| `pkg/domain/consumer/errors.go` | 🆕 | |
| `pkg/domain/policy/policy.go` | 🆕 | `Policy` aggregate. **No plugin chain field in B.2.** |
| `pkg/domain/policy/repository.go` | 🆕 | |
| `pkg/domain/policy/errors.go` | 🆕 | |
| `pkg/domain/auth/auth.go` | 🆕 | `Auth` aggregate (generic descriptor: type + opaque config). |
| `pkg/domain/auth/repository.go` | 🆕 | |
| `pkg/domain/auth/errors.go` | 🆕 | |
| `pkg/domain/common/` | 🆕 (small) | Shared `Page`, `Sort`, `Filter` value objects + `IsNotFoundError` helper. Only if it stays infra-free. |

### 3.2 App (`pkg/app/`)

Each entity gets four files, one per use case, **each containing
interface + impl + `//go:generate mockery`** (AGENT.md §10.2):

| Path | Action | Files (per entity × 5 entities = 20 files + 5 `mocks/` dirs) |
|---|---|---|
| `pkg/app/gateway/{creator,updater,deleter,finder}.go` | 🆕 | Creator, Updater, Deleter, Finder. Mocks generated to `pkg/app/gateway/mocks/`. |
| `pkg/app/backend/{...}` | 🆕 | idem. Creator must validate the polymorphic `Type` and its config payload. |
| `pkg/app/consumer/{...}` | 🆕 | idem. Creator/Updater also manage the many-to-many associations (consumer↔backend, consumer↔policy, consumer↔auth) — see §6.4 for option. |
| `pkg/app/policy/{...}` | 🆕 | idem. |
| `pkg/app/auth/{...}` | 🆕 | idem. |

### 3.3 Infra repositories (`pkg/infra/repository/`)

| Path | Action | Notes |
|---|---|---|
| `pkg/infra/repository/gateway/repository.go` | 🆕 | Implements `domain/gateway.Repository`. Uses `pgxpool` + `database.WithTx` for multi-row writes. |
| `pkg/infra/repository/backend/repository.go` | 🆕 | Same. Discriminator-aware reads/writes (see §6.1). |
| `pkg/infra/repository/consumer/repository.go` | 🆕 | Loads many-to-many joins on demand or eagerly per spec (decision in design). |
| `pkg/infra/repository/policy/repository.go` | 🆕 | |
| `pkg/infra/repository/auth/repository.go` | 🆕 | |

We **diverge from TrustGate's flat `pkg/infra/repository/<entity>_repository.go`** in favour of the subfolder pattern that AGENT.md §11 already endorses. Rationale: room for `mappers.go`, `queries.go`, and `*_test.go` per entity without polluting one giant directory.

### 3.4 Migrations (`pkg/infra/database/migrations/`)

One file per DDL change, registered via `init()`:

```
<unix_ts>_create_gateways_table.go
<unix_ts>_create_backends_table.go
<unix_ts>_create_consumers_table.go
<unix_ts>_create_policies_table.go
<unix_ts>_create_auths_table.go
<unix_ts>_create_consumer_backend_join.go
<unix_ts>_create_consumer_policy_join.go
<unix_ts>_create_consumer_auth_join.go
```

Each has `Up(ctx, tx)` + `Down(ctx, tx)` over `pgx.Tx`.

### 3.5 HTTP admin layer

| Path | Action | Files |
|---|---|---|
| `pkg/api/handler/http/create_<entity>_handler.go` | 🆕 | Five entities × one file each. |
| `pkg/api/handler/http/get_<entity>_handler.go` | 🆕 | Five entities. |
| `pkg/api/handler/http/list_<entity>_handler.go` | 🆕 | Five entities. |
| `pkg/api/handler/http/update_<entity>_handler.go` | 🆕 | Five entities. |
| `pkg/api/handler/http/delete_<entity>_handler.go` | 🆕 | Five entities. |
| `pkg/api/handler/http/request/<action>_<entity>_request.go` | 🆕 | One DTO per file (AGENT.md §10.3). |
| `pkg/api/handler/http/response/<entity>_response.go`, `list_<entity>_response.go` | 🆕 | One DTO per file (AGENT.md §10.4). |
| `pkg/api/handler/http/helpers/params.go`, `response.go`, `errors.go` | 🆕 (small) | UUID path param parsing, JSON response writers, domain-error → HTTP mapping. **No business logic.** |

### 3.6 DI modules & router

| Path | Action | Notes |
|---|---|---|
| `pkg/container/modules/gateway.go` | ✏️ | Replace `return nil` with concrete providers: domain repo iface, pgx repo impl, four app use cases, five handlers. |
| `pkg/container/modules/backend.go` | ✏️ | Same. |
| `pkg/container/modules/consumer.go` | ✏️ | Same + relation hydration logic. |
| `pkg/container/modules/policy.go` | ✏️ | Same. |
| `pkg/container/modules/auth.go` | ✏️ | Same. |
| `pkg/container/modules/api.go` | ✏️ | Add the 25 admin handlers to the admin `*Middlewares`/router params. **Do not** add any to the proxy module. |
| `pkg/server/router/admin_router.go` | ✏️ | Register `/v1/{gateways,backends,consumers,policies,auths}` routes pointing at the five handler structs per entity. |
| `pkg/server/router/proxy_router.go` | ⏸️ | B.2 is admin-only; proxy is touched in B.4/B.5. |

### 3.7 What we explicitly do not touch in B.2

- `pkg/config/config.go` (already covers DB; no B.2 env vars).
- `pkg/infra/logger/**` (done in B.0).
- `pkg/server/router/proxy_router.go` (admin-only scope).
- `pkg/api/middleware/**` (re-use existing chain; admin auth + audit are
  B.7 / B.9).
- `.cursor/sdd/run-280-port-reusable-components/**` (paused; resumed
  post-B.2).

## 4. Code-shape sketches (must respect AGENT.md §10)

### 4.1 Domain aggregate (one file per entity)

```go
// pkg/domain/gateway/gateway.go
package gateway

import (
    "time"

    "github.com/google/uuid"
)

type Gateway struct {
    ID          uuid.UUID
    Name        string
    Description string
    CreatedAt   time.Time
    UpdatedAt   time.Time
}

func New(name, description string) *Gateway { /* validations */ }
```

### 4.2 Domain repository interface (one file)

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
    List(ctx context.Context, page, size int) ([]*Gateway, int, error)
}
```

### 4.3 Application use case (one per file — interface + impl + `//go:generate`)

```go
// pkg/app/gateway/creator.go
package gateway

import (
    "context"
    "log/slog"

    domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
    requestdto "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/request"
)

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=gateway_creator_mock.go --case=underscore --with-expecter
type Creator interface {
    Create(ctx context.Context, req requestdto.CreateGatewayRequest) (*domain.Gateway, error)
}

type creator struct {
    repo   domain.Repository
    logger *slog.Logger
}

func NewCreator(repo domain.Repository, logger *slog.Logger) Creator {
    return &creator{repo: repo, logger: logger}
}

func (c *creator) Create(ctx context.Context, req requestdto.CreateGatewayRequest) (*domain.Gateway, error) {
    g := domain.New(req.Name, req.Description)
    if err := c.repo.Save(ctx, g); err != nil {
        c.logger.Error("save gateway", slog.String("err", err.Error()))
        return nil, err
    }
    return g, nil
}
```

### 4.4 Request DTO (one per file)

```go
// pkg/api/handler/http/request/create_gateway_request.go
package request

type CreateGatewayRequest struct {
    Name        string `json:"name" validate:"required,min=1,max=255"`
    Description string `json:"description"`
}

func (r CreateGatewayRequest) Validate() error { /* … */ }
```

### 4.5 Response DTO (one per file)

```go
// pkg/api/handler/http/response/gateway_response.go
package response

import "time"

type GatewayResponse struct {
    ID          string    `json:"id"`
    Name        string    `json:"name"`
    Description string    `json:"description"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}
```

### 4.6 Admin handler (one action per file)

```go
// pkg/api/handler/http/create_gateway_handler.go
package http

import (
    "github.com/gofiber/fiber/v2"

    appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
    "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/request"
    "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/response"
)

type CreateGatewayHandler struct {
    creator appgateway.Creator
}

func NewCreateGatewayHandler(c appgateway.Creator) *CreateGatewayHandler {
    return &CreateGatewayHandler{creator: c}
}

func (h *CreateGatewayHandler) Handle(c *fiber.Ctx) error {
    var req request.CreateGatewayRequest
    if err := c.BodyParser(&req); err != nil { /* 400 */ }
    if err := req.Validate(); err != nil { /* 422 */ }
    g, err := h.creator.Create(c.UserContext(), req)
    if err != nil { /* domain → http mapping */ }
    return c.Status(201).JSON(response.FromGateway(g))
}
```

### 4.7 Repository (one folder per entity)

```go
// pkg/infra/repository/gateway/repository.go
package gateway

import (
    "context"

    "github.com/NeuralTrust/AgentGateway/pkg/infra/database"
    domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
    "github.com/google/uuid"
    "github.com/jackc/pgx/v5"
)

type Repository struct {
    conn *database.Connection
}

func NewRepository(conn *database.Connection) *Repository { return &Repository{conn: conn} }

func (r *Repository) Save(ctx context.Context, g *domain.Gateway) error {
    return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
        _, err := tx.Exec(ctx,
            `INSERT INTO gateways (id, name, description, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5)`,
            g.ID, g.Name, g.Description, g.CreatedAt, g.UpdatedAt,
        )
        return err
    })
}
// FindByID, List, Update, Delete follow the same pattern.
```

### 4.8 Migration (one DDL per file)

```go
// pkg/infra/database/migrations/20260528090000_create_gateways_table.go
package migrations

import (
    "context"

    "github.com/NeuralTrust/AgentGateway/pkg/infra/database"
    "github.com/jackc/pgx/v5"
)

func init() {
    database.RegisterMigration(database.Migration{
        ID:   "20260528090000_create_gateways_table",
        Name: "create gateways table",
        Up: func(ctx context.Context, tx pgx.Tx) error {
            _, err := tx.Exec(ctx, `
                CREATE TABLE gateways (
                    id          UUID PRIMARY KEY,
                    name        TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    created_at  TIMESTAMPTZ NOT NULL,
                    updated_at  TIMESTAMPTZ NOT NULL
                );`)
            return err
        },
        Down: func(ctx context.Context, tx pgx.Tx) error {
            _, err := tx.Exec(ctx, `DROP TABLE IF EXISTS gateways;`)
            return err
        },
    })
}
```

### 4.9 DI module fill-in (one file per entity)

```go
// pkg/container/modules/gateway.go
package modules

import (
    apphttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http"
    appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
    "github.com/NeuralTrust/AgentGateway/pkg/container"
    domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
    infra "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/gateway"
)

func Gateway(c *container.Container) error {
    if err := c.Provide(func(r *infra.Repository) domain.Repository { return r }); err != nil { return err }
    if err := c.Provide(infra.NewRepository); err != nil { return err }
    if err := c.Provide(appgateway.NewCreator); err != nil { return err }
    if err := c.Provide(appgateway.NewUpdater); err != nil { return err }
    if err := c.Provide(appgateway.NewDeleter); err != nil { return err }
    if err := c.Provide(appgateway.NewFinder); err != nil { return err }
    if err := c.Provide(apphttp.NewCreateGatewayHandler); err != nil { return err }
    // …get, list, update, delete handlers…
    return nil
}
```

## 5. Approaches comparison

Four candidate slicings of the work. Scored against the 400-line PR budget,
parallelizability, blast radius, and reviewer load.

### Approach A — Per-layer horizontal slices (the Linear sub-issue shape)

PR 1: all migrations (RUN-295) → PR 2: all repositories (RUN-296) →
PR 3: all app services (RUN-297) → PR 4: all admin handlers (RUN-298).

| Axis | Score |
|---|---|
| PR size | ❌ Each PR is 5 entities wide × one layer deep. Estimated PR1 ≈ 600-800 LOC (8 migrations + tests); PR3 (app) ≈ 2000+ LOC. Every PR needs `size:exception`. |
| Parallelizable | ❌ PRs strictly sequential — layer N depends on layer N-1. |
| Blast radius | ✅ Each PR touches exactly one layer. |
| Reviewer load | ❌ Reviewer must hold 5 entity shapes in head per PR. |
| Match with Linear sub-issues | ✅ 1:1. |

### Approach B — Per-entity vertical slices

PR 1: Gateway end-to-end (domain + migration + repo + app + handlers).
PR 2: Backend end-to-end. PR 3: Consumer. PR 4: Policy. PR 5: Auth.

| Axis | Score |
|---|---|
| PR size | ⚠️ ~1400-1600 LOC per entity. All PRs need `size:exception`. |
| Parallelizable | ✅ Entities are mostly independent once Gateway lands the shared shape. Consumer depends on Backend/Policy/Auth being on `main` for the join-table FK constraints. |
| Blast radius | ✅ Each PR is one entity. |
| Reviewer load | ✅ One entity per PR — full vertical context in one place. |
| Match with Linear sub-issues | ⚠️ Each PR partially closes RUN-295/296/297/298 simultaneously. We label each PR with its primary sub-issue and mention the others. |

### Approach C — Hybrid: scaffold PR + per-entity vertical slices

PR 1: shared scaffolding only (helpers/params, response, errors, common
domain types, repository base test fixture) + Gateway end-to-end as the
reference shape. PR 2-5: Backend, Consumer, Policy, Auth — each
end-to-end, copying the Gateway shape.

| Axis | Score |
|---|---|
| PR size | ⚠️ PR 1 ≈ 1700-1900 LOC (worst); PRs 2-5 ≈ 1100-1400 LOC each. All need `size:exception`. |
| Parallelizable | ⚠️ PR 1 must land first; the rest can go in parallel. |
| Blast radius | ✅ Each PR is one entity or one scaffolding pass. |
| Reviewer load | ✅ Pattern is "establish in PR1, mirror in PRs 2-5". |
| Match with Linear sub-issues | ⚠️ Same as B. |

### Approach D — Chained PRs per entity (recommended)

For **each entity**, ship three chained PRs (per `_base.mdc` PR-review
budget — 400 lines, soft cap):

- PR _e.a_: domain aggregate + migration + repository (one entity).
- PR _e.b_: app services (creator, updater, deleter, finder) + their
  mocks.
- PR _e.c_: admin handlers (5) + request/response DTOs + router wiring +
  DI module fill-in.

Total: 5 entities × 3 PRs = **15 PRs**, each ~300-500 LOC.

| Axis | Score |
|---|---|
| PR size | ✅ Most PRs stay at-or-near the 400-line budget. A couple may need `size:exception` (entity migration + repository for Consumer w/ join tables likely 500-600 LOC). |
| Parallelizable | ✅ Once Gateway-a lands, all `<entity>-a` PRs go in parallel; `<entity>-b` follows its `<entity>-a`; `<entity>-c` follows its `<entity>-b`. Three PRs in flight simultaneously is realistic. |
| Blast radius | ✅ Each PR is one entity × one layer. |
| Reviewer load | ✅ Smallest unit = one entity × one layer; reviewer can hold it in their head. |
| Match with Linear sub-issues | ✅ Each PR closes one sub-issue cleanly: `<entity>-a` → RUN-295/296, `<entity>-b` → RUN-297, `<entity>-c` → RUN-298. RUN-295/296 collapse into the same PR because the repository can't compile without the migration shape. |

**Recommendation:** Approach D. Tasks (next phase) should plan the 15 PRs
explicitly and flag the 2-3 that may breach the budget, but the average PR
size sits inside the team budget without needing 5× `size:exception`.

A counter-argument worth keeping in mind: Approach D delays "first
working CRUD I can curl" to the third PR (Gateway-c). Approach B delivers
it earlier per entity at the cost of bigger PRs. Design will pick the
final cut.

## 6. Open questions for the human before propose

These need a decision before `sdd-propose` writes the proposal. Each has
a recommended default — accept silently if you agree.

### 6.1 Backend(LLM|A2A|MCP) polymorphism — schema shape

| Option | Description | Pros | Cons |
|---|---|---|---|
| **A. Single-table + JSONB (recommended)** | One `backends` table with `type` column (enum/varchar discriminator) + `config JSONB` for type-specific fields. | Simple, fast, no joins in hot path, adding a new backend type doesn't require migration. Matches TrustGate's pattern of JSONB-flexible upstream targets. | App-layer validation must cover JSONB shape per type. |
| B. Table-per-type | `backends` parent + `backend_llm_configs` / `backend_a2a_configs` / `backend_mcp_configs` child tables joined 1:1. | Strict column-level validation per type. | Joins on every read; migrations harder; B.2 spec doubles in size. |
| C. Three independent tables | Skip the `Backend` aggregate as a single concept; each type is its own aggregate. | Aligns FK targeting trivially. | Contradicts RUN-281 / RUN-279 wording ("`Backend (LLM \| A2A \| MCP)`" as one concept). |

**Recommended:** A. Validator lives in `pkg/app/backend/creator.go` and
`pkg/app/backend/updater.go`; the domain struct exposes
`Type BackendType` and `Config json.RawMessage` (or a typed `Config`
sealed-interface).

### 6.2 Identifiers

UUID v4 across the board (matches AgentGuardian + TrustGate). Stored as
`UUID` in Postgres, encoded as RFC 4122 string in JSON. The app layer
generates IDs (not the database).

### 6.3 Soft delete

**Recommended:** none in B.2. Use FK `ON DELETE CASCADE` on the three
join tables. If/when soft delete becomes a product requirement, we add
`deleted_at` to the relevant aggregates and filter in repositories
behind a single flag.

### 6.4 Many-to-many associations — storage and write semantics

The three join tables (`consumer_backend`, `consumer_policy`,
`consumer_auth`) are pure association tables (composite PK
`(consumer_id, <other>_id)` + optional `created_at`).

Open question: **who owns the writes?**

| Option | Description |
|---|---|
| **A. Consumer aggregate (recommended)** | `Consumer` aggregate exposes `AttachBackend`, `DetachBackend`, etc. `consumer.Repository.Save` is responsible for diffing the join tables inside `WithTx`. |
| B. Standalone link service | `pkg/app/consumer_backend_linker/` etc. — three separate use cases. |

Recommendation: A — Consumer owns the joins, mutations go through
`Updater.Update(ctx, consumer)` and the repository computes the diff
inside `WithTx`. Keeps the API surface smaller and the consistency
boundary explicit.

### 6.5 `Auth` aggregate shape (B.7 implements types, B.2 just persists)

**Recommended:** `Auth { ID UUID, Name string, Type string, Config
json.RawMessage, CreatedAt, UpdatedAt }`. App-layer validators in B.2
only check `Type ∈ {<the supported values>}` (we list the strings
B.7 plans to implement) and that `Config` is valid JSON. **No actual
verification logic.** Final list of supported `Type` strings should be
confirmed with whoever owns B.7.

### 6.6 `Policy` aggregate shape (B.4 implements matching, B.2 just persists)

**Recommended:** `Policy { ID UUID, Name string, Action string ('allow'
| 'log' | 'mask' | 'block'), Where json.RawMessage, When json.RawMessage,
CreatedAt, UpdatedAt }`. No `plugin_chain` field in B.2 (plugins are
B.3 / B.4). The hot-path matcher in B.4 reads this same row and adds
its plugin-chain join later.

### 6.7 Listing endpoints — pagination + filters

**Recommended:** cursorless offset pagination (`?page=1&size=20`,
defaults 1/20, max size 200). Filters: only what's strictly needed for
the admin console UI today — typically `?name=substring` for each
entity. Defer richer filtering (by tags, type, status) to a follow-up.

### 6.8 Repository folder shape — flat vs subfolder

TrustGate uses **flat** files (`pkg/infra/repository/gateway_repository.go`).
AGENT.md §11 says "A repository implementation → `pkg/infra/repository/<context>/`"
(subfolder). **Recommended:** honour AGENT.md (`pkg/infra/repository/gateway/repository.go`).
Diverging note added to `.agents/AGENT.md` if the team prefers flat
later.

### 6.9 Test strategy

- Unit-test domain constructors + validators with table-driven tests.
- Unit-test app services with mockery mocks of `domain.Repository`.
- Repositories: integration tests behind `PG_TEST_URL` env var (already
  flagged in AGENT.md §9). Skip cleanly when unset.
- Admin handlers: Fiber test app (`fiber.New().Test(req)`) driving the
  full handler with a mock of the use case interface.
- No end-to-end test in B.2 — covered by B.10 / functional test harness.

## 7. Risks & unknowns

| Risk | Likelihood | Mitigation |
|---|---|---|
| `Backend` JSONB validation drift (config doesn't match `type`). | Med | Strict app-layer validation per `BackendType`; failing fast in creator/updater. |
| Cross-entity FK ordering — migrations must respect parent-first ordering (gateways before backends before consumer_backend join). | Med | Migration filenames carry unix-timestamp prefix; runner sorts by that prefix. Order them deliberately. |
| `Consumer` is the busiest aggregate (n↔n with 3 sets). PR will likely breach budget. | High | Plan a `Consumer-a` PR for the aggregate + migrations only; `Consumer-b` for the linker logic + app; `Consumer-c` for handlers. Split further if needed. |
| AGENT.md §11 says repository subfolder; TrustGate uses flat. New contributors may copy the wrong shape. | Low | AGENT.md is the source of truth and was just updated; explore + propose enforce subfolder. |
| Many-to-many writes need `WithTx`. Forgetting one path silently breaks consistency. | Med | Repository tests must cover the diff scenarios (`add A, remove B, leave C alone`). Required scenario in spec. |
| Admin auth + audit not yet integrated. Handlers will compile/work without auth, then need a follow-up to add them. | Low | Out of scope for B.2 by issue body. B.7/B.9 wire `Middleware` interfaces over the existing admin chain — no handler refactor. |
| Cache invalidation events deferred (RUN-299). Repos are read-modify-write to DB only. After RUN-291 lands, RUN-299 will retrofit a `cache.Client` dependency. | Low | Keep the repository constructor signature stable so RUN-299 can wrap rather than rewrite. |

## 8. PR-budget forecast (rough)

Using TrustGate equivalents as yardsticks plus the §4 sketches. Numbers
are total changed lines (additions + deletions including tests).

| Slice | Files | Est. LOC | Budget? |
|---|---|---|---|
| Gateway-a (domain + migration + repo + repo tests) | 6 + 2 tests | ~380-450 | At budget. |
| Gateway-b (creator/updater/deleter/finder + mocks + tests) | 4 + 4 mocks + 4 tests | ~480-550 | ⚠️ Slightly over. Try to keep tests focused; otherwise `size:exception`. |
| Gateway-c (5 handlers + DTOs + router + DI module) | ~14 + 3 tests | ~380-450 | At budget. |
| Backend-a (with JSONB validation + type discriminator) | 6 + 2 tests | ~430-500 | ⚠️ Slightly over. |
| Backend-b | similar to Gateway-b | ~500-550 | ⚠️ |
| Backend-c | similar to Gateway-c | ~380-450 | At budget. |
| Consumer-a (entity + 3 joins migrations + repo + diffing logic) | 8 + 2 tests | ~600-700 | ❌ Over budget — split into `Consumer-a1` (entity + migrations) and `Consumer-a2` (repo + diffing). |
| Consumer-b | bigger because of attach/detach use cases | ~550-650 | ⚠️ |
| Consumer-c | similar to Gateway-c | ~380-450 | At budget. |
| Policy-a/b/c | similar to Gateway | ~380-500 each | Mostly at budget. |
| Auth-a/b/c | similar to Gateway | ~350-450 each | At budget. |

**Total estimate:** ~7000-7500 LOC across 16-17 PRs. Average ~400-450
LOC. About 4-5 PRs need `size:exception` (Backend-a/b, Consumer-a2/b,
maybe Gateway-b). Acceptable.

## 9. Strict non-goals (must reject in propose/design)

- Hot-path Policy matcher / resolver.
- Plugin chain wiring or plugin manager / catalog.
- Auth verification logic (just persist the descriptor).
- Audit log integration.
- Cache invalidation events / cache hooks in repositories.
- Streaming, provider adapters, load balancing.
- Hot-path traffic forwarding handler.
- Read-through caching.
- Tenant / Team filters on listing — B.2 ships single-team semantics.
- Admin API authentication / authorization.

## 10. Recommended next step

Move to `sdd-propose` with:

- **Approach:** D (chained PRs per entity, 3 PRs each).
- **Order:** Gateway → Backend → Consumer → Policy → Auth (Gateway first
  establishes the shape; Consumer last because joins depend on
  Backend/Policy/Auth landing first).
- **Open questions for human to confirm before propose:** §6.1, §6.5
  (final list of `Auth.Type` strings), §6.6 (final list of `Policy.Action`
  strings), §6.8 (subfolder vs flat). Everything else has a confident
  default.
- **Sub-issue mapping:**
  - RUN-295 → all `<entity>-a` PRs (Gateway-a, Backend-a, Consumer-a1+a2, Policy-a, Auth-a) — split across PRs but the same Linear sub-issue.
  - RUN-296 → same PRs (domain repo iface lives with the aggregate in `<entity>-a`; pgx impl lives with the migration in the same PR; this collapses RUN-295 and RUN-296 into the `-a` PRs because they're inseparable in practice).
  - RUN-297 → all `<entity>-b` PRs.
  - RUN-298 → all `<entity>-c` PRs.
  - RUN-299 → **explicitly deferred**; no PR in B.2.
