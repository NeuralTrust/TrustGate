---
name: trustgate-hexagonal
description: >
  Hexagonal architecture patterns for TrustGate in Go.
  Trigger: When writing Go code for TrustGate, creating handlers, app services, domain entities, repositories, or refactoring layers.
license: Apache-2.0
metadata:
  author: gentleman-programming
  version: "1.0"
---

## When to Use

- Adding a new bounded context (entity + repository + app service + handler)
- Creating or modifying HTTP handlers in `pkg/handlers/http/`
- Writing app-layer use cases in `pkg/app/`
- Defining domain entities, value objects, or repository ports in `pkg/domain/`
- Implementing repository adapters in `pkg/infra/repository/`
- Wiring dependencies in `pkg/dependency_container/`

## Layer Architecture

```
pkg/
├── handlers/http/         # Driving adapters (HTTP)
│   └── request/           # Request DTOs with Validate()
├── app/                   # Application services (use cases)
│   └── {context}/         # Creator, Updater, Finder, Deleter
├── domain/                # Entities, value objects, repository ports, domain errors
│   └── {context}/         # Entity, Repository interface, builder
├── infra/                 # Driven adapters
│   └── repository/        # Repository implementations (GORM, Redis)
└── dependency_container/  # Composition root (wiring)
```

### Dependency Direction

```
handlers → app → domain ← infra
```

- `handlers` imports `app` (interfaces) and `request` (DTOs)
- `app` imports `domain` (entities, repository ports) and `request` (DTOs)
- `domain` imports nothing from other layers
- `infra` imports `domain` (implements ports)
- `dependency_container` imports everything (composition root)

## Layer Rules

| Layer           | Responsibility                                                                                   | Must NOT                                                                           |
|-----------------|--------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|
| **Handler**     | Parse request, validate DTO, call app service, map domain errors to HTTP status                  | Contain business logic, access repositories directly, build domain entities        |
| **App service** | Orchestrate use case: check preconditions, call domain factories, persist via repos, emit events | Parse HTTP requests, return HTTP status codes, own validation that belongs to DTOs |
| **Domain**      | Define entities, value objects, factory functions (`New`), repository interfaces, domain errors  | Import from `app`, `handlers`, or `infra`; depend on frameworks                    |
| **Infra**       | Implement repository interfaces, external service clients                                        | Contain business logic, define domain types                                        |

## Critical Patterns

### 1. Handler — Thin, Validate, Delegate

Handlers only: parse input, validate the request DTO, call the app service, map errors.

```go
package http

type createThingHandler struct {
    logger  *logrus.Logger
    creator appThing.Creator
}

func NewCreateThingHandler(logger *logrus.Logger, creator appThing.Creator) Handler {
    return &createThingHandler{logger: logger, creator: creator}
}

func (h *createThingHandler) Handle(c *fiber.Ctx) error {
    gatewayID, err := uuid.Parse(c.Params("gateway_id"))
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid gateway ID"})
    }

    var req request.CreateThingRequest
    if err := c.BodyParser(&req); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid JSON payload"})
    }

    if err := req.Validate(); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
    }

    thing, err := h.creator.Create(c.Context(), gatewayID, &req)
    if err != nil {
        return h.handleError(c, err)
    }

    return c.Status(fiber.StatusCreated).JSON(thing)
}

func (h *createThingHandler) handleError(c *fiber.Ctx, err error) error {
    if errors.Is(err, domain.ErrGatewayNotFound) {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Gateway not found"})
    }
    if errors.Is(err, domain.ErrValidation) {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
    }
    h.logger.WithError(err).Error("failed to create thing")
    return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
}
```

### 2. Request DTO — Owns Input Validation

Request DTOs live in `pkg/handlers/http/request/`. Each DTO implements `Validate() error` for syntactic/structural checks.

```go
package request

type CreateThingRequest struct {
    Name    string   `json:"name"`
    Type    string   `json:"type"`
    Methods []string `json:"methods"`
}

func (r *CreateThingRequest) Validate() error {
    if r.Name == "" {
        return fmt.Errorf("name is required")
    }
    if r.Type == "" {
        return fmt.Errorf("type is required")
    }
    if err := validateHTTPMethods(r.Methods); err != nil {
        return err
    }
    return nil
}
```

Shared validation helpers go in `pkg/handlers/http/request/validators.go`.

### 3. App Service — Interface + Unexported Impl

Each use case is a **small, focused interface** with an unexported struct implementing it. Constructor returns the interface.

```go
package thing

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=creator_mock.go --case=underscore --with-expecter
type Creator interface {
    Create(ctx context.Context, gatewayID uuid.UUID, req *request.CreateThingRequest) (*thing.Thing, error)
}

type creator struct {
    logger      *logrus.Logger
    repo        thing.Repository
    gatewayRepo gateway.Repository
    cache       cache.Client
}

func NewCreator(
    logger *logrus.Logger,
    repo thing.Repository,
    gatewayRepo gateway.Repository,
    cache cache.Client,
) Creator {
    return &creator{
        logger:      logger,
        repo:        repo,
        gatewayRepo: gatewayRepo,
        cache:       cache,
    }
}

func (c *creator) Create(ctx context.Context, gatewayID uuid.UUID, req *request.CreateThingRequest) (*thing.Thing, error) {
    gw, err := c.gatewayRepo.FindByID(ctx, gatewayID)
    if err != nil {
        return nil, domain.ErrGatewayNotFound
    }

    entity, err := thing.New(thing.CreateParams{
        GatewayID: gw.ID,
        Name:      req.Name,
        Type:      req.Type,
    })
    if err != nil {
        return nil, fmt.Errorf("build thing: %w", err)
    }

    if err := c.repo.Create(ctx, entity); err != nil {
        return nil, fmt.Errorf("persist thing: %w", err)
    }

    _ = c.cache.Save(ctx, entity)

    return entity, nil
}
```

**SOLID compliance:**
- **S** — One interface per use case (`Creator`, `Updater`, `Finder`, `Deleter`)
- **O** — New use cases are new files, not modifications to existing ones
- **L** — Implementations satisfy their interface contract fully
- **I** — Small interfaces, not a single "Service" with 10 methods
- **D** — App services depend on domain interfaces (repository ports), never on infra

### 4. Domain Entity — Factory + Value Objects

Entities live in `pkg/domain/{context}/`. Factory function `New(CreateParams)` encapsulates ID generation, timestamps, and defaults.

```go
package thing

type Thing struct {
    ID        uuid.UUID `json:"id" gorm:"type:uuid;primaryKey"`
    GatewayID uuid.UUID `json:"gateway_id" gorm:"type:uuid;not null"`
    Name      string    `json:"name"`
    Type      Type      `json:"type" gorm:"not null"`
    Active    bool      `json:"active" gorm:"default:true"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
}

type CreateParams struct {
    GatewayID uuid.UUID
    Name      string
    Type      Type
}

func New(params CreateParams) (*Thing, error) {
    id, err := uuid.NewV7()
    if err != nil {
        return nil, fmt.Errorf("generate UUID: %w", err)
    }

    now := time.Now()
    t := params.Type
    if t == "" {
        t = DefaultType
    }

    return &Thing{
        ID:        id,
        GatewayID: params.GatewayID,
        Name:      params.Name,
        Type:      t,
        Active:    true,
        CreatedAt: now,
        UpdatedAt: now,
    }, nil
}
```

### 5. Repository Port — Interface in Domain

Repository interfaces live in `pkg/domain/{context}/repository.go`. Always include the `go:generate` mockery directive.

```go
package thing

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=thing_repository_mock.go --case=underscore --with-expecter
type Repository interface {
    Create(ctx context.Context, thing *Thing) error
    FindByID(ctx context.Context, id uuid.UUID) (*Thing, error)
    FindByGateway(ctx context.Context, gatewayID uuid.UUID, offset, limit int) ([]Thing, error)
    Update(ctx context.Context, thing *Thing) error
    Delete(ctx context.Context, id uuid.UUID) error
}
```

**Naming rules for repository methods:**
- Use short, intent-based names: `Create`, `Update`, `Delete`
- Use `FindByX` for queries: `FindByID`, `FindByGateway`, `FindByName`
- Use `FindByCriteria` for complex queries, NOT `FindThingsByGatewayIDAndStatusAndTypeSortedByCreatedAt`
- Avoid repeating the entity name: `Create` not `CreateThing` (the package already scopes it)

### 6. Repository Adapter — Infra Implementation

Implementations live in `pkg/infra/repository/`. Constructor returns the **domain interface type**.

```go
package repository

type thingRepository struct {
    db *gorm.DB
}

func NewThingRepository(db *gorm.DB) thing.Repository {
    return &thingRepository{db: db}
}

func (r *thingRepository) Create(ctx context.Context, t *thing.Thing) error {
    return r.db.WithContext(ctx).Create(t).Error
}

func (r *thingRepository) FindByID(ctx context.Context, id uuid.UUID) (*thing.Thing, error) {
    var t thing.Thing
    if err := r.db.WithContext(ctx).Where("id = ?", id).First(&t).Error; err != nil {
        if errors.Is(err, gorm.ErrRecordNotFound) {
            return nil, domain.NewNotFoundError("thing", id.String())
        }
        return nil, err
    }
    return &t, nil
}
```

### 7. Domain Errors

Sentinel errors in `pkg/domain/errors.go`. Handlers use `errors.Is` to map to HTTP status.

```go
package domain

var (
    ErrGatewayNotFound  = errors.New("gateway not found")
    ErrServiceNotFound  = errors.New("service not found")
    ErrUpstreamNotFound = errors.New("upstream not found")
    ErrValidation       = errors.New("validation error")
    ErrAlreadyExists    = errors.New("entity already exists")
)
```

### 8. Wiring in Composition Root

All dependency wiring happens in `pkg/dependency_container/container.go`. Follow the order: infra → repositories → app services → handlers.

```go
thingRepo := repository.NewThingRepository(di.DB.DB)

thingCreator := appThing.NewCreator(
    di.Logger,
    thingRepo,
    gatewayRepo,
    cacheInstance,
)

handlerTransport.CreateThingHandler = handlers.NewCreateThingHandler(
    di.Logger,
    thingCreator,
)
```

## Mockery Directive Format

Every interface that needs mocking **must** have this directive directly above:

```go
//go:generate mockery --name=InterfaceName --dir=. --output=./mocks --filename=snake_case_mock.go --case=underscore --with-expecter
```

| Flag              | Value                |
|-------------------|----------------------|
| `--name`          | Exact interface name |
| `--dir`           | `.` (same directory) |
| `--output`        | `./mocks`            |
| `--filename`      | `snake_case_mock.go` |
| `--case`          | `underscore`         |
| `--with-expecter` | Always include       |

## Checklist: Adding a New Bounded Context

1. **Domain** (`pkg/domain/{context}/`)
    - [ ] Entity struct in `{context}.go`
    - [ ] `CreateParams` + `New()` factory in `builder.go`
    - [ ] `Repository` interface in `repository.go` with `go:generate` directive
    - [ ] Domain errors if needed in `pkg/domain/errors.go`

2. **Infra** (`pkg/infra/repository/`)
    - [ ] Repository implementation returning domain interface from constructor
    - [ ] `gorm.ErrRecordNotFound` → `domain.NewNotFoundError` mapping

3. **App** (`pkg/app/{context}/`)
    - [ ] `Creator` interface + `NewCreator` constructor in `creator.go`
    - [ ] `Updater` interface + `NewUpdater` constructor in `updater.go`
    - [ ] `Finder` / `Deleter` as needed
    - [ ] All interfaces have `go:generate` mockery directive
    - [ ] Uses domain `New()` factory, never builds entities with struct literals

4. **Request DTOs** (`pkg/handlers/http/request/`)
    - [ ] Request struct with `json` tags
    - [ ] `Validate() error` method

5. **Handler** (`pkg/handlers/http/`)
    - [ ] Handler struct depends on app interface, not concrete type
    - [ ] `Handle`: BodyParser → `req.Validate()` → app service → error mapping
    - [ ] Register in `HandlerTransportDTO`

6. **Wiring** (`pkg/dependency_container/container.go`)
    - [ ] Instantiate repo, app service, handler
    - [ ] Assign to `Container` struct fields

7. **Generate mocks**
    - [ ] Run `go generate ./pkg/domain/{context}/...`
    - [ ] Run `go generate ./pkg/app/{context}/...`

## Anti-Patterns

| Do NOT                                                | Do Instead                                           |
|-------------------------------------------------------|------------------------------------------------------|
| Business logic in handlers                            | Move to app service                                  |
| Repository calls in handlers                          | Call app service, which calls repo                   |
| Building entities with struct literals in app layer   | Use domain `New(CreateParams)` factory               |
| One giant `Service` interface with 15 methods         | Split into `Creator`, `Updater`, `Finder`, `Deleter` |
| `GetAllThingsByGatewayIDWithPagination` on repo       | `FindByGateway(ctx, gatewayID, offset, limit)`       |
| Validation logic in app service that belongs to input | Put syntactic validation in `request.Validate()`     |
| Domain importing from `app` or `handlers`             | Domain has zero upward dependencies                  |
| Returning HTTP status from app service                | Return domain errors, handler maps them              |
| Skipping `go:generate` on new interfaces              | Always add the mockery directive                     |
| Concrete types in app service struct fields           | Use interfaces for all dependencies                  |

## Commands

```bash
# Generate mocks after adding/changing interfaces
go generate ./pkg/domain/...
go generate ./pkg/app/...

# Run tests
go test ./...

# Run tests with race detector
go test -race ./...

# Verify build
go build ./...
```
