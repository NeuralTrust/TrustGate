# App Services Specification

## Purpose

Define the application use cases per entity (`Creator`, `Updater`,
`Deleter`, `Finder`) that mediate between admin HTTP handlers and the
domain layer. Each use case is one file in `pkg/app/<entity>/<usecase>.go`
with the interface, its implementation, and a `//go:generate mockery`
directive, per `.agents/AGENT.md` §10.2.

## Requirements

### Requirement: One Use Case Per File

Each use case (Creator, Updater, Deleter, Finder) MUST live in its own
file alongside the others in `pkg/app/<entity>/`. A file MUST contain
exactly one exported interface, exactly one matching unexported struct
implementation, exactly one constructor, and exactly one
`//go:generate mockery` directive for that interface.

#### Scenario: Audit of an entity package

- GIVEN the `pkg/app/gateway/` directory
- WHEN files are inspected
- THEN it contains `creator.go`, `updater.go`, `deleter.go`,
  `finder.go`, each with one interface + impl + mockery directive
- AND no `<entity>_contracts.go` or similar multi-interface file
  exists

### Requirement: Mockery Generation Wired

Each use-case interface MUST have a `//go:generate mockery` directive
producing a mock in `pkg/app/<entity>/mocks/`. Running `go generate
./...` MUST produce up-to-date mocks for every use-case interface.

#### Scenario: Mocks are regenerated

- GIVEN any change to a use-case interface signature
- WHEN `go generate ./...` runs
- THEN the corresponding file in `mocks/` is updated
- AND `git diff` shows the regeneration

#### Scenario: Hand-written mock is rejected

- GIVEN a hypothetical hand-written mock file
- WHEN code review or CI inspects the file
- THEN it is treated as a violation of AGENT.md §10.5

### Requirement: Creator Contract

`Creator.Create(ctx, req)` MUST:

1. Validate the request (via `req.Validate()`).
2. Construct the domain aggregate (which itself enforces domain
   invariants).
3. Persist via `domain.Repository.Save`.
4. Return the persisted aggregate or a domain error.

The Creator MUST NOT touch HTTP types directly beyond the request DTO
input.

#### Scenario: Creating a Gateway happily

- GIVEN a valid `CreateGatewayRequest`
- WHEN `Creator.Create` runs
- THEN `Repository.Save` is called exactly once with the constructed
  aggregate
- AND the returned aggregate has a non-zero ID and timestamps

#### Scenario: Validation failure short-circuits

- GIVEN an invalid request (e.g., empty `name`)
- WHEN `Creator.Create` runs
- THEN `Repository.Save` is NOT called
- AND the returned error wraps the validation error

### Requirement: Updater Contract

`Updater.Update(ctx, id, req)` MUST:

1. Load the existing aggregate via `Repository.FindByID(id)`; return
   `ErrNotFound` if absent.
2. Apply the request's fields to the aggregate (selective; only
   provided fields).
3. Persist via `Repository.Update`.

For `Consumer`, the updater MUST also diff the three association sets
and the repository MUST persist all four changes (entity + 3 joins)
inside one `database.WithTx`.

#### Scenario: Updating a missing aggregate

- GIVEN an `UpdateGatewayRequest` with an unknown ID
- WHEN `Updater.Update` runs
- THEN it returns an error satisfying `errors.Is(err, ErrNotFound)`
- AND no write reaches the repository

#### Scenario: Updating a Consumer's backends

- GIVEN a Consumer with backends `{A, B}` and an update request with
  backends `{A, C}`
- WHEN `Updater.Update` runs
- THEN `Repository.Update` is called with the updated Consumer
- AND the persisted Consumer has backends `{A, C}` after commit

### Requirement: Deleter Contract

`Deleter.Delete(ctx, id)` MUST be idempotent in the sense that deleting
a non-existent ID returns `ErrNotFound`, not silent success.

#### Scenario: Deleting an existing aggregate

- GIVEN a persisted Gateway and its ID
- WHEN `Deleter.Delete` runs
- THEN the aggregate is removed from the database
- AND the call returns nil

#### Scenario: Deleting a missing aggregate

- GIVEN an ID that is not present
- WHEN `Deleter.Delete` runs
- THEN it returns an error satisfying `errors.Is(err, ErrNotFound)`

#### Scenario: Deleting a Gateway with backends

- GIVEN a Gateway with at least one Backend referencing it
- WHEN `Deleter.Delete` runs
- THEN it returns an error satisfying
  `errors.Is(err, ErrHasDependents)`
- AND nothing is removed

### Requirement: Finder Contract

`Finder.FindByID(ctx, id)` MUST return either the aggregate or
`ErrNotFound`. `Finder.List(ctx, req)` MUST return
`(items, total, err)` honouring the page/size/name-filter contract.

#### Scenario: Finding a present aggregate

- GIVEN a persisted Gateway
- WHEN `Finder.FindByID` runs with its ID
- THEN the aggregate is returned

#### Scenario: Listing returns total independent of page

- GIVEN 25 persisted Gateways and a request with `Page = 2, Size = 10`
- WHEN `Finder.List` runs
- THEN at most 10 items are returned
- AND `total = 25`

### Requirement: Logger Injection

Every use case MUST accept a `*slog.Logger` in its constructor and use
named attributes (not `fmt.Sprintf`) for log records.

#### Scenario: Use case logs an error

- GIVEN a use case whose `Repository` call returns an error
- WHEN the use case observes the error
- THEN it logs at `Error` level with named attrs (`slog.String("err",
  err.Error())`, entity context, ID) and propagates the error

### Requirement: No Infra Imports in App

App-service files MUST NOT import `pgx`, `fiber`, `redis`, `kafka`, or
any HTTP framework code. They MAY import domain packages, request DTOs
(`pkg/api/handler/http/request`), `log/slog`, `context`, and
`github.com/google/uuid`.

#### Scenario: Static import check

- GIVEN the `pkg/app/<entity>/` packages
- WHEN imports are inspected
- THEN no infra package (`pkg/infra/...`) is imported
- AND no `pkg/server/` or `pkg/api/handler/http/response` package is
  imported
