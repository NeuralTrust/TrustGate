# Domain Model Specification

## Purpose

Define the AgentGateway control-plane aggregates and their relationships:
`Gateway`, `Backend(LLM|A2A|MCP)`, `Consumer`, `Policy`, `Auth`, plus the
three many-to-many association sets owned by `Consumer`.

## Requirements

### Requirement: Aggregate Identity

Every aggregate MUST be identified by a UUID v4 generated at the
application layer (not the database). The ID MUST be set at construction
time and never mutated.

#### Scenario: New aggregate is constructed

- GIVEN a constructor call with valid inputs
- WHEN the aggregate is created
- THEN it has a non-zero UUID v4 ID
- AND `CreatedAt` and `UpdatedAt` are set to the current timestamp

#### Scenario: ID mutation is rejected

- GIVEN an existing aggregate with an assigned ID
- WHEN any code attempts to overwrite the ID
- THEN the operation is structurally impossible (no setter is exposed)

### Requirement: Infra Independence

Domain packages MUST NOT import infrastructure code (`pgx`, `fiber`,
`redis`, `kafka`, `slog` handlers, HTTP DTOs). They MAY import stdlib,
`github.com/google/uuid`, `encoding/json`, and `pkg/common/*`.

#### Scenario: Static import check

- GIVEN the domain packages
- WHEN imports are inspected
- THEN no import path points into `pkg/infra/`, `pkg/api/`,
  `pkg/server/`, or `pkg/container/`

### Requirement: Backend Polymorphism

The `Backend` aggregate MUST carry a `Type` discriminator drawn from a
finite enum (`llm`, `a2a`, `mcp`) and a `Config` payload whose shape is
opaque to the domain layer.

#### Scenario: Constructing a Backend with a known type

- GIVEN `Type = llm` and a non-nil `Config`
- WHEN the aggregate is constructed
- THEN it is returned without error

#### Scenario: Constructing a Backend with an unknown type

- GIVEN `Type` outside `{llm, a2a, mcp}`
- WHEN the aggregate is constructed
- THEN construction returns `ErrInvalidType`

### Requirement: Consumer Owns Associations

The `Consumer` aggregate MUST expose `AttachBackend`, `DetachBackend`,
`AttachPolicy`, `DetachPolicy`, `AttachAuth`, `DetachAuth` and MUST
guarantee per-set idempotence (attaching the same ID twice is a no-op,
detaching an absent ID is a no-op).

#### Scenario: Attaching a new backend

- GIVEN a Consumer with backends `{A, B}`
- WHEN `AttachBackend(C)` is called
- THEN the Consumer's backend set is `{A, B, C}`

#### Scenario: Attaching an existing backend is idempotent

- GIVEN a Consumer with backends `{A, B}`
- WHEN `AttachBackend(A)` is called
- THEN the Consumer's backend set is still `{A, B}`

#### Scenario: Detaching an absent backend is a no-op

- GIVEN a Consumer with backends `{A, B}`
- WHEN `DetachBackend(Z)` is called
- THEN the Consumer's backend set is still `{A, B}`

### Requirement: Policy Action Enum

`Policy.Action` MUST be one of `allow`, `log`, `mask`, `block`. Any
other value MUST be rejected at construction time.

#### Scenario: Constructing a Policy with a valid action

- GIVEN `Action = block`
- WHEN the Policy is constructed
- THEN it is returned without error

#### Scenario: Constructing a Policy with an invalid action

- GIVEN `Action = deny`
- WHEN the Policy is constructed
- THEN construction returns `ErrInvalidAction`

### Requirement: Gateway / Backend Hierarchy

Each `Backend` MUST carry a non-zero `GatewayID`. The domain layer does
not enforce referential integrity (that is the database's responsibility),
but it MUST reject construction when `GatewayID == uuid.Nil`.

#### Scenario: Constructing a Backend without a Gateway

- GIVEN `GatewayID = uuid.Nil`
- WHEN the Backend is constructed
- THEN construction returns `ErrInvalidGatewayID`

### Requirement: Sentinel Errors

Each domain package MUST expose `ErrNotFound`, `ErrAlreadyExists`, and
at least one `ErrInvalid<Field>` sentinel. Repository implementations
return these via `errors.Is`-friendly wrapping.

#### Scenario: Repository returns ErrNotFound

- GIVEN a `FindByID` call for an ID that is not in the database
- WHEN the repository executes the query
- THEN it returns an error such that `errors.Is(err, ErrNotFound) == true`
