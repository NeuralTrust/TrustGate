# Dependency Injection Specification (delta)

## Purpose

Extend the B.0 DI graph to expose B.2 aggregates end-to-end on the
admin server. This is a **delta** spec — it adds providers to existing
`pkg/container/modules/{gateway,backend,consumer,policy,auth}.go`
files (today they are empty placeholders) and to
`pkg/container/modules/api.go`.

## Requirements

### Requirement: Entity Module Provides Full Stack

Each entity module (`Gateway`, `Backend`, `Consumer`, `Policy`, `Auth`)
MUST provide, in this order of resolution:

1. The pgx repository struct (`*infra/repository/<entity>.Repository`).
2. The domain repository interface (`domain.<entity>.Repository`) bound
   to the pgx repository.
3. The four app-service use cases (`Creator`, `Updater`, `Deleter`,
   `Finder`) bound via their `New<UseCase>` constructors.
4. The five admin handlers (Create, Get, List, Update, Delete) bound
   via their `New<Action><Entity>Handler` constructors.

#### Scenario: Entity module is resolvable

- GIVEN a freshly built container with `modules.All()` registered
- WHEN `c.Invoke(func(h *http.CreateGatewayHandler) {})` is called
- THEN the container resolves the handler with all transitive
  dependencies (repository, app service)

#### Scenario: Module dependency is missing

- GIVEN a container built without `modules.Database` (no pgx pool)
- WHEN the gateway module's `Repository` constructor is resolved
- THEN dig returns an unresolved-dependency error at `Invoke` time

### Requirement: Domain Interface Binding

The domain repository interface MUST be provided as a separate dig
binding so that consumers (app services) depend on the interface, not
the concrete struct.

#### Scenario: App service resolves through the interface

- GIVEN the gateway module registers both the concrete pgx repository
  and the domain interface binding
- WHEN `Creator` is resolved
- THEN it receives a `domain.gateway.Repository` typed value, not the
  concrete `*infra/repository/gateway.Repository`

### Requirement: Admin Transport Composition

`pkg/container/modules/api.go` MUST register all 25 new CRUD handlers
as dig providers. `pkg/container/modules/server_admin.go` MUST consume
them via the admin `*Middlewares` / `*RouterParams` struct so they
appear in the admin Fiber app's route table.

#### Scenario: Admin server boot

- GIVEN the binary is invoked as `./agentgateway admin`
- WHEN the container resolves the admin transport
- THEN every `/v1/<entity>` route is bound to a real handler
- AND the proxy transport does NOT register any of them

### Requirement: Proxy Transport Untouched

The proxy transport composition (`pkg/container/modules/server_proxy.go`,
`pkg/server/router/proxy_router.go`) MUST NOT change in B.2.

#### Scenario: Proxy module diff is empty

- GIVEN the B.2 PR set
- WHEN `git diff` is inspected for `server_proxy.go` and
  `proxy_router.go`
- THEN the diff is empty

### Requirement: Test Overrides Still Work

`container.WithOverride` (which maps to `dig.Decorate`) MUST be usable
for test doubles of the new providers. A test for an admin handler
MUST be able to wrap the use-case provider with a mockery-generated
mock.

#### Scenario: Override the Creator with a mock

- GIVEN a test container with the gateway module registered
- WHEN `container.WithOverride(func(c appgateway.Creator) appgateway.Creator { return &mocks.Creator{} })` is applied
- AND `c.Invoke(func(h *http.CreateGatewayHandler) {})` runs
- THEN the handler receives the mock, not the real Creator

### Requirement: No Cache Wiring in B.2

The entity modules MUST NOT provide or consume a `cache.Client` in B.2.
Adding the cache decorator is RUN-299's responsibility (deferred).

#### Scenario: Module import audit

- GIVEN the entity modules in `pkg/container/modules/`
- WHEN imports are inspected
- THEN no import references `pkg/infra/cache`

### Requirement: Module Ordering Independence

The order in which entity modules are registered in `modules.All()`
MUST NOT affect resolution. Dig resolves on demand; cyclic registration
is forbidden by construction.

#### Scenario: Shuffling registration order

- GIVEN two test runs of the container
- WHEN run A registers `Gateway, Backend, Consumer, Policy, Auth`
- AND run B registers `Auth, Policy, Consumer, Backend, Gateway`
- THEN both resolve every admin handler identically
