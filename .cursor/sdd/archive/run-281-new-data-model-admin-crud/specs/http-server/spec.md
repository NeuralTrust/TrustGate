# HTTP Server Specification (delta)

## Purpose

Extend the admin server's router (built in B.0) to expose the B.2 CRUD
routes. This is a **delta** spec — it adds routes to
`pkg/server/router/admin_router.go` and field dependencies to
`adminRouterParams`, leaving the proxy server, middlewares, and base
server tuning untouched.

## Requirements

### Requirement: Admin Router Registers Per-Entity Routes

After installing the middleware chain, the admin router MUST register
the following routes (per entity in `{gateways, backends, consumers,
policies, auths}`):

```
POST   /v1/<entity>      → Create
GET    /v1/<entity>      → List
GET    /v1/<entity>/:id  → Get
PUT    /v1/<entity>/:id  → Update
DELETE /v1/<entity>/:id  → Delete
```

The pre-existing routes (`/healthz`, `/readyz`, `/__/version`) MUST
remain reachable and ordered before the `/v1` block.

#### Scenario: All admin routes reachable

- GIVEN the admin server is running
- WHEN each of the 5×5 CRUD endpoints is hit with valid input
- THEN each handler executes and returns the expected status

#### Scenario: Health routes unaffected

- GIVEN the same admin server
- WHEN `GET /healthz` and `GET /readyz` are issued
- THEN both still respond with their B.0 semantics

### Requirement: Router Params Struct Extended

`adminRouterParams` (or the equivalent `dig.In` struct) MUST add a
field per new handler, typed as the concrete handler pointer (e.g.
`CreateGatewayHandler *http.CreateGatewayHandler`). The constructor
`NewAdminRouter` MUST accept those handlers via the params struct so
that adding a new entity is mechanically the same edit.

#### Scenario: New handler added

- GIVEN a future addition of a new entity
- WHEN its 5 handlers are declared in the params struct and registered
  in `BuildRoutes`
- THEN no other file needs to change to make the router pick them up

### Requirement: Proxy Router Untouched

`pkg/server/router/proxy_router.go` MUST NOT change in B.2.
B.4 / B.5 are responsible for the proxy router edits.

#### Scenario: Diff audit on proxy router

- GIVEN the B.2 PR set
- WHEN `git diff` is run against `pkg/server/router/proxy_router.go`
- THEN the diff is empty

### Requirement: Middleware Chain Reuse

The admin router MUST reuse the existing `middleware.Transport` chain
(request id, recover, access log, security, CORS) without adding new
middleware. Admin auth and audit middlewares are explicitly deferred to
B.7 / B.9.

#### Scenario: Middleware chain audit

- GIVEN the admin server is running
- WHEN a request traverses the chain
- THEN exactly the B.0 middlewares execute in their B.0 order, plus
  the route handler at the end

### Requirement: Path Conventions

Path segments MUST be plural, lowercase, kebab-free (single words). IDs
in path params MUST use the canonical `:id` placeholder. Query params
MUST be lowercase (`page`, `size`, `name`).

#### Scenario: Path linting

- GIVEN the registered routes
- WHEN paths are inspected
- THEN every `/v1/<entity>` is lowercase plural
- AND every ID-bearing path uses `:id`
- AND no path contains `:Id`, `:ID`, `:gatewayId`, etc.

### Requirement: No Direct Domain Imports in Router

The router file MAY import `pkg/api/handler/http` (the handlers) and
`pkg/api/middleware` (the transport) only. It MUST NOT import
`pkg/app`, `pkg/infra`, or `pkg/domain`.

#### Scenario: Static import check

- GIVEN `pkg/server/router/admin_router.go`
- WHEN imports are inspected
- THEN no `pkg/app`, `pkg/infra`, or `pkg/domain` import appears

### Requirement: Admin and Proxy Composers Stay Distinct

The admin router MUST be served by the admin Fiber app
(`./agentgateway admin`) on the admin port (`ADMIN_HTTP_PORT`). The
proxy Fiber app (`./agentgateway proxy`) MUST NOT serve any of the
new `/v1/<entity>` routes.

#### Scenario: Cross-server isolation

- GIVEN both binaries running on their respective ports
- WHEN `GET /v1/gateways` is issued to the proxy port
- THEN the response is `404 Not Found`
