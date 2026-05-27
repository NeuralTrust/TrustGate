# AgentGateway — Agent guide

This document is the canonical orientation for any AI agent (or new
contributor) opening this repository. Read it before changing code.

The workspace-level rules (`/home/edu/.cursor/rules/*.mdc`) still apply.
Where this file disagrees with a workspace rule, the workspace rule wins —
but this file captures the AgentGateway-specific conventions on top.

## 1. What this repository is

AgentGateway is the **data-plane runtime** of NeuralTrust TrustGate
("Agent Runtime"). It sits between LLM/agent clients and upstream model
providers and enforces policies declared in the control plane.

Two HTTP servers, one binary:

| Server | Default port | Purpose |
|---|---|---|
| **admin** | `:8080` | Control-plane API for gateway / route / service / policy CRUD. |
| **proxy** | `:8081` | Data-plane traffic forwarder: inspects request/response, applies policies, calls the upstream LLM. |

Each server is meant to run in its **own pod / container** in production
(`./agentgateway admin` vs `./agentgateway proxy`). They share the same
DI graph and configuration but compose different middleware chains.

## 2. Boot sequence

```
godotenv.Load              # silent if .env missing
container.New(modules.All())  # build the dig graph
c.Invoke(runMigrations)    # always — 30s timeout
c.Invoke(runAdmin | runProxy) # one server, picked from argv[1]
<-SIGINT/SIGTERM
srv.Shutdown()
```

- `argv[1]` is `admin`, `proxy`, or absent (defaults to `proxy`, like
  TrustGate).
- Boot failures before the server starts exit via `log.Fatalf` (stdlib
  log); failures inside the server goroutine log via `slog` and
  `os.Exit(1)`.
- Migrations are in-code Go files under `pkg/infra/database/migrations/`
  that register themselves via `init()` against
  `database.RegisterMigration`. They run on every boot. There is no
  separate `run-migrations` subcommand.

## 3. Repository layout

Hexagonal-ish layout. The rule of thumb:

| Directory | Owns | Imports |
|---|---|---|
| `cmd/agentgateway/` | Binary entry point. Just composition. | `container`, `modules`, `database`, `server` |
| `pkg/version/` | Build info injected via `-ldflags`. | stdlib only |
| `pkg/common/errors/` | Cross-package sentinel errors (`ErrNotFound`, `ErrInvalidConfig`, `ErrBoot`). | stdlib only |
| `pkg/config/` | Env-only config loader (`LoadConfig`). | stdlib + `errors` |
| `pkg/infra/logger/` | `log/slog` with `MultiHandler`, `AsyncHandler`, `SourceFilterHandler`, `ColoredHandler`. | stdlib only |
| `pkg/infra/database/` | `pgx/v5` pool, `WithTx` helper, in-code migrations registry + runner. | `config`, `common/errors`, `pgx/v5` |
| `pkg/api/handler/http/` | Per-route HTTP handlers (e.g. `HealthHandler`, `VersionHandler`). | `version`, `fiber` |
| `pkg/api/handler/websocket/` | Per-route WS handlers (B.x). | `fiber` |
| `pkg/api/middleware/` | Cross-cutting middleware (request id, panic recover, access log, CORS, security headers, …). Each one implements the `Middleware` interface. | `config`, `fiber`, `slog` |
| `pkg/server/` | `Server` interface, `BaseServer` (Fiber tuning), `httpServer` impl. | `config`, `server/router`, `fiber` |
| `pkg/server/router/` | `ServerRouter` contract + `AdminRouter` / `ProxyRouter`. | `api/handler/http`, `api/middleware`, `fiber` |
| `pkg/container/` | `dig` wrapper (`Container`, `Module`, `WithModule`, `WithOverride`). | `dig` |
| `pkg/container/modules/` | One file per DI context — `core`, `api`, `cache`, `telemetry`, `auth`, `policy`, `plugins`, `gateway`, `backend`, `consumer`, `server_admin`, `server_proxy`. | their respective collaborators |
| `pkg/domain/` | Aggregate roots (B.x). | only stdlib + `common/*` |
| `pkg/app/` | Use cases / application services (B.x). | `domain`, `common/*`, repository interfaces |

### Dependency direction (must hold)

```
cmd → container → modules → {api, server, infra/*, app, domain}
api → {middleware, handler/http, handler/websocket}
server/router → {api/handler/*, api/middleware, server}
infra/* may import config + common/errors only
domain imports stdlib only (no infra, no fiber, no pgx)
app may import domain + repository interfaces (no concrete infra)
```

A `pkg/app/...` file importing `github.com/jackc/pgx` or `fiber` is a bug.

## 4. Dependency injection

We use `uber/dig` via the thin `pkg/container` wrapper:

```go
c, _ := container.New(modules.All()...)
c.Invoke(func(svc someInterface) { … })
```

Conventions:

1. **One file per context** under `pkg/container/modules/`. The file exports
   a single `Module` function (`func Core(c *container.Container) error`).
2. The `modules.All()` order is meaningful only for module that **decorates**
   an upstream provider. Otherwise dig resolves on demand.
3. **Named providers** for things that exist in multiple flavours
   (admin/proxy server, admin/proxy router, admin/proxy transport). Use
   `dig.Name("admin")` / `dig.Name("proxy")` and consume with
   ` `name:"admin"` ` field tags on `dig.In` structs.
4. **Per-server middleware composition**: `api.go` registers each
   middleware as its own singleton; `server_admin.go` and `server_proxy.go`
   each declare a `*Middlewares` struct (`dig.In`) listing the middleware
   they consume and a `*Transport` composer registered under the right
   `dig.Name`. To add a middleware to one server only, edit only that
   server's module — never put back a shared `*Transport` in `api.go`.
5. **Test overrides** use `container.WithOverride(decorator)` which maps
   to `dig.Decorate`. Wrap a producer of `T` with a function `func(orig T)
   T` returning the test double.

## 5. HTTP middleware

Implement `middleware.Middleware`:

```go
type Middleware interface { Middleware() fiber.Handler }
```

- Each middleware lives in its own file under `pkg/api/middleware/`.
- Constructors are named `New<Name>Middleware(...)` and take their
  dependencies positionally (logger, config, …) so dig can resolve them.
- The Fiber handler must call `c.Next()` exactly once (or short-circuit
  with a status code).
- Slog attrs: use **named attrs** (`slog.String("path", c.Path())`), never
  string formatting. The fields go straight into Cloud Logging / downstream
  Kafka consumers.
- Do not import `fiber` outside of `pkg/api/middleware`, `pkg/api/handler/*`,
  `pkg/server/*`. Use the `Middleware` interface upstream.

## 6. Configuration

- All configuration is **environment variables** loaded by
  `pkg/config/LoadConfig`. No YAML / TOML / JSON config files.
- In dev a `.env` file is loaded by `godotenv` at the very top of `main`.
  Production injects vars directly (Helm values, ECS task def, k8s
  ConfigMap + Secret).
- Defaults live in `config.go` (`default<Section><Field>` constants).
- Required fields are checked in `Config.Validate()`. The validator runs
  inside `LoadConfig` before the `*Config` is published to the container.
- Adding a new env var:
  1. Add the `default<...>` const block.
  2. Add the field to the right `<Section>Config` struct.
  3. Parse it in the `get<Section>Config()` getter.
  4. If required, extend `Validate()`.
  5. Document it in `.env.example`.

## 7. Database & migrations

- `pgx/v5` + `pgxpool`. The `*pgxpool.Pool` is wrapped in `database.Connection`.
- The pool is created with a **ping fail-fast** in `NewConnection` — boot
  aborts (`errors.ErrBoot`) if the DB is unreachable.
- Migrations are **in-code Go files** under
  `pkg/infra/database/migrations/`, named `<unix_timestamp>_<snake_name>.go`.
  Each file calls `database.RegisterMigration` from its `init()`. The
  runner commits each migration's DDL plus its `migration_version` row in
  a single transaction.
- For multi-statement business writes, use `database.WithTx(ctx, conn, fn)`
  rather than juggling Begin / Commit / Rollback by hand. Panics inside
  `fn` are propagated after a best-effort rollback.

## 8. Logging

- `log/slog` via the handler stack in `pkg/infra/logger/`. The DI graph
  resolves a `*slog.Logger` everywhere; do **not** call `slog.SetDefault`
  inside business code (only `modules.Core` does it, once).
- Log level + format come from env (`LOG_LEVEL`, `LOG_FORMAT`).
- Use **named attrs** (`slog.String("user_id", id)`), never `fmt.Sprintf`
  into the message.
- Before the logger exists (the first three lines of `main`), use stdlib
  `log.Fatalf`. After the logger exists, use `slog.Error(...) ; os.Exit(1)`.

## 9. Testing conventions

- `go test -race ./...` is the contract. Don't add platform-specific
  tests.
- Tests live next to the code they cover. No `tests/` mega-directory.
- Prefer behaviour assertions over internal-state inspection. If the test
  has to reach into unexported fields, the design is probably wrong.
- For DI-heavy tests, build a minimal container with `container.New` +
  `WithModule` + `WithOverride`. Don't import `modules.All()` — pull in
  only the modules you need.
- DB-touching tests are deferred to B.1 (they will gate on a
  `PG_TEST_URL` env var so CI can skip them on a missing socket).

## 10. Where do I put …

| New code | Goes in | Notes |
|---|---|---|
| A new HTTP endpoint for admin only | `pkg/api/handler/http/<name>_handler.go` + wire in `pkg/server/router/admin_router.go` | Add the handler as a provider in `modules.API`, add the field to `adminRouterParams`. |
| A new HTTP endpoint shared by admin + proxy | Same as above, wire in both routers. | Health probes already do this — copy that pattern. |
| A new cross-cutting middleware | `pkg/api/middleware/<name>.go` (implements `Middleware`) | Provide in `modules.API`, add the field to the relevant `*Middlewares` struct(s) + composer(s). |
| A new aggregate root | `pkg/domain/<context>/` | Pure Go. No `pgx`, no `fiber`, no logging. Define repository interfaces in this package. |
| A new use case | `pkg/app/<context>/` | Consumes domain + repository interfaces. Stays infra-free. |
| A repository implementation | `pkg/infra/repository/<context>/` (B.x) | Implements an interface from `pkg/domain/<context>`. Uses `database.WithTx` for atomic writes. |
| A DB migration | `pkg/infra/database/migrations/<unix_ts>_<name>.go` | Registers in `init()`. Idempotent up + down inside one tx. |
| A new env var | `pkg/config/config.go` (default + struct field + getter) + `.env.example` | If required, extend `Validate()`. |
| A new module | `pkg/container/modules/<name>.go` | Add to `modules.All()` if it's part of the canonical boot. |

## 11. Commits, PRs, branches

- Conventional Commits per `_base.mdc`. Examples:
  - `feat(server): admin and proxy server adapters`
  - `fix(config): parse CORS_MAX_AGE as string, not duration`
  - `test(container): assert WithOverride decorates providers`
- One PR per shippable slice; the team budget is **400 changed lines**.
  See `_base.mdc` "PR review budget" and `chained-pr` skill if you need to
  split.
- The Linear issue id (`RUN-###`) goes in the PR body. The implementation
  branch comes from `gitBranchName` on the Linear issue.

## 12. References

- Platform shape: `/home/edu/.cursor/rules/neuraltrust-platform.mdc`
- Domain glossary: `/home/edu/.cursor/rules/neuraltrust-domain.mdc`
- Work gates: `/home/edu/.cursor/rules/work-gates.mdc`
- Reference repositories (read-only mirrors for boot patterns):
  - `AgentGuardian/cmd/api/main.go` — flat-main + dig + migrations boot.
  - `AgentGuardian/internal/infra/database/` — pgx connection + in-code migrations.
  - `AgentGuardian/internal/infra/logging/logger.go` — slog handler stack.
  - `TrustGate/cmd/gateway/main.go` — `argv[1]` server selection.
  - `TrustGate/pkg/server/middleware/cors_global.go` — CORS shape we mirror.
