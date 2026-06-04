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

| Directory                        | Owns                                                                                                                                                                                                                                 | Imports                                                                     |
|----------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| `cmd/agentgateway/`              | Binary entry point. Just composition.                                                                                                                                                                                                | `container`, `modules`, `database`, `server`                                |
| `pkg/version/`                   | Build info injected via `-ldflags`.                                                                                                                                                                                                  | stdlib only                                                                 |
| `pkg/common/errors/`             | Cross-package sentinel errors (`ErrNotFound`, `ErrInvalidConfig`, `ErrBoot`).                                                                                                                                                        | stdlib only                                                                 |
| `pkg/config/`                    | Env-only config loader (`LoadConfig`).                                                                                                                                                                                               | stdlib + `errors`                                                           |
| `pkg/infra/logger/`              | `log/slog` with `MultiHandler`, `AsyncHandler`, `SourceFilterHandler`, `ColoredHandler`.                                                                                                                                             | stdlib only                                                                 |
| `pkg/infra/database/`            | `pgx/v5` pool, `WithTx` helper, in-code migrations registry + runner.                                                                                                                                                                | `config`, `common/errors`, `pgx/v5`                                         |
| `pkg/api/handler/http/`          | Per-route HTTP handlers (e.g. `HealthHandler`, `VersionHandler`). One handler per file.                                                                                                                                              | `version`, `fiber`, `api/handler/http/request`, `api/handler/http/response` |
| `pkg/api/handler/http/request/`  | Inbound request DTOs. **One DTO per file**, named after the action (e.g. `create_gateway_request.go`).                                                                                                                               | stdlib + `domain/*` value types                                             |
| `pkg/api/handler/http/response/` | Outbound response DTOs. **One DTO per file** (e.g. `list_rules_output.go`).                                                                                                                                                          | stdlib + `domain/*` value types                                             |
| `pkg/api/handler/websocket/`     | Per-route WS handlers (B.x).                                                                                                                                                                                                         | `fiber`                                                                     |
| `pkg/api/middleware/`            | Cross-cutting middleware (request id, panic recover, access log, CORS, security headers, …). Each one implements the `Middleware` interface.                                                                                         | `config`, `fiber`, `slog`                                                   |
| `pkg/server/`                    | `Server` interface, `BaseServer` (Fiber tuning), `httpServer` impl.                                                                                                                                                                  | `config`, `server/router`, `fiber`                                          |
| `pkg/server/router/`             | `ServerRouter` contract + `AdminRouter` / `ProxyRouter`.                                                                                                                                                                             | `api/handler/http`, `api/middleware`, `fiber`                               |
| `pkg/container/`                 | `dig` wrapper (`Container`, `Module`, `WithModule`, `WithOverride`).                                                                                                                                                                 | `dig`                                                                       |
| `pkg/container/modules/`         | One file per DI context — `core`, `api`, `cache`, `telemetry`, `auth`, `policy`, `plugins`, `gateway`, `backend`, `consumer`, `server_admin`, `server_proxy`.                                                                        | their respective collaborators                                              |
| `pkg/domain/<entity>/`           | Aggregate roots, value objects, repository **interfaces**.                                                                                                                                                                           | only stdlib + `common/*`                                                    |
| `pkg/app/<entity>/`              | Use cases / application services. **One use case per file** (`finder.go`, `creator.go`, `matcher.go`, …) containing the interface + its implementation + `//go:generate mockery` directive. Mocks land in `pkg/app/<entity>/mocks/`. | `domain`, `common/*`, repository interfaces                                 |

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

## 10. App layer & DTO placement (hard rules)

These rules are **mandatory** and mirror TrustGate (`TrustGate/pkg/app/**`,
`TrustGate/pkg/handlers/http/request/`, `…/response/`). Diverging breaks the
hexagonal boundaries and the team's review expectations.

### 10.1 Never group multiple interfaces in one file

There is no such thing as a `contracts.go` / `interfaces.go` /
`<thing>_contracts.go` aggregating several interfaces. Each interface lives
in **its own file**, next to its implementation when it has one. If you
catch yourself writing two `type … interface { … }` declarations in the same
file, stop.

### 10.2 Use cases live in `pkg/app/<entity>/<usecase>.go`

One file per use case, named after the verb / responsibility — `finder.go`,
`creator.go`, `updater.go`, `deleter.go`, `matcher.go`, `validator.go`, …
Inside that file, in this order:

1. Package-level sentinel errors (`var ErrInvalidCacheType = errors.New(...)`).
2. The `//go:generate mockery` directive for the interface.
3. The interface (exported, named after the responsibility — `Finder`,
   `Matcher`, `Creator`).
4. The unexported struct implementation and its dependencies.
5. The `New<Iface>` constructor returning the interface.
6. The methods.

Canonical shape (copy this, change the names):

```go
package upstream

//go:generate mockery --name=Finder --dir=. --output=./mocks --filename=upstream_finder_mock.go --case=underscore --with-expecter
type Finder interface {
    Find(ctx context.Context, gatewayID, upstreamID uuid.UUID) (*domain.Upstream, error)
}

type finder struct {
    repo   domain.Repository
    cache  cache.Client
    logger *slog.Logger
}

func NewFinder(repo domain.Repository, c cache.Client, l *slog.Logger) Finder {
    return &finder{repo: repo, cache: c, logger: l}
}

func (f *finder) Find(ctx context.Context, gatewayID, upstreamID uuid.UUID) (*domain.Upstream, error) {
    // …
}
```

Notes:

- Mocks **must** be generated by `go generate ./...` into
  `pkg/app/<entity>/mocks/<entity>_<usecase>_mock.go`. Don't hand-write
  mocks. Don't commit a mock without its source `//go:generate` line.
- Use cases consume **domain repository interfaces** (from
  `pkg/domain/<entity>`), never concrete `pgx` / `fiber` / HTTP types.
- If a use case depends on another use case, depend on its interface, not
  the concrete struct, so tests can inject the generated mock.

### 10.3 Request DTOs live in `pkg/api/handler/http/request/`

- **One DTO per file**, named after the action: `create_gateway_request.go`,
  `update_upstream_request.go`, `forward_proxy_request.go`.
- The file holds the struct + its JSON tags + any `Validate()` method.
- Handlers in `pkg/api/handler/http/` consume these by importing
  `pkg/api/handler/http/request`.
- Request DTOs may reference domain value types but must not import infra
  (`pgx`, `redis`, `kafka`, …).

### 10.4 Response DTOs live in `pkg/api/handler/http/response/`

- **One DTO per file**, named after the action's output:
  `list_rules_response.go`, `get_gateway_response.go`.
- Same import discipline as request DTOs.

### 10.5 Anti-patterns (do not do these)

- Do **not** bundle interfaces into `pkg/api/handler/http/*_contracts.go` /
  `*_interfaces.go`. Move them to `pkg/app/<entity>/<usecase>.go`.
- Do **not** define the interface in one file and its only implementation in
  another file in the same package "for cleanliness". Keep them together;
  the `mocks/` package is the indirection.
- Do **not** put request / response DTOs in `pkg/types` or inside the handler
  file. They belong in `request/` and `response/`.
- Do **not** hand-roll mocks. Always `go:generate mockery`.

## 11. Code style (hard rules)

### 11.1 No comments (Go doc comments included)

Code in this repository **must not contain comments — and that explicitly
includes Go doc comments** (the `//` lines above packages, types, functions,
methods, fields, and constants). There is no exception for "idiomatic Go
doc comments": do **not** add a doc comment just because a symbol is exported.
The codebase relies on small files, named symbols, typed signatures, and
use-case-per-file layout (§10) to communicate intent. Comments rot, lie under
refactor, and silently duplicate information that the diff history already
captures.

This rule is enforced by a pre-commit hook that strips comments. Don't fight
it: write the code without comments in the first place, and when porting code
from other repos strip the comments as part of the port (see below).

**Above all: never add large comment blocks.** Do not write multi-line `//`
runs, banner headers, or `/* … */` paragraphs that summarise a file,
function, or change. A wall of comment text is the single most common thing
reviewers reject. If you feel the urge to write more than a few words of
prose, that is a signal to rename a symbol, split the function, or add a test
— not to keep typing the comment.

```go
// BAD — never generate anything like this.
//
// forwardRequest takes the inbound proxy request, validates the consumer,
// resolves the upstream backend, applies the policy chain, and finally
// forwards the request to the LLM provider. It returns the response or an
// error. We do it this way because the old approach was slow and ...
func forwardRequest(...) { … }
```

```go
// GOOD — the names and types already say all of this.
func forwardRequest(...) { … }
```

This applies to:

- Doc comments above packages, types, functions, methods, fields, constants.
- Inline `//` comments narrating what the next line does.
- Block `/* … */` comments explaining structure or rationale.
- Comments describing why a change was made — that belongs in the commit
  message, not in the file.
- Section banners (`// === Helpers ===`, `// --- internal ---`, …).
- TODO / FIXME / XXX / HACK markers. Open a Linear ticket instead and let
  the issue tracker carry the context.

The only comments allowed in committed code are the ones the toolchain
itself reads as instructions, not prose:

- `//go:generate …` directives consumed by `go generate`.
- Compiler / static-analysis directives (`//go:build`, `//go:embed`,
  `//nolint:<rule>`, `// #nosec G…`).
- The single-line copyright header, when one is required by upstream policy.

If the code needs an explanation to be understood, that is a signal to
rename a symbol, split a function, or add a test that documents the
behaviour through an assertion — not to add a comment. Reviewers will
ask for comments to be removed; CI may also reject them via a lint pass
in the future.

When porting code from other Neuraltrust repositories (TrustGate,
AgentGuardian, …), strip the comments during the port. Don't leave them
behind "for later".

## 12. Where do I put …

| New code | Goes in | Notes |
|---|---|---|
| A new HTTP endpoint for admin only | `pkg/api/handler/http/<name>_handler.go` + wire in `pkg/server/router/admin_router.go` | Add the handler as a provider in `modules.API`, add the field to `adminRouterParams`. |
| A new HTTP endpoint shared by admin + proxy | Same as above, wire in both routers. | Health probes already do this — copy that pattern. |
| A new cross-cutting middleware | `pkg/api/middleware/<name>.go` (implements `Middleware`) | Provide in `modules.API`, add the field to the relevant `*Middlewares` struct(s) + composer(s). |
| A new request DTO | `pkg/api/handler/http/request/<action>_request.go` | One DTO per file. Imported by the handler. |
| A new response DTO | `pkg/api/handler/http/response/<action>_response.go` | One DTO per file. Imported by the handler. |
| A new aggregate root | `pkg/domain/<entity>/` | Pure Go. No `pgx`, no `fiber`, no logging. Define repository interfaces in this package. |
| A new use case / finder | `pkg/app/<entity>/<usecase>.go` | Interface + impl + `//go:generate mockery` together. See §10.2. |
| A repository implementation | `pkg/infra/repository/<entity>/` (B.x) | Implements an interface from `pkg/domain/<entity>`. Uses `database.WithTx` for atomic writes. |
| A DB migration | `pkg/infra/database/migrations/<unix_ts>_<name>.go` | Registers in `init()`. Idempotent up + down inside one tx. |
| A new env var | `pkg/config/config.go` (default + struct field + getter) + `.env.example` | If required, extend `Validate()`. |
| A new module | `pkg/container/modules/<name>.go` | Add to `modules.All()` if it's part of the canonical boot. |

## 13. Commits, PRs, branches

- Conventional Commits per `_base.mdc`. Examples:
  - `feat(server): admin and proxy server adapters`
  - `fix(config): parse CORS_MAX_AGE as string, not duration`
  - `test(container): assert WithOverride decorates providers`
- One PR per shippable slice; the team budget is **400 changed lines**.
  See `_base.mdc` "PR review budget" and `chained-pr` skill if you need to
  split.
- The Linear issue id (`RUN-###`) goes in the PR body.
- Branch names follow `type/short-description`, where `type` is one of
  `feat|fix|refactor|test|chore|docs` (e.g. `feat/admin-crud-api`,
  `fix/cors-max-age`). Do NOT use Linear's `gitBranchName` (it prefixes the
  author's username); derive the branch from the change type instead.

## 14. Data-plane policy execution & caching (hard rules)

Learned invariants for the proxy hot path, the plugin executor, and the
control-plane caches. Diverging from these has caused real bugs (404s, stale
projections, concurrent-map panics, dead gates), so treat them as contracts.

### 14.1 Stamp the request target before `pre_request`

`RequestContext.RegistryID` and `RequestContext.Provider` must be set at
backend selection (and re-set on every failover retarget) **before** the
`pre_request` stage runs. Provider-aware `pre_request` plugins read
`req.Provider` (e.g. `token_rate_limiter`, whose budget gate short-circuits when
the provider is empty). The provider invoker only sets `req.Provider` during
upstream invocation, which is too late for `pre_request`. Use the single
`stampTarget(req, backend)` helper in `forwarder.go`; do not stamp `RegistryID`
/ `Provider` ad hoc in more than one place.

### 14.2 Parallel plugins never share mutable maps

A parallel batch (`policy.Parallel == true`, same priority) runs each plugin on
an **isolated clone** of the Request/Response context; per-plugin mutations are
merged back sequentially, in deterministic batch order, after `errgroup.Wait()`.
Plugins must not write the shared `Headers` / `Metadata` maps concurrently — Go
will panic on a concurrent map write. Single-plugin batches skip the clone.

### 14.3 Policy chains are precomputed (`StagePlan`), not per-request

The ordered, per-stage plugin chain for a consumer's effective policy set is
precomputed once as a `StagePlan` and cached inside the per-gateway
consumer-data aggregate (`RoutableConsumer.PolicyPlan`). The executor consumes
the plan; it must not resolve, dedup, or sort the chain on every request. When
no `post_response` plugin exists in the plan, skip post_response snapshotting,
goroutine spawning, and stream buffering entirely.

### 14.4 Invalidate every cache whose read projection changed

When you mutate a junction (`consumer_registry`, `consumer_auth`,
`consumer_policy`), invalidate **all** entity caches whose read model reflects
that change — not just the consumer. Concretely: attaching/detaching a
policy↔consumer link changes the policy's `consumer_ids` reverse projection, so
the associator drops the policy entity cache (`PolicyTTLName`) on attach and
detach. Only the policy exposes a reverse projection today; auth and registry
do not, so they need no extra invalidation. The admin plane runs as a single
replica, so an in-process `TTLMap.Delete` is sufficient (no pub/sub needed for
entity caches).

### 14.5 Cache invalidation is gateway-level

Any update/delete/associate on a consumer, policy, registry, auth, or
association invalidates the **whole gateway's** consumer-data aggregate
(`InvalidateGatewayDataEvent` / `InvalidateRegistryCacheEvent`), which forces
the `RoutableConsumer` set and every `StagePlan` to recompute. Per-consumer
invalidation is unsafe because path routing and global policies make consumers
interdependent. `create` operations do **not** publish invalidation — nothing is
cached for a resource that does not yet participate in any aggregate.

### 14.6 Global vs consumer-scoped policy composition

A policy is gateway-wide when its `global` flag is set (via the `/global`
endpoint), not by attachment. Composition rule: consumer-scoped policies come
first, then globals, and a **consumer-scoped policy overrides a global one with
the same slug** (the global is dropped). When changing this logic, keep the
override keyed on slug.

### 14.7 Functional proxy routes: path must match the consumer name

A consumer's routing path is derived from its name (`/v1/<name>` in
`validConsumerPayload`). In functional tests, the path you POST to the proxy
must match the consumer's name exactly, or `MatchPath` returns 404. Wire setup
helpers so the returned path and the created consumer's name stay in sync.

## 15. References

- Platform shape: `/home/edu/.cursor/rules/neuraltrust-platform.mdc`
- Domain glossary: `/home/edu/.cursor/rules/neuraltrust-domain.mdc`
- Work gates: `/home/edu/.cursor/rules/work-gates.mdc`
- Reference repositories (read-only mirrors for boot patterns):
  - `AgentGuardian/cmd/api/main.go` — flat-main + dig + migrations boot.
  - `AgentGuardian/internal/infra/database/` — pgx connection + in-code migrations.
  - `AgentGuardian/internal/infra/logging/logger.go` — slog handler stack.
  - `TrustGate/cmd/gateway/main.go` — `argv[1]` server selection.
  - `TrustGate/pkg/server/middleware/cors_global.go` — CORS shape we mirror.
  - `TrustGate/pkg/app/apikey/finder.go` — canonical use-case shape (interface + `//go:generate mockery` + impl in one file).
  - `TrustGate/pkg/app/upstream/mocks/upstream_creator_mock.go` — what mockery output should look like.
  - `TrustGate/pkg/handlers/http/request/create_gateway_request.go` — canonical request DTO shape (one DTO per file).

NO CODE COMMENTS!!!!