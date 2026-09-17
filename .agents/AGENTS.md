# TrustGate — Agent guide

AI gateway for LLM/MCP traffic: a stateless data plane (proxy, MCP) plus an
admin plane, wired with `uber/dig` and built in Go on a hexagonal architecture.

This file is the canonical orientation for any AI agent (or new contributor)
opening this repository. Read it before changing code.

**Instruction priority:** Work gates (`work-gates.mdc`) > user instructions > these conventions.

## What this repository is

TrustGate sits between LLM/agent clients and upstream model providers and
enforces policies declared in the control plane. One binary, several servers:

| Server | Typical port | Purpose |
|---|---|---|
| **admin** | `:8080` | Control-plane API: gateway / registry / consumer / policy / auth CRUD. |
| **proxy** | `:8081` | Data-plane LLM forwarder: inspects request/response, applies policies, calls upstream. |
| **mcp** | | Data-plane MCP gateway (tools, OAuth, store). |
| **run** | | Admin + proxy in one process (local/single-node). |

Each production server is meant to run in its **own pod** (`./trustgate admin` vs
`./trustgate proxy` vs `./trustgate mcp`). They share the DI graph and config but
compose different middleware chains. `argv[1]` selects the plane; omitted
defaults to `proxy`.

## Repo layout

```
cmd/trustgate/   # entrypoint: server selection + DI build + graceful shutdown
pkg/
  api/           # driving adapters: HTTP handlers, middleware, routers
    handler/http/<entity>/request|response/  # one DTO per file, per entity
    handler/http/httpio/  # shared HTTP request-decode + response-encode helpers
  app/           # application core: one use case per file (proxy, consumer, oauth, plugins, ...)
  domain/        # entities, value objects, repository ports — no framework/infra imports
  infra/         # driven adapters: DB repositories, cache, providers, loadbalancer, plugins
  runtimeconfig/ # DB-less snapshot data plane (config sync + snapshot repositories)
  container/     # composition root: dig wrapper + modules/* wiring
  config/        # env-var config
  server/        # server lifecycle + routers
```

## Boot sequence

```
godotenv.Load (.env, /etc/secrets/.env, /etc/secrets/secrets)
plane := argv[1]                          # admin | proxy | mcp | run (default proxy)
dbless := CONFIG_SYNC_DATA_PLANE_ENABLED && plane in {proxy, mcp}
container.New(modules.All(plane, dbless))
if !dbless: migrations + cache event listener
c.Invoke(runAdmin | runProxy | runMCP | run)   # one plane (run = admin+proxy)
<-SIGINT/SIGTERM
srv.Shutdown()
```

- Boot failures before the server starts exit via `log.Fatalf`; failures inside
  the server goroutine log via `slog` and `os.Exit(1)`.
- Migrations are in-code Go files under `pkg/infra/database/migrations/` that
  register via `init()` against `database.RegisterMigration`. They run on every
  non-DB-less boot. There is no separate `run-migrations` subcommand.

## Hexagonal architecture rules

Dependency direction (never violated):

```
HTTP handlers/middleware (driving) → app use cases → domain ← infra (driven)
container/modules wires everything (composition root)
```

- Handlers are thin: decode request, call an app use case, encode response/error. No business logic.
- `domain` depends on nothing framework-specific; ports (interfaces) live with the core, concrete adapters in `infra`.
- One interface per use case; **accept interfaces, return structs**; small consumer-defined interfaces.
- `dig` resolves by **exact type**: when a use case depends on a segregated interface, register a view provider (e.g. `func(r consumer.Repository) consumer.Reader { return r }`) in `container/modules/*`.
- `//go:generate mockery` on mockable interfaces; wiring in `container/modules/*`.
- A `pkg/app/...` file importing `github.com/jackc/pgx` or `fiber` is a bug.
- Do not import `fiber` outside `pkg/api/middleware`, `pkg/api/handler/*`, `pkg/server/*`.

See the `trustgate-hexagonal` skill for patterns.

## Dependency injection

`uber/dig` via the thin `pkg/container` wrapper. `main` calls
`modules.All(plane, dbless)` — **distinct module sets**, never `dig.Decorate` to
swap Postgres repositories (that would still construct the pool).

- **One file per context** under `pkg/container/modules/`. Each exports a
  `Module` function (`func Core(c *container.Container) error`).
- **Named providers** for things that exist in multiple flavours (admin/proxy/mcp
  server, router, transport). Use `dig.Name("admin")` / `name:"admin"` on `dig.In`.
- **Per-server middleware**: `api.go` registers each middleware as a singleton;
  `server_admin.go` / `server_proxy.go` / `server_mcp.go` declare a `*Middlewares`
  `dig.In` and a `*Transport` composer. To add a middleware to one server only,
  edit only that server's module.
- **Test overrides** use `container.WithOverride` (`dig.Decorate`). Wrap
  `func(orig T) T`. Do not import `modules.All()` in tests — pull in only the
  modules you need.

## App layer and DTO placement

### Use cases — `pkg/app/<entity>/<usecase>.go`

One file per use case (`finder.go`, `creator.go`, `updater.go`, `deleter.go`, …).
No `contracts.go` / `interfaces.go` aggregating several interfaces. Inside each
file, in this order:

1. Package-level sentinel errors.
2. `//go:generate mockery` for the interface.
3. The exported interface (`Finder`, `Creator`, …).
4. The unexported struct + `New<Iface>` constructor returning the interface.
5. The methods.

Mocks **must** be generated by `go generate` into
`pkg/app/<entity>/mocks/<entity>_<usecase>_mock.go`. Do not hand-write mocks.
Use cases consume **domain repository interfaces**, never concrete `pgx` / `fiber`
/ HTTP types.

### Request / response DTOs

- Request: `pkg/api/handler/http/<entity>/request/<action>_request.go`
- Response: `pkg/api/handler/http/<entity>/response/<action>_response.go`
- **One DTO per file.** Struct + JSON tags + `Validate()` when needed.
- Shared encode/decode helpers live in `pkg/api/handler/http/httpio/`.
- DTOs may reference domain value types; they must not import infra.

## Configuration, database, logging

- All configuration is **environment variables** via `pkg/config/LoadConfig`.
  Defaults live as `default<Section><Field>` constants; required fields are
  checked in `Config.Validate()`. Adding a var: const → struct field → getter →
  `Validate()` if required → `.env.example`.
- `pgx/v5` + `pgxpool`, wrapped in `database.Connection`. Ping fail-fast at boot
  (`errors.ErrBoot`). For multi-statement writes use `database.WithTx`.
- Migrations: `pkg/infra/database/migrations/<unix_ts>_<snake_name>.go`,
  `RegisterMigration` from `init()`, idempotent up+down in one transaction.
- `log/slog` from `pkg/infra/logger/`. Named attrs (`slog.String("path", …)`),
  never `fmt.Sprintf` into the message. Only `modules.Core` calls
  `slog.SetDefault`. Before the logger exists, use `log.Fatalf`.

## Testing

- `go test -race ./...` (`make test-race`) is the contract. Tests live next to
  the code they cover.
- Prefer behaviour assertions over unexported-field inspection.
- Repository integration tests gate on `PG_TEST_URL` (`make test-repositories`);
  skip when unset. Functional tests live under `tests/functional/` behind the
  `functional` build tag (`make test-functional`) and need Postgres + Redis
  (+ Kafka).

## Go rules (binding)

- `gofmt` + `goimports`; `make lint` (`golangci-lint`) and `make fmt` (`gofmt` + `go vet`) clean before done.
- `ctx context.Context` is the **first parameter** on I/O/blocking calls — never stored in a struct.
- Errors are values: handle every error; wrap with `%w`; sentinels via `errors.New` + `errors.Is`.
- Every goroutine has an explicit lifecycle (start/stop/join) and honors `ctx.Done()`; no leaks.
- Concurrency-sensitive code is tested with `-race` (`make test-race`).
- Config via env vars (`pkg/config`); no hardcoded addrs/timeouts scattered as `os.Getenv`.

## Code comments policy (strict)

Mirrors `go-comments.mdc`, plus the swagger exception below. Narrative comments
are forbidden; exported Go doc comments **are** allowed.

**Allowed only:**
- Doc comments on **exported** identifiers (a full sentence starting with the identifier name).
- One package comment per package.
- Tooling directives: `//go:generate`, `//go:embed`, `//nolint:<linter> // reason`, build tags.
- Rare **"why"** comments for a non-obvious trade-off/workaround (with a ticket ref where possible).
- **Apache 2.0 license headers** (`make license` / `make license-check`).
- **Swagger annotations** on HTTP handlers (`// @Summary`, `// @Router`, `// @Param`, `// @Success`, `// @Failure`, `// @Tags`, `// @Description`, `// @Accept`, `// @Produce`, ...). These feed `make swagger` / `make openapi` and are the source of `docs/swagger.{json,yaml}` and `docs/openapi.json`. **Never strip them.**

**Forbidden:**
- Narrative comments restating code (`// loop over items`, `// return the result`).
- Judgment/teaching labels (`// Good:`, `// Bad:`, `// Best:`).
- Inline annotations (`// default`, `// zero value`, `// capture loop var`).
- Decorative banners / section dividers (`// ====`, `// ---------`).
- Comments explaining the change being made; commented-out code (delete it — git remembers).
- Doc comments on self-evident unexported identifiers.
- TODO / FIXME / XXX / HACK markers — open a Linear ticket instead.

Rule of thumb: if a comment wouldn't survive review as adding real value, don't write it. The
`scripts/check-comments.sh` guard (run from the pre-commit hook) blocks the mechanical offenders
(banner dividers, commented-out code) on staged Go files while exempting license/directives/swagger.

## Where do I put …

| New code | Goes in |
|---|---|
| Admin-only HTTP endpoint | `pkg/api/handler/http/<entity>/<name>_handler.go` + wire in the admin router |
| Cross-cutting middleware | `pkg/api/middleware/<name>.go` (implements `Middleware`); provide in `modules.API`, add to the relevant `*Middlewares` |
| Request / response DTO | `pkg/api/handler/http/<entity>/request/` or `…/response/` — one DTO per file |
| Aggregate root | `pkg/domain/<entity>/` — pure Go; repository interfaces in this package |
| Use case | `pkg/app/<entity>/<usecase>.go` — interface + impl + `//go:generate mockery` |
| Repository implementation | `pkg/infra/repository/<entity>/` — implements the domain port; `database.WithTx` for atomic writes |
| DB migration | `pkg/infra/database/migrations/<unix_ts>_<name>.go` |
| Env var | `pkg/config/config.go` + `.env.example` |
| DI module | `pkg/container/modules/<name>.go` — add to `fullModules` / `dataPlaneModules` as appropriate |

## Data-plane policy execution and caching

Learned invariants for the proxy hot path. Diverging has caused real bugs (404s,
stale projections, concurrent-map panics, dead gates).

### Stamp the request target before `pre_request`

`RequestContext.RegistryID` and `RequestContext.Provider` must be set at backend
selection (and re-set on every failover retarget) **before** `pre_request` runs.
Provider-aware plugins (e.g. `token_rate_limiter`) read `req.Provider` and
short-circuit when it is empty. The provider invoker only sets `req.Provider`
during upstream invocation — too late. Use the single `stampTarget(req, backend)`
helper in `forwarder.go`.

### Parallel plugins never share mutable maps; the executor is the single writer of the body

Batch grouping happens at `StagePlan` build time. The planner sorts each stage's
entries by `priority → slug → id` and greedily forms batches so that every
parallel batch admits **at most one** request-body mutator, **one** response-body
mutator, and **one** metadata mutator. Excess mutators are forced into the next
batch.

A parallel batch runs each plugin on an **isolated clone**; `Headers` and
`Metadata` mutations merge back sequentially after `errgroup.Wait()`. Plugins
MUST treat the context as read-only and return body changes via
`Result.RequestBody` / `Result.Body`. The executor is the **single writer** of
`req.Body` / `resp.Body`.

### Policy chains are precomputed (`StagePlan`), not per-request

The ordered per-stage plugin chain for a consumer's effective policy set is a
cached `StagePlan` inside `RoutableConsumer.PolicyPlan`. The executor must not
resolve, dedup, or sort the chain on every request. When no `post_response`
plugin exists, skip post_response snapshotting, goroutine spawning, and stream
buffering.

### Invalidate every cache whose read projection changed

Mutating a junction (`consumer_registry`, `consumer_auth`, `consumer_policy`)
must invalidate **all** entity caches whose read model reflects that change.
Attaching/detaching a policy↔consumer link drops the policy entity cache
(`PolicyTTLName`) because of the `consumer_ids` reverse projection. The admin
plane is a single replica, so in-process `TTLMap.Delete` is sufficient.

### Cache invalidation is gateway-level

Any update/delete/associate on a consumer, policy, registry, auth, or association
invalidates the **whole gateway's** consumer-data aggregate
(`InvalidateGatewayDataEvent` / `InvalidateRegistryCacheEvent`). Per-consumer
invalidation is unsafe because path routing and global policies make consumers
interdependent. `create` does **not** publish invalidation.

### Global vs consumer-scoped policy composition

A policy is gateway-wide when its `global` flag is set (via `/global`), not by
attachment. Consumer-scoped policies come first, then globals; a **consumer-scoped
policy overrides a global one with the same slug**. Keep the override keyed on slug.

### Functional proxy routes: path must match the consumer name

A consumer's routing path is derived from its name (`/v1/<name>`). In functional
tests the path you POST to the proxy must match the consumer's name exactly, or
`MatchPath` returns 404.

## DB-less data plane (pull-based config sync)

The **proxy** and **mcp** data planes can run **without Postgres**, resolving
every `domain.Repository` from an in-memory snapshot pulled from the control
plane. Gated by `CONFIG_SYNC_DATA_PLANE_ENABLED` (default **OFF**). Flag-off
planes keep their Postgres-backed finders and TTL caches unchanged.

`main` computes `dbless = config.DBLessDataPlaneEnabled() && isDataPlane(plane)`
and calls `modules.All(plane, dbless)`:

- **Full / control set** (`admin`, `run`, or any flag-off plane): Postgres graph
  (`Core`, `Gateway`, `Registry`, `Consumer`, `Catalog`, `Store`, `Auth`,
  `Policy`, `MCPVaultPostgres`, …) **+** `ControlConfigSync` (compiler, holder,
  debounced recompiler, gRPC hub, authed gRPC listener).
- **DB-less DP set** (`(proxy|mcp) && dbless`): `CoreData` (config / logger /
  redis / crypto + snapshot-adapter bindings; `provideNilConnection` for
  `optional:"true"` consumers), `Cache`, `Plugins`, `Proxy`, `MCP` (with
  `MCPVaultRedis`), `ServerProxy` / `ServerMCP`, `ConfigSyncData` (store, codec,
  crypto, gRPC fetcher, LKG, converge `Worker`). `main` skips migrations, cache
  event listener, and catalog sync; `runProxy` / `runMCP` start `Worker.Run`.

**Transport is gRPC**, not HTTP. The control plane serves `ConfigSync`
(`GetSnapshot` bulk transfer + long-lived bidi `Sync` for version notices/acks)
on `CONFIG_SYNC_GRPC_LISTEN_ADDR` (default `:8083`), authenticated with
`CONFIG_SYNC_TOKEN`. The data plane dials `CONFIG_SYNC_GRPC_ENDPOINT`. Version is
the hex SHA-256 of the deterministic protobuf bytes; identical config recompiles
to the identical version and publishes no new notice. Admin writes `Signal` a
debounced recompile (`CONFIG_SYNC_RECOMPILE_DEBOUNCE`).

**Env (flag ON):** proxy/mcp do **not** need `DB_*`. `Validate()` requires the
`CONFIG_SYNC_*` set below; **`REDIS_HOST` and `KAFKA_BROKERS` stay required**.
Boot fails fast (`ErrInvalidConfig`) when token, gRPC endpoint, LKG path/key, or
poll interval are missing/invalid.

Encrypted LKG at `CONFIG_SYNC_LKG_PATH` (AES-256-GCM under `CONFIG_SYNC_LKG_KEY`,
base64 → exactly 32 bytes). `/readyz` gates on snapshot presence (`503` until
first converge or LKG restore) and exposes **no** `postgres` dependency on the
DB-less plane.

**Vault on Redis (DB-less MCP):** `vaultrepo.NewRedisRepository` instead of
Postgres. Key `vault:{gatewayID}:{principalSub}:{provider}`; `Find` miss →
`vaultdomain.ErrNotFound` (re-consent).

Proto: `pkg/infra/configsnapshot/proto/snapshot.proto` — regenerate with
`make proto`. Never hand-edit generated files.

| Env | Meaning | Default |
|---|---|---|
| `CONFIG_SYNC_DATA_PLANE_ENABLED` | DB-less data-plane master flag | `false` |
| `CONFIG_SYNC_TOKEN` | shared secret (CP authenticates DP) | `""` |
| `CONFIG_SYNC_GRPC_ENDPOINT` | CP gRPC address the DP dials | `""` |
| `CONFIG_SYNC_GRPC_LISTEN_ADDR` | CP gRPC listen address | `:8083` |
| `CONFIG_SYNC_TLS_INSECURE` | skip TLS verify (local dev only) | `false` |
| `CONFIG_SYNC_LKG_PATH` | encrypted LKG file path | `/var/lib/trustgate/snapshot.lkg` |
| `CONFIG_SYNC_LKG_KEY` | AES-256 key, base64 → 32 bytes | `""` |
| `CONFIG_SYNC_POLL_INTERVAL` | backstop re-pull interval | `5m` |
| `CONFIG_SYNC_RECOMPILE_DEBOUNCE` | CP recompile debounce | `250ms` |
| `CONFIG_SYNC_INSTANCE_ID` | fleet-visibility id | `HOSTNAME` |

DB-less functional tests (`make test-functional`, tag `functional`):

```
go test -tags functional -run 'TestDBLessDataPlane|TestDBLessMCPVault' ./tests/functional/...
```

## Commands

```bash
make fmt            # gofmt + go vet
make lint           # golangci-lint
make test           # unit tests
make test-race      # unit tests with the race detector
make test-functional    # functional tests (Postgres + Redis + Kafka)
make test-repositories  # repository integration (PG_TEST_URL)
make generate       # go generate (mocks etc.)
make proto          # buf generate for snapshot proto
make swagger        # regenerate Swagger 2.0 from handler annotations
make docs           # Swagger 2.0 + OpenAPI 3
make install-pre-commit  # install scripts/pre-commit.sh into .git/hooks
```

## Work gates

- Feature branches only. **Never commit/push on `main`/`master`/`develop`.**
  Branch: `type/<ticket>-<slug>` (`feat/`, `fix/`, `chore/`, …). Do **not** use
  Linear's `gitBranchName` (it prefixes the author's username).
- **Commit only when the user explicitly asks.** Conventional Commits: `type(scope): subject`.
- PRs include the Linear id (`RUN-###`); one shippable slice per PR (soft cap 400 lines).
- New code paths need tests unless `WIP`/docs-only; run `-race` for concurrency paths.
- Never commit secrets; `.env*` is never read/written/referenced in code.
- Full gate details: `work-gates.mdc`.
