# Design: B.0 Project Setup & Scaffolding (RUN-282)

## Technical Approach

TrustGate-shaped hexagonal layout. `cmd/gateway` cobra binary boots one `dig` container of per-context modules, exposing `Server` adapters (admin, proxy) on Fiber v2. Postgres/Redis/Kafka+ZK/ClickHouse are core providers, healthchecked and ping-gated. Migrations via `run-migrations`. B.0 ships skeleton only; B.x extends via new modules and `pkg/{app,domain,handlers}` files.

## Architecture Decisions

| # | Topic | Choice | Rejected | Rationale |
|---|---|---|---|---|
| 1 | DB driver | **`pgx/v5` + `pgxpool`** | gorm, sqlx | Port of AgentGuardian `internal/infra/database`. One driver across pool + migrations + repos; no `database/sql` round-trip. |
| 2 | Migrations | **In-code Go migrations** via `database.RegisterMigration` + `init()` | golang-migrate, gormigrate | Port of AgentGuardian `migrations_manager.go`. Files `<unix_ts>_<snake_name>.go` register on `init()`; `ApplyPending` runs each in its own tx; record + DDL commit atomically in `public.migration_version`. |
| 3 | Logger | **`log/slog`** (stdlib) JSON multi-handler (`pkg/infra/logger/logger.go`) | logrus, zap | Port of AgentGuardian `internal/infra/logging/logger.go`: MultiHandler (console + file), AsyncHandler, SourceFilterHandler, optional ColoredHandler for dev. GCP-friendly JSON via stdlib. |
| 4 | Config | **`os.Getenv` + `godotenv`** (env-only, `.env` in dev) | viper, envconfig+yaml | Port of AgentGuardian `internal/config`. Per-key getters with sanitized parse-error logs; `.env.example` committed; `.env` gitignored. No YAML/TOML format. |
| 5 | `--server both` | **Single dig graph** | Two graphs | Shared singletons; modules register both `Server`s, cobra picks which `Run()`. Shutdown reverse order: **proxy → admin** so proxy drains first. |
| 6 | dig modules | One `Module()` per context: `core`, `telemetry`, `cache`, `auth`, `policy`, `plugins`, `gateway`, `backend`, `consumer`, `server_admin`, `server_proxy` | Monolithic | Matches `pkg/app` boundaries; B.x adds file, never edits root. |
| 7 | Test overrides | **`Override(opts...)`** wraps `dig.Decorate` | Build-tag forks | Real container + swap providers. |
| 8 | Build info | **`-ldflags -X version.*`** | `debug.ReadBuildInfo` only | Distroless-compatible; feeds `version` + `/healthz`. |
| 9 | Boot failure | **Fail-fast + structured log** | Silent exit, panic | Any provider build / ping fail → ERROR JSON `{component, error}` then `os.Exit(1)`. Stdlib `log.Fatalf` pre-logger, logrus after. Mirrors TrustGate `logger.Fatalf`. |
| 10 | Kafka stack | **`cp-kafka:7.6.0` + `cp-zookeeper:7.6.0`** | Bitnami KRaft | TrustGate parity. AG adds healthchecks (TrustGate omits) so `service_healthy` gate works. |

## Data Flow

```
cobra ──► config.Load ──► container.New(modules...) ──► dig.Invoke(Run)
                                  │
            core providers ───────┤
            (logrus, gorm, redis, ├──► server_admin.Run()  (:8080)
             kafka, clickhouse)   └──► server_proxy.Run()  (:8081)
                  └──── shared singletons ────┘

SIGINT/SIGTERM ──► Shutdown loop (reverse): proxy → admin → workers
                   any Shutdown() error → os.Exit(1)
```

Compose: pg/redis/ch/zookeeper/kafka declare `healthcheck`; `gateway` uses `depends_on: condition: service_healthy` and pings each on `Run`.

## File Changes

All rows are **Create** (greenfield). No modifies or deletes.

| File | Purpose |
|---|---|
| `go.mod`, `go.sum` | Go 1.26 |
| `cmd/gateway/main.go` | → `cmd.Execute()` |
| `cmd/gateway/cmd/root.go` | Cobra root |
| `cmd/gateway/cmd/run_server.go` | `--server admin\|proxy\|both`, signal+reverse Shutdown |
| `cmd/gateway/cmd/run_migrations.go` | `up/down/version/force` |
| `cmd/gateway/cmd/version.go` | Print build info |
| `pkg/version/version.go` | ldflag vars |
| `pkg/config/config.go` | Env-only loader (`LoadConfig`) — port from AgentGuardian |
| `pkg/config/config_test.go` | Env precedence + defaults |
| `pkg/infra/logger/logger.go` | slog multi/async/source-filter/colored handlers + `NewLogger(level)` (port from AgentGuardian) |
| `pkg/common/errors/errors.go` | Sentinels |
| `pkg/domain/.keep` | B.x reserve |
| `pkg/app/.keep` | B.x reserve |
| `pkg/infra/database/connection.go` | `*Connection` over `*pgxpool.Pool` — port from AgentGuardian |
| `pkg/infra/database/migrations_manager.go` | In-code migrations registry + `ApplyPending` (port from AgentGuardian) |
| `pkg/infra/database/provider.go` | dig-friendly factories for Connection / MigrationsManager |
| `pkg/infra/database/migrations/.keep` | Reserve; B.1 adds first migration as `<ts>_<name>.go` |
| `.env.example` | Committed env template (matches AgentGuardian) |
| `pkg/api/handler/http/health_handler.go` | `/healthz`, `/readyz` (port AG) |
| `pkg/api/handler/http/version_handler.go` | `/__/version` (returns `version.GetInfo()`) |
| `pkg/api/handler/websocket/.keep` | B.x reserve |
| `pkg/api/middleware/middleware.go` | `Middleware` iface + `Transport` aggregator (port AG) |
| `pkg/api/middleware/request_id.go` | Wraps Fiber's `requestid.New()` |
| `pkg/api/middleware/access_log.go` | slog access-log middleware |
| `pkg/api/middleware/panic_recover.go` | slog panic-recover middleware (port AG) |
| `pkg/server/server.go` | `Server` iface (`Run`/`Shutdown`) + `BaseServer` Fiber tuning (port AG) |
| `pkg/server/http_server.go` | `httpServer` impl + `NewHTTPServer(name,addr,cfg,logger,routers)` |
| `pkg/server/router/router.go` | `ServerRouter` iface |
| `pkg/server/router/admin_router.go` | Admin routes |
| `pkg/server/router/proxy_router.go` | Proxy routes |
| `pkg/dependency_container/container.go` | `Container`, `New`, `Invoke`, `Override` |
| `pkg/dependency_container/options.go` | `Option`, `WithOverride` |
| `pkg/dependency_container/modules/core.go` | log/db/redis/kafka/ch |
| `pkg/dependency_container/modules/telemetry.go` | Metrics, tracer |
| `pkg/dependency_container/modules/cache.go` | Redis cache |
| `pkg/dependency_container/modules/auth.go` | Stubs |
| `pkg/dependency_container/modules/policy.go` | Stubs |
| `pkg/dependency_container/modules/plugins.go` | Stubs |
| `pkg/dependency_container/modules/gateway.go` | Stubs |
| `pkg/dependency_container/modules/backend.go` | Stubs |
| `pkg/dependency_container/modules/consumer.go` | Stubs |
| `pkg/dependency_container/modules/server_admin.go` | Admin provider (group) |
| `pkg/dependency_container/modules/server_proxy.go` | Proxy provider (group) |
| `pkg/dependency_container/container_test.go` | Override smoke |
| `Makefile` | `build/test/lint/migrate/run/docker/compose-up` |
| `Dockerfile` | Multi-stage, ldflag |
| `.dockerignore` | `.git`, `vendor`, tests |
| `docker-compose.yaml` | pg, redis, ch, **`cp-zookeeper:7.6.0`**, **`cp-kafka:7.6.0`**, gateway — all healthchecked |
| `.github/workflows/ci.yml` | Lint + test + build |
| `.golangci.yml` | TrustGate linter set |
| `.agents/AGENT.md` | Repo conventions |
| `README.md` | Quickstart + subcommands |

## Interfaces / Contracts

```go
type Server interface {
    Run() error
    Shutdown() error
}
type Module func(*dig.Container) error
type Container struct{ dig *dig.Container }
func New(opts ...Option) (*Container, error)
func (c *Container) Invoke(fn any) error
type Option func(*Container) error
func WithOverride(decorator any) Option

// database (port from AgentGuardian)
type Connection struct { Pool *pgxpool.Pool }
func NewConnection(ctx context.Context, cfg *config.DatabaseConfig) (*Connection, error)
func (c *Connection) HealthCheck(ctx context.Context) error
type Migration struct {
    ID, Name string
    Up, Down func(ctx context.Context, tx pgx.Tx) error
}
func RegisterMigration(m Migration)
type MigrationsManager struct { /* pool */ }
func NewMigrationsManager(pool *pgxpool.Pool) *MigrationsManager
func (m *MigrationsManager) ApplyPending(ctx context.Context) error
```

## Testing Strategy

| Layer | What | How |
|---|---|---|
| Unit | config, version, middleware, logger, migrations registry ordering | `go test ./...`, table-driven |
| Integration | pgxpool, migrations apply, redis ping, overrides | testcontainers-go swapped via `WithOverride` |
| E2E | compose smoke | CI brings stack up, curls `/healthz`, tears down |

B.0 scope: compiles, `make test`/`make lint` green, override-harness smoke proves DI swap. **No business-logic tests** — those land in B.x.

## Migration / Rollout

No migration required. Greenfield single-PR drop; revert = `git revert`. B.0 ships the migrations runtime with an empty registry; B.1 adds the first registered migration as `pkg/infra/database/migrations/<ts>_<name>.go` and blank-imports the package from `cmd/agentgateway` so `init()` runs.

## Open Questions

- [x] Embed git sha via `-ldflags` — **resolved** in Makefile + Dockerfile.
- [x] Kafka image — **resolved**: Confluent `cp-kafka:7.6.0` + `cp-zookeeper:7.6.0` (TrustGate parity).
- [x] `--server both` shutdown order — **resolved**: proxy → admin → workers, reverse of `Run()`.
- [x] **Logger lib** — **resolved**: `log/slog` (stdlib), porting AgentGuardian's `internal/infra/logging/logger.go`. JSON output is Cloud-Logging-friendly via stdlib; `level → severity` is a one-line `ReplaceAttr` if we want strict GCP later.
- [x] **DB driver** — **resolved**: `pgx/v5` + `pgxpool`, no gorm. Port AgentGuardian's `internal/infra/database/{connection,provider}.go`.
- [x] **Migrations system** — **resolved**: in-code Go migrations via `database.RegisterMigration` + `init()` (port AgentGuardian's `migrations_manager.go`). No golang-migrate, no `.sql` files. Migrations live as `<unix_ts>_<snake_name>.go` and blank-imported from main.
- [x] **Config loader** — **resolved**: `os.Getenv` + `godotenv` (no viper, no YAML). Port AgentGuardian's `internal/config/config.go`; `.env.example` committed at repo root.
