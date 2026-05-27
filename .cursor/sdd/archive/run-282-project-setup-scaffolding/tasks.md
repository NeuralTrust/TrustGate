# Tasks: B.0 Project Setup & Scaffolding (RUN-282)

## Phase 1: Foundation <!-- RUN-333 -->

- [x] 1.1 `go mod init github.com/NeuralTrust/AgentGateway` (Go 1.26) + deps: fiber/v2, uber/dig, **pgx/v5** (drops gorm + golang-migrate), **joho/godotenv** (drops viper), cobra, redis, kafka-go, ClickHouse client. **slog is stdlib — no logger dep.**
- [x] 1.2 `pkg/version/version.go`: `Version`, `Commit`, `BuildDate`, `String()`, `GetInfo()` (ldflag-fed; `APPLICATION_VERSION` env override).
- [x] 1.3 `pkg/common/errors/errors.go`: `ErrNotFound`, `ErrInvalidConfig`, `ErrBoot`.
- [x] 1.4 Port `pkg/infra/logger/logger.go` from AgentGuardian `internal/infra/logging/logger.go` (slog `MultiHandler`/`AsyncHandler`/`SourceFilterHandler`/`ColoredHandler` + `NewLogger(level)` / `NewLoggerWithFormat(level, format)`).
- [x] 1.5 `.keep`: `pkg/{domain,app,handlers/websocket}/.keep`.

## Phase 2: Config & DB infra <!-- RUN-327 -->

- [x] 2.1 `pkg/config/config.go`: env-only loader (`LoadConfig`) — port from AgentGuardian (`os.Getenv` + per-key getters, no viper).
- [x] 2.2 `.env.example` at repo root with the full env shape (server/db/redis/kafka/clickhouse/logger); `.env` already gitignored.
- [x] 2.3 `pkg/infra/database/connection.go`: `*Connection` over `*pgxpool.Pool` with ping fail-fast (`errors.ErrBoot`) — port from AgentGuardian.
- [x] 2.4 `pkg/infra/database/migrations_manager.go`: `RegisterMigration` + `MigrationsManager.ApplyPending` — port from AgentGuardian. Per-migration tx commits DDL + `public.migration_version` insert atomically.
- [x] 2.5 `pkg/infra/database/provider.go`: dig-friendly factories. `pkg/infra/database/migrations/.keep` reserves the dir; B.1 lands first `<ts>_<name>.go` migration.
- [x] 2.6 `pkg/infra/database/tx.go`: `WithTx(ctx, *Connection, func(pgx.Tx) error)` — begin/commit/rollback wrapper that survives panics. (We don't use gorm; `pgx.Tx` is the equivalent abstraction and is now available to repositories landing in B.x.)

## Phase 3: HTTP server foundation <!-- RUN-328 -->

- [x] 3.1 `pkg/server/server.go`: `Server` iface (`Run`/`Shutdown`) + `BaseServer` (Fiber tuning, port from AgentGuardian).
- [x] 3.2 `pkg/server/http_server.go`: `httpServer` impl + `NewHTTPServer(name, addr, cfg, logger, routers)` factory — instantiated twice (admin, proxy) in B.4.
- [x] 3.3 `pkg/server/router/router.go`: `ServerRouter` iface + `ErrInvalidHandlerTransport`.
- [x] 3.4 `pkg/api/middleware/{middleware,request_id,access_log,panic_recover,cors,security_headers}.go`: `Middleware` iface + `Transport` aggregator + X-Request-Id + slog access log + slog panic-recover + static-allowlist CORS (port TrustGate `cors_global` shape, env-driven) + baseline `X-Content-Type-Options/X-Frame-Options/Referrer-Policy/COOP/CORP/HSTS` security headers. Both new middlewares are wired into admin and proxy `*Middlewares` structs.
- [x] 3.5 `pkg/api/handler/http/{health,version}_handler.go`: `/healthz`, `/readyz` (port AG) + `/__/version` exposing `version.GetInfo()`.

## Phase 4: Admin & proxy adapters <!-- RUN-301 -->

- [x] 4.1 `pkg/server/router/admin_router.go`: `NewAdminRouter` mounts `/healthz`, `/readyz`, `/__/version` + middleware chain.
- [x] 4.2 `pkg/server/router/proxy_router.go`: `NewProxyRouter` mounts `/healthz`, `/readyz` + middleware chain. (Traffic forwarder lands in B.x.)

## Phase 5: Dependency injection <!-- RUN-300, RUN-302 -->

- [x] 5.1 `pkg/container/container.go`: `Container`, `New(opts...)`, `Provide`, `Invoke(fn)` over `dig.Container`. (Renamed from `pkg/dependency_container` for brevity.)
- [x] 5.2 `pkg/container/options.go`: `Option`, `WithModule`, `WithOverride(decorator)` → `dig.Decorate`.
- [x] 5.3 `pkg/container/modules/{core,telemetry,cache}.go`: logger, config, db, migrations, redis, kafka, metrics/tracer placeholders.
- [x] 5.4 `pkg/container/modules/api.go`: per-route handlers + each cross-cutting middleware as its own singleton (RequestID, PanicRecover, AccessLog). Per-server `*middleware.Transport` is composed by `server_admin` / `server_proxy`, never by `api`.
- [x] 5.5 `pkg/container/modules/{auth,policy,plugins,gateway,backend,consumer}.go`: empty `Module` stubs for B.x.
- [x] 5.6 `pkg/container/modules/{server_admin,server_proxy}.go`: each registers its own `Transport`, `ServerRouter`, and `Server` under `dig.Name("admin"|"proxy")`. Admin and proxy can run **different middleware chains** by editing only their own `*Middlewares` struct + `*Transport` composer in the corresponding module. `modules.All()` aggregates the full set.

## Phase 6: CLI <!-- RUN-326 -->

**Rewritten (user-locked 2026-05-27): no cobra, no subcommands; admin and proxy run in separate processes.** AgentGateway is a single-purpose binary that mirrors `AgentGuardian/cmd/api/main.go` for boot shape and `TrustGate/cmd/gateway/main.go` for server selection. Migrations always run on boot. `argv[1]` selects which server to run (default: `proxy`) — in production each pod runs one container with the appropriate argument.

- [x] 6.1 `cmd/agentgateway/main.go`: `godotenv.Load` → `container.New(modules.All()...)` → `c.Invoke(runMigrations)` → `c.Invoke(runAdmin|runProxy)`; blank-imports the migrations package. Failures before `runServer` exit via `log.Fatalf`; failures inside the server goroutine log via slog and `os.Exit(1)`.
- [x] 6.2 `runMigrations(*database.MigrationsManager, *slog.Logger)` — 30s timeout, calls `ApplyPending`.
- [x] 6.3 `runAdmin` / `runProxy` resolve only the named `server.Server` they need via `dig.In` + `dig.Name`. Single `runServer` helper launches the goroutine, traps SIGINT/SIGTERM, and calls `Shutdown()`.
- [x] 6.4 Build info exposed via `/__/version` only; no CLI command. Operators read it from logs or the HTTP endpoint.
- [x] 6.5 Convenience targets `make run-admin` / `make run-proxy` plus Dockerfile `CMD ["proxy"]` default; k8s manifests override via `args: ["admin"]` for the admin pod.

## Phase 7: Dev tooling <!-- RUN-330, RUN-331, RUN-332 -->

- [x] 7.1 `Makefile`: `build/test/test-race/test-cover/lint/fmt/tidy/run/migrate/docker-build/docker-push/compose-{up,down,logs}/version/help`; ldflag injects version.
- [x] 7.2 `Dockerfile` multi-stage `golang:1.26-bookworm` → `gcr.io/distroless/static-debian12:nonroot` + `.dockerignore`.
- [x] 7.3 `docker-compose.yaml`: pg/redis/clickhouse/`cp-zookeeper:7.6.0`/`cp-kafka:7.6.0`/agentgateway; healthchecks on every service; `depends_on: service_healthy`.
- [x] 7.4 `.github/workflows/ci.yml`: NeuralTrust/workflows reusable `tests.yml` (lint+coverage) + `sast.yml` (gosec).
- [x] 7.5 `.golangci.yml`: AgentGuardian-aligned linter set (errcheck, govet, ineffassign, staticcheck, unused).

## Phase 8: Docs <!-- RUN-329 -->

- [x] 8.1 `README.md`: quickstart, layout, migrations note, argv server selection.
- [x] 8.2 `.agents/AGENT.md`: canonical orientation for AI agents and new contributors — what the repo is, two-server boot, hexagonal layout + dependency direction, dig conventions (named providers, per-server middleware composition, `WithOverride` for tests), middleware contract, config rules, migrations + `WithTx`, logging, testing conventions, "where do I put X" decision table, commit/PR conventions, and pointers to reference repos.

## Phase 9: Tests & verification

- [x] 9.1 `pkg/config/config_test.go`: defaults applied, env overrides, duration parsing, invalid-int fallback, Validate fires for blank required fields — `http-server:Configuration Validation`.
- [x] 9.5 `pkg/container/container_test.go`: `WithModule` ordering + `WithOverride` swaps provider + context propagation — `dependency-injection:Test Overrides`.
- [x] 9.6 `go build ./...`, `go vet ./...`, `go test -race ./...` all green; `golangci-lint run ./...` → `0 issues.`
- [x] CLI smoke: `agentgateway version` + `agentgateway --help` + boot-fail emits structured `ERROR boot failure component=migrations error=...` and exits 1 — `cli-entrypoint:Boot Failure Reporting, Subcommand Surface, Server Selection, Version Reporting`.
- [ ] 9.2 `pkg/api/middleware/*_test.go` (panic→500, req-id propagation, access-log fields) — deferred to B.1 with first real HTTP integration (Fiber test harness lands alongside actual routes).
- [ ] 9.3 `pkg/infra/database/*_test.go` (pgx `WithTx` rollback, migration runner integration) — deferred to B.1; needs a live Postgres (or `pgxmock`). The `WithTx` helper itself is shipped in B.0 (task 2.6), but it gates on a `PG_TEST_URL` env var in CI which we'll add with the first repository implementation.

## PR Budget Forecast

Per-phase line estimate (additions+deletions; all new files):

| Phase | Capability | Files | Est. |
|---|---|---|---|
| 1 | foundation | 7 (logger port 168 + go.mod/sum + 3 .keep) | ~430 |
| 2 | config + database-infra | 6 | ~280 |
| 3 | http-server core | 6 | ~210 |
| 4 | admin/proxy | 4 | ~160 |
| 5 | dependency-injection | 13 | ~390 |
| 6 | cli-entrypoint | 5 | ~210 |
| 7 | dev-tooling | 6 | ~450 |
| 8 | docs | 2 | ~270 |
| 9 | tests | 5 | ~250 |

**Total: ~2,650 lines** (range 2,400–2,900).

**Decision (user-locked 2026-05-27): `single-pr-with-size-exception`.** Override of subagent's `chained-stacked` recommendation.

**Rationale**: B.0 is 100% greenfield scaffolding — Dockerfile, compose, CI yml, golangci config, dig stubs, `.keep` markers, markdown docs, and a byte-for-byte TrustGate logger port. Cognitive load per line is low; reviewer fatigue is mitigated by phase-by-phase commit history (one commit per phase, see "Commit Plan" below). B.1+ slices ship as normal-sized PRs.

**PR meta**:
- Label: `size:exception`
- Body must include: forecast (~2,650 lines), this rationale, and a phase→file index so reviewers can jump.

### Commit Plan (single-PR, reviewable history)

One commit per phase to give the reviewer a clean phase-by-phase narrative inside the PR. Conventional Commits per `_base.mdc`:

| Commit | Phase | Subject |
|---|---|---|
| 1 | 1 | `chore(scaffold): bootstrap module, version, errors, logger port` |
| 2 | 2 | `feat(infra): viper config + gorm pool + migrations runner` |
| 3 | 3 | `feat(server): Fiber server interface, router, base middleware, health` |
| 4 | 4 | `feat(server): admin and proxy server adapters` |
| 5 | 5 | `feat(di): dig container, modules, override harness` |
| 6 | 6 | `feat(cli): cobra entrypoint with run-server, run-migrations, version` |
| 7 | 7 | `chore(tooling): Makefile, Dockerfile, docker-compose, CI, golangci` |
| 8 | 8 | `docs: AGENT.md and README quickstart` |
| 9 | 9 | `test: per-capability unit and integration tests` |
