# Proposal: B.0 Project Setup & Scaffolding (RUN-282)

## Intent

AgentGateway is greenfield (only `.gitignore`). Land foundational scaffolding so downstream B.x slices have a TrustGate-shaped home. Covers RUN-282 and its 11 sub-issues.

## Scope

### In Scope (Linear Mapping)

Each sub-issue lands one piece of B.0. Empty `pkg/` leaves get a `doc.go`.

| Issue | One-liner |
|---|---|
| RUN-326 | `main.go` + CLI subcommands |
| RUN-327 | DB infra (conn, migrations, tx) |
| RUN-328 | Fiber servers + middleware + config |
| RUN-329 | `.agents/AGENT.md` conventions |
| RUN-330 | Makefile targets |
| RUN-331 | Dockerfile + compose |
| RUN-332 | CI (lint/test/build) |
| RUN-333 | `pkg/` hexagonal skeleton |
| RUN-300 | dig container + modules |
| RUN-301 | Admin vs proxy wiring |
| RUN-302 | Test harness w/ overrides |

### Out of Scope
- Entity schemas / business logic (B.1–B.9)
- Helm, production deploy, observability stack

## Capabilities

### New Capabilities
- `cli-entrypoint`: binary + subcommands + flags + version
- `database-infra`: pool, migrations runner, tx helpers
- `http-server`: Fiber admin/proxy servers, middleware, config loader
- `dependency-injection`: dig container, per-context modules, test overrides
- `dev-tooling`: Makefile, Dockerfile, compose, CI, `AGENT.md`

### Modified Capabilities
- None (first spec drop for this repo).

## Approach

Mirror TrustGate's hexagonal layout (`pkg/{app,domain,handlers,infra,server,common,config,dependency_container}`) and `cmd/` + Makefile + compose shape. Fiber for HTTP, `uber/dig` for wiring. Each bounded context exports `Module()`; admin and proxy compose disjoint subsets so they can run as one or two processes. Test harness reuses the container via override hooks.

## Affected Areas

All **New** (greenfield).

| Area | Description |
|---|---|
| `cmd/gateway/` | Binary entrypoint + subcommands |
| `pkg/{app,domain,common,version}/` | Hexagonal layers + build info |
| `pkg/handlers/{http,websocket}/` | Transport adapters (empty) |
| `pkg/infra/database/` | Pool, migrations, tx helpers |
| `pkg/server/{admin,proxy,middleware,router}/` | Fiber servers + middleware |
| `pkg/config/` | Env + file loader |
| `pkg/dependency_container/` | dig root, modules, overrides |
| `Makefile` | run/test/lint/build/migrate/docker |
| `Dockerfile`, `docker-compose.yaml` | Multi-stage build + Postgres/Redis/Kafka/ClickHouse |
| `.github/workflows/ci.yml` | Lint + test + build |
| `.agents/AGENT.md` | Project + Go conventions |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Layout drifts from TrustGate | Med | Document in `AGENT.md`; cross-link in PR |
| dig wiring hard to follow as modules grow | Med | One `Module()` per context, `doc.go` in `dependency_container/` |
| Compose flakiness on dev machines | Low | Pin image tags; healthchecks gate gateway start |

## Rollback Plan

Greenfield drop — no prior state. Revert the merge commit or `git reset --hard <pre-PR sha>` on `main`. No data migrations, no provisioned externals.

## Dependencies

- Go toolchain, `golangci-lint`, Docker + Compose
- TrustGate layout as conceptual reference (no code reuse)

## Success Criteria

- [x] `make test` green on empty project
- [x] `docker compose up` boots Postgres + Redis + Kafka; gateway connects (ClickHouse + in-compose gateway dropped — see Delivery Notes #3)
- [x] CI runs lint + test + build on every PR
- [x] Folder layout matches `AGENT.md`
- [x] Admin and proxy each boot via `./agentgateway admin` / `./agentgateway proxy` (argv-based, not flag-based — see Delivery Notes #2)

## Delivery Notes (2026-05-27, archived)

The change shipped with several deliberate deviations from the original
proposal / specs. They were locked by user decision during implementation
and are recorded here so the archived change stays internally consistent
with the working tree.

1. **Toolchain pinned to Go 1.26** (proposal was version-agnostic). `go.mod`
   declares `go 1.26`; Dockerfile uses `golang:1.26-bookworm`.

2. **No CLI subcommands.** The original `cli-entrypoint` capability called
   for `cobra` with `run-server` / `run-migrations` / `version` subcommands
   and `--server admin|proxy|both`. Final shape mirrors TrustGate's
   `cmd/gateway/main.go`: a flat `main()`, no cobra, `argv[1]` selects
   `admin` or `proxy` (default `proxy`), and migrations always run on boot.
   `specs/cli-entrypoint/spec.md` describes the original surface and is
   retained for history but is **superseded** by the Phase 6 user-lock
   captured in `tasks.md`.

3. **Compose drops ClickHouse and the in-compose `agentgateway` service.**
   The original `dev-tooling` capability called for pg + redis + kafka +
   clickhouse + gateway, mirroring TrustGate. User confirmed ClickHouse
   is not needed at B.0 (no telemetry sink yet) and the gateway runs
   locally via `make run-admin` / `make run-proxy`. Compose now boots
   pg + redis + zookeeper + kafka only.

4. **Logger / config / database stack uses AgentGuardian conventions, not
   TrustGate.** `log/slog` + custom handler stack (not `logrus`), env-only
   `os.Getenv` + `godotenv` (not `viper` + YAML), `pgx/v5` + `pgxpool`
   + in-code Go migrations (not `gorm` + `golang-migrate`). The
   `database-infra` spec lists `WithTx` over `pgx.Tx` as the transaction
   abstraction; `gorm`-style scopes are not provided.

5. **Layout differs from the proposal's `Affected Areas` table.** Final
   layout uses `pkg/api/handler/http`, `pkg/api/handler/websocket`,
   `pkg/api/middleware`, and `pkg/container` (not `pkg/handlers/*`,
   `pkg/server/middleware`, `pkg/dependency_container`). `.agents/AGENT.md`
   §3 and `tasks.md` Phase 5 are authoritative for the shipped layout;
   the table above is left untouched for historical context.

6. **Per-server middleware composition.** Admin and proxy each register
   their own `*middleware.Transport` under `dig.Name("admin")` /
   `dig.Name("proxy")`, composed from the same singleton middlewares.
   Different middleware chains per server are an explicit affordance and
   documented in `AGENT.md` §4.

7. **Known acknowledged gaps deferred past archive.** Recorded as residual
   items by `sdd-verify` and accepted by the user (option B at archive
   time): `make test` does not invoke lint (covered by `make lint` and
   CI); pre-server boot failures use stdlib `log.Fatalf` (the slog logger
   is not yet constructed at that point); `pkg/api/handler/websocket/.keep`
   was not added in B.0; `Migration.Down` is declared but unused; argv
   validation is permissive (`./agentgateway adimn` boots a proxy);
   `ErrInvalidHandlerTransport` is referenced in `tasks.md` 3.3 but never
   defined. These do not block any downstream B.x slice and will be
   revisited in the first follow-up B.x change that touches the affected
   code path.
