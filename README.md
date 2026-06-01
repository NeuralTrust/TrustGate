# AgentGateway

NeuralTrust **AgentGateway** is the data-plane runtime that fronts LLM and agent traffic. It exposes an **admin** plane and a **proxy** plane, each run as a separate process.

> Architectural scaffolding only — this repo currently ships **B.0**. Business behaviour (routes, services, upstreams, plugins, policies) lands in B.x.

## Quickstart

```bash
# 1. Copy the env template and adjust as needed.
cp .env.example .env

# 2. Boot the local dev infra (Postgres, Redis, Kafka, Zookeeper).
make compose-up

# 3. Run the admin and the proxy in two separate terminals.
make run-admin      # terminal 1 — applies migrations, starts admin on :8080
make run-proxy      # terminal 2 — applies migrations, starts proxy on :8081

# 4. Hit the health probes.
curl localhost:8080/healthz   # admin
curl localhost:8081/healthz   # proxy
curl localhost:8080/__/version
```

The `agentgateway` binary itself runs from your local machine so you can
attach a debugger and iterate without rebuilding the docker image. `make
compose-down` stops the infra stack (and `-v` wipes the volumes).

### Run everything in Docker

To run the admin and proxy servers as containers alongside the infra stack
(no local Go toolchain needed), use `make run-servers`. It combines
`docker-compose.yaml` (Postgres, Redis, Kafka, Zookeeper) with
`docker-compose.api.yaml` (admin on :8080, proxy on :8081):

```bash
make run-servers              # build + start the full stack and both servers
docker compose -f docker-compose.yaml -f docker-compose.api.yaml logs -f
docker compose -f docker-compose.yaml -f docker-compose.api.yaml down
```

The server containers load `.env` and override the host-based defaults
(`DB_HOST`, `REDIS_HOST`, `KAFKA_BROKERS`) so they reach the compose services
by hostname. If your private NeuralTrust modules need auth at build time,
export `GITHUB_TOKEN` before running.

> The image is pinned to `linux/amd64`: `confluent-kafka-go` v1.9.2 only
> bundles an amd64 `librdkafka`, so on Apple Silicon the build/run happens
> under emulation (slower first build, but it works out of the box).

## Boot sequence

`agentgateway` has no subcommands. Each invocation runs **one** HTTP server,
selected by `argv[1]` (default: `proxy`):

```bash
./agentgateway              # → proxy (default, matches TrustGate)
./agentgateway proxy        # → proxy
./agentgateway admin        # → admin
```

In production each pod runs one container with the appropriate argument so
admin and proxy can scale independently.

Boot sequence (identical for both servers):

1. Load `.env` if present (silently ignored otherwise).
2. Build the DI container from `modules.All()`.
3. Apply pending database migrations (30s timeout).
4. Start the selected HTTP server in its own goroutine.
5. On SIGINT/SIGTERM, call `Shutdown()` on the server and exit.

Any failure in steps 1–3 exits non-zero with a `log.Fatal` line; failures
inside the server goroutine log via slog and exit non-zero.

## Local development

```bash
make build           # compile bin/agentgateway with version ldflags
make run             # build + run proxy (alias for run-proxy)
make run-admin       # build + run admin server
make run-proxy       # build + run proxy server
make run-servers     # build + run full stack and both servers in docker
make test            # go test ./pkg/...
make test-race       # with -race
make test-cover      # with coverage profile
make lint            # golangci-lint
make fmt             # gofmt + go vet
```

The full target list is in the `Makefile`; `make help` prints it.

## Repository layout

```
cmd/agentgateway/      # entry point
pkg/version/           # ldflag-fed build info
pkg/common/errors/     # cross-package sentinel errors
pkg/config/            # env-only config loader (.env via godotenv in dev)
pkg/domain/            # domain entities, value objects and port interfaces
pkg/app/               # application services (use cases)
pkg/infra/logger/      # log/slog multi/async/source-filter/colored handlers
pkg/infra/database/    # pgx/v5 pgxpool + in-code Go migrations registry
pkg/api/handler/http/  # per-route HTTP handlers (health, version)
pkg/api/middleware/    # request_id, access_log, panic_recover (slog-based)
pkg/server/            # Server interface + BaseServer (Fiber tuning) + httpServer
pkg/server/router/     # ServerRouter contract + admin / proxy routers
pkg/container/         # dig wrapper + Module contract
pkg/container/modules/ # one file per DI context (core, api, server_admin, ...)
```

## Configuration

All configuration is read from environment variables. In development copy `.env.example` to `.env`; `godotenv` loads it automatically. Production deployments inject env vars directly (Helm values, ECS task def, k8s ConfigMap+Secret).

See `.env.example` for the full set with safe defaults.

## Migrations

Migrations are **in-code Go files** under `pkg/infra/database/migrations/`. Each file is named `<unix_timestamp>_<snake_name>.go` and calls `database.RegisterMigration` from its `init()`. The runner is `pgx`-backed and commits each migration's DDL plus its `migration_version` row in a single transaction. The pattern is a direct port of the NeuralTrust AgentGuardian system.

## License

Copyright © NeuralTrust. All rights reserved.
