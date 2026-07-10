# TrustGate — Agent guide

AI gateway for LLM/MCP traffic: a stateless data plane (proxy, MCP) plus an admin
plane, wired with `uber/dig` and built in Go on a hexagonal architecture.

**Instruction priority:** Work gates (`work-gates.mdc`) > user instructions > these conventions.

## Repo layout

```
cmd/trustgate/   # entrypoint: server selection (admin | proxy | mcp) + DI build
pkg/
  api/           # driving adapters: HTTP handlers, middleware, routers
    handler/http/httpio/  # shared HTTP request-decode + response-encode helpers
  app/           # application core: use cases (proxy, consumer, oauth, metrics, plugins, ...)
  domain/        # entities, value objects, repository ports — no framework/infra imports
  infra/         # driven adapters: DB repositories, cache, providers/adapter, loadbalancer, plugins
  runtimeconfig/ # DB-less snapshot data plane (config sync + snapshot repositories)
  container/     # composition root: dig wrapper + modules/* wiring
  config/        # env-var config
  server/        # server lifecycle
```

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

See `.agents/skills/` (`trustgate-hexagonal`) for patterns.

## Go rules (binding)

- `gofmt` + `goimports`; `make lint` (`golangci-lint`) and `make fmt` (`gofmt` + `go vet`) clean before done.
- `ctx context.Context` is the **first parameter** on I/O/blocking calls — never stored in a struct.
- Errors are values: handle every error; wrap with `%w`; sentinels via `errors.New` + `errors.Is`.
- Every goroutine has an explicit lifecycle (start/stop/join) and honors `ctx.Done()`; no leaks.
- Concurrency-sensitive code is tested with `-race` (`make test-race`).
- Config via env vars (`pkg/config`); no hardcoded addrs/timeouts scattered as `os.Getenv`.

## Code comments policy (strict)

Mirrors `go-comments.mdc`, plus the swagger exception below.

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

Rule of thumb: if a comment wouldn't survive review as adding real value, don't write it. The
`scripts/check-comments.sh` guard (run from the pre-commit hook) blocks the mechanical offenders
(banner dividers, commented-out code) on staged Go files while exempting license/directives/swagger.

## Commands

```bash
make fmt            # gofmt + go vet
make lint           # golangci-lint
make test           # unit tests
make test-race      # unit tests with the race detector
make generate       # go generate (mocks etc.)
make swagger        # regenerate Swagger 2.0 from handler annotations
make docs           # Swagger 2.0 + OpenAPI 3
make install-pre-commit  # install scripts/pre-commit.sh into .git/hooks
```

## Work gates

- Feature branches only. **Never commit/push on `main`/`master`/`develop`.**
- **Commit only when the user explicitly asks.** Conventional Commits: `type(scope): subject`.
- New code paths need tests unless `WIP`/docs-only; run `-race` for concurrency paths.
- Never commit secrets; `.env*` is never read/written/referenced in code.
- Full gate details: `work-gates.mdc`.
