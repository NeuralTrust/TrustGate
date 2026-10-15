# TrustGate rules

Read the sources from the reviewed tree (they move with `develop`). This file is
an index plus the checks most often broken; the sources win on conflict.

## Sources (read before reviewing)

| Source | Covers |
|---|---|
| `<tree>/.agents/AGENTS.md` | Layout, hexagonal rules, DI, DTO placement, config, logging, data-plane invariants, DB-less, comments, work gates |
| `<tree>/.cursor/rules/*.mdc` | Path-scoped rules, e.g. `telemetry-event-contract.mdc` for telemetry/metrics paths |
| `<tree>/.golangci.yml`, `.github/workflows/ci.yml` | What CI enforces (golangci, gosec high, license headers, functional tests with `-race`) |
| `<tree>/scripts/check-comments.sh` | Mechanical comment guard run by the pre-commit hook |

Optional, if present on the host (NeuralTrust agent baseline):

| Source | Covers |
|---|---|
| `~/.cursor/rules/golang.mdc`, `go-comments.mdc` | Go conventions, comment policy |
| `~/.cursor/rules/work-gates.mdc`, `pr-metadata-validation.mdc` | Branch, PR title/body, Linear id |
| `~/.cursor/skills/trustgate-hexagonal/SKILL.md` | Use case / repository / handler patterns (older paths: map `pkg/handlers` → `pkg/api/handler`, `dependency_container` → `pkg/container/modules`) |

## High-frequency checks

Architecture
- `pkg/app` must not import `pgx`, `fiber` or `pkg/infra/*`; `fiber` only in `pkg/api/{middleware,handler}` and `pkg/server`.
- One use case per file in `pkg/app/<entity>/`, order: sentinels → `//go:generate mockery` → interface → unexported struct + `New<Iface>` → methods. No `interfaces.go` aggregates.
- Mocks generated, never hand-written, at `pkg/app/<entity>/mocks/<entity>_<usecase>_mock.go`.
- DTOs: one per file under `pkg/api/handler/http/<entity>/{request,response}/`; DTOs never import infra.
- DI: one module file per context in `pkg/container/modules/`; segregated interfaces need a view provider; added to the right module set (`fullModules` / `dataPlaneModules`); never `dig.Decorate` to swap Postgres.

Go
- `ctx` first param on I/O, never stored; errors wrapped with `%w`; no `_ =` without a reason.
- `log/slog` with named attrs, no `fmt.Sprintf` in messages, no `slog.SetDefault` outside `modules.Core`.
- Config only via `pkg/config` (const default → field → getter → `Validate()` → `.env.example`); no scattered `os.Getenv`.
- Multi-statement writes through `database.WithTx`.

Comments
- Only exported doc comments, package comments, directives, license headers, swagger annotations, rare "why" with ticket ref.
- Forbidden: narrative, banners, commented-out code, TODO/FIXME/XXX/HACK, change-explaining comments.
- gosec false positives: inline `#nosec Gxxx -- reason` is the repo convention.

Contracts
- Handler changes keep swagger annotations in sync; API change → `make docs` output in its own commit.
- Telemetry/metrics paths: additive-only attribute keys, keys as constants, contract doc updated, `pkg/metrics` column changes need version bump + migration.
- Proto changes regenerated with `make proto`, never hand-edited.
- New env var present in `.env.example` and, if required, in `Validate()`.

PR hygiene
- Title Conventional Commits with Linear id (`RUN-###` / `ENG-###`); one shippable slice (soft cap 400 lines).
- Base: feature work → `develop`; only prod hotfixes → `main`. Never a develop→main promotion.
- New code paths have tests; concurrency paths exercised under `-race`.
- No `.cursor/`, `openspec/` scratch, `.env*` or Claude attribution in the PR.
