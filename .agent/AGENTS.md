# TrustGate — Agent Guidelines

Meta-guidance for AI agents working in this repository. This is the only
project-local agent guidance file; repository-specific conventions live here
instead of in local skills.

## Stack & Context

- **Language**: Go 1.26
- **Architecture**: Hexagonal (ports & adapters). Code lives under `pkg/`.
- **Role**: API gateway with HTTP/WebSocket handlers, pluggable upstreams,
  cache, audit, and Prometheus instrumentation.

## Recommended External Skills

The repository no longer ships local skills under `.agent/skills/`. Use the
globally installed Go skills when they are available:

| Skill | Activate when… | Source of truth for… |
|---|---|---|
| `golang-pro` | Designing concurrency (goroutines, channels, contexts), gRPC services, performance-critical paths, generics, benchmarks, table-driven tests with `-race`. | Concurrency patterns, performance, gRPC, profiling with pprof. |
| `golang-patterns` | Writing any new Go code, refactoring existing code, choosing between interfaces vs concrete types, error wrapping, package design. | Idiomatic Go, error handling, interface design, naming conventions. |

**Decision flow**:

```
New code in pkg/?              → follow the TrustGate architecture rules below
                                  + golang-patterns (always)
                                  + golang-pro (if concurrency / perf)

Refactor in pkg/?              → TrustGate architecture rules + golang-patterns

Pure utility / cmd / scripts?  → golang-patterns
                                  + golang-pro (if applicable)
```

If a recommendation from one skill seems to contradict another, the order
of precedence is:

1. This `AGENTS.md` file (project-specific architecture wins).
2. `golang-patterns` (idiomatic Go baseline).
3. `golang-pro` (advanced patterns, applied only when the simpler approach
   is insufficient).

## TrustGate Architecture Rules

- Keep hexagonal boundaries strict: domain defines entities and ports, infra
  implements adapters, handlers translate transport concerns, and dependency
  wiring lives in `pkg/dependency_container/`.
- Place use-case behavior in `pkg/app/<bounded-context>/` using the local
  Creator/Updater/Finder/Deleter style where it already exists.
- Keep domain packages free of infra, logging, HTTP, cache, database, and
  framework imports.
- Repositories are ports at the consumer boundary. App services should depend
  on the smallest role-specific interface needed for the use case.
- Entity construction should follow the existing builder/validation pattern
  for sibling bounded contexts such as `forwarding_rule` and `upstream`.

## Cross-Cutting Principles

These apply to EVERY change, regardless of which skills are active.

### Clean Code

- **Names reveal intent**. `rule.UpstreamID` not `rule.UID`. `createForwardingRule`
  not `doCreate`. If the name needs a comment to explain it, rename it.
- **Small functions**. A function should do one thing at one level of
  abstraction. If you need to scroll, split it.
- **No magic literals**. Move HTTP status codes, timeouts, cache key
  patterns, and env-var names to named constants in a sensible package.
- **Comments explain WHY, not WHAT**. The code already says what it does.
  Comments belong on non-obvious tradeoffs, gotchas, and references to
  external constraints (RFCs, vendor quirks, migration history).
- **Errors carry context**. Wrap with `fmt.Errorf("create rule: %w", err)`,
  never bare-return. Domain errors live in `pkg/domain/errors.go` and are
  matched with `errors.Is` / `errors.As`.
- **No dead code**. If it's not called, delete it. Git remembers.

### SOLID — applied to Go

| Principle | What it means here |
|---|---|
| **S** — Single Responsibility | One Creator per entity. One Repository interface per aggregate. One handler per route. If a struct has more than ~5 fields of unrelated concerns, split it. |
| **O** — Open/Closed | Extend behavior via new implementations of existing interfaces (e.g. new `Upstream` strategy), not by editing the consumer. Use the registry/factory pattern already established in `pkg/app/` for pluggable behavior. |
| **L** — Liskov Substitution | Any implementation of a repository or finder interface MUST honor the same contract (error semantics, nil handling, context cancellation). Tests with mocks must pass against real adapters too. |
| **I** — Interface Segregation | Define small, role-based interfaces at the **consumer** side, not on the implementation side. `pkg/app/rule/creator.go` should depend on a `upstream.Finder` with one method, not on a fat `upstream.Repository`. |
| **D** — Dependency Inversion | Domain defines interfaces (ports). Infra implements them (adapters). Wiring happens ONLY in `pkg/dependency_container/`. No `pkg/domain/**` file may import `pkg/infra/**`. |

### Concretely Forbidden

- God structs (`Service` holding 15 fields across unrelated concerns).
- Anonymous structs leaking out of a function as a public API.
- Direct `gorm.DB` calls from `pkg/app/**` or `pkg/handlers/**`. Go through
  the repository port.
- Logging from `pkg/domain/**`. Domain is pure; observability is an adapter
  concern.
- `panic` in request paths. Return errors, let middleware convert to HTTP.
- Mutating package-level globals after `init()`.
- Comments that narrate the next line of code.

### Testing Baseline

- **Domain entities**: table-driven tests for `Validate()` and builder
  invariants. No mocks needed — pure logic.
- **App services**: mock the repository ports; assert on returned errors
  (`errors.Is(err, domain.ErrXxx)`) and on the repository call shape.
- **Handlers**: integration-style tests via httptest, mocking only the
  outermost adapters (cache, external HTTP).
- **Migrations & repositories**: testcontainers (Postgres) — no SQLite
  fakes, the dialect differences bite later.
- Always run with `-race`. Concurrency bugs found in CI cost 10x more.

## When in Doubt

1. Look at a sibling bounded context (e.g. `forwarding_rule`, `upstream`)
   for the established pattern, and follow it.
2. If the established pattern is wrong, raise it in a SDD change proposal
   — don't fix it inline as a side effect of another change.

## Workflow Integration

For non-trivial changes, follow the SDD workflow already configured in
this repo (`openspec/` + the installed `sdd-*` skills). If a change is linked
to Linear, mirror the task breakdown after `sdd-tasks`.

### Changelog & openspec/fixes

The repository auto-feeds `CHANGELOG.md` from openspec proposals. Concretely:

- Every PR that lands a substantive change MUST include a `proposal.md`
  under `openspec/changes/<name>/` (full SDD flow) or `openspec/fixes/<name>/`
  (quick fixes that don't warrant the full spec/design/tasks loop). Both
  shapes share the same frontmatter contract.
- Required frontmatter fields:

  ```yaml
  ---
  linear: ENG-XXX          # optional; links the issue in the changelog
  type: breaking           # required: breaking | feat | fix | refactor | perf | chore | docs | security
  changelog: "One-line summary that ends up in CHANGELOG.md."
  ---
  ```

- `type` maps to a Keep-a-Changelog section: `breaking → Breaking`,
  `feat → Added`, `fix → Fixed`, `refactor`/`perf`/`chore → Changed`,
  `docs → Docs`, `security → Security`.
- `changelog:` is a single line. If missing, the workflow falls back to the
  `# Proposal: <title>` H1 of the proposal.
- On PR merge to `main`, `.github/workflows/changelog.yml` appends the entry
  under `## [Unreleased]` in `CHANGELOG.md`. Auto-release later promotes
  the Unreleased block to `## [vX.Y.Z] — YYYY-MM-DD` when it cuts the tag.
- Do not edit `## [Unreleased]` by hand — the workflow is the source of
  truth and dedupes on `(#PR, change-name)`.

## Git Discipline

- **NEVER commit without explicit user permission.** Do not run `git commit`,
  `git push`, `git merge`, `git rebase`, or any history-rewriting command on
  your own initiative. Even after a "fix" or completed task, stop and wait.
- Staging (`git add`) is also off-limits unless the user asks for it or
  asks you to commit (in which case you may stage and commit in one flow).
- When the user does ask for a commit, follow the standard rules: review
  staged changes, draft a message reflecting the WHY, never include secrets,
  never use `--no-verify`, never amend pushed commits.
- If unsure whether the user wants a commit, ASK. "Want me to commit this?"
  is always the correct fallback.
