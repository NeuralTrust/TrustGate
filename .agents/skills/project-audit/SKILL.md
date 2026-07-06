---
name: project-audit
description: >-
  Audit a whole Go project for SOLID, clean code, code smells, good practices &
  patterns, Go conventions, and concurrency/performance (race conditions,
  concurrency misuse, latency optimization), validating it against a chosen
  architecture profile (hexagonal, go-library, cqrs, clean-architecture,
  layered, event-driven, microservice). Also runs a write sub-agent that strips
  novel/narrative code comments, keeping only strictly necessary ones. Trigger:
  "/project-audit
  [hexagonal|go-library|cqrs]", "audita el proyecto", "code audit", "auditoría
  SOLID / clean code / arquitectura". Forces one dedicated sub-agent per audit
  category and aggregates a single report.
license: Apache-2.0
metadata:
  author: neuraltrust
  version: "1.0"
---

# Project Audit

You are the AUDIT ORCHESTRATOR. Audit the **entire** project against five
quality axes, validated for the declared architecture. You do NOT read the code
yourself for the findings — you MUST delegate each axis to its own sub-agent and
then merge their reports.

## Activation Contract

Invoked as `/project-audit [architecture]` where `architecture` is one of:

| Value | Meaning |
|---|---|
| `hexagonal` | Ports & adapters (domain / app / infra / handlers + composition root) |
| `go-library` | Reusable Go library / package (idiomatic package design, minimal public API) |
| `cqrs` | Command Query Responsibility Segregation (separate command/query handlers & models) |
| `clean-architecture` | Concentric layers with the dependency rule (entities → use cases → adapters → frameworks) |
| `layered` | Classic n-tier (presentation → business/service → data access) |
| `event-driven` | Producers/consumers over a message bus (events, handlers, projections) |
| `microservice` | Service with a versioned transport contract (gRPC/REST), independently deployable |

If the architecture argument is **missing or not one of the supported values**,
STOP and ask the user which profile applies before doing anything else. Never
guess the architecture.

## Hard Rules (non-negotiable)

1. **Exactly six sub-agents, one per category** — you MUST launch a separate
   sub-agent for each of:
   - `SOLID`
   - `CLEAN CODE`
   - `CODE SMELLS`
   - `GOOD PRACTICES & PATTERNS`
   - `GO CONVENTIONS`
   - `CONCURRENCY & PERFORMANCE`
   Never audit a category inline in this thread. Never merge two categories into
   one sub-agent.
2. **Launch them in parallel on a high-capability reasoning model** — issue all
   six `Task` calls in a single message. Each auditor MUST run on a top-tier
   reasoning model, **never** `composer-2.5-fast`: use
   **`claude-opus-4-8-thinking-high`** (preferred) or **`gpt-5.5-high`**, passing
   the `model:` field in every `Task` call. Use a **read-only** exploration
   sub-agent (prefer `explore`; use `generalPurpose` with `readonly: true` if
   `explore` is unavailable). The audit never modifies files. (Only the
   comment-cleanup sub-agent in Rule 7 uses the fast `composer-2.5-fast` model —
   it is mechanical; the six auditors need deep reasoning.)
3. **Whole-project scope** — each sub-agent audits the complete repository for
   its axis, not a single file or diff, unless the user explicitly scopes it.
4. **Inject context into every sub-agent** — pass (a) the selected architecture
   profile from this file, (b) the category brief for that agent, (c) the report
   contract, and (d) any repo `AGENT.md` / `.cursor/rules` conventions you found.
   Sub-agents cannot see this conversation; the prompt must be self-contained.
5. **Aggregate, don't editorialize** — after all six return, merge their
   findings into one report using the template below. Do not drop or soften
   findings; deduplicate overlaps and cross-reference them.
6. **Evidence required** — every finding must cite `path:line` (or `path` +
   symbol) so it is actionable. Instruct sub-agents to reject vague findings.
7. **Comment-cleanup sub-agent runs FIRST and alone (WRITE, Composer 2.5)** —
   before the six read-only auditors, you MUST launch ONE additional sub-agent
   that **edits the code** to strip novel/narrative comments, keeping only
   100%-necessary ones (see [Comment Cleanup](#comment-cleanup-write-phase)). It
   MUST run on the **`composer-2.5-fast`** model (pass `model:
   "composer-2.5-fast"` in the `Task` call). It is **not** read-only and runs in
   its **own phase**, never in the parallel read-only batch, so the audit line
   numbers stay stable. It edits comments only — never logic. Skip it only if the
   user explicitly asked for a pure read-only audit.

## Workflow

Copy this checklist and track progress:

```
- [ ] 1. Resolve architecture profile (arg → profile). Ask if missing/invalid.
- [ ] 2. Detect repo conventions (AGENT.md, .cursor/rules, Makefile, go.mod).
- [ ] 3. Comment-cleanup WRITE sub-agent (own phase, first). Skip if read-only asked.
- [ ] 4. Launch 6 read-only sub-agents in parallel (one per category).
- [ ] 5. Collect the 6 category reports.
- [ ] 6. Merge into a single audit report (template below).
- [ ] 7. Present verdict + prioritized remediation list (incl. cleanup summary).
```

**Step 1 — Profile.** Map the argument to the matching profile in
[Architecture Profiles](#architecture-profiles). Keep the full profile text; you
will paste it into each sub-agent prompt.

**Step 2 — Conventions.** Quickly locate `go.mod` (module path, Go version),
`Makefile` / `Taskfile` (lint/test/vet targets), and any `AGENT.md`,
`AGENTS.md`, or `.cursor/rules/*.mdc`. Repo rules OVERRIDE generic advice — e.g.
if `AGENT.md` forbids code comments, the GO CONVENTIONS agent must NOT flag
"missing doc comments" as an issue. Note the override in each prompt.

**Step 3 — Comment cleanup (WRITE, alone).** Launch the cleanup sub-agent (see
[Comment Cleanup](#comment-cleanup-write-phase)) and wait for it to finish before
anything else. Pass it the repo comment policy you detected in step 2. It edits
files; nothing else runs while it does. Capture its summary of what was removed.

**Step 4 — Delegate.** For each category, send a `Task` call (on the reasoning
model from Rule 2 — `claude-opus-4-8-thinking-high` or `gpt-5.5-high`) whose
prompt = architecture profile + category brief + repo conventions + report
contract + severity legend. Tell the agent to audit the whole module and return
ONLY its category report section.

**Step 5–7 — Merge & report.** Assemble the sections, compute the per-category
verdict and an overall verdict, then list the highest-severity items first, and
include the comment-cleanup summary in the report Notes.

## Category Briefs

Give each sub-agent the matching brief verbatim. Each brief is that agent's sole
responsibility.

### SOLID
Audit adherence to the five principles across packages:
- **S**ingle Responsibility — types/functions/packages with one reason to
  change; god-structs, "manager"/"service" catch-alls, multi-purpose files.
- **O**pen/Closed — behavior extended via new types/implementations, not by
  editing switch-ladders on a type tag scattered across the code.
- **L**iskov — implementations honor their interface contract; no
  `panic("not implemented")`, no nil-returns that violate the contract.
- **I**nterface Segregation — small, consumer-defined interfaces; flag fat
  interfaces (many methods) that force partial implementations.
- **D**ependency Inversion — high-level code depends on interfaces, not concrete
  infra; flag concrete DB/HTTP/SDK types wired into business logic.

### CLEAN CODE
Readability and maintainability: naming (intention-revealing, no `data`/`tmp`/
`mgr`), function length & nesting depth, argument counts, duplication (DRY),
dead code, magic numbers/strings vs named constants, error-handling clarity
(early returns / guard clauses vs deep nesting), consistent formatting, and
comment quality (respect the repo's comment policy — see conventions).

### CODE SMELLS
Structural smells: long methods, large classes/structs, feature envy,
inappropriate intimacy, shotgun surgery, primitive obsession, data clumps,
`util`/`common`/`helpers` grab-bag packages, cyclic dependencies, global mutable
state, boolean/flag arguments toggling behavior, leaky abstractions, temporal
coupling, and error swallowing (`_ = err`, ignored returns).

### GOOD PRACTICES & PATTERNS
Design & robustness: correct use of GoF/idiomatic patterns (factory,
strategy, options, decorator) vs over-engineering; dependency injection &
composition over inheritance; configuration handling; observability (structured
logging, metrics) and secrets hygiene (no secrets/PII in logs); resource
lifecycle (closing bodies/rows, context cancellation, goroutine ownership);
testability and test coverage of new code paths; API/versioning discipline.

### GO CONVENTIONS
Idiomatic Go & toolchain compliance:
- `gofmt`/`goimports` clean; `go vet ./...` and `golangci-lint run` clean.
- `ctx context.Context` as first param on I/O/blocking calls; ctx honored in
  select loops; never stored in structs.
- Errors as values: wrap with `%w`, sentinel/typed errors, `errors.Is/As`; no
  `panic` for normal errors.
- Small interfaces; accept interfaces, return structs.
- Table-driven tests, run with `-race`; every goroutine has an explicit
  start/stop/join lifecycle (no leaks).
- No reflection without justification; no naked returns in long functions; no
  `util`/`common` grab-bags.
- Package/identifier naming per Effective Go; exported-symbol docs **only if the
  repo policy allows comments** (some repos forbid all comments — respect that).

### CONCURRENCY & PERFORMANCE
Hunt for concurrency bugs and always push for lower latency. This axis is
mandatory on every audit regardless of architecture.

**Race conditions & concurrency misuse:**
- Shared mutable state accessed from multiple goroutines without
  synchronization; maps written concurrently (Go maps are not safe → panic);
  fields mutated without a mutex/atomic.
- Locking defects: forgotten `Unlock` (missing `defer`), copying a `sync.Mutex`/
  `sync.WaitGroup` by value, `RLock` held while writing, lock ordering that can
  deadlock, over-broad critical sections that serialize the hot path.
- Channel misuse: send on a closed channel, close from the receiver side, double
  close, unbuffered channels causing hidden blocking, `nil`-channel blocks.
- Goroutine lifecycle: goroutines started without a way to stop them (leaks),
  no `ctx.Done()` in select loops, `WaitGroup.Add` inside the goroutine, the
  loop-variable capture bug in `for … { go … }` (pre-Go 1.22), unbounded
  goroutine fan-out per request.
- `context` propagation: blocking calls without a context/deadline; ignoring
  cancellation.
- Recommend verifying with `go test -race ./...` and `go vet`; flag code paths
  that are concurrent but have no `-race` test.

**Performance & latency:**
- Hot-path allocations: avoidable allocations in loops, `[]byte`↔`string`
  conversions, missing slice/map pre-sizing, no `sync.Pool` for hot buffers.
- N+1 queries / per-item round trips; missing batching; queries inside loops;
  chatty external/RPC calls that could be parallelized or coalesced.
- Blocking I/O on the request path that could be async/cached; missing timeouts
  causing tail-latency blowups; serial work that is safely parallelizable.
- Lock contention on the hot path; a single global lock where sharding/atomics
  would scale; wrong data structure (linear scan where a map/index fits).
- Missing/ineffective caching, or caching that risks staleness; unbounded caches.
- Streaming vs buffering large payloads in memory; premature full reads.
- Recommend `pprof`/benchmarks (`testing.B`, `-benchmem`) to confirm before/after
  for any perf claim; never assert a speedup without a measurable basis.

Findings must name the goroutine/lock/channel or the specific hot path and cite
`path:line`, with a concrete, lower-latency or race-free fix.

## Comment Cleanup (WRITE phase)

This sub-agent **edits the code** to delete comments that read like novels and
keep only the ones that are 100% necessary. Run it on the **`composer-2.5-fast`**
model (`Task` call with `model: "composer-2.5-fast"`). Give it this brief:

> You are a comment-cleanup agent. Edit the whole module to remove
> narrative/"novel" comments and keep only strictly necessary ones. You MUST NOT
> change any code logic, behavior, names, or formatting other than the comments
> you remove or trim. Preserve blank-line/structure so diffs stay minimal.

**Follow the repo comment policy first (it wins):**
- If the repo policy forbids ALL comments (e.g. TrustGate `AGENT.md`: "DO NOT PUT
  CODE COMMENTS"), remove **every** comment except the tooling/compiler
  directives listed below. Do not keep doc comments even on exported symbols.
- Otherwise, keep only comments that carry information the code cannot: a
  non-obvious **why**, a trade-off/workaround with a ticket ref, a genuine gotcha,
  or a required license header.

**Always remove (unless a directive/header — see keep-list):**
- Multi-line prose blocks / banner headers that summarize a file, function, or
  change; `/* … */` paragraphs of explanation.
- Narrative `//` lines restating what the next line does (`// loop over items`,
  `// return the result`, `// increment counter`).
- Redundant doc comments that just repeat the symbol name/signature.
- Commented-out code (delete it — git remembers).
- Change-explanation comments ("we do it this way because the old approach…"),
  section dividers (`// === Helpers ===`), and `TODO`/`FIXME`/`XXX`/`HACK`
  markers without an issue reference.

**Always keep (never touch):**
- Tooling/compiler directives: `//go:generate`, `//go:build`/build tags,
  `//go:embed`, `//nolint:<rule>`, `// #nosec G…`, and other `//go:` pragmas.
- Required single-line license/copyright headers.
- The rare "why" comment described above (only when the repo allows comments).

**Safety:**
- Comments only. Zero behavior change. Do not delete a `//nolint`/`#nosec`
  directive even if it looks like prose — those change tool behavior.
- Do not run formatters that would reflow code; if the repo has `gofmt`, a
  comment-only removal already stays gofmt-clean.
- This phase edits the working tree but **does not commit** (see work gates).

Return a short summary: files touched, comment lines removed, and any borderline
comments kept with a one-line reason.

## Architecture Profiles

Paste the ONE that matches the argument into every sub-agent prompt so findings
are evaluated against the right structure.

### hexagonal
Ports & adapters. Expected layers and the one rule that must hold:

```
handlers/transport (driving adapters) → app (use cases) → domain ← infra (driven adapters)
composition root / DI wires everything
```

- **domain** imports only stdlib + shared errors — never framework, DB driver,
  HTTP, or `app`/`handlers`. Holds entities, value objects, repository/port
  interfaces, domain errors.
- **app** orchestrates use cases; depends on domain ports (interfaces), never on
  concrete infra. One interface per use case (`Creator`, `Finder`, …), each with
  its own file + generated mock.
- **infra** implements ports (repositories, external clients); contains no
  business logic.
- **handlers** are thin: decode → validate DTO → call app → map errors. No
  business logic, no direct repository access.
- **Violations to flag:** domain importing infra/framework; business logic in
  handlers; concrete infra types in app struct fields; god "Service" interfaces;
  DTOs living inside handler files instead of dedicated request/response
  packages; hand-rolled mocks.

### go-library
Reusable, importable Go package(s). No mandatory `cmd/main`.

- Small, cohesive packages named after what they provide; no `util`/`common`/
  `misc` grab-bags; no cyclic imports.
- **Minimal exported surface** — export only what consumers need; keep internals
  in `internal/` or unexported. Every exported symbol is deliberate.
- Accept interfaces, return concrete structs; zero global mutable state; no
  package-level singletons that hide dependencies.
- Functional-options or config structs for extensible constructors, not long
  positional param lists.
- `context.Context` threaded through blocking APIs; errors are sentinel/typed
  and wrapped; the library never calls `log.Fatal`/`os.Exit` or `panic` on
  caller input.
- Testable in isolation (no hard infra deps); `Example` tests for public API;
  stable, semver-friendly API.
- **Violations to flag:** framework/transport coupling leaking into the public
  API; over-broad exports; hidden global state; init-order dependencies;
  swallowed errors.

### cqrs
Command Query Responsibility Segregation.

- **Commands** mutate state and return nothing (or only an id/ack) — no rich
  read models returned from a command handler.
- **Queries** are side-effect free and never mutate state.
- Separate command handlers and query handlers, each handling ONE message type;
  a dispatcher/bus routes messages to handlers.
- Distinct command/query DTOs; ideally separate write model vs read model
  (projections) rather than reusing one ORM entity for both.
- Handlers depend on abstractions (repositories/projections), not concrete infra.
- **Violations to flag:** query handler performing writes; command handler
  returning full read models; a single handler serving both a command and a
  query; shared mutable model used for both sides when the profile calls for
  separation; missing/duplicated bus registration.

### clean-architecture
Concentric layers governed by the **dependency rule**: source-code dependencies
point only inward.

```
entities (enterprise rules) ← use cases (application rules) ← interface adapters ← frameworks & drivers
```

- **entities** are the innermost, framework-free business objects; depend on
  nothing outward.
- **use cases** orchestrate entities via boundary interfaces (input/output
  ports); depend only on entities and their own ports.
- **interface adapters** (controllers, presenters, gateways, repositories) map
  between use cases and the outside world; convert DTOs both directions.
- **frameworks & drivers** (web, DB, message brokers) sit outermost and are
  plugged in; inner layers never import them.
- Crossing a boundary inward uses interfaces defined by the inner layer
  (dependency inversion at every ring).
- **Violations to flag:** any inward import of an outer ring (use case importing
  the web framework or DB driver, entity importing an adapter); business rules
  leaking into controllers/presenters; DTOs from the framework used directly as
  entities; ports defined in the outer ring instead of the inner one.

### layered
Classic n-tier with a strict top-down call direction.

```
presentation (HTTP/CLI) → business/service → data access (repositories/DAOs) → data store
```

- Each layer calls only the layer directly beneath it; no skipping (presentation
  must not touch data access directly) and no upward calls.
- Business/service holds the logic; presentation is thin; data access hides the
  store behind repository/DAO types.
- Cross-cutting concerns (logging, auth, tx) are isolated, not duplicated per
  layer.
- **Violations to flag:** presentation calling data access directly; SQL/ORM
  types bleeding up into presentation; business logic in controllers or in the
  data layer; circular calls between layers; a "manager" that spans all layers.

### event-driven
Producers, a message bus/broker, and consumers reacting to events.

- Events are immutable, named in past tense, and carry a stable, versioned schema
  (avro/protobuf/JSON schema); no leaking internal structs onto the wire.
- Producers publish without knowing consumers; consumers are decoupled and each
  handler processes one event type.
- Consumers are **idempotent** (safe on redelivery) and handle
  ordering/at-least-once semantics explicitly; poison messages go to a DLQ or
  retry policy, never silently dropped.
- Offsets/acks committed only after successful processing; long work does not
  block the consumer loop; context cancellation stops consumers cleanly.
- **Violations to flag:** synchronous request/response smuggled over the bus;
  handlers with side effects that aren't idempotent; unbounded in-memory queues;
  swallowed errors that ack-and-lose messages; schema changes without
  versioning; consumer goroutines without lifecycle/backpressure control.

### microservice
An independently deployable service exposing a versioned transport contract.

- The public contract (gRPC `.proto` / OpenAPI) is the source of truth; generated
  stubs are not hand-edited, and internal domain types are not exposed on the
  wire.
- Clear service boundary: no shared database with other services; talks to peers
  only through their published APIs.
- Transport handlers are thin adapters (decode → call app → encode/map errors);
  business logic lives behind them.
- Config via env; health/readiness endpoints; structured logging with correlation
  ids; timeouts, retries, and context deadlines on every outbound call.
- Graceful shutdown drains in-flight work; secrets/PII never logged.
- **Violations to flag:** business logic inside transport handlers; reaching into
  another service's DB; hand-edited generated stubs; missing timeouts/deadlines on
  outbound calls; no graceful shutdown; unversioned breaking contract changes;
  domain types serialized directly onto the wire.

## Report Contract & Template

Instruct every sub-agent to return its own category section **as a Markdown
table**, one row per finding, sorted by severity (🔴 → 🟡 → 🟢). Severity legend:

- 🔴 **Critical** — breaks the architecture contract, correctness, or security.
- 🟡 **Major** — significant maintainability/quality issue; should fix.
- 🟢 **Minor** — polish / nice-to-have.

Per-category table format (keep these exact columns):

| Severity | Location | Issue | Why it matters | Suggested fix |
|---|---|---|---|---|
| 🔴 | `path:line` | <what> | <impact> | <concrete fix> |

If a category has no findings, emit a single row:
`| 🟢 | — | No issues found | — | — |`.

Merge everything into this final report:

```markdown
# Project Audit — <module path> (<architecture> profile)

## Verdict
Overall: 🔴 / 🟡 / 🟢  — <one-line summary>

| Category | Verdict | 🔴 | 🟡 | 🟢 |
|---|---|---|---|---|
| SOLID | | | | |
| Clean Code | | | | |
| Code Smells | | | | |
| Good Practices & Patterns | | | | |
| Go Conventions | | | | |
| Concurrency & Performance | | | | |
| Architecture (<profile>) compliance | | | | |

## Top remediations (do these first)
1. 🔴 <finding> — <path:line>
2. ...

## SOLID

| Severity | Location | Issue | Why it matters | Suggested fix |
|---|---|---|---|---|
| | | | | |

## Clean Code

| Severity | Location | Issue | Why it matters | Suggested fix |
|---|---|---|---|---|
| | | | | |

## Code Smells

| Severity | Location | Issue | Why it matters | Suggested fix |
|---|---|---|---|---|
| | | | | |

## Good Practices & Patterns

| Severity | Location | Issue | Why it matters | Suggested fix |
|---|---|---|---|---|
| | | | | |

## Go Conventions

| Severity | Location | Issue | Why it matters | Suggested fix |
|---|---|---|---|---|
| | | | | |

## Concurrency & Performance

| Severity | Location | Issue | Why it matters | Suggested fix |
|---|---|---|---|---|
| | | | | |

## Notes
- Repo conventions applied: <e.g. no-comments policy, lint config>
- Scope audited: <whole module / subset>
- Comment cleanup: <files touched, comment lines removed, borderline kept + why>
```

## Output Contract

Report to the user:
- The architecture profile used and why (from the argument).
- Confirmation that the comment-cleanup WRITE sub-agent ran first (or was skipped
  because the user asked for a read-only audit), with its removal summary.
- Confirmation that six separate read-only sub-agents ran (name each category).
- The merged report using the template above.
- A prioritized remediation list, highest severity first.

## References

- `~/.cursor/skills/trustgate-hexagonal/SKILL.md` — canonical hexagonal layout
  and SOLID mapping (use as the reference for the `hexagonal` profile).
- Repo `AGENT.md` / `AGENTS.md` / `.cursor/rules/*.mdc` — binding conventions
  that override generic advice (comment policy, lint config, layout).
