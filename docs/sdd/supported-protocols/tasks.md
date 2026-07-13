# Tasks: Supported Protocols (RUN-966)

Atomic, checkbox tasks derived from `design.md` (11 FIXED decisions) and `spec.md`
(Q1–Q5 scenarios). Grouped into the **3 phases** from design §9. Each phase is a
single reviewable work-unit / commit and is green on its own. Ordering `1 → 2 → 3`
is the only valid order (Phase 2 needs the method + resolver from Phase 1; Phase 3
needs the method from Phase 1).

Binding conventions: `.agents/AGENT.md` (hexagonal §3, DI §4, DTO/use-case §10,
**strict no-comments §11** — new `.go` files carry only the Apache license header),
`golang-pro` (`%w` wrap, `ctx` first, small consumer-defined interfaces, `-race`
table tests). Every new `.go` file: `make license`. Each phase closes only when
`go vet ./...` + `golangci-lint run` + `go test -race ./...` are green.

Legend: `[P]` production · `[T]` test · `[G]` generated (mock/swagger — never
hand-edited).

---

## Phase 1 — Contract + type + registry enforcement + all 16 plugins + mocks/fakes

Compile gate: the moment `Register` enforces non-empty protocols, every plugin
**and** every in-package `Plugin` fake must declare protocols in the same commit or
the `plugins` package won't build. This phase is the whole plugin-side contract.

### 1.1 Protocol type
- [x] **[P]** Create `pkg/app/plugins/protocol.go` (package `plugins`, Apache header,
  no comments): `type Protocol string`; consts `ProtocolLLM="LLM"`,
  `ProtocolMCP="MCP"`, `ProtocolA2A="A2A"`; `var ErrInvalidProtocols`;
  `Protocols() []Protocol`; `(Protocol) IsValid()` switch over the 3 values;
  `validateDeclaredProtocols(name string, protocols []Protocol) error` (empty →
  `%w ErrInvalidProtocols`, invalid value → `%w ErrInvalidProtocols`). Mirror
  `pkg/app/plugins/modes.go:25-44`. (design §1)

### 1.2 Contract method on the descriptor
- [x] **[P]** In `pkg/app/plugins/plugin.go`, add `SupportedProtocols() []Protocol`
  to the `PluginDescriptor` interface (lines 31-44), immediately after
  `SupportedModes()` (line 39). No comment. (design §2)

### 1.3 Registry enforcement
- [x] **[P]** In `pkg/app/plugins/registry.go` `Register` (lines 48-81), after the
  `validateDeclaredModes` call (lines 76-78) and before `r.plugins[name] = p`
  (line 79), add the `validateDeclaredProtocols(name, p.SupportedProtocols())`
  guard returning `err`. Mirrors the stages/modes checks. (design §3)

### 1.4 Implement `SupportedProtocols()` on all 16 built-in plugins
For each file below, add
`func (p *Plugin) SupportedProtocols() []appplugins.Protocol { return []appplugins.Protocol{…} }`
adjacent to `SupportedModes()`. Confirm the `appplugins` alias in each import block
first (grep `pkg/app/plugins"`); use that file's alias if it differs. (design §4)

- [x] **[P]** `pkg/infra/plugins/cors/plugin.go` (`cors`) → `ProtocolLLM, ProtocolMCP`
- [x] **[P]** `pkg/infra/plugins/requestsize/plugin.go` (`request_size_limiter`) → `ProtocolLLM, ProtocolMCP`
- [x] **[P]** `pkg/infra/plugins/ratelimit/plugin.go` (`rate_limiter`) → `ProtocolLLM, ProtocolMCP`
- [x] **[P]** `pkg/infra/plugins/trustguard/plugin.go` (`trustguard`) → `ProtocolLLM, ProtocolMCP` (leave the unexported wire consts `protocolLLM/MCP/A2A` at lines 41-45 untouched)
- [x] **[P]** `pkg/infra/plugins/pertoolratelimit/plugin.go` (`per_tool_rate_limiter`) → `ProtocolMCP`
- [x] **[P]** `pkg/infra/plugins/costcap/plugin.go` (`cost_cap`) → `ProtocolLLM`
- [x] **[P]** `pkg/infra/plugins/tokenratelimit/plugin.go` (`token_rate_limiter`) → `ProtocolLLM`
- [x] **[P]** `pkg/infra/plugins/modelallowlist/plugin.go` (`model_allowlist`) → `ProtocolLLM`
- [x] **[P]** `pkg/infra/plugins/prompttemplate/plugin.go` (`prompt_template`) → `ProtocolLLM`
- [x] **[P]** `pkg/infra/plugins/tooltransform/plugin.go` (`tool_definition_transformation`) → `ProtocolLLM`
- [x] **[P]** `pkg/infra/plugins/toolallowlist/plugin.go` (`tool_allowlist`) → `ProtocolLLM`
- [x] **[P]** `pkg/infra/plugins/tool_call_validation/plugin.go` (`tool_call_validation`) → `ProtocolLLM`
- [x] **[P]** `pkg/infra/plugins/openaimoderation/plugin.go` (`openai_moderation`) → `ProtocolLLM`
- [x] **[P]** `pkg/infra/plugins/bedrockguardrail/plugin.go` (`bedrock_guardrail`) → `ProtocolLLM`
- [x] **[P]** `pkg/infra/plugins/azurecontentsafety/plugin.go` (`azure_content_safety`) → `ProtocolLLM`
- [x] **[P]** `pkg/infra/plugins/semanticcache/plugin.go` (`semantic_cache`) → `ProtocolLLM`

### 1.5 Regenerate the Plugin mock
- [x] **[G]** Run `make gen-mocks` (or `go generate ./...`) so
  `pkg/app/plugins/mocks/plugin_mock.go` gains `SupportedProtocols`. Do NOT
  hand-edit. Confirm `pkg/app/plugins/mocks/registry_mock.go` is unchanged
  (`Registry` interface is untouched). (design §8)

### 1.6 Update in-package test fakes
- [x] **[T]** `pkg/app/plugins/registry_test.go` — `stagePlugin` (lines 27-41) gains
  `SupportedProtocols()` returning a non-empty valid set (e.g. `[]Protocol{ProtocolLLM}`). (design §3 ripple)
- [x] **[T]** `pkg/app/plugins/executor_test.go` — `fakePlugin` (lines 31-54) gains
  the same method (else executor/catalog tests fail to compile / panic on registration). (design §3 ripple)

### 1.7 Registry rejection tests
- [x] **[T]** In `pkg/app/plugins/registry_test.go`, add table-driven cases: (a)
  plugin with empty `SupportedProtocols()` → `Register` returns error
  (`errors.Is(err, ErrInvalidProtocols)`); (b) plugin with an invalid protocol value
  → `Register` errors. Run with `-race`. (spec: "Registry rejects invalid protocol
  declarations at startup")

### 1.8 Matrix guard test (drift protection)
- [x] **[T]** Add `TestNewPluginRegistry_SupportedProtocolsMatrix` to
  `pkg/container/modules/plugins_test.go`, reusing `newTestPluginRegistry(t)`. Assert
  each of the 16 slugs returns exactly its matrix set via `assert.ElementsMatch`
  (map from design §9). Guards the confirmed matrix against drift; also asserts no
  plugin reports `A2A`. (spec: "Each plugin reports exactly its matrix protocols")

### 1.9 Phase 1 gate
- [x] Run `go build ./...`, `go vet ./...`, `golangci-lint run`,
  `go test -race ./...` — all green. Phase 1 compiles and is green independently
  (catalog still compiles: extra descriptor method is additive; no attach changes).

---

## Phase 2 — Attach validation + resolver port/adapter + dig wiring + sentinel + tests

Depends only on Phase 1's `SupportedProtocols` + `ProtocolResolver`. Catalog untouched.

### 2.1 Consumer-side narrow port
- [x] **[P]** Create `pkg/app/consumer/plugin_protocol_resolver.go` (package
  `consumer`, license header, no comment): unexported
  `pluginProtocolResolver interface { SupportedProtocols(slug string) ([]string, bool) }`.
  Its own file (AGENT.md §10.1). Returns `[]string` so `app/consumer` never imports
  `app/plugins`. (design §5.1)

### 2.2 Exported adapter over the registry
- [x] **[P]** Create `pkg/app/plugins/protocol_resolver.go` (package `plugins`,
  license header, no comment): `type ProtocolResolver struct { registry Registry }`;
  `NewProtocolResolver(registry Registry) *ProtocolResolver`;
  `(*ProtocolResolver) SupportedProtocols(slug string) ([]string, bool)` — `registry.Get(slug)`,
  return `nil,false` if not found, else convert `[]Protocol → []string`. Structurally
  satisfies `consumer.pluginProtocolResolver`. (design §5.2)

### 2.3 Error sentinel
- [x] **[P]** In `pkg/domain/consumer/errors.go`, add to the existing sentinel block:
  `ErrPolicyProtocolMismatch = fmt.Errorf("consumer: policy protocol mismatch: %w", commonerrors.ErrValidation)`.
  Wraps `ErrValidation` → maps to HTTP 422. (design §6.4)

### 2.4 `NewAssociator` signature + struct field
- [x] **[P]** In `pkg/app/consumer/associator.go`: add `resolver pluginProtocolResolver`
  to the `associator` struct (after `signaler`, line 57) and as a trailing
  `NewAssociator` parameter (after `signaler`, line 69); assign it in the returned
  struct literal. (design §5.3)

### 2.5 `policyInGateway` returns the policy
- [x] **[P]** Change `policyInGateway` (lines 268-277) to return
  `(*policydomain.Policy, error)`: return `pol` on success, `nil, err` on repo error,
  `nil, policydomain.ErrNotFound` on gateway mismatch. Only `AttachPolicy` calls it,
  so the change is local. (design §6.1)

### 2.6 `validatePolicyProtocol` helper
- [x] **[P]** Add `validatePolicyProtocol(cons *domain.Consumer, pol *policydomain.Policy) error`
  to `associator.go`: return nil if `pol.IsGlobal()`; return nil if `cons.Type` is
  neither `TypeLLM` nor `TypeMCP` (covers A2A); resolve
  `a.resolver.SupportedProtocols(pol.Slug)` — skip (nil) if `ok==false`; return nil if
  `string(cons.Type)` is in the set; else
  `fmt.Errorf("%w: plugin %s does not support consumer protocol %s", domain.ErrPolicyProtocolMismatch, pol.Slug, cons.Type)`. (design §6.3)

### 2.7 Wire validation into `AttachPolicy`
- [x] **[P]** Update `AttachPolicy` (lines 195-209): capture `pol` from the new
  `policyInGateway`, call `validatePolicyProtocol(cons, pol)` and return on error,
  **before** `repo.AttachPolicy`. Keep the existing `invalidate` + `policyCache.Delete`
  on success. (design §6.2)

### 2.8 dig wiring — plugins module
- [x] **[P]** In `pkg/container/modules/plugins.go` `Plugins(c)` (after the registry
  provider, lines 63-65), add `c.Provide(appplugins.NewProtocolResolver)` with error
  check. dig resolves it from the existing `Registry` provider. (design §5.4)

### 2.9 dig wiring — consumer module
- [x] **[P]** In `pkg/container/modules/consumer.go` Associator provider (lines 88-92),
  add the `resolver *appplugins.ProtocolResolver` parameter and pass it as the trailing
  arg to `appconsumer.NewAssociator(...)`; add the `appplugins` import. (design §5.4)

### 2.10 `NewAssociator` call-site sweep
- [x] **[P/T]** `grep -rn "NewAssociator(" pkg/` before finishing. Known sites: the
  dig provider (`consumer.go:88`, task 2.9) and `associator_test.go`'s `newAssociator`
  helper (task 2.12). Update any additional caller found. (design §10 risk 1)

### 2.11 Test fake resolver
- [x] **[T]** In `pkg/app/consumer/associator_test.go` (external `consumer_test`
  package), add `fakeProtocolResolver{ protocols map[string][]string }` implementing
  `SupportedProtocols(slug) ([]string,bool)` structurally. (design §9 Phase 2)

### 2.12 Update `newAssociator` helper + existing success test
- [x] **[T]** Update the `newAssociator` test helper to pass the fake resolver; update
  `AttachPolicy_Success` so its `policyRepo.FindByID` stub returns a policy with a
  `Slug` and the resolver is stubbed to match. (design §9 Phase 2; spec: "Matching
  single-protocol policy is allowed")

### 2.13 Associator behaviour tests (Q1–Q4)
- [x] **[T]** Add `-race` table tests to `associator_test.go`:
  - reject LLM-only policy → MCP consumer with `ErrPolicyProtocolMismatch` (422), no
    `repo.AttachPolicy` call (Q1)
  - reject MCP-only (`per_tool_rate_limiter`) → LLM consumer (Q2)
  - allow dual-protocol (`trustguard`/`cors`) → both LLM and MCP consumers (Q3)
  - skip validation + allow when `pol.IsGlobal()` (Q4)
  - skip validation + allow for A2A consumer
  - skip validation + allow when resolver returns `ok=false` (unknown slug)
  (spec: attach reject/allow/skip requirements; design §6.3)

### 2.14 Phase 2 gate
- [x] Run `go build ./...`, `go vet ./...`, `golangci-lint run`,
  `go test -race ./...` — all green.

---

## Phase 3 — Catalog exposure + Swagger/OpenAPI regen

Depends only on Phase 1's `SupportedProtocols()`. Additive.

### 3.1 Catalog field
- [ ] **[P]** In `pkg/app/plugins/catalog.go`, add
  `SupportedProtocols []Protocol \`json:"supported_protocols"\`` to `CatalogEntry`
  (struct lines 76-85), after `SupportedModes`. No comment. (design §7)

### 3.2 Populate in the catalog service
- [ ] **[P]** In `catalogService.Catalog()`, at the `CatalogEntry{...}` literal
  (lines 135-144), set `SupportedProtocols: plugin.SupportedProtocols()` after
  `SupportedModes`. Behavioural (from the descriptor), NOT from `catalog_metadata.go`. (design §7)

### 3.3 Catalog test
- [ ] **[T]** In `pkg/app/plugins/catalog_test.go`, assert each catalog entry includes
  `supported_protocols` matching the plugin's matrix row (spot-check dual, LLM-only,
  MCP-only). (spec: "Catalog reports supported_protocols per plugin", Q5)

### 3.4 Regenerate Swagger + OpenAPI
- [ ] **[G]** Run `make swagger` then `make openapi` → regenerates
  `docs/swagger.json`, `docs/swagger.yaml`, `docs/docs.go`, `docs/openapi.json` with
  the new `supported_protocols` field. Do NOT hand-edit generated files. No
  `@Failure` annotation change needed (AttachPolicy already documents 400/401/404). (design §8)

### 3.5 Phase 3 gate
- [ ] Run `go build ./...`, `go vet ./...`, `golangci-lint run`,
  `go test -race ./...` — all green. Confirm `make license` applied to any new file.

---

## Review Workload Forecast

Per-phase estimated changed lines (additions + deletions), split production / test /
generated. Team PR review budget = **400 changed lines** (`_base.mdc`). Generated
code (mocks, Swagger, OpenAPI) is mechanical and typically does **not** consume
reviewer focus, but is flagged so reviewers can skip it deliberately.

| Phase | Production | Test | Generated | Total | Reviewer-facing (prod + test) | Fits 400? |
|---|---|---|---|---|---|---|
| **1** — contract + 16 plugins + fakes | ~110 | ~55 | ~35 (plugin mock) | ~200 | ~165 | ✅ well under |
| **2** — attach validation + resolver + dig + tests | ~65 | ~120 | 0 | ~185 | ~185 | ✅ under |
| **3** — catalog + swagger/openapi | ~2 | ~6 | ~60–150 (swagger/openapi/docs.go) | ~10 hand + generated | ~8 | ✅ trivially under |

Notes:
- **Phase 1** generated churn is the regenerated `plugin_mock.go` (~35 lines) — small
  and mechanical. Reviewer-facing content (~165) is comfortably under budget. The 16
  plugin methods are near-identical 4-line blocks — low cognitive cost despite the
  file count.
- **Phase 2** is the highest-risk review: all lines are reviewer-facing (no generated
  code) and the logic (skip-global / skip-A2A / unknown-slug / mismatch) is the
  behavioural core. Still ~185, under budget.
- **Phase 3** hand-written change is ~8 lines; the Swagger/OpenAPI regen can be large
  and noisy (~60–150 lines across 4 files) but is purely generated. Call it out in
  the PR description so reviewers focus only on `catalog.go` + `catalog_test.go`.

### Ship decision: THREE stacked/chained PRs (recommended), not one

- Each phase compiles and is green on its own and is independently shippable; order
  `1 → 2 → 3` is mandatory (2 and 3 depend on Phase 1's method/resolver).
- A single combined PR would total ~395 reviewer-facing lines (165 + 185 + ~8 + up
  to ~150 generated) — right at / over the 400 soft cap once generated churn is
  counted, and it mixes three distinct concerns (contract, attach-validation,
  catalog). **Split into a chained PR series** (`chained-pr` skill): PR1 = Phase 1,
  PR2 = Phase 2 (on PR1), PR3 = Phase 3 (on PR2). This keeps each reviewer-facing
  diff small and single-concern.
- If the team prefers a single PR, it is *technically* within the soft cap on
  reviewer-facing lines (~358) but should carry a clear "generated Swagger churn —
  review only `catalog.go`" note; chaining remains the default per `_base.mdc`.

### Residual risks (from design §10)
- **`NewAssociator` call-site sweep** (task 2.10) — grep before Phase 2 to catch any
  caller beyond the dig provider + test helper.
- **Unknown-slug skip** (task 2.6) — intentional; confirm no product expectation that
  AttachPolicy reject unknown-slug policies.
- **Global-policy skip** — un-enforced today; new test (2.13) locks in the behaviour.
- **No-comments (§11)** — write all new symbols comment-free; the pre-commit hook
  strips doc comments regardless.
- **Swagger/OpenAPI diff noise** (Phase 3) — keep hand-written change to 2 lines; flag
  generated churn in the PR body.
