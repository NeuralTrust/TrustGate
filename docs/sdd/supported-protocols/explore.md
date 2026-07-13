# Exploration: supported-protocols (RUN-966)

Add `SupportedProtocols() []Protocol` to the plugin contract, implement it on all
16 built-in plugins per the confirmed matrix, validate consumer type vs plugin
protocol on `Associator.AttachPolicy`, expose it in the catalog + Swagger.

Worktree: `/Users/edu/Neuraltrust/TrustGate-supported-protocols` (branch
`feat/supported-protocols`, based on `origin/develop` incl. RUN-965/#207).

---

## 1. `PluginDescriptor` interface — current shape

`pkg/app/plugins/plugin.go` lines 31-44:

```go
type PluginDescriptor interface {
	Name() string
	MandatoryStages() []policy.Stage   // always-run stages (subset of SupportedStages)
	SupportedStages() []policy.Stage   // every stage the plugin can run on
	SupportedModes() []policy.Mode
	ValidateConfig(settings map[string]any) error
	MutatesRequestBody() bool
	MutatesResponseBody() bool
	MutatesMetadata() bool
}
```

`Plugin` (lines 55-58) embeds `PluginDescriptor` and adds
`Execute(ctx, ExecInput) (*Result, error)`. `//go:generate mockery --name=Plugin`
is declared on it (line 54) → mock at `pkg/app/plugins/mocks/plugin_mock.go`.

**Insertion point for `SupportedProtocols() []Protocol`**: add to the
`PluginDescriptor` interface (e.g. right after `SupportedModes()`, line 39).

A new `Protocol` type + values must be introduced. It should live in
`pkg/app/plugins` (NOT reuse `consumer.Type`, to avoid an
`app/plugins → domain/consumer` import that would invert layering). Proposed:
`Protocol` string with `ProtocolLLM = "LLM"`, `ProtocolMCP = "MCP"`, reserve
`ProtocolA2A = "A2A"`, plus an `IsValid()` helper — mirroring `consumer.Type`
(`pkg/domain/consumer/consumer.go:25-43`). Mapping `consumer.Type → Protocol`
happens at the validation site (associator), keeping the plugin layer clean.

Existing static-declaration helpers are validated at registration:
- `pkg/app/plugins/stages.go` — `EffectiveStages` / `ValidateStages`.
- `pkg/app/plugins/modes.go` — `validateDeclaredModes` (requires at least one
  mode and mandates `ModeEnforce`).
- `pkg/app/plugins/registry.go:48-81` `Register` calls `SupportedStages()`,
  `MandatoryStages()`, `validateDeclaredModes(...)`. This is the natural place to
  add an optional `SupportedProtocols()` non-empty check (design decision — see
  open questions).

---

## 2. The 16 built-in plugins — where each declares its descriptor methods

Each plugin is a `type Plugin struct{}` under `pkg/infra/plugins/<dir>/plugin.go`
with a `const PluginName = "<slug>"` and a block of descriptor methods
(`Name`, `MandatoryStages`, `SupportedStages`, `SupportedModes`,
`ValidateConfig`, `Mutates*`). `SupportedProtocols()` must be added to each block.
Registered in `pkg/container/modules/plugins.go:91-108` (`newPluginRegistry`).

| # | Dir / file | `PluginName` slug | Matrix protocol(s) |
|---|---|---|---|
| 1 | `cors/plugin.go` | `cors` | LLM + MCP |
| 2 | `requestsize/plugin.go` | `request_size_limiter` | LLM + MCP |
| 3 | `ratelimit/plugin.go` | `rate_limiter` | LLM + MCP |
| 4 | `costcap/plugin.go` | `cost_cap` | LLM |
| 5 | `tokenratelimit/plugin.go` | `token_rate_limiter` | LLM |
| 6 | `modelallowlist/plugin.go` | `model_allowlist` | LLM |
| 7 | `prompttemplate/plugin.go` | `prompt_template` | LLM |
| 8 | `tooltransform/plugin.go` | `tool_definition_transformation` | LLM |
| 9 | `toolallowlist/plugin.go` | `tool_allowlist` | LLM |
| 10 | `tool_call_validation/plugin.go` | `tool_call_validation` | LLM |
| 11 | `pertoolratelimit/plugin.go` | `per_tool_rate_limiter` | MCP |
| 12 | `openaimoderation/plugin.go` | `openai_moderation` | LLM |
| 13 | `bedrockguardrail/plugin.go` | `bedrock_guardrail` | LLM |
| 14 | `azurecontentsafety/plugin.go` | `azure_content_safety` | LLM |
| 15 | `semanticcache/plugin.go` | `semantic_cache` | LLM |
| 16 | `trustguard/plugin.go` | `trustguard` | LLM + MCP |

Reference method-block anchors (line of `SupportedModes`, methods are adjacent):
cors:58, requestsize:57, tokenratelimit:64, semanticcache:128, toolallowlist:61,
tool_call_validation:59, tooltransform:58, trustguard:89. `trustguard` already has
internal `protocolLLM/protocolMCP/protocolA2A` consts (`plugin.go:41-45`) and
branches on `in.Request.MCP` at runtime — the only plugin doing so today.

No default/catch-all — every plugin implements the method explicitly (per scope).

---

## 3. `consumer.Type`

`pkg/domain/consumer/consumer.go:25-43`:

```go
type Type string
const ( TypeLLM Type = "LLM"; TypeMCP Type = "MCP"; TypeA2A Type = "A2A" )
func Types() []Type { return []Type{TypeLLM, TypeMCP, TypeA2A} }
func IsValidType(t Type) bool { /* LLM|MCP|A2A */ }
```

`Consumer.Type` is field `Type Type` (line 81). `Validate()` defaults empty type
to `TypeLLM` (lines 230-232). So a resolved consumer always has a valid type.

---

## 4. `Associator.AttachPolicy` — full flow & insertion point

`pkg/app/consumer/associator.go`.

Interface (lines 34-43) — `AttachPolicy(ctx, gatewayID, consumerID, policyID) error`.

Struct deps (lines 47-58): `repo` (consumer), `registryRepo`, `roleRepo`,
`authRepo`, `policyRepo`, `memoryCache`, `policyCache`, `publisher`, `logger`,
`signaler`. **No plugin registry today.**

`AttachPolicy` (lines 195-209):
```go
cons, err := a.consumerInGateway(ctx, gatewayID, consumerID) // repo.FindByID + gw check
...
if err := a.policyInGateway(ctx, gatewayID, policyID); err != nil { return err } // discards policy!
...
if err := a.repo.AttachPolicy(ctx, consumerID, policyID); err != nil { return err }
a.invalidate(ctx, cons); a.policyCache.Delete(policyID.String())
```

`policyInGateway` (lines 268-277) fetches the policy via `policyRepo.FindByID`
but **returns only `error`, throwing away the `*policy.Policy`**.

### How a policy maps to plugin name(s) — 1:1 via `Slug`

Confirmed in `pkg/app/plugins/chain.go:47` (`NewStagePlan`): `reg.Get(pol.Slug)`.
**A policy's `Slug` IS the plugin name/slug.** One policy = one plugin. `Settings`
is that plugin's config. There is no separate policy→plugins list.

### Exact insertion point for validation

Between the policy lookup and `repo.AttachPolicy`:
1. Change `policyInGateway` to return `(*policy.Policy, error)` (or add a variant),
   so `AttachPolicy` gets the policy object.
2. Resolve the plugin descriptor: `plugin, ok := registry.Get(pol.Slug)`.
3. Map `cons.Type` → `plugins.Protocol` and check membership in
   `plugin.SupportedProtocols()`. On mismatch return a validation error
   (see §error-mapping) before `repo.AttachPolicy`.

**New dependency required**: the associator needs a lookup from slug →
`SupportedProtocols()`. Options in §Approaches. Registry is provided by dig in
`pkg/container/modules/plugins.go` and can be injected into the consumer module
(no import cycle: `app/plugins` does not import `app/consumer`).

### Error mapping (for the propose phase)

`httpio.WriteError` maps sentinel errors to HTTP status. Precedents:
- registry type-mismatch → `registrydomain.ErrInvalidRegistryID`
  (`associator.go:97-100`).
- auth/role conflicts → `commonerrors.ErrConflict` (409).
- `commonerrors.ErrValidation` → 400.
The AttachPolicy Swagger currently documents 400/401/404 (association_handler.go
lines 224-226). A protocol mismatch fits `ErrValidation` (400) or `ErrConflict`
(409) — decision deferred to propose. A new sentinel (e.g.
`consumer.ErrProtocolMismatch` wrapping one of those) is likely cleanest.

---

## 5. Global vs consumer-scoped policies

- `pkg/domain/policy/policy.go`: `Policy.Global bool` (line 32) +
  `Policy.ConsumerIDs []ids.ConsumerID` (line 27) + `func (p *Policy) IsGlobal()`
  (lines 42-44). There is **no nullable consumer id and no separate table/path** —
  it's a boolean flag on the policy plus a consumer-association join.
- Global flag is toggled independently via a **Scoper** use case
  (`pkg/app/policy` — `SetGlobal`/`UnsetGlobal`, see `scoper_test.go`), NOT via
  `AttachPolicy`.
- Runtime scope: `plugins.RuntimeScope{Global bool}` (`plugin.go:73-98`) is derived
  from `Policy.Global` + resolved consumer; `chain.go:69` sets
  `global: pol.IsGlobal()`.
- **Key fact for the open question**: `AttachPolicy` always binds a policy to a
  *concrete* `consumerID`, so at attach time a real `cons.Type` always exists —
  even for a policy whose `Global` flag is true. A global policy applies
  gateway-wide across all consumer types, and LLM-only plugins already no-op for
  MCP traffic at runtime. So validating a global policy against one consumer's
  type may be too strict / semantically wrong. This is the central open question.

---

## 6. Catalog metadata & API/Swagger exposure

- `pkg/app/plugins/catalog.go`:
  - `CatalogEntry` struct (lines 76-85) — JSON fields incl. `supported_stages`,
    `supported_modes`, `default_mode`, `settings_schema`. **Add
    `SupportedProtocols []Protocol \`json:"supported_protocols"\`` here.**
  - `catalogService.Catalog()` (lines 118-171) builds entries by iterating
    `registry.Names()` → `registry.Get(name)` and reading live descriptor methods
    (`plugin.MandatoryStages()`, `SupportedStages()`, `SupportedModes()`). **Add
    `SupportedProtocols: plugin.SupportedProtocols()`** at the `CatalogEntry{...}`
    literal (lines 135-144). Stages/modes come from the plugin (not curated meta),
    so protocols should too — keeps catalog from drifting from behaviour.
- `pkg/app/plugins/catalog_metadata.go` — curated per-slug UI meta (`catalogMeta`
  = name/group/description/schema). Protocols are behavioural, not curated, so they
  should come from the descriptor, not this map (no change needed here unless
  product wants curated protocol copy).
- HTTP: `pkg/api/handler/http/catalog/list_policy_catalog_handler.go` —
  `GET /v1/policies-catalog`, `@Success 200 {object} appplugins.Catalog`. No code
  change; the new field flows through automatically.
- Swagger/OpenAPI: generated files `docs/swagger.json`, `docs/swagger.yaml`,
  `docs/docs.go` (swag). They do **not** currently mention supported_protocols.
  Must be regenerated (`swag init` / repo make target) after the struct change.

---

## 7. Plugin registry — slug → descriptor at attach time

`pkg/app/plugins/registry.go`:
- `Registry` interface (lines 30-36): `Register`, `Get(name) (Plugin, bool)`,
  `Validate`, `ValidateStages`, `Names`.
- `registry.Get` (lines 83-86) returns the registered `Plugin` (which is a
  `PluginDescriptor`) by slug. This is exactly what validation needs:
  `Get(pol.Slug)` → `SupportedProtocols()`.
- Built at startup in `newPluginRegistry` (`plugins.go:79-115`), provided via dig
  (`Plugins(c)` at `plugins.go:62-75`). Injectable into the consumer module.

---

## 8. Existing test patterns

- **Associator**: `pkg/app/consumer/associator_test.go`. Table/case-style with
  `mockery` mocks (`repomocks`, `policymocks`, etc.). Helper `newAssociator(...)`
  (lines 38-48) constructs via `appconsumer.NewAssociator(...)`. `AttachPolicy`
  success test lines 206-225 (`policyRepo.FindByID` returns a `Policy{ID,GatewayID}`
  — will need a `Slug` + a registry stub once validation is added). **Changing
  `NewAssociator`'s signature ripples to** `newAssociator` helper + every call
  site in this file, plus the dig provider in `pkg/container/modules/consumer.go`
  (lines 88-90). New tests: reject on mismatched protocol, allow on matching, and
  the chosen global-policy behaviour.
- **Catalog**: `pkg/app/plugins/catalog_test.go` + `registry_test.go` use a fake
  `stagePlugin` (`registry_test.go:27-40`) implementing the descriptor; **it must
  gain `SupportedProtocols()`**. `catalog_test.go` has `builtinSlugs` (lines 28-38)
  and asserts groups/stages/schema — add protocol assertions.
  `pkg/container/modules/plugins_test.go` and
  `pkg/infra/plugins/pertoolratelimit/plugin_test.go:219` also build the catalog
  from the real registry — good end-to-end coverage of the new field.

### Ripple / regeneration checklist
- `mockery` regen: `pkg/app/plugins/mocks/plugin_mock.go` (Plugin interface gains a
  method). `//go:generate` already present.
- Fakes to update: `registry_test.go` `stagePlugin`; any other test doubles
  implementing `Plugin`/`PluginDescriptor`.
- `NewAssociator` signature change → dig provider + test helper + all call sites.
- Swagger regen: `docs/swagger.json|yaml`, `docs/docs.go`.

---

## Approaches (validation dependency wiring)

1. **Inject the full `appplugins.Registry` into the associator** — Pros: reuses the
   existing `Get(slug)` lookup, minimal new surface. Cons: `app/consumer` gains a
   dependency on `app/plugins`; associator gets a broad interface it only partly
   uses. Effort: Low.
2. **Define a narrow consumer-side port** (e.g. `type protocolResolver interface {
   SupportedProtocols(slug string) ([]plugins.Protocol, bool) }`) implemented by an
   adapter over the registry — Pros: hexagonal-clean, associator depends on a tiny
   consumer-defined interface (matches repo conventions). Cons: one more small
   adapter + dig wiring. Effort: Low-Medium.
3. **Validate in the HTTP handler / a dedicated policy-attach service** instead of
   the associator — Pros: keeps associator unchanged. Cons: scatters the invariant
   away from where the association is persisted; easier to bypass via other
   callers. Effort: Medium. Not recommended.

**Recommendation**: Approach 2 (narrow port) — aligns with the repo's
"accept interfaces, one interface per use case" hexagonal rules and keeps the
associator's dependency surface minimal, while keeping the invariant at the
persistence boundary.

---

## OPEN QUESTIONS (need product/decision before implement)

1. **Global-policy validation (critical).** `AttachPolicy` always has a concrete
   consumer type, even when `Policy.Global == true`. Do we (a) validate against the
   consumer type regardless of global, (b) **skip** validation when
   `pol.IsGlobal()` (global applies gateway-wide; LLM-only plugins no-op for MCP at
   runtime), or (c) reject attaching a global policy to a consumer entirely? The
   proposal leans toward "validate only when consumer-scoped; skip when global",
   but there is no code path that enforces global-vs-consumer at attach time today.
2. **Error type / HTTP status.** Protocol mismatch → `ErrValidation` (400) or
   `ErrConflict` (409)? (AttachAuth mismatches use 409; registry mismatch uses a
   domain `ErrInvalid*`.) New sentinel name?
3. **Registration-time enforcement.** Should `registry.Register` require a non-empty
   `SupportedProtocols()` (like it does for stages/modes), failing startup if a
   plugin omits it? Recommended for "no default/catch-all", but is a behaviour
   change to `Register`.
4. **A2A.** Type is reserved but not enforced (out of scope). Confirm the validator
   simply treats `A2A` consumers as "no plugin supports A2A yet" (→ every attach
   rejected) vs. bypassing validation for A2A. Likely: reserve the constant, do not
   add it to any plugin's list, and decide the A2A-consumer attach behaviour.
5. **Pre-existing associations.** Validation is only on *new* attaches. Any existing
   consumer↔policy rows that violate the matrix are untouched (no migration/backfill
   in scope) — confirm that's acceptable.
6. **`tool_call_validation` scope field.** Its schema has an inert `scope` field;
   unrelated, but confirm no interaction expected.

---

## Ready for Proposal
**Yes.** Code shape is fully understood; the only true blockers are product
decisions on the global-policy behaviour (Q1), error semantics (Q2), and
registration enforcement (Q3). Everything else is mechanical.
