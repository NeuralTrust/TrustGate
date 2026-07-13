# Proposal: Supported Protocols (RUN-966)

## Why

Consumers have a `Type` (`LLM` / `MCP` / `A2A`), but today **any policy can attach
to any consumer** via `Associator.AttachPolicy` regardless of whether the underlying
plugin actually supports that protocol. This lets operators build meaningless or
misleading configurations (e.g. attaching `cost_cap`, an LLM-only plugin, to an MCP
consumer) with no feedback. There is also no machine-readable way for the control
plane / UI to know which protocols a plugin supports.

We add an explicit, plugin-declared protocol contract, enforce it at registration
(startup) and at attach time (400 on mismatch), and expose it in the catalog + Swagger.

## What Changes

1. New `Protocol` type + values in `pkg/app/plugins`.
2. `SupportedProtocols() []Protocol` added to the `PluginDescriptor` contract; all 16
   built-in plugins implement it explicitly per the confirmed matrix.
3. `registry.Register` requires a non-empty, all-valid `SupportedProtocols()`.
4. `Associator.AttachPolicy` validates consumer type vs plugin protocol (skipped for
   global policies and A2A consumers), via a narrow consumer-side port.
5. `CatalogEntry` gains `supported_protocols`, populated from the descriptor; Swagger
   regenerated.

## Confirmed Protocol Matrix (fixed — not re-litigated)

| Protocols | Plugins |
|---|---|
| **LLM + MCP** | `cors`, `request_size_limiter`, `rate_limiter`, `trustguard` |
| **LLM only** | `cost_cap`, `token_rate_limiter`, `model_allowlist`, `prompt_template`, `tool_definition_transformation`, `tool_allowlist`, `tool_call_validation`, `openai_moderation`, `bedrock_guardrail`, `azure_content_safety`, `semantic_cache` |
| **MCP only** | `per_tool_rate_limiter` (RUN-965, already on `develop`) |

## Chosen Design (11 resolved decisions — FIXED)

1. **Protocol type location** — New `Protocol` string type in `pkg/app/plugins`
   (`ProtocolLLM="LLM"`, `ProtocolMCP="MCP"`, reserved `ProtocolA2A="A2A"`) with an
   `IsValid()` helper, mirroring `consumer.Type`. *Rationale: reusing `consumer.Type`
   would force `app/plugins → domain/consumer`, inverting layering. Mapping
   `consumer.Type → Protocol` lives at the validation site.*

2. **Contract** — Add `SupportedProtocols() []Protocol` to `PluginDescriptor`
   (`pkg/app/plugins/plugin.go`). Every built-in plugin implements it explicitly.
   *Rationale: no default/catch-all; the matrix must be intentional per plugin.*

3. **Registration enforcement (Q3=YES)** — `registry.Register`
   (`pkg/app/plugins/registry.go`) requires a non-empty `SupportedProtocols()` with
   every value valid, mirroring the existing stages/modes checks; missing/invalid
   fails startup. *Rationale: makes the "no catch-all" rule structurally enforced.*

4. **Validation site** — In `Associator.AttachPolicy`
   (`pkg/app/consumer/associator.go`). A policy maps 1:1 to a plugin via `pol.Slug`
   (`reg.Get(pol.Slug)`). `policyInGateway` changes to return `(*policy.Policy, error)`
   so AttachPolicy has the policy, resolves supported protocols, maps `cons.Type`, and
   rejects on mismatch **before** `repo.AttachPolicy`. *Rationale: enforce the
   invariant at the persistence boundary, not scattered in handlers.*

5. **Wiring (hexagonal)** — Define a NARROW consumer-side port
   `pluginProtocolResolver { SupportedProtocols(slug string) ([]string, bool) }`
   returning `[]string`, so `app/consumer` does **not** import `app/plugins`. An
   adapter over `appplugins.Registry` implements it (converts `[]plugins.Protocol` →
   `[]string`), wired via dig. Injected into `NewAssociator`. *Rationale: "accept
   interfaces / one interface per use case"; keeps the associator's dependency surface
   minimal and avoids a layer-inverting import.*

6. **Global-policy behaviour (Q1=SKIP when global)** — Validate protocol fit **only**
   when the policy is consumer-scoped. When `pol.IsGlobal()`, skip validation.
   *Rationale: global policies apply gateway-wide across all consumer types, and
   LLM-only plugins already no-op for MCP traffic at runtime — validating a global
   against a single consumer's type would be semantically wrong.*

7. **A2A behaviour (Q4=SKIP for A2A consumers)** — Reserve `ProtocolA2A`, assign it to
   NO plugin. When `cons.Type == A2A`, skip validation. Only LLM and MCP consumer
   types are actively validated. *Rationale: A2A is reserved, not runtime-enforced yet;
   validating it would reject every attach.*

8. **Error semantics (Q2=400)** — Protocol mismatch returns HTTP 400. Introduce a
   named domain sentinel in the consumer domain (`ErrPolicyProtocolMismatch`) that
   wraps/maps to `commonerrors.ErrValidation` (confirmed → 400), with a message like
   *"plugin <slug> does not support consumer protocol <type>"*. *Rationale: named
   sentinel is testable; `ErrValidation` gives the correct status. AttachPolicy Swagger
   already documents 400.*

9. **Catalog exposure** — Add `SupportedProtocols []Protocol \`json:"supported_protocols"\``
   to `CatalogEntry` (`pkg/app/plugins/catalog.go`), populated from
   `plugin.SupportedProtocols()` in `catalogService.Catalog()` (behavioural, from the
   descriptor — NOT the curated `catalog_metadata.go`). Swagger regenerates from the
   struct. *Rationale: stages/modes already come from the descriptor; protocols follow
   suit so the catalog never drifts from behaviour.*

10. **Pre-existing associations (Q5)** — No backfill/migration. Validation applies only
    to **new** attaches; existing consumer↔policy rows are untouched. *Rationale:
    scope-limited, avoids a risky data migration.*

11. **Out of scope** — New MCP implementations for other plugins; MCP-native
    `tool_call_validation`; A2A runtime enforcement.

## Affected Areas

| Area | Impact | Change |
|---|---|---|
| `pkg/app/plugins/plugin.go` | Modified | `Protocol` type + values + `IsValid()`; add `SupportedProtocols()` to `PluginDescriptor` |
| `pkg/app/plugins/registry.go` | Modified | `Register` enforces non-empty/valid protocols |
| `pkg/app/plugins/catalog.go` | Modified | `CatalogEntry.SupportedProtocols` + populate in `Catalog()` |
| `pkg/infra/plugins/*/plugin.go` (×16) | Modified | Each implements `SupportedProtocols()` per matrix |
| `pkg/container/modules/plugins.go` | Modified | Provide the protocol-resolver adapter over the registry |
| `pkg/domain/consumer/` | Modified | New `ErrPolicyProtocolMismatch` sentinel (own file) |
| `pkg/app/consumer/associator.go` | Modified | `policyInGateway` returns policy; new port dep; validation in `AttachPolicy`; `NewAssociator` signature |
| `pkg/container/modules/consumer.go` | Modified | Inject resolver into `NewAssociator` provider |
| `docs/swagger.json` · `docs/swagger.yaml` · `docs/docs.go` | Regenerated | New `supported_protocols` field |
| `pkg/app/plugins/mocks/plugin_mock.go` | Regenerated | Plugin gains a method |

## Test Strategy

- **Associator** (`pkg/app/consumer/associator_test.go`): reject on protocol mismatch
  (400 / `ErrPolicyProtocolMismatch`); allow on match; **skip** when `pol.IsGlobal()`;
  **skip** for A2A consumers. Update `newAssociator` helper + all call sites for the new
  resolver dep; `policyRepo.FindByID` stubs now need a `Slug`.
- **Registry** (`registry_test.go`): `Register` rejects a plugin with empty/invalid
  `SupportedProtocols()`; fake `stagePlugin` gains the method.
- **Catalog** (`catalog_test.go`, `plugins_test.go`,
  `pertoolratelimit/plugin_test.go`): catalog exposes `supported_protocols`.
- **Per-plugin matrix assertion**: table-driven test asserting each of the 16 plugins
  returns exactly its confirmed protocol set (guards the matrix against drift).

## Regeneration Checklist

- [ ] `go generate ./...` → `pkg/app/plugins/mocks/plugin_mock.go` (Plugin) and any
      `Registry`/descriptor mocks gain `SupportedProtocols`.
- [ ] Update hand-written test fakes implementing the descriptor (`stagePlugin`, etc.).
- [ ] Swagger: `swag init` / repo make target → `docs/swagger.json|yaml`, `docs/docs.go`.
- [ ] `go build ./...` + `go test -race ./...` green after the `NewAssociator` ripple.

## Rollback Plan

Change is additive and behind no feature flag but low-blast-radius: revert the branch /
commit. Because there is no migration and no data change, reverting immediately restores
prior behaviour (any-policy-to-any-consumer). Pre-existing associations are never mutated.

## Success Criteria

- [ ] All 16 plugins declare `SupportedProtocols()`; startup fails if one omits it.
- [ ] `AttachPolicy` returns 400 on protocol mismatch for consumer-scoped policies;
      allows matches; skips global policies and A2A consumers.
- [ ] `GET /v1/policies-catalog` returns `supported_protocols` per plugin; Swagger shows it.
- [ ] `go test -race ./...` and build pass; mocks + Swagger regenerated.

## Capabilities

### New Capabilities
- None (no `openspec/specs/` in this repo; behaviour tracked via this hybrid doc).

### Modified Capabilities
- None at spec-file level — behavioural changes captured here and enforced by tests.
