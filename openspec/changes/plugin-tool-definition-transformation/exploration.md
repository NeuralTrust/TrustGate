# Exploration: Tool definition transformation plugin — RUN-707

A `pre_request` plugin that rewrites the `tools[]` array before the model sees it:
patch tool schemas / descriptions (`transform_tools`), inject new tools
(`inject_tools`), and resolve name collisions via `on_conflict`
(`gateway_wins | client_wins | reject`). It does **not** gate access — that is the
allowlist/strip behaviour already provided by `per_tool_rate_limiter`. The repo's
existing `per_tool_rate_limiter` is a near-exact structural template: it already
decodes `tools[]` from any provider format, mutates them, re-encodes, grafts the
change back onto the raw body, and returns it via `Result.RequestBody`.

## Current State

### How the request body and `tools[]` are represented (Q1, Q6)
- The proxy never hand-parses provider JSON in plugins. Each provider format has
  an adapter behind `pkg/infra/providers/adapter/registry.go` that decodes the
  raw body into a **provider-neutral `CanonicalRequest`** and re-encodes it.
- `CanonicalRequest.Tools []CanonicalTool` (`adapter/canonical.go:29`,`:49-54`):
  ```
  type CanonicalTool struct {
      Name        string                 `json:"name"`
      Description string                 `json:"description,omitempty"`
      Schema      map[string]interface{} `json:"schema,omitempty"`
  }
  ```
  `Schema` is the full JSON-Schema parameters object as a generic map — exactly
  what `schema_patch` (RFC 7386 merge patch) needs to operate on.
- The canonical layer is **provider-agnostic for tools**:
  - OpenAI completions: `function.parameters` ⇄ `CanonicalTool.Schema`
    (`openai_completions_adapter.go:214-220` decode, `:279-288` encode).
  - Anthropic: `input_schema` ⇄ `CanonicalTool.Schema`
    (`anthropic_adapter.go:327-336` decode, `:426-439` encode); supports both flat
    and `type+custom` tool shapes.
  - Gemini / Bedrock / Mistral / OpenAI-Responses adapters all populate
    `CanonicalTool.{Name,Description,Schema}` the same way.
  So a transform plugin that operates on `canonical.Tools` works across every
  provider with no per-provider branching.
- Decode entry points used by plugins:
  `registry.DecodeRequestFor(body, adapter.Format(format))` →`*CanonicalRequest`
  and `ad.EncodeRequest(canonical)` → `[]byte` (`registry.go:128`,`:53-56`).
- Wire format selection: `req.SourceFormat` then `req.Provider` (the
  `wireFormat()` helper in `pertoolratelimit/plugin.go:513-521`).

### Where a request-mutating plugin runs and how it forwards the new body (Q1, Q3)
- `pkg/app/proxy/forwarder.go::Forward` order (`forwarder.go:126-172`):
  `resolveRouting` → `applyIntentToBody` → `stampConsumerScope` →
  `routeBackend` → **`stampTarget` (sets `req.Provider`/`RegistryID`, `:145`)** →
  **`runPreRequest` (`:154`)** → build `forwardRequestDTO` from `in.Request`
  (`:160-169`) → `invokeWithFailover`.
- At `pre_request`, `req.Provider`/`RegistryID` are set and the body model is
  normalized. The plugin reads/mutates `req.Body` here.
- **`Result` already carries a sanctioned request-body rewrite channel**:
  `Result.RequestBody []byte` (`pkg/app/plugins/plugin.go:91-97`). The executor
  applies it with `req.Body = res.RequestBody` (`executor.go:270-272`), and the
  forwarder then forwards `in.Request` (same pointer) to the upstream. This is the
  exact mechanism `per_tool_rate_limiter.stripTools` uses to drop tools from the
  request. **This is materially different from the budget-plugin finding** — body
  rewrite is first-class here.
- Short-circuit / reject 400: return `nil, &appplugins.PluginError{StatusCode,
  Type, Message, Headers, Body}` (`pkg/app/plugins/errors.go:21-27`). The
  executor records it; the proxy error layer renders it. `PluginError` already has
  a `Type string` field and a `Body []byte` field, so the issue's
  `{ "error": { "type": "tool_name_reserved", "name": "safety_check" } }` body can
  be produced either by setting `Body` to the marshalled JSON or by relying on the
  proxy's error envelope (**confirm which — see Open Questions**).

### Plugin architecture: definition, registration, config, scope, ordering (Q2)
- Contract: `pkg/app/plugins/plugin.go` — `Plugin` interface (`Name`,
  `MandatoryStages`, `SupportedStages`, `SupportedModes`, `ValidateConfig`,
  `Execute`). Input is `ExecInput{Stage, Mode, Config, Scope, Request, Response,
  Event}`; output is the single `*Result`.
- Registration: `pkg/container/modules/plugins.go::newPluginRegistry`
  (`plugins.go:66-87`) constructs every built-in with its deps and `reg.Register`.
  `pluginParams` (dig.In, `:40-47`) currently injects `Cache`, `Adapters
  (*adapter.Registry)`, `Locator`, `Logger`, `Pricing`. A tool-transform plugin
  needs **only `Adapters`** (no Redis, no pricing) — add one line:
  `tooltransform.New(p.Adapters)` to the catalog slice (`:71-80`).
- Catalog / control-plane JSON schema: `pkg/app/plugins/catalog_metadata.go`
  (hand-authored `SettingsSchema` per slug) + `pkg/app/plugins/catalog.go`
  (`Field`/`FieldType` vocabulary incl. `object`, `array`, `map`, `enum`,
  `duration`). Stages are read from the plugin, never duplicated. Test:
  `catalog_test.go`. The `per_tool_rate_limiter` entry
  (`catalog_metadata.go:429-508`) is the template for arrays-of-objects schema.
- **Scope (consumer vs global) is derived from `Policy.Global`, not config**
  (`RuntimeScope.Subject()`, `plugin.go:75-86`). Both `per_tool_rate_limiter`
  (`pertoolratelimit/config.go:55`) and `tool_call_validation`
  (`tool_call_validation/config.go:44`) keep an **informational** `scope` config
  field (enum `consumer|global`) that does not drive behaviour. The issue's
  `"scope": "consumer"` should follow this convention: accept it, validate the
  enum, document it as informational.
- Ordering: precomputed `StagePlan` (`pkg/app/plugins/plan.go`). Within a stage,
  entries are sorted by **`pol.Priority` ascending** (`plan.go:72-77`). There is
  **no hardcoded inter-plugin ordering** — "runs AFTER Tool allowlist" is achieved
  purely by giving this policy a higher `priority` number than the allowlist
  policy. Parallel batches (same priority, `pol.Parallel`) run on isolated clones.

### Canonical sibling to mirror (Q2)
`pkg/infra/plugins/pertoolratelimit/` — specifically `plugin.go` and `config.go`.
It is the closest analogue and demonstrates every primitive this change needs:
- `MandatoryStages`/`SupportedStages`/`SupportedModes` declarations
  (`plugin.go:83-93`).
- `wireFormat()` → `registry.DecodeRequestFor` → iterate `canonical.Tools`
  (`plugin.go:124-173`).
- Glob tool-name matching via `path.Match` with `/`→sentinel substitution
  (`plugin.go:498-504`; pattern validated in `config.go:108`).
- Tool-set mutation → re-encode → **`graftChangedFields`** to preserve untouched
  raw fields, returning `Result{RequestBody: body}` (`plugin.go:186-246`).
- `reject` via `*appplugins.PluginError` (`plugin.go:430-446`).
`tool_call_validation/` is a secondary reference (multi-file engine, reject/redact
behaviours, `scope` config convention).

### Glob matching helper (Q5)
Three existing options, no new dependency needed:
1. **`path.Match`** (stdlib) with the `/`→`\x00` sentinel trick used by
   `per_tool_rate_limiter` (`pertoolratelimit/plugin.go:498-504`). Supports `*`,
   `?`, `[...]`. **Recommended — it is the established repo convention for tool
   name globs and matches the issue's `search_*` / `send_email` examples.**
2. A hand-rolled `globMatch` + longest-match `bestMatch[T]` already exists in
   `pkg/infra/plugins/tokenratelimit/glob.go:19-72` (added by the budget plugin),
   but it is package-private to `tokenratelimit`.
3. `github.com/bmatcuk/doublestar/v4` is in `go.mod` (indirect) if `**` is ever
   needed — overkill for flat tool names.

### JSON merge patch RFC 7386 (Q4)
- **No merge-patch helper exists** anywhere in the repo, and there is **no
  merge-patch dependency** in `go.mod` (no `evanphx/json-patch`, no
  `github.com/wI2L/jsondiff`, etc.). `google/jsonschema-go` is present but is for
  validation, not patching.
- RFC 7386 is ~20 lines of stdlib recursion over `map[string]interface{}`
  (set value, recurse on nested objects, **delete key when patch value is JSON
  `null`**). The plugin operates on `CanonicalTool.Schema` which is already a
  decoded `map[string]interface{}`, so the merge patch applies in-memory before
  re-encode — no extra marshal round-trip. **Recommended: a small internal
  `mergepatch.go` in the new plugin package.** Add a dep only if the team prefers
  a vetted library (would require `go get` + review).

### Body re-serialization before forwarding (Q6)
The plugin produces the new body; it does **not** re-serialize the whole request
from scratch. Mirror `graftChangedFields` (`pertoolratelimit/plugin.go:219-246`):
decode raw → mutate canonical → `EncodeRequest(full)` and `EncodeRequest(mutated)`
→ graft only the fields that changed (here: `tools`) back onto the **original raw
body**. This preserves provider-specific top-level fields the canonical model
drops, while still rewriting `tools[]`. The executor's `applyResult` then writes
`req.Body`, and `invokeWithFailover` forwards it.

### Structural template (Q7)
`openspec/changes/archive/budget-plugin/` is the SDD structure to mirror
(`exploration.md` → `proposal.md` → `design.md` → `tasks.md`). For *code* layout,
`per_tool_rate_limiter` is the better mirror than the budget plugin (which lives
inside `tokenratelimit`): a dedicated `pkg/infra/plugins/tooltransform/` package
with small files (`plugin.go`, `config.go`, `transform.go`, `inject.go`,
`mergepatch.go`, `glob.go` or reuse `path.Match`, `data.go`).

## Affected Areas
- **New** `pkg/infra/plugins/tooltransform/` (or `tool_definition/`) — the plugin,
  config, merge-patch, transform/inject logic, trace `data.go`, unit tests.
- `pkg/container/modules/plugins.go` — register the new plugin (one line in the
  catalog slice; only needs `p.Adapters`).
- `pkg/app/plugins/catalog_metadata.go` (+ `catalog_test.go`) — hand-authored
  `SettingsSchema` for `transform_tools[]`, `inject_tools[]`, `on_conflict`,
  `scope`. `inject_tools` is a free-form tool object → likely
  `FieldTypeMap`/`object` with a generic schema (confirm catalog supports
  arbitrary nested JSON for the injected `parameters`).
- `tests/functional/` — a `functional`-tagged test mirroring
  `plugin_per_tool_rate_limiter_test.go` (setup policy route, send a request with
  `tools[]`, assert the upstream-received body was patched/injected, assert reject
  → 400).

## Approaches

1. **New dedicated plugin package operating on the canonical model.** New
   `pkg/infra/plugins/tooltransform/`; decode → match (glob) → apply
   `description_override` + `schema_patch` (merge patch on `Schema`) → append
   `inject_tools` with `on_conflict` resolution → graft → `Result.RequestBody`.
   - Pros: clean separation; one slug; provider-agnostic via canonical; mirrors
     `per_tool_rate_limiter` almost line-for-line; small files per AGENT.md.
   - Cons: canonical round-trip can only carry `Name/Description/Schema` for an
     injected tool — provider-exotic tool fields (e.g. Anthropic `cache_control`,
     OpenAI `strict`) on **injected** tools would be lost unless grafted as raw.
   - Effort: **Medium**.

2. **Raw-JSON manipulation (operate directly on `tools[]` in the raw body).**
   Parse `req.Body` into `map[string]json.RawMessage`, edit the `tools` array
   in place, re-marshal.
   - Pros: perfect fidelity for injected tools (arbitrary fields preserved);
     direct RFC 7386 on raw schema.
   - Cons: must re-implement per-provider tool-shape knowledge (OpenAI
     `function.parameters` vs Anthropic flat `input_schema` vs `type+custom` vs
     Gemini/Bedrock) that the adapters already encapsulate; brittle; diverges from
     the repo's canonical convention.
   - Effort: **Medium-High**.

3. **Hybrid: canonical for matching/patching, raw graft for injected fidelity.**
   Use the canonical model for `transform_tools` (description/schema patch) and
   collision detection, but inject raw tool JSON objects directly into the grafted
   `tools` array so injected tools keep arbitrary provider fields verbatim.
   - Pros: best of both; transforms stay provider-agnostic; injected tools are
     byte-faithful to the operator's config.
   - Cons: two code paths for "tool"; the injected raw object must be re-shaped
     per provider (OpenAI `{type,function}` vs Anthropic flat) — partially
     reintroduces approach 2's provider knowledge for injection only.
   - Effort: **Medium-High**.

## Recommendation
**Approach 1** (canonical, dedicated package) as the primary, with the
`graftChangedFields` raw-graft pattern from `per_tool_rate_limiter` so untouched
top-level request fields survive. Implement:
- Tool-name matching with stdlib `path.Match` + `/`→sentinel (repo convention).
- `schema_patch` as an in-memory RFC 7386 merge patch over `CanonicalTool.Schema`
  (new ~20-line `mergepatch.go`, null⇒delete).
- `description_override` as a direct `CanonicalTool.Description` set.
- `inject_tools` mapped from the OpenAI-style `{type, function{name, description,
  parameters}}` config into `CanonicalTool{Name, Description, Schema}` and appended
  to `canonical.Tools`; on name collision apply `on_conflict`
  (`gateway_wins` overwrite / `client_wins` skip / `reject` → 400 `PluginError`).
- `scope` config field accepted + enum-validated but **informational** (effective
  scope from `Policy.Global`), matching the two existing tool plugins.
- Single stage `pre_request` (`Mandatory`+`Supported`), modes at least `enforce`.

Escalate to **Approach 3** for injection only **iff** the orchestrator confirms
injected tools must carry provider-exotic fields beyond name/description/schema.

Key design consequences to encode in the proposal:
- The new body must be returned via `Result.RequestBody`; reject via `PluginError`
  with `Type: "tool_name_reserved"` and a body carrying the colliding `name`.
- Ordering after the allowlist is a **policy `priority`** concern, documented for
  operators — there is no code-level dependency to wire.
- Glob matching of multiple `transform_tools` against one tool: define precedence
  (first-match vs all-match-merged) — the issue implies apply-all; `bestMatch`
  longest-match (tokenratelimit) is an alternative.

## Risks
- **Injected-tool fidelity through the canonical model.** Round-tripping an
  injected tool only preserves `name/description/schema`; any extra provider field
  in the operator's `inject_tools` JSON is dropped (Approach 1). Mitigation: graft
  raw (Approach 3) or document the limitation.
- **`PluginError` body shape.** Need to confirm whether setting `PluginError.Body`
  emits the raw `{ "error": { "type": ..., "name": ... } }` verbatim, or whether
  the proxy error renderer wraps/overrides it. The issue mandates an exact body;
  the renderer behaviour must be checked (`pkg/app/proxy` error handling +
  `executor.applyResult`).
- **Parallel-batch body rewrites.** `Result.RequestBody` survives parallel batches
  (it is applied from the `Result`, not the discarded clone — `executor.go:80-84`,
  `:270-272`), but if **two** parallel plugins both return `RequestBody`, the last
  applied wins and silently discards the other's edit. A tool-transform plugin
  should run **non-parallel** (own priority) or this must be documented.
- **No `Tool allowlist` plugin exists yet.** The issue's "runs AFTER Tool
  allowlist" references a plugin not present in the repo (only
  `per_tool_rate_limiter`'s `strip_tool_from_request` behaviour gates tools).
  Ordering is fine via priority, but the dependency named in the issue is
  conceptual, not a concrete sibling to coordinate with.
- **Schema-patch semantics.** RFC 7386 deletes keys on `null`. The issue's example
  (`"include_archived": { "enum": [false] }`) only sets; but null-removal must be
  implemented and tested to honour the issue's explicit RFC 7386 note.
- **Glob ambiguity for overlapping `transform_tools`.** If `search_*` and
  `search_logs` both match, undefined precedence could merge conflicting patches.
- **Tools absent / non-tool requests.** Plugin must no-op cleanly when
  `canonical.Tools` is empty (mirror `pertoolratelimit` early returns) and when the
  format is unknown/undecodable.
- **OpenAI Responses API tools** use a different tool envelope than Chat
  Completions; verify `OpenAIResponsesAdapter` maps tools into `CanonicalTool`
  before claiming full coverage.

## Open Questions for the orchestrator
1. **Reject body shape** — does `PluginError.Body` pass through verbatim, or does
   the proxy error envelope reshape it? Likely answer in `pkg/app/proxy` response/
   error rendering and how `StageOutcome.Body`/`PluginError` are surfaced to the
   client (`executor.go::applyResult`, the forwarder's error path, and any
   `pkg/api/handler/http/response` error DTO). Resolve before fixing the 400 body.
2. **Injected-tool fidelity** — must `inject_tools` preserve arbitrary provider
   fields (Approach 3), or is `{name, description, parameters}` sufficient
   (Approach 1)? Inspect real consumer payloads / `inject_tools` intent; check
   `CanonicalTool` round-trip in each adapter (`adapter/*_adapter.go` tool
   encode/decode) to see exactly what is dropped.
3. **`transform_tools` precedence** — apply **all** matching patches in order, or
   first-match-wins, or longest-match (`tokenratelimit/glob.go::bestMatch`)?
   Decide the matching contract; the cleanest answer lives in how operators expect
   overlapping globs (`search_*` vs `send_email`) to compose.
4. **`on_conflict` collision scope** — does a collision mean an injected tool name
   equal to an **existing client tool name** only, or also to **another injected
   tool**? Confirm against the issue intent; the data model is `canonical.Tools`
   (client) + the `inject_tools` list.
5. **Stage & ordering contract vs the (nonexistent) Tool allowlist** — confirm the
   plugin is `pre_request`-only and that ordering relative to allowlist/strip is
   left to policy `priority` (`plan.go:72-77`). Decide whether to ship guidance/
   defaults so this lands after `per_tool_rate_limiter`'s strip.
6. **Merge-patch implementation** — accept a ~20-line in-repo RFC 7386
   `mergepatch.go` (recommended, no dep), or add a vetted dependency? If a dep,
   which one (none currently in `go.mod`).
7. **`scope` field** — confirm it is informational only (matching
   `per_tool_rate_limiter`/`tool_call_validation`), driven by `Policy.Global`,
   rather than an enforced config axis.
8. **Slug & package name** — `tool_definition_transformation`? `tool_transform`?
   Pick the catalog slug and the `pkg/infra/plugins/<name>/` directory; it must be
   added to `newPluginRegistry` and `catalog_metadata.go`.
9. **Provider coverage scope for v1** — OpenAI (completions + responses) +
   Anthropic only, or all eight registered formats? Verify each adapter's tool
   mapping (Gemini/Bedrock/Mistral) before promising universal coverage.

## Ready for Proposal
**Yes.** The architecture is well understood and the heavy lifting already exists:
`per_tool_rate_limiter` is a line-for-line template for decode→mutate→graft→
`Result.RequestBody`, the canonical model carries tool `Name/Description/Schema`
uniformly across providers, glob matching has an established `path.Match`
convention, and request-body rewrite is a first-class `Result` channel (unlike the
budget-plugin's body-mutation limitation). The only genuinely new code is a small
RFC 7386 merge-patch helper. Tell the orchestrator to resolve the 9 open questions
above first — most critically the **reject body shape** (Q1), **injected-tool
fidelity** (Q2), and **transform precedence** (Q3) — before `sdd-propose`.
