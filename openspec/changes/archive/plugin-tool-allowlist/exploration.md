# Exploration: Tool allowlist plugin — RUN-706

New `pre_request` plugin that does **access control on the `tools[]` array** of an
LLM request: restrict which tools a consumer/gateway may expose to the model,
**before** the upstream provider sees the request. Absorbs the EE
`tool_permission` plugin (exact-match white_list / deny_list) and generalises it
with glob patterns + an `on_empty_after_filter` policy. Parallel to
`model_allowlist` but for the tool array instead of the model field.

## Current State

### The EE plugin being absorbed (`tool_permission`)
- `LegacyGateway-EE/internal/infra/plugins/tool_permission/tool_permission.go` —
  runs on `PreRequest` only. Decodes config (`white_list`, `deny_list`) via
  `mapstructure`, requires at least one list. Reads `req.Provider`,
  `req.SourceFormat`, builds an `llm.NewCanonicalParser(provider, sourceFormat)`,
  calls `ExtractBatches(req.Body)` → `contentBatches.GetTools()` (the EE
  normalizer), filters, and on removal rewrites the raw JSON body itself.
- **Filter semantics** (`filterTools`): if `white_list` is non-empty it is a pure
  whitelist (deny_list ignored — whitelist wins); else deny_list is a blacklist.
  Exact string match only (no globs).
- **Body-rewrite cleanup** (`removeToolsFromRequest`, the critical bit to port):
  it edits the raw body map; matches tools by `tool["name"]` **or**
  `tool["function"]["name"]`; and when the filtered array is empty it
  **deletes `tools`, `tool_choice`, AND `parallel_tool_calls`** — because leaving
  `tool_choice` with no `tools` makes OpenAI return 400. This is exactly the
  `strip_tools_field` behaviour the spec requires.
- EE returns `*plugintypes.PluginResponse{StatusCode, Message}` on success and
  `*plugintypes.PluginError{StatusCode, Message}` to reject. There is **no**
  reject-on-empty path in EE today — it only ever strips (it never 403s when the
  array becomes empty). The 403 `no_tools_allowed` behaviour is **net-new** in the
  RUN-706 spec.
- Spec ⇆ EE field mapping: `allow_tools` ← `white_list`, `deny_tools` ←
  `deny_list`. Spec adds: glob matching, deny-after-allow ordering,
  `on_empty_after_filter` (`reject` | `pass_through_empty` | `strip_tools_field`).

### Plugin framework in THIS repo (the new TrustGate)
- **Contract**: `pkg/app/plugins/plugin.go` — `Plugin` interface: `Name()`,
  `MandatoryStages()`, `SupportedStages()`, `SupportedModes()`,
  `ValidateConfig(settings map[string]any)`, `Execute(ctx, ExecInput) (*Result, error)`.
  `ExecInput{Stage, Mode, Config (policy.PluginConfig{ID,Slug,Settings}), Scope
  (RuntimeScope), Request *infracontext.RequestContext, Response, Event
  *metrics.EventContext}`.
- **`Result` is the sanctioned output channel** (`pkg/app/plugins/plugin.go`):
  `Result{StatusCode int, Body []byte, RequestBody []byte, Headers
  map[string][]string, StopUpstream bool}`. **Key finding:** unlike the budget
  exploration's era, `Result` now has a first-class **`RequestBody`** field, and
  `executor.applyResult` does `req.Body = res.RequestBody` when it is non-nil
  (`pkg/app/plugins/executor.go:270`). So a `pre_request` body rewrite is a
  supported, framework-blessed operation — no need to mutate `req.Body` directly.
- **Reject with a custom JSON body + status**: return a `Result{StopUpstream:true,
  StatusCode:403, Headers:{"Content-Type":["application/json"]}, Body: <json>}`.
  `model_allowlist` does exactly this (`newRejectResult`,
  `pkg/infra/plugins/modelallowlist/plugin.go:141`). Alternatively return a
  `*appplugins.PluginError{StatusCode, Type, Message, Headers, Body}`
  (`pkg/app/plugins/errors.go`) — both short-circuit the chain. For a fixed
  custom body the `Result` route is cleanest and is the established pattern.
- **Registry**: `pkg/app/plugins/registry.go` — `Register(p Plugin)` validates
  stages/modes; every plugin must support `policy.ModeEnforce`. Built in DI by
  `pkg/container/modules/plugins.go::newPluginRegistry`, which constructs each
  plugin from `pluginParams` (dig.In: `Cache`, `Adapters *adapter.Registry`,
  `Locator`, `Logger`, `Pricing`) and appends it to the `catalog []Plugin` slice.
- **Config schema for the control plane**: `pkg/app/plugins/catalog_metadata.go`
  — a hand-authored `pluginCatalogMeta` map keyed by slug, each with `name`,
  `group`, `description`, and a `SettingsSchema` built from `Field`/`FieldType`
  (`catalog.go`: `FieldTypeString|Integer|Number|Boolean|Enum|Duration|Array|
  Object|Map`). **Hard wiring requirement**: `catalog_test.go:268` iterates over
  the registered plugin slugs and asserts every slug has a `pluginCatalogMeta`
  entry — so a new plugin without metadata fails the catalog test.
- **Config decode/validate**: per-plugin `config.go` with `mapstructure` tags,
  parsed by the generic `pluginutil.Parse[T](settings)`
  (`pkg/infra/plugins/pluginutil/decode.go`, `WeaklyTypedInput:true`). Validation
  lives in a `(*config).validate()` invoked from `parseConfig`, surfaced to the
  control plane via the plugin's `ValidateConfig`.
- **Metrics / event extras**: `in.Event` is a `*metrics.EventContext` (nil-safe);
  plugins call `event.SetExtras(<struct or map>)` and optionally
  `appplugins.SetDecision(event, mode)`. Trace payload structs live in the
  plugin's `data.go` (see `modelallowlist/data.go`,
  `pertoolratelimit/data.go`).

### Provider / protocol info on the request context
- `pkg/infra/context/request_context.go::RequestContext` exposes
  **`Provider`**, **`SourceFormat`**, **`TargetFormat`**, **`Body`**,
  **`RequestedModel`**, **`AllowedModels`**, plus `GatewayID`/`ConsumerID` (used to
  derive scope). This is the direct equivalent of EE's `req.Provider` /
  `req.SourceFormat` / `req.Body`.
- **§14.1 invariant**: `req.Provider` and `req.RegistryID` are stamped at backend
  selection **before** `pre_request` runs, so a `pre_request` plugin can rely on
  `req.Provider`. `req.SourceFormat` is the wire format the client sent.

### Canonical tool-array parser/normalizer — **already exists, no build needed**
- `pkg/infra/providers/adapter` is the new repo's equivalent of EE's
  `llm.NewCanonicalParser` / `ExtractBatches` / `GetTools`:
  - `adapter.Registry.DecodeRequestFor(body, Format) (*CanonicalRequest, error)`
    normalizes the provider body into `CanonicalRequest{Tools []CanonicalTool{Name,
    Description, Schema}, ToolChoice *CanonicalToolChoice, ...}` (`canonical.go`).
    OpenAI `tools[].function.name`, Anthropic top-level `tools[].name`, etc. all
    normalise to the flat `CanonicalTool.Name` (`openai_completions_adapter.go:214`).
  - `Registry.GetAdapter(Format).EncodeRequest(*CanonicalRequest)` re-encodes.
  - `Format` constants (`format.go`): `openai`, `openai_responses`, `anthropic`,
    `google`, `bedrock`, `azure`, `groq`, `vertex`, `mistral`, `deepseek`.
- **The exact working pattern to copy is `per_tool_rate_limiter`**
  (`pkg/infra/plugins/pertoolratelimit/plugin.go`). Its `preRequest`:
  1. `format := wireFormat(req)` = `req.SourceFormat` else `req.Provider`.
  2. `canonical, _ := registry.DecodeRequestFor(req.Body, adapter.Format(format))`;
     skip when nil/no tools.
  3. iterate `canonical.Tools`, decide which to strip.
  4. `stripTools(...)`: re-encode full vs stripped canonical, then
     `graftChangedFields(original, fullEncoded, strippedEncoded)` surgically
     applies only the changed top-level keys back onto the **original** body
     (preserving fields the canonical model doesn't represent), and returns
     `Result{RequestBody: body}`.
- This means **most of the protocol-aware machinery already exists**; the new
  plugin is essentially `model_allowlist`'s glob/allow/deny + reject-body design
  applied to the tool array using `per_tool_rate_limiter`'s decode/strip plumbing.

### Glob matching — exists in two flavours
- `model_allowlist` (`config.go:97 matchGlob`): a hand-rolled `*`-only multi-segment
  matcher (`search_*`, `*_admin`, `a*b`). Used by the closest analog.
- `per_tool_rate_limiter` (`plugin.go:498 matchToolPattern`): `path.Match` with a
  `/`→sentinel swap so `/` is not treated as a path separator. Full glob (`*`,
  `?`, `[...]`). `config.go` validates patterns with `path.Match(pattern, "")`.
- The spec examples (`search_*`, `calculate`) only need `*`. Either util works;
  `path.Match` (per-tool style) is the more capable and is already used by the
  sibling tool plugin.

### Scope (consumer vs global)
- **Not a plugin-config concern.** Scope is derived from `Policy.Global` + the
  resolved consumer via `RuntimeScope.Subject()` → (`global`+gatewayID |
  `consumer`+consumerID) (`plugin.go:75`, AGENT.md §14.6). The spec's
  `"scope":"consumer"|"global"` field does **not** drive behaviour here.
  Precedent: `per_tool_rate_limiter` keeps a `scope` config field but its catalog
  description says "Informational; effective scope derives from the policy global
  flag" (`catalog_metadata.go:500`); `tool_call_validation` marks `scope`
  "Reserved for future use; currently inert". For a pure `tools[]` filter the
  scope field has **no functional effect at all** (the filter is stateless and
  identical regardless of partition) — so it is purely informational/no-op.

## Affected Areas
- `pkg/infra/plugins/toolallowlist/` (**new package**) — `plugin.go`, `config.go`,
  `data.go`, plus tests. Mirror `modelallowlist` (small files, no comments).
- `pkg/container/modules/plugins.go` — add `toolallowlist.New(p.Adapters)` to the
  `catalog` slice in `newPluginRegistry` (needs only `*adapter.Registry`; no
  Redis/pricing).
- `pkg/app/plugins/catalog_metadata.go` — add a `pluginCatalogMeta["tool_allowlist"]`
  entry (slug, group `Routing` or `Traffic Control`, `SettingsSchema` for
  `allow_tools`/`deny_tools`/`on_empty_after_filter`/`scope`). **Mandatory** or
  `catalog_test.go` fails.
- `pkg/app/plugins/catalog_test.go` — extend the per-slug schema assertions if the
  test enumerates expected slugs/fields.
- `tests/functional/` — new functional test (mirror
  `plugin_token_rate_limiter_test.go` / model-allowlist functional test) for
  allow/deny/empty behaviours across OpenAI + Anthropic.
- `openspec/changes/plugin-tool-allowlist/` — proposal, design, spec, tasks.

## Approaches

1. **New `tool_allowlist` plugin package, canonical-adapter based** — new
   `pkg/infra/plugins/toolallowlist/`; decode with
   `adapter.Registry.DecodeRequestFor`, filter `CanonicalRequest.Tools` by
   allow/deny globs, re-encode + graft (the `per_tool_rate_limiter` pattern) for
   the strip case, and return `Result{StopUpstream,403,Body}` for the reject case.
   - Pros: protocol-aware for free across all registered formats; consistent with
     `model_allowlist` (analog) and `per_tool_rate_limiter` (tool-array sibling);
     uses the blessed `Result.RequestBody` channel; small files; hexagonal-clean
     (infra plugin importing only `app/plugins` + `adapter`, already precedented).
   - Cons: canonical round-trip is **lossy for fields not in `CanonicalRequest`**
     (e.g. `parallel_tool_calls` is absent from the canonical model). The graft
     trick mitigates strip, but the `strip_tools_field` empty case still needs
     **explicit deletion of `tools`/`tool_choice`/`parallel_tool_calls`** (the EE
     cleanup) — `CanonicalToolChoice` exists in the model, so a naive re-encode
     could re-emit `tool_choice` with no tools and break OpenAI.
   - Effort: **Low–Medium**.

2. **New plugin, raw-JSON-map based (direct EE port)** — port EE's
   `removeToolsFromRequest` almost verbatim: `json.Unmarshal(req.Body)` into a
   map, match by `name`/`function.name`, delete the three keys when empty, return
   `Result{RequestBody: marshaled}`.
   - Pros: byte-exact replica of EE behaviour incl. the empty-array cleanup;
     trivially correct for `strip_tools_field`; no canonical lossiness.
   - Cons: re-implements per-format tool-name extraction by hand (OpenAI vs
     Anthropic vs Gemini `functionDeclarations` vs Bedrock) instead of reusing the
     adapter; diverges from the repo's normalisation strategy; brittle as new
     providers/shapes arrive.
   - Effort: **Low**.

3. **Hybrid (recommended): adapter decode for *matching/identification*, targeted
   raw-map mutation for *rewrite*** — use `DecodeRequestFor` to enumerate
   `canonical.Tools[].Name` (protocol-agnostic identification + glob decisions),
   but apply the result to the body with a small explicit raw-JSON edit that
   (a) for partial strip uses the graft approach, and (b) for the empty case
   replicates the EE deletion of `tools`/`tool_choice`/`parallel_tool_calls`.
   - Pros: best of both — reuses the canonical normaliser for the hard part
     (cross-provider tool-name extraction) while guaranteeing the OpenAI-safe
     empty-array cleanup the spec mandates.
   - Cons: two body representations to reason about; must keep the
     name→wire-tool mapping aligned (graft handles it, but worth a focused test).
   - Effort: **Medium**.

## Recommendation
Go with **Approach 3 (hybrid)**, structured as a new
`pkg/infra/plugins/toolallowlist/` package that copies the `model_allowlist`
skeleton (config/validate/glob/reject-body) and borrows `per_tool_rate_limiter`'s
`DecodeRequestFor`→filter→`graftChangedFields` plumbing for tool-array
identification and partial strip. For the `strip_tools_field` empty case and for
`reject`, do an explicit body edit: when the filtered set is empty, delete
`tools`, `tool_choice` and `parallel_tool_calls` from the body map (the ported EE
cleanup) — do not rely on a canonical re-encode, because `CanonicalToolChoice`
would otherwise be re-emitted without tools.

Design decisions to encode in the proposal:
- **Slug**: `tool_allowlist` (parallels `model_allowlist`). Group `Traffic
  Control` or `Routing` (model_allowlist is `Routing`).
- **Stages/modes**: `MandatoryStages = SupportedStages = [StagePreRequest]`;
  `SupportedModes = [ModeEnforce, ModeObserve]` (observe → never mutate/reject,
  only `SetExtras`, like `model_allowlist`).
- **Filter order** (spec): start from client tools → apply `allow_tools` whitelist
  (glob) if set → apply `deny_tools` (glob) after (deny wins). Note this **differs
  from EE**, where a non-empty `white_list` ignored `deny_list`; the spec says
  deny is evaluated *after* allow, so deny can remove an allowed tool. Call this
  out as an intentional behaviour change.
- **`on_empty_after_filter`**: `reject` (403 `no_tools_allowed` body),
  `pass_through_empty` (leave an empty `tools:[]` — but still strip `tool_choice`/
  `parallel_tool_calls`? — open question), `strip_tools_field` (EE cleanup).
- **403 body**: `{ "error": { "type": "no_tools_allowed", "requested": [...],
  "allowed_after_filter": [] } }` via `Result{StopUpstream,403,Body}`.
- **Output channel**: `Result.RequestBody` for rewrites; `Result.Body +
  StopUpstream` for reject.
- **Telemetry**: `data.go` with `ToolAllowlistData{Provider, ToolsRequested,
  ToolsAllowed, ToolsRemoved, Action, OnEmpty, Decision}` via `event.SetExtras`.

## Risks
- **Bedrock coverage gap.** The issue says "Bedrock `toolConfig.tools`", but the
  repo's `BedrockAdapter` (`bedrock_adapter.go`) does **not** parse the Bedrock
  *Converse* API `toolConfig.tools`; it dispatches by model family to native
  formats (Claude→Anthropic top-level `tools`, etc.). And `bedrock` is **not** a
  `SupportedSourceFormat` (`format.go:94`). In practice the plugin decodes the
  **inbound source** body (`SourceFormat`), so a client sending OpenAI/Anthropic
  that is routed to a Bedrock backend is covered; a client sending a raw Bedrock
  Converse body is **not** covered by the canonical path. Must scope Bedrock
  expectations explicitly.
- **Canonical model is lossy.** `CanonicalRequest` has no `parallel_tool_calls`
  field; a pure decode→encode silently drops it. Strip must use `graftChangedFields`
  (preserves unknown keys) and the empty case must delete the three keys
  explicitly. Tool `Schema`/`Description` survive the round-trip but verify with a
  golden test that a non-stripping pass leaves the body byte-stable (graft returns
  original when nothing changed).
- **Deny-after-allow vs EE precedence.** Behaviour change from EE (whitelist no
  longer fully shadows denylist). Intentional per spec; document for migrating
  configs.
- **`scope` config field is a no-op.** Including it (for parity / migration from
  EE-style configs) risks operators thinking it changes partitioning. Mark
  "Informational" in catalog like the sibling plugins, or omit entirely.
- **Parallel-batch body merge.** `mergeIsolated` (executor.go:212) merges only
  `Metadata` + `Headers` back from isolated clones, **not `Body`/`RequestBody`**.
  So a `RequestBody` rewrite is lost if this plugin runs in a *parallel* same-priority
  `pre_request` batch. Single-plugin batches keep the rewrite (the common case).
  Same caveat the budget plugin documented (§14.2). Reject (`StopUpstream`) is
  applied via `applyResult` even in batches, but body rewrites need single-plugin.
- **No-tools / non-LLM request.** Must no-op gracefully (mirror
  `pertoolratelimit`: skip when body empty, format unresolved, decode fails, or
  `len(Tools)==0`) — never 403 a request that simply had no tools unless the spec
  wants empty-after-filter to fire only when tools were present (it does: filter
  acts on a non-empty starting array).

## Open Questions
1. **`pass_through_empty` semantics**: when tools filter to empty and the policy is
   `pass_through_empty`, do we forward `"tools": []` as-is, or also strip
   `tool_choice`/`parallel_tool_calls` (OpenAI 400s on `tool_choice` without
   tools)? Recommend: pass an empty array but still drop a dangling `tool_choice`.
   Needs product confirmation.
2. **Deny-after-allow** confirmed as the intended order (deny overrides allow),
   diverging from EE's "whitelist shadows denylist"? (Spec text says yes.)
3. **`scope` field**: include it as an inert/informational field (EE parity,
   smoother config migration) or omit it entirely? (Recommend inert + documented.)
4. **Bedrock**: is raw Bedrock-Converse-format inbound traffic in scope for v1, or
   only requests whose `SourceFormat` is a supported format (OpenAI/Anthropic/
   Gemini/Mistral) that may target a Bedrock backend? (Recommend the latter for v1.)
5. **Matching target**: match `deny_tools`/`allow_tools` against the tool *name*
   only (canonical `CanonicalTool.Name`), confirmed? (EE matched name; Gemini uses
   `functionDeclarations[].name` — does the GeminiAdapter normalise that into
   `CanonicalTool.Name`? Needs a quick check during design.)
6. **Glob util choice**: reuse `path.Match` (per-tool style, full glob) vs the
   `model_allowlist` `*`-only matcher? (Recommend `path.Match`-style for capability
   parity with the sibling tool plugin.)
7. **403 body shape vs framework**: confirm a `403` `Result.Body` with
   `Content-Type: application/json` is acceptable as the client-facing error here
   (model_allowlist precedent returns a provider-agnostic JSON error, not a
   provider-shaped error envelope).

## Ready for Proposal
**Yes.** The architecture is well understood and almost entirely reuses existing
infrastructure: the `adapter.Registry` canonical tool normaliser, the
`Result.RequestBody` rewrite channel, the `model_allowlist` reject/glob/config
skeleton, and the `per_tool_rate_limiter` decode/strip/graft plumbing. The new
plugin is small (config + glob + filter + 3 empty-array behaviours + a 403 body +
catalog metadata + wiring + tests). The orchestrator should resolve the 7 open
questions (especially `pass_through_empty` cleanup, deny-after-allow precedence,
the `scope` field, and Bedrock scope) before `sdd-propose`.

### Files a future implementer must touch
- **New**: `pkg/infra/plugins/toolallowlist/plugin.go`
- **New**: `pkg/infra/plugins/toolallowlist/config.go`
- **New**: `pkg/infra/plugins/toolallowlist/data.go`
- **New**: `pkg/infra/plugins/toolallowlist/plugin_test.go` + `config_test.go`
- **Edit**: `pkg/container/modules/plugins.go` (register `toolallowlist.New(p.Adapters)`)
- **Edit**: `pkg/app/plugins/catalog_metadata.go` (add `tool_allowlist` metadata — mandatory)
- **Edit**: `pkg/app/plugins/catalog_test.go` (schema assertions, if slug-enumerated)
- **New**: `tests/functional/plugin_tool_allowlist_test.go`
- **New**: `openspec/changes/plugin-tool-allowlist/{proposal,design,tasks}.md` + `specs/`

### Reference implementations to copy from
- `pkg/infra/plugins/modelallowlist/{plugin,config,data}.go` — closest analog
  (allow-list + glob + 403 reject body + observe mode).
- `pkg/infra/plugins/pertoolratelimit/plugin.go` — tool-array decode/strip/graft
  via `adapter.Registry`; `wireFormat()` helper.
- `LegacyGateway-EE/internal/infra/plugins/tool_permission/tool_permission.go` —
  the empty-array cleanup (`tools`/`tool_choice`/`parallel_tool_calls`) to port
  into `strip_tools_field`.
