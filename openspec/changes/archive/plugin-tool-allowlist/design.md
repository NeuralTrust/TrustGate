# Design: Tool allowlist plugin (pre-request tool-array access control) — RUN-706

## Technical Approach

New first-class `pre_request` plugin, slug `tool_allowlist`, in a new package
`pkg/infra/plugins/toolallowlist/`. It mirrors `model_allowlist`'s skeleton
(config + glob + 403 reject body + observe mode) and borrows
`per_tool_rate_limiter`'s `adapter.Registry` decode → re-encode → graft plumbing,
applied to the canonical `tools[]` array instead of the model field.

Per the exploration's **Approach 3 (hybrid)**: use
`adapter.Registry.DecodeRequestFor` to enumerate `CanonicalRequest.Tools[].Name`
for protocol-agnostic glob matching, then apply the result to the wire body two
ways: **partial strip** uses canonical re-encode + `graftChangedFields`
(preserves unknown keys like `parallel_tool_calls`); **empty-after-filter** cases
do an explicit raw-JSON-map edit (the ported EE `removeToolsFromRequest` cleanup)
so a canonical re-encode never re-emits `tool_choice` with no tools.

Output is returned exclusively through the framework-blessed channel
`appplugins.Result` (executor.go:270-271 applies `req.Body = res.RequestBody`
when non-nil; reject short-circuits via `StopUpstream`).

All Go is written **without comments** save the repo-wide Apache license header
that every existing file in these packages carries (see Decision Record DR-8).
Follows golang-pro: errors wrapped with `%w`, `context` propagated, table-driven
`-race` tests.

## Package file layout — `pkg/infra/plugins/toolallowlist/`

| File | Responsibility | Key symbols (unexported unless noted) |
|------|----------------|---------------------------------------|
| `plugin.go` | Plugin contract + `Execute` + decode/filter/rewrite/reject + DI constructor | `PluginName` (const `"tool_allowlist"`), `Plugin` (exported, `struct{ registry *adapter.Registry }`), `New(adapters *adapter.Registry) appplugins.Plugin`, `Name/MandatoryStages/SupportedStages/SupportedModes/ValidateConfig/Execute`, `wireFormat`, `filter`, `stripTools`, `rewriteEmpty`, `newRejectResult`, `okResult`, `setExtras`, `matchAny`, `matchToolPattern`, `graftChangedFields` |
| `config.go` | Config struct + `parseConfig` + `validate` + defaults | `config`, `parseConfig`, `(*config).applyDefaults`, `(*config).validate`, glob/enum validation |
| `data.go` | Telemetry trace payload + 403 reject body structs + decision/action consts | `ToolAllowlistData` (exported), `errorBody`/`errorDetail`, `decision*`/`action*`/`onEmpty*` consts |
| `plugin_test.go` | Table-driven `Execute` tests (`-race`) | filter precedence, globs, each `on_empty`, partial strip graft, no-op, observe |
| `config_test.go` | Table-driven `validate` tests | allow/deny presence, glob validity, enum validity |

The package exports only `Plugin`, `New`, `PluginName`, and `ToolAllowlistData`.
No interfaces are introduced, so the interface-per-file rule (AGENT.md §10.1) is
unaffected. `matchToolPattern` and `graftChangedFields` are copied **locally**
because the originals are unexported in `pertoolratelimit` (DR-1, DR-2).

## Architecture Decisions

| Decision | Choice | Rejected | Rationale |
|----------|--------|----------|-----------|
| Plugin package/slug | New `toolallowlist` pkg, slug `tool_allowlist` | Extend an existing plugin | Issue intent; parallels `model_allowlist`; additive, zero migration |
| Body identification | `adapter.Registry.DecodeRequestFor` canonical tool names | Hand-rolled per-format extraction (EE port) | Protocol-aware across all formats for free; one normalisation source |
| Partial-strip rewrite | canonical re-encode + `graftChangedFields` | Pure canonical re-encode | Graft preserves keys absent from `CanonicalRequest` (`parallel_tool_calls`) |
| Empty-after-filter rewrite | Explicit raw-JSON-map key deletion (ported EE cleanup) | Canonical re-encode | `CanonicalToolChoice` would be re-emitted without tools → OpenAI 400 |
| Glob matcher | Local `matchToolPattern` (`path.Match` + `/`-sentinel) | Reuse `pertoolratelimit` (unexported) / `model_allowlist` `*`-only | Capability parity with sibling tool plugin; no cross-plugin dep |
| Graft helper | Local copy of `graftChangedFields` | Export from `pertoolratelimit` and import | Avoids cross-plugin coupling; helper is ~25 lines |
| `scope` field | Inert, informational only | Drive partitioning / omit entirely | Scope derives from `Policy.Global` (AGENT.md §14.6); EE-config parity |
| Reject envelope | `Result{StopUpstream,403,Body}` provider-agnostic JSON | `PluginError{Body}` | Established `model_allowlist` pattern (`newRejectResult`) |
| Modes | `[ModeEnforce, ModeObserve]`; observe never mutates/rejects | Enforce-only | Mirrors `model_allowlist`; observe = `SetExtras` only |
| Constructor return | `New(*adapter.Registry) appplugins.Plugin` | concrete `*Plugin` | Per task; siblings return `*Plugin` but DI slice is `[]appplugins.Plugin` so both compile (DR-9) |

## Config struct (`config.go`)

```go
type config struct {
	Scope              string   `mapstructure:"scope"`
	AllowTools         []string `mapstructure:"allow_tools"`
	DenyTools          []string `mapstructure:"deny_tools"`
	OnEmptyAfterFilter string   `mapstructure:"on_empty_after_filter"`
}
```

Parsed by `pluginutil.Parse[config](settings)` (decode.go:38, `WeaklyTypedInput`).
`applyDefaults` then `validate` run inside `parseConfig`, exactly like
`modelallowlist.parseConfig` (config.go:38-48).

`applyDefaults`: `OnEmptyAfterFilter == ""` → `"reject"`.

`validate` (table-driven friendly):
- at least one of `AllowTools` / `DenyTools` non-empty, else
  `"tool_allowlist: at least one of allow_tools or deny_tools must be provided"`.
- every pattern in both lists is non-blank and a valid `path.Match` glob —
  validated with `path.Match(pattern, "")` returning a nil error (the same probe
  `pertoolratelimit` uses, config.go:108).
- `OnEmptyAfterFilter ∈ {reject, pass_through_empty, strip_tools_field}` (after
  defaulting `""` → `reject`), else an error.
- `Scope`, if set, `∈ {consumer, global}` (parity with `pertoolratelimit`
  config.go:76-81); but it is otherwise unused.

Enum constants live in `config.go`:

```go
const (
	onEmptyReject      = "reject"
	onEmptyPassThrough = "pass_through_empty"
	onEmptyStripField  = "strip_tools_field"
)
```

## Filter semantics

Start from the decoded `canonical.Tools[]`. For each tool name:
1. If `AllowTools` is non-empty and the name matches **no** allow glob → removed.
2. Else if the name matches **any** `DenyTools` glob → removed (deny applied
   **after** allow, so deny overrides allow — intentional divergence from EE,
   DR-7).
3. Else kept.

`matchAny(name string, patterns []string) (string, bool)` returns the first
matching pattern (mirrors `modelallowlist.matchAny`, config.go:88-95) but uses
the local `matchToolPattern` glob.

Matching is on the canonical **name** only (`CanonicalTool.Name`), which the
adapters normalise uniformly: OpenAI `tools[].function.name`, Anthropic top-level
`tools[].name`, Gemini `functionDeclarations[].name`
(gemini_adapter.go:205-210). Open question 5 resolved — Gemini names normalise
into `CanonicalTool.Name`.

## Execution flow (`Execute`)

`MandatoryStages = SupportedStages = [policy.StagePreRequest]`;
`SupportedModes = [policy.ModeEnforce, policy.ModeObserve]`. Only one stage, so
no `switch in.Stage` dispatch is needed (unlike `pertoolratelimit`).

```
Execute(ctx, in):
  cfg := parseConfig(in.Config.Settings)            # wrap err with %w
  if in.Request == nil || len(in.Request.Body) == 0: return okResult()
  format := wireFormat(in.Request)                  # SourceFormat else Provider
  if format == "": return okResult()
  canonical, err := registry.DecodeRequestFor(Body, adapter.Format(format))
  if err != nil || canonical == nil || len(canonical.Tools) == 0:
      return okResult()                             # no-op: unsupported/empty/decode-fail

  requested := names(canonical.Tools)
  kept, removed := filter(canonical.Tools, cfg)
  blocks := appplugins.Blocks(in.Mode)

  if len(removed) == 0:                             # nothing to do
      setExtras(allowed); return okResult()

  if !blocks:                                       # OBSERVE: never mutate/reject
      setExtras(would_filter, requested, kept, removed, action=observe)
      appplugins.SetDecision(in.Event, in.Mode)
      return okResult()

  # ENFORCE
  if len(kept) > 0:                                 # partial strip
      setExtras(action=stripped, ...)
      return stripTools(Body, format, canonical, removedSet)   # graft → RequestBody

  # all tools filtered out → on_empty_after_filter
  switch cfg.OnEmptyAfterFilter:
    reject:            setExtras(action=rejected); return newRejectResult(requested)
    strip_tools_field: setExtras(action=stripped_field); return rewriteEmpty(Body, deleteTools=true)
    pass_through_empty:setExtras(action=passed_empty); return rewriteEmpty(Body, deleteTools=false)
```

`req.Provider`/`req.SourceFormat` are stamped at backend selection before
`pre_request` runs (AGENT.md §14.1), so `wireFormat` is reliable. `wireFormat`
is a local copy of `pertoolratelimit.wireFormat` (plugin.go:513-521).

`Blocks` and `SetDecision` are the same `appplugins` helpers `model_allowlist`
uses (plugin.go:62, 104).

## Body rewrite

### Partial strip — `stripTools` (mirror of `pertoolratelimit.stripTools`, plugin.go:186-217)

```go
ad := registry.GetAdapter(adapter.Format(format))
fullEncoded := ad.EncodeRequest(canonical)
canonical.Tools = kept
strippedEncoded := ad.EncodeRequest(canonical)
body, err := graftChangedFields(originalBody, fullEncoded, strippedEncoded)
if err != nil { body = strippedEncoded }
return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: body}, nil
```

`graftChangedFields` (local copy of plugin.go:219-246) diffs full vs stripped
encodings and applies only changed top-level keys onto the **original** body, so
keys the canonical model omits (`parallel_tool_calls`) survive untouched. When
some tools remain, `tool_choice` is byte-identical between full and stripped
encodings → not grafted → preserved.

### Empty cases — `rewriteEmpty` (ported EE `removeToolsFromRequest`, tool_permission.go:275-282)

```go
var m map[string]json.RawMessage
json.Unmarshal(originalBody, &m)
delete(m, "tool_choice")
delete(m, "parallel_tool_calls")
if deleteTools {
	delete(m, "tools")                 # strip_tools_field
} else {
	m["tools"] = json.RawMessage("[]") # pass_through_empty
}
body, _ := json.Marshal(m)
return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: body}, nil
```

Both empty cases drop the dangling `tool_choice`/`parallel_tool_calls` (resolves
open question 1: `pass_through_empty` forwards `tools: []` but still strips the
dangling fields, since OpenAI 400s on `tool_choice` without tools).

### Reject — `newRejectResult` (mirror of `modelallowlist.newRejectResult`, plugin.go:141-155)

```go
body, err := json.Marshal(newErrorBody(requested))
if err != nil { return nil, &appplugins.PluginError{StatusCode: http.StatusForbidden, Message: "no tools allowed"} }
return &appplugins.Result{
	StopUpstream: true,
	StatusCode:   http.StatusForbidden,
	Headers:      map[string][]string{"Content-Type": {"application/json"}},
	Body:         body,
}, nil
```

## 403 reject body & telemetry (`data.go`)

```go
type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Type               string   `json:"type"`
	Requested          []string `json:"requested"`
	AllowedAfterFilter []string `json:"allowed_after_filter"`
}

func newErrorBody(requested []string) errorBody {
	return errorBody{Error: errorDetail{
		Type:               "no_tools_allowed",
		Requested:          requested,
		AllowedAfterFilter: []string{},
	}}
}

type ToolAllowlistData struct {
	Provider       string   `json:"provider"`
	ToolsRequested []string `json:"tools_requested"`
	ToolsAllowed   []string `json:"tools_allowed"`
	ToolsRemoved   []string `json:"tools_removed"`
	Action         string   `json:"action"`
	OnEmpty        string   `json:"on_empty,omitempty"`
	Decision       string   `json:"decision"`
}
```

`Provider` is sourced from `in.Request.Provider`. `setExtras` is nil-safe
(`if event == nil { return }`, mirror of plugin.go:159-164) and calls
`event.SetExtras(data)`. `appplugins.SetDecision(in.Event, in.Mode)` is called on
the observe path (matching `model_allowlist`).

## Glob matcher (`plugin.go`)

Local copy of `pertoolratelimit.matchToolPattern` (plugin.go:498-504):

```go
func matchToolPattern(pattern, name string) bool {
	const sentinel = "\x00"
	p := strings.ReplaceAll(pattern, "/", sentinel)
	n := strings.ReplaceAll(name, "/", sentinel)
	ok, err := path.Match(p, n)
	return err == nil && ok
}
```

Full `path.Match` glob (`*`, `?`, `[...]`); the `/`→sentinel swap stops `/` being
treated as a path separator. Config-time validation uses `path.Match(pattern, "")`.

## DI wiring (`pkg/container/modules/plugins.go`)

`pluginParams` already injects `Adapters *adapter.Registry` (plugins.go:40-47);
no struct change is needed. Add the import and one slice entry to
`newPluginRegistry` (plugins.go:71-80):

```go
import "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/toolallowlist"

catalog := []appplugins.Plugin{
	...
	modelallowlist.New(),
	toolallowlist.New(p.Adapters),
	tool_call_validation.New(p.Adapters, openai.NewOpenaiClient(), p.Logger),
}
```

The constructor needs only the adapter registry — no Redis/cache/pricing/locator.

## Catalog metadata (`pkg/app/plugins/catalog_metadata.go`)

Add `pluginCatalogMeta["tool_allowlist"]`. Group `groupRouting` (`"Routing"`) to
match `model_allowlist` (catalog_metadata.go:563). `SettingsSchema.Fields`:

| Key | Type | Notes |
|-----|------|-------|
| `allow_tools` | `FieldTypeArray` (item `FieldTypeString`) | glob whitelist |
| `deny_tools` | `FieldTypeArray` (item `FieldTypeString`) | glob denylist (applied after allow) |
| `on_empty_after_filter` | `FieldTypeEnum` | enum `[reject, pass_through_empty, strip_tools_field]`, default `reject` |
| `scope` | `FieldTypeEnum` | enum `[consumer, global]`, description "Informational; effective scope derives from the policy global flag." |

```go
"tool_allowlist": {
	name:        "Tool Allowlist",
	group:       groupRouting,
	description: "Restrict which tools a consumer or gateway may expose to the model, matching tool names with glob patterns. Allow-list, deny-list (applied after allow), and choose what happens when filtering empties the array: reject (403), strip the tools field, or forward an empty array.",
	schema: SettingsSchema{Fields: []Field{ ... }},
},
```

## `catalog_test.go` changes (REQUIRED — see OQ-1)

The existing test uses a **hardcoded** `builtinSlugs` subset, not the live
registry. To keep `tool_allowlist` curated and covered:

1. `builtinSlugs` (lines 28-35): add `"tool_allowlist"`.
2. `registerBuiltins` `specs` (lines 45-51): add
   `{"tool_allowlist", []policy.Stage{policy.StagePreRequest}, []policy.Stage{policy.StagePreRequest}}`.
3. `TestCatalogService_GroupsAndOrder` (line 76): extend the Routing
   `assert.ElementsMatch` to `{"semantic_cache", "model_allowlist", "tool_allowlist"}`.
4. (Optional) add `TestToolAllowlistSchema` asserting the four fields/enums, in
   the style of `TestTokenRateLimiterSchema_*`.

`TestPluginCatalogMeta_CoversBuiltins` (line 261) and
`TestCatalogService_EntriesHaveStagesAndSchema` (line 79) then automatically
assert the new slug has name, description, a valid group, non-empty schema, and
`ModeEnforce` support.

## Data flow

```
client ─▶ forwarder.Forward
            stampTarget(req)              req.Provider, req.SourceFormat set (§14.1)
            runPreRequest ─▶ executor ─▶ Plugin.Execute(pre)
                                          DecodeRequestFor(Body, format) ─▶ canonical.Tools
                                          filter(allow→deny) ─▶ kept / removed
                                          partial  ─▶ stripTools ─▶ Result.RequestBody (graft)
                                          empty    ─▶ rewriteEmpty ─▶ Result.RequestBody (raw map)
                                          reject   ─▶ Result{StopUpstream,403,Body}
            applyResult: req.Body = res.RequestBody (executor.go:270)
            invokeOnce ─▶ provider.go (req.Body ─▶ AdaptRequest) ─▶ upstream
```

## Testing strategy

| Layer | What | How |
|-------|------|-----|
| Unit (`config_test.go`) | validate: missing both lists, blank pattern, bad glob (`[`), bad `on_empty` enum, bad `scope`, default `on_empty`→reject | table-driven, `-race` |
| Unit (`plugin_test.go`) | allow-only drops non-matches; deny-only removes matches; allow+deny precedence (deny wins on an allowed tool); glob (`search_*`); each `on_empty` (reject 403 body, strip_tools_field deletes 3 keys, pass_through_empty sets `[]` + drops 2 keys); partial strip preserves `parallel_tool_calls` via graft; no-op (nil request, empty body, unresolved format, decode error, no tools); observe mode never mutates/rejects | table-driven, `-race`, OpenAI + Anthropic fixtures |
| Functional (`tests/functional/plugin_tool_allowlist_test.go`) | allow/deny/empty across OpenAI + Anthropic; assert forwarded `tools[]` and 403 | mirror `plugin_per_tool_rate_limiter_test.go` helpers: `setupPolicyRoute`, `policyPlugin`, `proxyRequest`, `mustJSON`, `chatRequestWithTools`, `forwardedToolNames`, `Track`, `fakeUpstream` (all in `plugin_e2e_common_test.go`); `//go:build functional` |

Run unit with `go test -race ./pkg/infra/plugins/toolallowlist/...`; functional
with the `functional` build tag. Also run `go vet` + `golangci-lint`.

## Decision Records

### DR-1 — Local glob matcher, not cross-plugin reuse
- **Decision:** copy `matchToolPattern` (`path.Match` + `/`-sentinel) into
  `toolallowlist`.
- **Rationale:** `pertoolratelimit.matchToolPattern` is unexported (plugin.go:498);
  exporting it to share would couple two infra plugins. The helper is 5 lines.
- **Alternatives:** export from `pertoolratelimit`; reuse `model_allowlist`'s
  `*`-only `matchGlob` (config.go:97) — rejected for weaker glob support.
- **Consequences:** two identical copies of a tiny matcher; capability parity with
  the sibling tool plugin.

### DR-2 — Hybrid canonical-decode + raw-map edit, not pure canonical
- **Decision:** identify tools via canonical decode; rewrite partial strips via
  canonical re-encode + graft, but rewrite empty cases via raw-map key deletion.
- **Rationale:** `CanonicalRequest` has no `parallel_tool_calls` (canonical.go:25-39),
  and `CanonicalToolChoice` (canonical.go:57-62) would be re-emitted on an empty
  re-encode → OpenAI 400. Raw deletion of `tools`/`tool_choice`/`parallel_tool_calls`
  is the proven EE cleanup (tool_permission.go:275-282).
- **Alternatives:** pure canonical re-encode (lossy, breaks empty case); pure
  raw-map port (re-implements per-format extraction, brittle).
- **Consequences:** two body representations; covered by a graft golden test and
  per-`on_empty` tests.

### DR-7 — Deny applied after allow (deny overrides allow)
- **Decision:** `deny_tools` is evaluated after `allow_tools`; a denied tool is
  removed even if allow-listed.
- **Rationale:** RUN-706 spec; clearer composition than EE's "whitelist shadows
  denylist" (tool_permission.go:202-235).
- **Alternatives:** EE precedence (non-empty whitelist ignores denylist).
- **Consequences:** behaviour change from EE; documented as a migration note in
  the proposal. Resolves open question 2.

### DR-8 — License header is the only permitted comment
- **Decision:** new files carry the repo-wide Apache 2.0 header (present in every
  file in these packages); no other comments, including Go doc comments.
- **Rationale:** AGENT.md §11 forbids code/doc comments; the license header is a
  legal banner, not documentation, and is universal across the codebase
  (e.g. modelallowlist/*.go carry only the header).
- **Alternatives:** omit the header — rejected (inconsistent with every sibling
  file and likely a license-check failure).
- **Consequences:** files open with the header block, then `package toolallowlist`,
  then code.

### DR-9 — Constructor returns `appplugins.Plugin`
- **Decision:** `func New(adapters *adapter.Registry) appplugins.Plugin`.
- **Rationale:** the DI catalog slice is `[]appplugins.Plugin`; returning the
  interface satisfies it directly (per task).
- **Alternatives:** return concrete `*Plugin` like `modelallowlist.New`
  (plugin.go:35) / `pertoolratelimit.New` (plugin.go:69) — also compiles into the
  slice. Either is acceptable; keep `var _ appplugins.Plugin = (*Plugin)(nil)`
  regardless.
- **Consequences:** none functional; noted so the orchestrator does not flag a
  signature mismatch against siblings.

### DR-10 — Inert `scope` field
- **Decision:** keep `scope` in config + catalog, validated to
  `{consumer, global}` but otherwise unused.
- **Rationale:** scope derives from `Policy.Global` + resolved consumer via
  `RuntimeScope.Subject()` (plugin.go:75-86, AGENT.md §14.6); a stateless tool
  filter is identical regardless of partition. Precedent: `pertoolratelimit`
  (catalog_metadata.go:500-505), `tool_call_validation` (catalog_metadata.go:605-609).
- **Alternatives:** omit entirely — rejected for EE-config migration parity.
- **Consequences:** operators might misread it as functional; catalog description
  marks it informational. Resolves open question 3.

### DR-11 — Bedrock scope: source-format only for v1
- **Decision:** cover any request whose `SourceFormat` is a supported canonical
  format (OpenAI/Anthropic/Gemini/Mistral/…); raw Bedrock-Converse inbound bodies
  are out of scope.
- **Rationale:** `bedrock` is not a `SupportedSourceFormat` (format.go:94-96) and
  the Bedrock adapter does not parse `toolConfig.tools`. Such requests no-op
  gracefully (decode error → `okResult`). Resolves open question 4.
- **Alternatives:** hand-parse Bedrock Converse — rejected as out of scope.
- **Consequences:** documented limitation; a client sending OpenAI/Anthropic
  routed to a Bedrock backend is still covered.

### DR-12 — Parallel-batch body-rewrite limitation
- **Decision:** body rewrites (`RequestBody`) are reliable only in single-plugin
  `pre_request` batches; document the caveat.
- **Rationale:** `mergeIsolated` (executor.go:212-224) merges only `Metadata` +
  `Headers` from isolated clones, **not** `Body`/`RequestBody`. A `RequestBody`
  rewrite is dropped if this plugin runs in a parallel same-priority batch. Reject
  via `StopUpstream` is applied by `applyResult` regardless.
- **Alternatives:** extend the framework to merge body — out of scope (same caveat
  the budget plugin documented, §14.2).
- **Consequences:** operators should not group `tool_allowlist` in a parallel
  `pre_request` batch when relying on strip/pass-through; single-plugin batches
  (the common case) preserve rewrites.

## Migration / Rollout

Additive and self-contained. Ships as one cohesive change (small plugin). Rollback
= delete `pkg/infra/plugins/toolallowlist/`, revert the `tool_allowlist` catalog
metadata + `catalog_test` edits + the `newPluginRegistry` slice entry. No existing
plugin/config is affected. EE migration: `allow_tools` ← `white_list`,
`deny_tools` ← `deny_list`, set `on_empty_after_filter: strip_tools_field` to
preserve EE behaviour (default is `reject`), and re-check deny ordering (DR-7).

## Open Questions (from real code)

- **OQ-1 — catalog_test does NOT enforce metadata for every registered slug.**
  The exploration/proposal claim that `catalog_test.go` forces metadata for every
  registered plugin is **inaccurate**. `builtinSlugs` (catalog_test.go:28-35) is a
  hardcoded list of **6** slugs and omits `per_tool_rate_limiter` and
  `tool_call_validation`, which `newPluginRegistry` (plugins.go:71-80) actually
  registers. So adding `tool_allowlist` metadata is **not auto-forced**; without
  the explicit edits in the "`catalog_test.go` changes" section the new slug would
  surface uncurated (group `Other`, empty schema) but tests stay green. The design
  treats the four edits as required to keep parity. Confirm this is the desired
  bar (i.e. add to `builtinSlugs` rather than switch the test to the live
  registry).
- **OQ-2 — `TestCatalogService_GroupsAndOrder` Routing assertion is exact.**
  Line 76 `assert.ElementsMatch(..., {"semantic_cache", "model_allowlist"}, byType[groupRouting])`
  will fail once `tool_allowlist` joins `groupRouting` via `builtinSlugs`. It must
  be extended to include `"tool_allowlist"`. Flagged so the apply phase does not
  miss it.
- **OQ-3 — constructor signature vs siblings.** Task specifies
  `New(*adapter.Registry) appplugins.Plugin`; siblings return concrete `*Plugin`
  (modelallowlist plugin.go:35, pertoolratelimit plugin.go:69). Both compile into
  the `[]appplugins.Plugin` catalog. Proceeding with the task signature (DR-9);
  confirm no house-style preference for the concrete return.
