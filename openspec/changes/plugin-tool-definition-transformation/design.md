# Design: Tool definition transformation plugin — RUN-707

## Technical Approach

New self-contained plugin package `pkg/infra/plugins/tooltransform/`, slug
`tool_definition_transformation`, that mirrors `per_tool_rate_limiter`
(`pkg/infra/plugins/pertoolratelimit/`) almost line-for-line. Single stage
`pre_request`, single mode `enforce`. The plugin decodes `in.Request.Body` via
the provider `*adapter.Registry` into the provider-neutral
`adapter.CanonicalRequest`, mutates `canonical.Tools` (transform then inject),
re-encodes, grafts only the changed `tools` field back onto the original raw
body via the copied `graftChangedFields` helper, and returns the new body via
`Result.RequestBody`. A name collision during injection resolves via
`on_conflict` (`gateway_wins` | `client_wins` | `reject`); `reject` returns a
`*appplugins.PluginError` whose `Body` is the verbatim nested 400 envelope.

The only genuinely new logic is an in-package RFC 7386 JSON merge patch
(`mergepatch.go`, ~20 lines, no new dependency) operating directly on
`CanonicalTool.Schema` (already a decoded `map[string]interface{}`).

All Go is written **without comments** (AGENT.md NO-COMMENTS policy): only the
Apache license header and `//go:generate` directives are permitted. Code follows
golang-pro conventions — `%w` error wrapping, `context` propagation, no goroutine
leaks (this plugin spawns none), table-driven `-race`-clean tests, and
`go vet`/`golangci-lint`-clean output.

## Package file layout — `pkg/infra/plugins/tooltransform/`

| File | Responsibility | Key symbols (unexported unless noted) |
|------|----------------|----------------------------------------|
| `plugin.go` | Plugin contract + `Execute` dispatch + DI constructor + `preRequest` orchestration + `wireFormat`/`graftChangedFields`/`matchToolPattern`/`okResult` (copied from `pertoolratelimit`) | `PluginName` (const), `Plugin` (exported), `New(registry *adapter.Registry)`, `Name/MandatoryStages/SupportedStages/SupportedModes/ValidateConfig/Execute`, `preRequest`, `encodeAndGraft` |
| `config.go` | Config structs + `parseConfig` + `validate` + `onConflict()` accessor | `config`, `fnDef`, `injectDef`, `transformDef`, `parseConfig`, `(*config).validate`, `(*config).onConflict` |
| `mergepatch.go` | RFC 7386 merge patch over `map[string]interface{}` | `mergePatch(target, patch map[string]interface{}) map[string]interface{}` |
| `transform.go` | Per-tool transform application (glob match + cumulative patch + description override) | `applyTransforms(tools []adapter.CanonicalTool, entries []transformDef) (changed bool)` |
| `inject.go` | Injection + `on_conflict` resolution + reject error builder | `applyInjections(tools []adapter.CanonicalTool, entries []injectDef, mode string) ([]adapter.CanonicalTool, []injectOutcome, error)`, `rejectError(name string) error` |
| `data.go` | Trace payload (exported) | `ToolTransformData` |
| `plugin_test.go` | Table-driven unit tests for the whole package | — |

`mergepatch.go`, `transform.go`, and `inject.go` declare no interfaces; the
interface-per-file rule (AGENT.md §10.1) is unaffected — the package exports only
`Plugin`, `New`, `PluginName`, and `ToolTransformData`. This mirrors the
`pertoolratelimit` package shape (one plugin, helpers split by concern).

## Architecture Decisions

| Decision | Choice | Rejected | Rationale |
|----------|--------|----------|-----------|
| Package / slug | New `pkg/infra/plugins/tooltransform/`, slug `tool_definition_transformation` | Extend `pertoolratelimit` | Different intent (reshape vs gate); clean separation; one slug per concern (exploration Approach 1) |
| Tool representation | Canonical `adapter.CanonicalRequest.Tools` | Raw-JSON `tools[]` manipulation | Provider-agnostic; no per-provider tool-shape knowledge; mirrors repo convention (exploration Approach 1 over 2) |
| Injected-tool fidelity | Canonical `{Name,Description,Schema}` only | Raw-graft injection (Approach 3) | v1 non-goal: config-authored tools need no provider-exotic fields; documented limitation |
| Merge patch | In-package ~20-line RFC 7386 helper | Add `evanphx/json-patch` dependency | No dep in `go.mod`; trivial recursion over an already-decoded map; no marshal round-trip |
| Glob matching | stdlib `path.Match` + `/`→`\x00` sentinel (copied from `pertoolratelimit`) | `tokenratelimit.bestMatch` longest-match; `doublestar` | Established repo convention; matches issue `search_*` examples; apply-all (not best-match) is the settled contract |
| Transform precedence | ALL matching entries, declaration order, cumulative; last `description_override` wins | first-match / longest-match | Settled contract (proposal/spec); composable steering |
| `on_conflict` default | `gateway_wins` (empty → `gateway_wins` via `onConflict()` accessor) | `reject` default | Settled contract; least-surprise for operator-injected tools |
| Reject body | Set `PluginError.Body` to marshaled nested envelope | Rely on proxy default envelope | `pluginErrorResult` passes `pe.Body` verbatim when non-nil (confirmed `plugin_runner.go:201`); proxy default wraps `{error,message}` only |
| Deps | `New(*adapter.Registry)` only | Inject Redis / Pricing | Stateless reshape; no counters, no pricing |
| Scope | Informational config field, enum-validated; effective scope from `Policy.Global` | Config-driven scope axis | Matches `per_tool_rate_limiter` + `tool_call_validation` |
| Stage/mode | `pre_request` mandatory+supported, `enforce` only | Multi-stage | Request-leg reshape only; no response behavior |

## Config struct(s) — `config.go`

```go
type fnDef struct {
	Name        string                 `mapstructure:"name"`
	Description string                 `mapstructure:"description"`
	Parameters  map[string]interface{} `mapstructure:"parameters"`
}

type injectDef struct {
	Type     string `mapstructure:"type"`
	Function fnDef  `mapstructure:"function"`
}

type transformDef struct {
	Tool                string                 `mapstructure:"tool"`
	SchemaPatch         map[string]interface{} `mapstructure:"schema_patch"`
	DescriptionOverride *string                `mapstructure:"description_override"`
}

type config struct {
	Scope          string         `mapstructure:"scope"`
	TransformTools []transformDef `mapstructure:"transform_tools"`
	InjectTools    []injectDef    `mapstructure:"inject_tools"`
	OnConflict     string         `mapstructure:"on_conflict"`
}
```

`parseConfig` mirrors `pertoolratelimit.parseConfig` exactly:

```go
const (
	conflictGatewayWins = "gateway_wins"
	conflictClientWins  = "client_wins"
	conflictReject      = "reject"
)

var validScopes = map[string]struct{}{"consumer": {}, "global": {}}

var validConflicts = map[string]struct{}{
	conflictGatewayWins: {},
	conflictClientWins:  {},
	conflictReject:      {},
}

func parseConfig(settings map[string]any) (*config, error) {
	cfg, err := pluginutil.Parse[config](settings)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}
```

`validate()` (table-driven friendly), all errors prefixed
`tool_definition_transformation:`:

- `Scope != ""` ⇒ must be in `{consumer, global}`.
- `OnConflict != ""` ⇒ must be in `{gateway_wins, client_wins, reject}`.
- Each `transform_tools[i]`: `Tool` non-empty; `path.Match(Tool, "")` must not
  error (invalid glob rejected).
- Each `inject_tools[i]`: `Function.Name` non-empty.
- At least one of `TransformTools`/`InjectTools` non-empty (otherwise the policy
  is a no-op and almost certainly misconfigured).

```go
func (c *config) onConflict() string {
	if c.OnConflict != "" {
		return c.OnConflict
	}
	return conflictGatewayWins
}
```

The empty-string default to `gateway_wins` lives **only** in `onConflict()`;
`validate()` accepts the empty string. This matches how
`pertoolratelimit.behaviorDefault()` defaults an empty `behavior_default`.

## Merge patch (RFC 7386) — `mergepatch.go`

`mergePatch` operates in-memory on `CanonicalTool.Schema` (a decoded
`map[string]interface{}`), so no marshal round-trip is needed. Semantics per
RFC 7386: a `nil` patch value **deletes** the key; when both target and patch
values are objects it **recurses**; otherwise the patch value **replaces**.
A nil `target` is allocated so a patch against a missing schema produces a fresh
object.

```go
func mergePatch(target, patch map[string]interface{}) map[string]interface{} {
	if target == nil {
		target = make(map[string]interface{}, len(patch))
	}
	for k, v := range patch {
		if v == nil {
			delete(target, k)
			continue
		}
		patchObj, patchIsObj := v.(map[string]interface{})
		targetObj, targetIsObj := target[k].(map[string]interface{})
		if patchIsObj && targetIsObj {
			target[k] = mergePatch(targetObj, patchObj)
			continue
		}
		target[k] = v
	}
	return target
}
```

Note RFC 7386: when the patch value is an object but the target value is a
scalar/array/absent, the object **replaces** (no recursion into a non-object
target). Arrays are opaque values and always replace wholesale — there is no
element-wise array merge. This is the behaviour the spec's "scalars/arrays
replace" requirement mandates.

## Transform application — `transform.go`

```go
func applyTransforms(tools []adapter.CanonicalTool, entries []transformDef) bool {
	changed := false
	for i := range tools {
		for j := range entries {
			if !matchToolPattern(entries[j].Tool, tools[i].Name) {
				continue
			}
			if len(entries[j].SchemaPatch) > 0 {
				tools[i].Schema = mergePatch(tools[i].Schema, entries[j].SchemaPatch)
				changed = true
			}
			if entries[j].DescriptionOverride != nil {
				tools[i].Description = *entries[j].DescriptionOverride
				changed = true
			}
		}
	}
	return changed
}
```

`matchToolPattern` is copied verbatim from `pertoolratelimit/plugin.go:498-504`
(stdlib `path.Match` with `/`→`\x00` sentinel). Iterating tools-outer /
entries-inner guarantees ALL matching entries apply to each tool in declaration
order, cumulatively; the last `description_override` wins. A tool matched by no
entry is left untouched (`changed` stays false for it).

## Injection + conflict resolution — `inject.go`

A collision is an injected name equal to a surviving tool name (post-transform
client tools) **or** to an already-injected name. The conflict set is therefore
the live `tools` slice as it is being built, so injected-vs-injected collisions
are handled identically to injected-vs-client.

```go
type injectOutcome struct {
	Name    string
	Outcome string
}

const (
	outcomeAppended = "appended"
	outcomeReplaced = "replaced"
	outcomeDropped  = "dropped"
	outcomeRejected = "rejected"
)

func applyInjections(
	tools []adapter.CanonicalTool,
	entries []injectDef,
	conflict string,
) ([]adapter.CanonicalTool, []injectOutcome, error) {
	outcomes := make([]injectOutcome, 0, len(entries))
	for i := range entries {
		fn := entries[i].Function
		ct := adapter.CanonicalTool{
			Name:        fn.Name,
			Description: fn.Description,
			Schema:      fn.Parameters,
		}
		idx := indexOfTool(tools, ct.Name)
		if idx < 0 {
			tools = append(tools, ct)
			outcomes = append(outcomes, injectOutcome{Name: ct.Name, Outcome: outcomeAppended})
			continue
		}
		switch conflict {
		case conflictGatewayWins:
			tools[idx] = ct
			outcomes = append(outcomes, injectOutcome{Name: ct.Name, Outcome: outcomeReplaced})
		case conflictClientWins:
			outcomes = append(outcomes, injectOutcome{Name: ct.Name, Outcome: outcomeDropped})
		case conflictReject:
			return nil, nil, rejectError(ct.Name)
		}
	}
	return tools, outcomes, nil
}

func indexOfTool(tools []adapter.CanonicalTool, name string) int {
	for i := range tools {
		if tools[i].Name == name {
			return i
		}
	}
	return -1
}
```

`gateway_wins` replaces the same-named entry **in place** (preserving tool
order); for injected-vs-injected this keeps the later definition. `client_wins`
keeps the existing entry (for injected-vs-injected the earlier injected one).
`reject` short-circuits with the exact envelope.

### Reject `PluginError`

The proxy's `pluginErrorResult` passes `PluginError.Body` **verbatim** when
non-nil (`plugin_runner.go:201`: `body := pe.Body; if body == nil { ... default
envelope ... }`), so the nested 400 envelope must be the marshaled `Body`.

```go
func rejectError(name string) error {
	payload := map[string]any{
		"error": map[string]any{
			"type": "tool_name_reserved",
			"name": name,
		},
	}
	body, _ := json.Marshal(payload)
	return &appplugins.PluginError{
		StatusCode: http.StatusBadRequest,
		Type:       "tool_name_reserved",
		Message:    fmt.Sprintf("tool name %q is reserved", name),
		Body:       body,
	}
}
```

`json.Marshal` of a `map[string]any` produces sorted keys, yielding the exact
bytes `{"error":{"name":"<tool>","type":"tool_name_reserved"}}`. The spec's
canonical form lists `type` before `name`; key order is irrelevant for a JSON
object, but the test asserts a **semantic** match (unmarshal + compare) AND, for
the byte-exact scenario, marshals the same `map[string]any` to derive the
expected bytes — never a hand-written string with a fixed key order. (If a fixed
field order is ever mandated by a downstream consumer, switch to a small typed
struct with ordered fields; documented here so the test does not over-constrain.)

## Plugin contract + Execute dispatch — `plugin.go`

```go
const PluginName = "tool_definition_transformation"

var _ appplugins.Plugin = (*Plugin)(nil)

type Plugin struct {
	registry *adapter.Registry
}

func New(registry *adapter.Registry) *Plugin {
	return &Plugin{registry: registry}
}

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce}
}

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	if p.registry == nil {
		return okResult(), nil
	}
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("tool_definition_transformation: %w", err)
	}
	dimension, subject, err := in.Scope.Subject()
	if err != nil {
		return okResult(), nil
	}
	switch in.Stage {
	case policy.StagePreRequest:
		return p.preRequest(cfg, in, dimension, subject)
	default:
		return okResult(), nil
	}
}
```

`ctx` is accepted to satisfy the interface and propagated for symmetry with the
siblings even though no I/O occurs here. `dimension`/`subject` are resolved (and
on error the plugin no-ops, mirroring `pertoolratelimit`) purely for the trace
extras (effective scope), consistent with the spec's "effective scope from
`Policy.Global`" requirement — config `scope` never drives behaviour.

### preRequest orchestration

```go
func (p *Plugin) preRequest(
	cfg *config,
	in appplugins.ExecInput,
	dimension, subject string,
) (*appplugins.Result, error) {
	if in.Request == nil || len(in.Request.Body) == 0 {
		return okResult(), nil
	}
	format := wireFormat(in.Request)
	if format == "" {
		return okResult(), nil
	}
	canonical, err := p.registry.DecodeRequestFor(in.Request.Body, adapter.Format(format))
	if err != nil || canonical == nil {
		return okResult(), nil
	}
	if len(canonical.Tools) == 0 && len(cfg.InjectTools) == 0 {
		return okResult(), nil
	}

	before := cloneTools(canonical.Tools)

	transformed := applyTransforms(canonical.Tools, cfg.TransformTools)

	injected, outcomes, err := applyInjections(canonical.Tools, cfg.InjectTools, cfg.onConflict())
	if err != nil {
		setExtras(in.Event, rejectData(format, dimension, subject, cfg.InjectTools))
		return nil, fmt.Errorf("tool_definition_transformation: %w", err)
	}
	canonical.Tools = injected

	if !transformed && len(outcomes) == 0 {
		return okResult(), nil
	}

	setExtras(in.Event, p.data(format, dimension, subject, before, canonical.Tools, outcomes))
	return p.encodeAndGraft(in.Request.Body, format, before, canonical)
}
```

`cloneTools` deep-copies the pre-mutation tool slice (so the graft baseline is
computed from the original decode, not the mutated slice). The `Schema` map is
shallow-cloned per tool; that is sufficient because `mergePatch` replaces map
**values** (and recurses by re-assigning), and the baseline is only ever
re-encoded, never patched again.

### Encode + graft

```go
func (p *Plugin) encodeAndGraft(
	originalBody []byte,
	format string,
	before []adapter.CanonicalTool,
	mutated *adapter.CanonicalRequest,
) (*appplugins.Result, error) {
	ad, err := p.registry.GetAdapter(adapter.Format(format))
	if err != nil {
		return nil, fmt.Errorf("tool_definition_transformation: graft: %w", err)
	}
	baselineReq := *mutated
	baselineReq.Tools = before
	baseline, err := ad.EncodeRequest(&baselineReq)
	if err != nil {
		return nil, fmt.Errorf("tool_definition_transformation: graft: %w", err)
	}
	encoded, err := ad.EncodeRequest(mutated)
	if err != nil {
		return nil, fmt.Errorf("tool_definition_transformation: graft: %w", err)
	}
	body, err := graftChangedFields(originalBody, baseline, encoded)
	if err != nil {
		body = encoded
	}
	return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: body}, nil
}
```

`graftChangedFields`, `wireFormat`, `matchToolPattern`, and `okResult` are
copied verbatim from `pertoolratelimit` (same package-private helpers; they are
not exported from `pertoolratelimit`, so copying is the established pattern — the
budget plugin likewise reimplemented `glob.go` rather than importing). The
baseline is `EncodeRequest` of the canonical request with the **original** tools;
`encoded` is with the mutated tools; only the fields that differ (here `tools`)
are grafted onto the original raw body, preserving provider-specific top-level
fields. On graft error the plugin falls back to the fully re-encoded `encoded`
body (matching `pertoolratelimit.stripTools`).

## Observability — `data.go`

```go
type ToolTransformData struct {
	Stage        string             `json:"stage"`
	Format       string             `json:"format"`
	Dimension    string             `json:"dimension"`
	Subject      string             `json:"subject"`
	Transformed  []TransformedTool  `json:"transformed,omitempty"`
	Injected     []InjectedOutcome  `json:"injected,omitempty"`
}

type TransformedTool struct {
	Tool          string `json:"tool"`
	DescriptionSet bool  `json:"description_set"`
	SchemaPatched bool   `json:"schema_patched"`
}

type InjectedOutcome struct {
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
}
```

`setExtras` mirrors `pertoolratelimit.setExtras` (nil-checks `in.Event`, calls
`event.SetExtras(data)`). `p.data(...)` diffs `before` vs the final tool set to
populate `Transformed` flags and maps `outcomes` to `Injected`; `rejectData(...)`
builds a minimal payload recording the offending injected name(s) with outcome
`rejected` (so the reject path is auditable even though no `Result` is returned).
This satisfies the spec Observability scenarios (extras on mutation AND on
reject).

## DI wiring — `pkg/container/modules/plugins.go`

`pluginParams` is **unchanged** — `Adapters *adapter.Registry` is already
injected. Add one import and one catalog-slice line in `newPluginRegistry`:

```go
import (
	...
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/tooltransform"
	...
)

catalog := []appplugins.Plugin{
	ratelimit.New(redisClient),
	tokenratelimit.New(redisClient, p.Adapters, p.Pricing),
	pertoolratelimit.New(redisClient, p.Adapters),
	tooltransform.New(p.Adapters),
	requestsize.New(),
	cors.New(),
	semanticcache.New(store, p.Locator, p.Adapters),
	modelallowlist.New(),
	tool_call_validation.New(p.Adapters, openai.NewOpenaiClient(), p.Logger),
}
```

No Redis, no pricing, no new `pluginParams` field. The constructor signature is
`func New(registry *adapter.Registry) *Plugin`.

## Catalog metadata — `pkg/app/plugins/catalog_metadata.go`

Add a `pluginCatalogMeta["tool_definition_transformation"]` entry; group
`groupOther` ("Other"), name "Tool Definition Transformation". Stages/modes are
read from the plugin (never duplicated in metadata). The `per_tool_rate_limiter`
entry (`catalog_metadata.go:429-508`) is the array-of-objects template. Field
vocabulary confirmed in `pkg/app/plugins/catalog.go`: `FieldTypeString`,
`FieldTypeEnum`, `FieldTypeObject`, `FieldTypeArray`, `FieldTypeMap`, plus the
`Field.Item`/`Field.Fields`/`Field.Value` containers.

`SettingsSchema.Fields`:

- `transform_tools` — `FieldTypeArray`, `Item` = object with fields:
  - `tool` (`FieldTypeString`, required),
  - `schema_patch` (`FieldTypeObject`, **no child `Fields`** — free-form
    JSON-Schema map; documented v1 degradation, see below),
  - `description_override` (`FieldTypeString`).
- `inject_tools` — `FieldTypeArray`, `Item` = object with fields:
  - `type` (`FieldTypeEnum`, `["function"]`),
  - `function` (`FieldTypeObject`) with children `name` (`FieldTypeString`,
    required), `description` (`FieldTypeString`), `parameters`
    (`FieldTypeObject`, free-form, **no child `Fields`**).
- `on_conflict` — `FieldTypeEnum`, `["gateway_wins","client_wins","reject"]`,
  `Default: "gateway_wins"`.
- `scope` — `FieldTypeEnum`, `["consumer","global"]`, description
  "Informational; effective scope derives from the policy global flag."

### v1 catalog degradation (opaque object fields)

`schema_patch` and `inject_tools[].function.parameters` are arbitrary nested
JSON-Schema. The catalog `Field` vocabulary has **no recursive free-form-object
type** (an object renders its declared `Fields`; a `FieldTypeMap` needs a single
`Value` schema). v1 represents both as a bare `FieldTypeObject` with **no
declared `Fields`** — the admin UI must treat it as an opaque JSON blob (raw JSON
editor). This is a deliberate, documented degradation: the runtime accepts and
applies arbitrary JSON; only the form-builder fidelity is reduced. A richer
recursive-schema `FieldType` is a follow-up, not a v1 requirement.

`catalog_test.go` is extended to assert the new slug appears, its group is
"Other", stages = `[pre_request]` (mandatory+supported), modes = `[enforce]`,
and the top-level field keys/types/enums match the schema above.

## Parallel-batch RequestBody hazard (document, do NOT modify executor)

The executor merges `Headers`/`Metadata` across a parallel batch but applies
`RequestBody` per-result (`req.Body = res.RequestBody`), so when two
body-rewriting `pre_request` plugins share a parallel batch the **last applied
wins** and silently discards the other's edit. This plugin returns
`Result.RequestBody`, so it is exposed to the hazard exactly like
`pertoolratelimit.stripTools` and the budget downgrade.

**Recommendation (operator guidance, not code):** give this policy its own
`priority` so it runs in a non-parallel batch, separate from any other
body-rewriting `pre_request` plugin (notably `per_tool_rate_limiter`'s
`strip_tool_from_request` and `token_rate_limiter`'s downgrade). The
"runs AFTER Tool allowlist" ordering is likewise pure `priority` ordering
(`plan.go` sorts ascending). We do **not** modify the executor in this change;
the hazard is documented in the proposal Risks table and surfaced in operator
docs.

## Error-wrapping conventions

- `Execute` wraps `parseConfig` failures: `fmt.Errorf("tool_definition_transformation: %w", err)`.
- `encodeAndGraft` wraps adapter failures: `"tool_definition_transformation: graft: %w"`.
- `rejectError` returns a `*appplugins.PluginError` directly (a sentinel control
  error, not wrapped) so `appplugins.AsPluginError` (which uses `errors.As`)
  unwraps it through any `%w` chain — `Execute` may safely wrap it as
  `%w` if needed without breaking the proxy's `AsPluginError` detection.
- `ValidateConfig` returns the `parseConfig` error unwrapped (the config-prefixed
  message is already meaningful), matching `pertoolratelimit.ValidateConfig`.
- No `context` cancellation paths exist (no I/O); `ctx` is propagated only to
  satisfy the interface.

## Data flow

```
client ─▶ forwarder.Forward
            stampTarget(req)              req.Provider / SourceFormat set
            runPreRequest ─▶ executor ─▶ Plugin.Execute(pre_request)
               wireFormat(req)
               registry.DecodeRequestFor(body, format) ─▶ *CanonicalRequest
               before := cloneTools(canonical.Tools)
               applyTransforms(canonical.Tools, cfg.TransformTools)     # cumulative, glob, RFC 7386
               applyInjections(canonical.Tools, cfg.InjectTools, onConflict)
                  ├─ append (no collision)
                  ├─ gateway_wins ─▶ replace in place
                  ├─ client_wins  ─▶ drop injected
                  └─ reject       ─▶ PluginError{400, tool_name_reserved, Body:<envelope>}
               ad.EncodeRequest(before) / ad.EncodeRequest(mutated)
               graftChangedFields(originalBody, baseline, encoded)
               Result{StatusCode:200, RequestBody: body}
            executor.applyResult ─▶ req.Body = res.RequestBody
            invokeWithFailover ─▶ provider.go (AdaptRequest) ─▶ upstream
```

## Testing Strategy

All tests live in `plugin_test.go`, table-driven, `go test -race`-clean,
`go vet`/`golangci-lint`-clean. The adapter `*adapter.Registry` is constructed
from the real `adapter` package (the registered OpenAI/Anthropic/… adapters), as
`pertoolratelimit`'s tests do, so the round-trip path is exercised end to end.

### Unit: `mergePatch` (RFC 7386)

| Case | Input target | Patch | Expected |
|------|--------------|-------|----------|
| set scalar | `{type:object}` | `{title:"x"}` | `{type:object,title:"x"}` |
| replace scalar | `{n:1}` | `{n:2}` | `{n:2}` |
| null deletes | `{a:1,b:2}` | `{b:null}` | `{a:1}` |
| nested recurse | `{props:{x:{t:s}}}` | `{props:{x:{t:n},y:{t:s}}}` | `{props:{x:{t:n},y:{t:s}}}` |
| nested null delete | `{props:{x:1,y:2}}` | `{props:{y:null}}` | `{props:{x:1}}` |
| array replaces wholesale | `{required:[a,b]}` | `{required:[c]}` | `{required:[c]}` |
| object replaces scalar (no recurse) | `{a:5}` | `{a:{nested:1}}` | `{a:{nested:1}}` |
| nil target allocates | `nil` | `{a:1}` | `{a:1}` |
| spec example | `{properties:{include_archived:{...},internal_only:{...}}}` | `{properties:{include_archived:{enum:[false]},internal_only:null},required:[query]}` | `internal_only` removed, `enum` set, sibling keys preserved, `required` added |

### Unit: glob (`matchToolPattern`)

`search_*` vs `search_docs` (match) / `send_email` (no match); `?`
single-char; `[abc]` class; invalid pattern `[` rejected by `validate()`
(via `path.Match(tool, "")` erroring); `/`-containing names handled by the
sentinel.

### Unit: `applyTransforms`

- single match patches schema + sets description; `changed == true`.
- no match leaves tool untouched; `changed == false`.
- **cumulative**: entries `search_*` and `search_logs` both match `search_logs`
  → both schema patches accrue; last `description_override` wins.
- description-only entry (nil `SchemaPatch`) sets description, doesn't touch
  schema; schema-only entry (nil `DescriptionOverride`) patches schema, keeps
  description.

### Unit: `applyInjections` (on_conflict matrix)

| Scenario | conflict | Expected |
|----------|----------|----------|
| no collision | any | appended; outcome `appended` |
| client-name collision | gateway_wins | injected replaces existing **in place** (order preserved); outcome `replaced` |
| client-name collision | client_wins | injected dropped, existing kept; outcome `dropped` |
| client-name collision | reject | `rejectError(name)`; `PluginError{400, type=tool_name_reserved}` |
| injected-vs-injected (same name twice) | gateway_wins | later kept (first appended, second replaces in place) |
| injected-vs-injected | client_wins | earlier kept, later dropped |
| injected-vs-injected | reject | 400 with the duplicated name |
| empty `on_conflict` | (default) | behaves as `gateway_wins` via `onConflict()` |

### Unit: reject body byte-exactness

Assert `PluginError.StatusCode == 400`, `Type == "tool_name_reserved"`, and
`Body` unmarshals to `{"error":{"type":"tool_name_reserved","name":"safety_check"}}`.
Derive the expected bytes by marshaling the same `map[string]any` (not a hardcoded
string) to avoid over-constraining key order; also assert a semantic
deep-equal after `json.Unmarshal`.

### Unit: inject-after-transform ordering

Config with a transform on `search_*` and an injection of `safety_check`: assert
the final `canonical.Tools` contains the **transformed** client tool AND the
injected tool, and that injection observed the post-transform set (e.g. a
transform that renames is out of scope, but an injection colliding with a tool
only present after transform is covered by the injected-vs-client cases).

### Unit: per-provider round-trip (graft)

For each format — **OpenAI completions + responses, Anthropic** (mandatory
minimum), plus Gemini/Bedrock/Mistral (coverage parity with
`pertoolratelimit`): build a raw request body with one tool and a
provider-specific top-level field, run `preRequest` with a transform + an
injection, then decode the returned `RequestBody` back via the same adapter and
assert: (a) the transformed tool carries the patched schema/description, (b) the
injected tool is present, (c) the untouched top-level field survives **verbatim**
in the grafted body. Cross-provider equivalence: equivalent OpenAI and Anthropic
requests with the same logical tools + same config yield equivalent canonical
tool sets.

### Unit: no-op / passthrough

- empty/nil body → `okResult()`, no `RequestBody`.
- unknown/empty wire format → `okResult()`.
- undecodable body for the format → `okResult()`.
- tools present, no transform matches, no `inject_tools` → `okResult()` (no
  rewrite).
- `len(Tools)==0 && len(InjectTools)==0` → `okResult()`.

### Unit: config validation (`ValidateConfig`)

| Config | Expect |
|--------|--------|
| valid transform-only | ok |
| valid inject-only | ok |
| `scope:"team"` | error |
| `on_conflict:"merge"` | error |
| inject with empty `function.name` | error |
| `transform_tools[].tool:""` | error |
| `transform_tools[].tool:"["` (invalid glob) | error |
| both `transform_tools` and `inject_tools` empty | error |
| empty `on_conflict` with injects | ok (defaults gateway_wins) |

### Functional (`tests/functional/`, `functional` build tag)

Mirror `plugin_per_tool_rate_limiter_test.go`: set up a policy route binding the
plugin, send a request with `tools[]`, assert the upstream-received body was
patched/injected (capture via a recording upstream), and assert the `reject`
collision path returns `400` with the exact envelope. (Functional tests are
sketched here for `sdd-tasks`; not all are required for the first chained PR.)

## Migration / Rollout

Additive and self-contained. New package + one `newPluginRegistry` line + one
catalog metadata entry. No schema migrations, no shared state, no `pluginParams`
change. Ships as chained PRs (`sdd-tasks` forecasts the split): config+validate
+ mergepatch → transform/inject + plugin orchestration → DI + catalog + catalog
test → functional tests. Rollback = remove the registry line, the catalog entry,
and the package; zero impact on existing traffic.

## Open questions (resolve in code during apply)

1. **OpenAI Responses tool envelope** — confirm `OpenAIResponsesAdapter`
   populates `CanonicalTool.{Name,Description,Schema}` on decode AND re-emits the
   Responses-API tool shape on encode (it differs from Chat Completions). Resolve
   in `pkg/infra/providers/adapter/openai_responses_adapter.go` (tool
   decode/encode) — add a round-trip test row; if a format drops tools, exclude
   it from the v1 coverage claim.
2. **Anthropic `type+custom` tool shape on re-encode** — the Anthropic adapter
   supports both flat and `type+custom` tool shapes on decode
   (`anthropic_adapter.go:327-336`); confirm `EncodeRequest`
   (`:426-439`) round-trips an injected (flat canonical) tool into a shape
   Anthropic accepts, and that `graftChangedFields` doesn't double-wrap. Resolve
   in the Anthropic round-trip test.
3. **`schema_patch` non-object top-level** — `mergePatch` assumes the patch root
   is an object (it is, per config typing `map[string]interface{}`). Confirm
   mapstructure decodes a JSON object into `map[string]interface{}` (not
   `map[interface{}]interface{}`) so the `.(map[string]interface{})` type
   assertions in `mergePatch` hold for nested values. Resolve in
   `pluginutil.Decode` config (it uses mapstructure; verify the decoder hook
   produces `map[string]interface{}`) and a nested-patch test.
4. **Catalog free-form object rendering** — confirm `catalog_test.go` and any
   frontend contract tolerate a `FieldTypeObject` with empty `Fields` (the v1
   opaque-blob degradation). If a non-empty `Fields` or a dedicated raw-JSON
   field type is required, adjust the metadata. Resolve in `catalog.go` /
   `catalog_test.go`.

