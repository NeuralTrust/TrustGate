# Design: Prompt template plugin — RUN-702

## Technical Approach

A net-new infra plugin `prompt_template` under
`pkg/infra/plugins/prompttemplate/`, registered in the catalog and run at
`pre_request`. It mirrors `model_allowlist` exactly: it reads the raw
provider-native request JSON (`in.Request.Body`), mutates the
`system` / `messages[]` shape, and returns the rewritten bytes via
`Result.RequestBody`. Config is parsed with `pluginutil.Parse[config]`
(mapstructure), validated admin-time in `ValidateConfig`, and rejected at
runtime through `*appplugins.PluginError{StatusCode, Type, ...}`.

Two cooperating modes share one instance:

- **Mode A (context injection)** — render each `inject_templates[]` entry from
  `context_variables{}` (header / unverified jwt_claim) and inject it as a
  `system` message per `on_existing_system`.
- **Mode B (template reference)** — detect `{template://<name>@<label>}` in the
  inbound body, resolve the named version by label (with `default_label`
  fallback), validate client-supplied variables against `required_variables`,
  render, and splice the result into the body.

The template engine is a **dependency-free internal `{{variable}}` renderer**
(see Architecture Decisions). All Go is written **without comments** (AGENT.md
§11, only the Apache header) and follows golang-pro: `%w` wrapping, `context`
propagation, table-driven `-race` tests, interface-per-file (§10.1 — the
package exports only `Plugin` and `PromptTemplateData`).

## Package file layout — `pkg/infra/plugins/prompttemplate/`

| File | Responsibility | Key symbols (unexported unless noted) |
|------|----------------|----------------------------------------|
| `plugin.go` | Plugin contract, DI `New()`, `Execute` dispatch (Mode B then Mode A), `okResult`, reject helpers + `Type` constants | `PluginName` (const), `Plugin` (exported), `New()`, `Name/MandatoryStages/SupportedStages/SupportedModes/ValidateConfig/Execute`, `reject(...)`, error-`Type` consts |
| `config.go` | Full config struct tree + `parseConfig` + `applyDefaults` + `validate` (engine gate: mustache only, jinja2_subset 4xx) | `config`, `contextVar`, `injectTemplate`, `namedTemplate`, `templateVersion`, `requiredVar`, enums, `parseConfig`, `(*config).validate` |
| `render.go` | Internal logic-less `{{var}}` renderer + control-char escaping | `renderTemplate(tmpl string, vars map[string]string) (string, []string)`, `escapeControlChars(string) string`, `placeholderRe` |
| `variables.go` | Context-variable resolution (header + jwt_claim) + `on_missing_context_variable` policy | `resolveContextVars(cfg, req) (map[string]string, error)`, `resolveOne(spec, req)` |
| `jwt.go` | Unverified bearer-claim read | `bearerToken(req) string`, `unverifiedClaim(token, name) (string, bool)` |
| `body.go` | Provider-native body read/mutate: detect `system`-string vs `messages[]` shape, inject/merge/replace the system prompt, replace the `messages` array, scan reference tokens, decode + strip the top-level `properties` field | `requestBody` (struct), `decodeBody`, `injectSystem(mode, role, content)`, `replaceMessages(fragment)`, `findReferences`, `takeProperties()`, `(rb).marshal()` |
| `modea.go` | Mode A orchestration over `inject_templates[]` | `applyModeA(cfg, rb, ctxVars) (decision, error)` |
| `modeb.go` | Mode B: reference detection, label/version resolution, render, replace `messages` | `applyModeB(cfg, rb, clientVars) (decision, error)`, `resolveVersion(nt, label, defaultLabel)` |
| `validate.go` | `required_variables` presence/type/enum/max_length validation | `validateClientVars(version, supplied) error` |
| `data.go` | Trace payload | `PromptTemplateData` (exported), decision consts |
| `*_test.go` | Table-driven `-race` tests, one per source file | — |

`render.go`, `variables.go`, `jwt.go`, `body.go`, `validate.go` hold no
interfaces, so §10.1 is satisfied (same pattern as `tokenratelimit`'s
`glob.go` / `keys.go`).

## Architecture Decisions

| Decision | Choice | Rejected | Rationale |
|----------|--------|----------|-----------|
| Template engine | **Internal `{{var}}` renderer** (regex `\{\{\s*([\w.-]+)\s*\}\}`) | `cbroglie/mustache`, `hoisie/mustache` | Spec needs only logic-less placeholder interpolation (no sections/partials/lambdas). An internal renderer adds **no dependency**, keeps the sandbox trivial (values are substituted as data, never executed), and is fully `-race` testable. Mustache libs add a supply-chain surface and lambda/section features we explicitly do not want exposed to untrusted client variables. |
| `go.mod` change | **None** | Add a mustache lib | Consequence of the internal renderer. This **deviates from the proposal's Impact table** (which listed `go.mod` modified); the deviation is intentional and lower-risk. |
| `jinja2_subset` | Accept in schema, **reject in `ValidateConfig`** with "engine not yet supported" | Ship a partial sandbox | Per V1 scope #4; a sandboxed engine is a follow-up. |
| Body rewrite channel | **`Result.RequestBody`** (executor applies `req.Body = res.RequestBody`, `executor.go:270`) | Direct `in.Request.Body =` mutation | Contract-aligned ("return every mutation through Result", `plugin.go` doc). NOTE: `model_allowlist` actually mutates `in.Request.Body` **directly** and returns `okResult()` — the proposal's claim that it uses `Result.RequestBody` is inaccurate. Both are equivalent **only in a single-plugin batch**; in a parallel batch `mergeIsolated` (`executor.go:212`) merges Headers+Metadata but **not Body**, so neither survives. We pick `Result.RequestBody` for clarity. |
| Parallel-batch safety | Document: must not be grouped in a parallel `pre_request` batch when it rewrites the body (AGENT.md §14.2) | Framework change to merge Body | Out of scope; same constraint `model_allowlist` lives under. |
| Client-variable transport | **Top-level body field `properties`** (object), parsed for Mode B substitution then **stripped** from the forwarded body | `template_variables`, header, `metadata.*` | Canonical D1: Kong-compatible; RUN-702 says "validate `properties` against `required_variables`". Client values take precedence over context vars. |
| Mode B body splice | **Replace** the request `messages` array with the rendered template fragment (v1 replace-only) | `prepend` / inline token replace / a `reference_mode` config | Canonical D3: Kong semantics. No `reference_mode` knob in v1 — replace is the only behavior. |
| Variable resolution order | **client > context** | context > client | Per task constraint; client-supplied `properties` values override same-named context variables. |
| Mode order in `Execute` | **Mode B first, then Mode A** | A then B | Mode B is client-driven and may reject (validation) and rebuilds `messages`; Mode A then wraps the resulting conversation's system prompt. Mode B replaces `messages`, Mode A edits the system prompt, so they compose cleanly in this order. |
| Provider shape detection / Mode A target | Top-level `system` **string** present → operate on `system`; else insert/merge a system-role entry in `messages[]` | Handle both simultaneously | Canonical D4: a single request is not expected to carry both; pick `system` when present, else `messages[]`. |
| JWT verification | **Unverified** `ParseUnverified` | Re-verify signature | V1 scope #2: auth middleware already authenticated upstream of `pre_request`; the plugin reads claims only for substitution and makes no auth decision. |

## Config structs (`config.go`)

```go
type engine string

const (
	engineMustache engine = "mustache"
	engineJinja2   engine = "jinja2_subset"
)

type onMissingContext string

const (
	onMissingContextError       onMissingContext = "error"
	onMissingContextEmptyString onMissingContext = "empty_string"
	onMissingContextSkip        onMissingContext = "skip_injection"
)

type onMissingClient string

const (
	onMissingClientError       onMissingClient = "error"
	onMissingClientEmptyString onMissingClient = "empty_string"
)

type onExistingSystem string

const (
	onExistingMerge   onExistingSystem = "merge"
	onExistingReplace onExistingSystem = "replace"
)

type varSource string

const (
	sourceHeader   varSource = "header"
	sourceJWTClaim varSource = "jwt_claim"
)

type contextVar struct {
	Source varSource `mapstructure:"source"`
	Name   string    `mapstructure:"name"`
}

type injectTemplate struct {
	ID               string           `mapstructure:"id"`
	Position         string           `mapstructure:"position"`
	Role             string           `mapstructure:"role"`
	Content          string           `mapstructure:"content"`
	OnExistingSystem onExistingSystem `mapstructure:"on_existing_system"`
}

type requiredVar struct {
	Type      string   `mapstructure:"type"`
	Enum      []string `mapstructure:"enum"`
	MaxLength int      `mapstructure:"max_length"`
}

type templateVersion struct {
	Version          string                 `mapstructure:"version"`
	Labels           []string               `mapstructure:"labels"`
	Content          string                 `mapstructure:"content"`
	RequiredVariables map[string]requiredVar `mapstructure:"required_variables"`
}

type namedTemplate struct {
	Name     string            `mapstructure:"name"`
	Versions []templateVersion `mapstructure:"versions"`
}

type config struct {
	TemplateEngine          engine                  `mapstructure:"template_engine"`
	ContextVariables        map[string]contextVar   `mapstructure:"context_variables"`
	InjectTemplates         []injectTemplate        `mapstructure:"inject_templates"`
	NamedTemplates          []namedTemplate         `mapstructure:"named_templates"`
	AllowUntemplatedRequests bool                   `mapstructure:"allow_untemplated_requests"`
	OnMissingContextVariable onMissingContext        `mapstructure:"on_missing_context_variable"`
	OnMissingClientVariable  onMissingClient         `mapstructure:"on_missing_client_variable"`
	DefaultLabel            string                  `mapstructure:"default_label"`
	EscapeJSONControlChars  *bool                   `mapstructure:"escape_json_control_chars"`
}
```

**`applyDefaults`** (run inside `parseConfig` before `validate`):

- `TemplateEngine == ""` → `mustache`.
- `OnMissingContextVariable == ""` → `error`; `OnMissingClientVariable == ""`
  → `error`.
- per-`injectTemplate`: `Position == ""` → `"system"`; `Role == ""` →
  `"system"`; `OnExistingSystem == ""` → `merge`.
- `EscapeJSONControlChars == nil` → `true` (pointer so "explicit false" is
  distinguishable from "unset").

**`validate`** (table-driven friendly):

- `template_engine ∈ {mustache, jinja2_subset}`; `jinja2_subset` →
  `fmt.Errorf("prompt_template: template_engine %q not yet supported", ...)`.
- every `context_variables[*].source ∈ {header, jwt_claim}` and `name`
  non-blank.
- at least one of `inject_templates` / `named_templates` non-empty.
- per `injectTemplate`: `id` non-blank, `content` non-blank, `position ==
  "system"` (v1), `on_existing_system ∈ {merge, replace}`, `role` non-blank.
- `named_templates`: unique `name`; each has ≥1 version; unique `version`
  within a name; labels unique across versions of the same name (a label points
  at exactly one version); `required_variables[*].type ∈ {string, number,
  boolean}`; `max_length >= 0`.
- if `named_templates` non-empty and `default_label != ""`, the label must
  resolve in at least each referenced name OR be a documented soft fallback
  (validation only checks it is non-blank; runtime resolution handles "label
  not found").
- every placeholder in each `content` is a `[\w.-]+` token (renderer-parseable).

## Execute control flow

`Execute` mirrors `model_allowlist`: parse config (wrap errors `%w`), guard
`in.Request == nil` → `okResult()`, compute `blocks := appplugins.Blocks(in.Mode)`.

```mermaid
sequenceDiagram
    participant Ex as executor
    participant P as prompt_template
    participant B as body.go
    Ex->>P: Execute(in)
    P->>P: cfg = parseConfig(in.Config.Settings)
    alt in.Request == nil
        P-->>Ex: okResult()
    end
    P->>B: rb = decodeBody(in.Request.Body)
    P->>B: properties = rb.takeProperties()  (parse + strip top-level "properties")
    alt len(NamedTemplates) > 0
        P->>P: applyModeB(cfg, rb, properties)
        Note over P: detect {template://name@label} in messages[].content + system<br/>resolve version (label, default_label)<br/>validateClientVars(properties)<br/>render -> replace rb.messages with fragment
        alt validation/resolution fails AND blocks
            P-->>Ex: PluginError{4xx, type}
        end
    end
    alt len(InjectTemplates) > 0
        P->>P: ctxVars = resolveContextVars(cfg, in.Request)
        P->>P: applyModeA(cfg, rb, ctxVars)
        Note over P: render each inject_template<br/>injectSystem(on_existing_system)
        alt unresolved ctx var AND on_missing=error AND blocks
            P-->>Ex: PluginError{500, template_variable_unresolved}
        end
    end
    alt not blocks (observe)
        P->>P: setExtras(decision=would_*) ; SetDecision
        P-->>Ex: okResult()  (no mutation)
    end
    P->>P: setExtras(decision, names, versions)
    P->>B: out = rb.marshal()
    P-->>Ex: Result{StatusCode:200, RequestBody: out}
```

**Observe mode (`!blocks`)**: never mutate the body, never reject; compute the
decision that *would* have been taken, write it via `event.SetExtras` +
`appplugins.SetDecision(in.Event, in.Mode)`, and return `okResult()`. Mirrors
`model_allowlist`'s observe branch.

### Body merge semantics (Mode A, `body.go`)

Detection (canonical D4): decode `in.Request.Body` into
`map[string]json.RawMessage`. If a top-level `"system"` **string** is present →
operate on `system`; else operate on `messages[]`. A request is not expected to
carry both; the design does **not** handle both simultaneously — `system` wins
when present.

Inject at `position == "system"` with rendered `content` and configured `role`:

```
top-level "system" string present
  merge   -> system = existing + "\n\n" + rendered   (existing non-empty)
          -> system = rendered                        (absent/empty)
  replace -> system = rendered

otherwise messages[] (find first role=="system")
  found, merge   -> msg.content = msg.content + "\n\n" + rendered
  found, replace -> msg.content = rendered
  none           -> insert {role: <role>, content: rendered} at messages[0]
```

When `role != "system"` (e.g. `developer`), the rendered entry is always
inserted as a new `messages[]` entry at index 0 and `on_existing_system` is
ignored for that entry. v1 only validates `position == "system"`.

### Body splice semantics (Mode B, `body.go` + `modeb.go`)

Client variables source (canonical D1): the client supplies a **top-level body
field `properties`** (object of string→scalar). `rb.takeProperties()` decodes
it and **strips it from the forwarded body** (it is a gateway-only field, never
sent upstream — stripped whether or not Mode B runs). Client `properties` values
**take precedence** over context variables.

Reference tokens are found by `findReferences` scanning every `messages[].content`
string **and** the top-level `system` string (canonical D2) for
`{template://<name>@<label>}` (`templateRefRe =
\{template://([\w.-]+)(?:@([\w.-]+))?\}`).

Splice (canonical D3 — **replace-only**, Kong semantics; no `reference_mode`
config in v1):

```
replace -> the rendered template fragment REPLACES the request "messages" array.
           The version "content" renders to a provider messages fragment: when
           the rendered text parses as a JSON array of {role,content} objects it
           becomes the new messages[]; a bare-string render is wrapped as a
           single {role:"user", content: rendered} element. The original
           messages (carrying the {template://...} reference) are discarded.
```

If `named_templates` is non-empty, no reference is present, and
`allow_untemplated_requests == false` → reject `400 template_required`.

## Variable resolution module (`variables.go`, `jwt.go`)

`resolveContextVars(cfg, req)` iterates `cfg.ContextVariables` and resolves each:

- `source == header` → `req.HeaderValue(spec.Name)`.
- `source == jwt_claim` → `bearerToken(req)` then `unverifiedClaim(token,
  spec.Name)` via `jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})`
  (golang-jwt, already a dependency — `auth_chain.go`). A missing/unparsable
  token or absent claim is treated as **missing**.

`on_missing_context_variable` handling (applied per missing variable inside
Mode A, because the policy is about injection):

| Policy | Behavior |
|--------|----------|
| `error` | collect the missing key; after resolution, if any are missing and `blocks` → `PluginError{500, template_variable_unresolved}` |
| `empty_string` | substitute `""` for the missing key |
| `skip_injection` | drop the entire `inject_templates[]` entry that references a missing key |

`renderTemplate` returns `(rendered string, missing []string)` so the caller
applies the policy uniformly; the renderer never errors on an unknown
placeholder — it reports it.

`bearerToken`/`unverifiedClaim` live in `jwt.go`, ported from the
`auth_chain.go` pattern (comment-free). **Trust boundary** (documented in
proposal §scope-2): claims are used only as substitution data, never for an
auth decision.

## Named-template resolution + client-variable validation (`modeb.go`, `validate.go`)

`resolveVersion(nt, label, defaultLabel)`:

1. effective label = parsed `@label` if present, else `cfg.DefaultLabel`.
2. find the version of `nt` whose `Labels` contains the effective label.
3. not found → `400 template_not_found` (name or label unknown).

`validateClientVars(version, properties)` over `version.RequiredVariables`,
where `properties` is the decoded top-level `properties` object (canonical D1):

| Check | Failure |
|-------|---------|
| key present in `properties` | `400 template_variable_missing` |
| `type` matches (`string`/`number`/`boolean`, weak-typed coercion via the decoded JSON scalar) | `400 template_variable_invalid` |
| value `∈ enum` (when `enum` set) | `400 template_variable_invalid` |
| `len(value) <= max_length` (when `max_length > 0`, string only) | `400 template_variable_invalid` |

A placeholder referenced in `content` but **not** declared in
`required_variables` and **not** present in `properties` follows
`on_missing_client_variable` (`error` → `template_variable_missing`;
`empty_string` → `""`). Resolution order **client > context**: when rendering a
Mode B version, the renderer's variable map is `context ∪ properties` with
`properties` keys overriding.

**`escape_json_control_chars`**: the plugin renders into Go string values inside
the decoded body structure and re-marshals with `encoding/json`, which already
escapes control characters — so the forwarded JSON is always well-formed.
When the flag is `true` (default) `escapeControlChars` additionally **strips**
raw C0 control bytes (`U+0000`–`U+001F`, preserving `\n`/`\t`) from every
resolved/rendered value before insertion, so client- or header-supplied values
cannot inject stray control runes into the prompt. When `false`, control bytes
are preserved (still JSON-safe via marshal).

## Error mapping → `PluginError` (`plugin.go`)

All rejections build `&appplugins.PluginError{StatusCode, Type, Message,
Headers: {"Content-Type": {"application/json"}}, Body}` where `Body` is
`{"error":"plugin_rejected","type":<Type>,...}` shaped by the proxy. Only
emitted when `appplugins.Blocks(in.Mode)` is true.

| Condition | Mode | StatusCode | `Type` |
|-----------|------|-----------|--------|
| Unresolved context variable, `on_missing_context_variable:error` | A | 500 | `template_variable_unresolved` |
| Missing client variable, `on_missing_client_variable:error` | B | 400 | `template_variable_missing` |
| Client variable fails type/enum/max_length | B | 400 | `template_variable_invalid` |
| Referenced template/label not found | B | 400 | `template_not_found` |
| No reference + `allow_untemplated_requests:false` | B | 400 | `template_required` |
| Malformed config at runtime | — | (parse err wrapped `%w`, returned as plain `error`, surfaced 500 by proxy) | — |

`Type` codes are package consts in `plugin.go`.

## Catalog metadata (`catalog_metadata.go`)

Add `pluginCatalogMeta["prompt_template"]` (group `groupOther`, or a new
`groupTransform` if introduced — defaulting to `groupOther` to avoid taxonomy
churn). `SettingsSchema.Fields` (using existing `FieldType*`, mirroring the
`token_rate_limiter` nesting depth):

```go
"prompt_template": {
	name:        "Prompt Template",
	group:       groupOther,
	description: "Inject context-bound system prompts (Mode A) and/or render client-referenced named, versioned templates (Mode B) into the request before it reaches the model.",
	schema: SettingsSchema{
		Fields: []Field{
			{Key: "template_engine", Label: "Template Engine", Type: FieldTypeEnum, Enum: []string{"mustache", "jinja2_subset"}, Default: "mustache"},
			{Key: "context_variables", Label: "Context Variables", Type: FieldTypeMap, Value: &Field{Key: "var", Label: "Variable", Type: FieldTypeObject, Fields: []Field{
				{Key: "source", Label: "Source", Type: FieldTypeEnum, Enum: []string{"header", "jwt_claim"}, Required: true},
				{Key: "name", Label: "Name", Type: FieldTypeString, Required: true},
			}}},
			{Key: "inject_templates", Label: "Inject Templates", Type: FieldTypeArray, Item: &Field{Key: "tmpl", Label: "Template", Type: FieldTypeObject, Fields: []Field{
				{Key: "id", Label: "ID", Type: FieldTypeString, Required: true},
				{Key: "position", Label: "Position", Type: FieldTypeEnum, Enum: []string{"system"}, Default: "system"},
				{Key: "role", Label: "Role", Type: FieldTypeString, Default: "system"},
				{Key: "content", Label: "Content", Type: FieldTypeString, Required: true},
				{Key: "on_existing_system", Label: "On Existing System", Type: FieldTypeEnum, Enum: []string{"merge", "replace"}, Default: "merge"},
			}}},
			{Key: "named_templates", Label: "Named Templates", Type: FieldTypeArray, Item: &Field{Key: "nt", Label: "Named Template", Type: FieldTypeObject, Fields: []Field{
				{Key: "name", Label: "Name", Type: FieldTypeString, Required: true},
				{Key: "versions", Label: "Versions", Type: FieldTypeArray, Item: &Field{Key: "v", Label: "Version", Type: FieldTypeObject, Fields: []Field{
					{Key: "version", Label: "Version", Type: FieldTypeString, Required: true},
					{Key: "labels", Label: "Labels", Type: FieldTypeArray, Item: &Field{Key: "label", Label: "Label", Type: FieldTypeString}},
					{Key: "content", Label: "Content", Type: FieldTypeString, Required: true},
					{Key: "required_variables", Label: "Required Variables", Type: FieldTypeMap, Value: &Field{Key: "rv", Label: "Required Variable", Type: FieldTypeObject, Fields: []Field{
						{Key: "type", Label: "Type", Type: FieldTypeEnum, Enum: []string{"string", "number", "boolean"}},
						{Key: "enum", Label: "Enum", Type: FieldTypeArray, Item: &Field{Key: "opt", Label: "Option", Type: FieldTypeString}},
						{Key: "max_length", Label: "Max Length", Type: FieldTypeInteger},
					}}},
				}}},
			}}},
			{Key: "allow_untemplated_requests", Label: "Allow Untemplated Requests", Type: FieldTypeBoolean, Default: true},
			{Key: "on_missing_context_variable", Label: "On Missing Context Variable", Type: FieldTypeEnum, Enum: []string{"error", "empty_string", "skip_injection"}, Default: "error"},
			{Key: "on_missing_client_variable", Label: "On Missing Client Variable", Type: FieldTypeEnum, Enum: []string{"error", "empty_string"}, Default: "error"},
			{Key: "default_label", Label: "Default Label", Type: FieldTypeString},
			{Key: "escape_json_control_chars", Label: "Escape JSON Control Chars", Type: FieldTypeBoolean, Default: true},
		},
	},
}
```

`catalog_test.go` asserts the new entry exists, supports `enforce`, and its
schema round-trips.

## Registration wiring (`modules/plugins.go`)

Add the import and the catalog entry; `New()` takes no infra deps (the plugin
is stateless — no Redis, no adapters), so no `pluginParams` change:

```go
import "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/prompttemplate"

catalog := []appplugins.Plugin{
	// ...existing...
	modelallowlist.New(),
	prompttemplate.New(),
	tool_call_validation.New(p.Adapters, openai.NewOpenaiClient(), p.Logger),
}
```

## Test plan (table-driven, `-race`)

| File | Layer | Cases |
|------|-------|-------|
| `config_test.go` | Unit | defaults applied; mustache accepted; **jinja2_subset rejected**; bad source rejected; duplicate name/version/label rejected; empty (no inject + no named) rejected; bad `required_variables.type` rejected; placeholder syntax rejected |
| `render_test.go` | Unit | `{{var}}` substitution; whitespace tolerance `{{ var }}`; unknown placeholder reported in `missing`; control-char strip on/off; no-placeholder passthrough |
| `variables_test.go` | Unit | header resolve (case-insensitive); jwt_claim resolve from unverified token; missing token → missing; absent claim → missing |
| `jwt_test.go` | Unit | bearer extraction; non-bearer/empty → ""; unverified parse of valid + tampered token (still reads claims) |
| `body_test.go` | Unit | `system`-string shape detect + merge/replace/absent; `messages[]` shape system merge/replace/insert; reference scan over `messages[].content` + `system`; `takeProperties` parses + strips `properties`; `replaceMessages` with JSON-array and bare-string fragment; marshal stable |
| `validate_test.go` | Unit | presence/type/enum/max_length over `properties` pass + each failure → correct `Type` |
| `modea_test.go` | Unit | inject + merge; inject + replace; `on_missing` error→500 / empty_string / skip_injection; observe mode no mutation |
| `modeb_test.go` | Unit | reference detect+resolve+validate+render → **replace `messages`**; `properties` precedence over context; `default_label` fallback; unknown name/label→`template_not_found`; missing/invalid var codes; `allow_untemplated_requests:false`→`template_required`; `properties` stripped from forwarded body; observe mode no mutation/no reject |
| `plugin_test.go` | Unit | contract (Name/Stages/Modes); `Execute` nil request; Mode A only; Mode B only; both; `RequestBody` set on success |
| `catalog_test.go` | Unit (existing) | new entry + schema |
| `tests/functional/plugin_prompt_template_test.go` | Functional | end-to-end Mode A injection from header+jwt; Mode B render via proxy; all five error codes; observe vs enforce. Reuse `setupPolicyRoute`/`createScopedPolicy`/`proxyRequest` helpers (§14.7: POST path must equal consumer name) |

## Phase breakdown (chained PRs, ≤400 changed lines each)

| Phase | Scope | Why shippable |
|-------|-------|---------------|
| **P1** | `plugin.go` skeleton (contract + `Execute` returning `okResult()` no-op) + full `config.go` (structs, `applyDefaults`, `validate` incl. jinja2 reject) + `catalog_metadata.go` entry + `modules/plugins.go` registration + `config_test.go` + `catalog_test.go` | Plugin appears in catalog, validates config (incl. engine reject) end-to-end; no body mutation yet — inert. |
| **P2** | `render.go` + `variables.go` + `jwt.go` + `escapeControlChars` + unit tests | Engine + context resolution proven in isolation; not yet wired into `Execute`. |
| **P3** | `body.go` + `modea.go` + Mode A wiring in `Execute` + `on_missing_context_variable` + observe + `data.go` + tests | Mode A fully functional (inject/merge/replace from header+jwt); shippable feature on its own. |
| **P4** | `modeb.go` + `validate.go` + `properties` parse/strip + reference detection + label/version resolution + `required_variables` validation + **replace-`messages` splice** + all client-side error codes + tests | Mode B fully functional. |
| **P5** | `tests/functional/plugin_prompt_template_test.go` + any catalog test finalization | End-to-end coverage through the proxy. |

Each phase is independently green under `go vet`, `golangci-lint`, and
`go test -race ./...`.

## Resolved decisions (canonical — orchestrator)

- [x] **D1 — Client-variable transport**: client supplies variables in a
  top-level body field **`properties`** (Kong-compatible). The plugin parses
  `properties`, uses it for Mode B substitution (client values take precedence
  over context vars), and **strips `properties`** from the body before the
  rewritten body is forwarded upstream.
- [x] **D2 — Reference token placement**: scan `{template://name@label}` in
  `messages[].content` strings and the top-level `system` string. (Confirmed as
  designed.)
- [x] **D3 — Mode B splice = replace-only**: Mode B **replaces** the request
  `messages` array with the rendered template messages fragment (Kong
  semantics). No `prepend` option, no `reference_mode` config in v1.
- [x] **D4 — Dual `system`+`messages`**: if the body has a top-level `system`
  string, Mode A operates on `system`; otherwise it inserts/merges a
  system-role entry in `messages[]`. Not handled simultaneously — `system` wins
  when present.

## Open Questions

None blocking. The four prior open questions are resolved above.
