# Exploration: Bedrock Guardrail plugin (RUN-719)

Re-implement LegacyGateway's `bedrock_guardrail` on the new TrustGate plugin SDK.
Do NOT port verbatim. This document maps the SDK contract, the canonical sibling
(`azure_content_safety`), the legacy source, and the AWS SDK surface, then lists
open questions that block design.

Worktree: `/Users/edu/Neuraltrust/TrustGate-bedrock-guardrail`

---

## 1. TrustGate plugin SDK contract

### The `appplugins.Plugin` interface
`pkg/app/plugins/plugin.go`

```go
type Plugin interface {
    Name() string
    MandatoryStages() []policy.Stage   // always run; subset of SupportedStages
    SupportedStages() []policy.Stage   // every stage the plugin may run on
    SupportedModes() []policy.Mode     // must include ModeEnforce
    ValidateConfig(settings map[string]any) error
    Execute(ctx context.Context, in ExecInput) (*Result, error)
    MutatesRequestBody() bool
    MutatesResponseBody() bool
    MutatesMetadata() bool
}
```

### `Execute` input — `ExecInput` (`plugin.go:51`)
```go
type ExecInput struct {
    Stage    policy.Stage
    Mode     policy.Mode
    Config   policy.PluginConfig          // .Settings is map[string]any
    Scope    RuntimeScope                 // GatewayID/ConsumerID/Global
    Request  *infracontext.RequestContext // nil-check
    Response *infracontext.ResponseContext// nil-check (set on PreResponse)
    Event    *metrics.EventContext        // nil when traces disabled; nil-check
}
```

- `in.Mode` drives enforce/observe via `appplugins.Blocks(in.Mode)` (`modes.go:45`):
  `Blocks` returns `true` for everything except `policy.ModeObserve`.
- `RequestContext` (`pkg/infra/context/request_context.go`): key fields are
  `Body []byte`, `Provider string`, `SourceFormat string`, `Headers`, `Metadata`.
- `ResponseContext` (`pkg/infra/context/response_context.go`): `Body []byte`,
  `StatusCode int`, `Streaming bool`, `Headers`, `Metadata`.

### `Result` and the mutation model (`plugin.go:94`)
```go
type Result struct {
    StatusCode   int
    Body         []byte   // response body to return (applied only on StopUpstream)
    RequestBody  []byte   // mutated upstream request body (applied in place)
    Headers      map[string][]string
    StopUpstream bool     // short-circuit the chain
}
```

How the executor (`pkg/app/plugins/executor.go:259 applyResults`) applies a Result:
- **Mutate request body (PreRequest)**: return `&Result{StatusCode:200, RequestBody: masked}`
  with `StopUpstream:false`. Executor sets `req.Body = res.RequestBody` in place and
  the (masked) body is forwarded upstream. Declare `MutatesRequestBody()==true`.
- **Mutate response body (PreResponse)**: return
  `&Result{StatusCode:200, Body: masked, StopUpstream:true}`. Executor only writes
  `resp.Body = res.Body` when `StopUpstream` is set. This is exactly the pattern
  `tool_call_validation` uses for redaction (`tool_call_validation/plugin.go:127`).
  Declare `MutatesResponseBody()==true`.
- **Pass through**: return `&Result{StatusCode: http.StatusOK}` (helper
  `passThrough()` in siblings).
- Parallel batches run on isolated request/response clones; only the first writer
  in deterministic order wins (`warnExcessWriter`). Plugins must funnel all
  mutations through `Result`, never mutate `in.Request`/`in.Response` directly.

### How a plugin signals block / 403
Return a `*appplugins.PluginError` as the `error` (NOT via Result):
`pkg/app/plugins/errors.go`
```go
type PluginError struct {
    StatusCode int
    Type       string
    Message    string
    Headers    map[string][]string
    Body       []byte   // raw JSON body sent verbatim to the client
}
```
- The executor propagates the error up (`executor.go:160` records status on the event).
- The proxy converts it: `pkg/app/proxy/plugin_runner.go:200 pluginErrorResult`
  builds a `ForwardResult{StatusCode, Headers, Body}`. **If `pe.Body` is set it is
  returned verbatim**, so the plugin fully controls the JSON error shape.
- PreRequest path: `runPreRequest` → `AsPluginError(err)` → `pluginErrorResult` (`plugin_runner.go:51`).
- PreResponse path: `runPreResponseGated` returns the `*PluginError` directly (`plugin_runner.go:66`).
  Note: in PreResponse, a non-PluginError failure fails **closed** (502) only when
  the stage is a blocking stage (`preResponseBlocks`).

### How a plugin records data on the event
- `in.Event.SetExtras(anyStruct)` — attaches a JSON-serializable struct (the
  per-plugin `Data`). Pattern: `data.go` defines `Data` + `setExtras(event, data)`
  that nil-checks then calls `event.SetExtras`.
- `appplugins.SetDecision(in.Event, in.Mode)` (`modes.go:64`) records
  block/observe/throttle.
- `in.Event.SetError(err)` records an error on the span.
- Always nil-check `in.Event` first.

---

## 2. On-disk structure of a sibling guardrail (`azure_content_safety`)

Canonical layout under `pkg/infra/plugins/<name>/`
(`/Users/edu/Neuraltrust/TrustGate-azure-content-safety-guardrail/pkg/infra/plugins/azurecontentsafety/`):

| File | Responsibility |
|------|----------------|
| `plugin.go` | `Plugin` struct, `New(...)`, interface methods, `Execute` orchestration, text extraction, evaluate. |
| `config.go` | `Settings` struct (`mapstructure` tags), `parseConfig` via `pluginutil.Parse[Settings]`, `applyDefaults`, `validate`. |
| `client.go` | HTTP/SDK client wrapper + request/response wire structs. |
| `data.go` | `Data` event struct (`json` tags) + `setExtras(event, data)`. |
| `reject.go` | `blockError(...) *appplugins.PluginError` + JSON `blockBody(...)`. |
| `*_test.go` | unit tests per file; `tests/functional/plugin_azure_content_safety_test.go` for e2e. |

Constructor & interface declaration (`azurecontentsafety/plugin.go`):
```go
const PluginName = "azure_content_safety"
var _ appplugins.Plugin = (*Plugin)(nil)
type Plugin struct { registry *adapter.Registry; client *client; logger *slog.Logger }
func New(registry *adapter.Registry, logger *slog.Logger) *Plugin { ... }
func (p *Plugin) MandatoryStages() []policy.Stage { return []policy.Stage{policy.StagePreRequest} }
func (p *Plugin) SupportedStages() []policy.Stage { return []policy.Stage{policy.StagePreRequest} }
func (p *Plugin) SupportedModes()  []policy.Mode  { return []policy.Mode{policy.ModeEnforce, policy.ModeObserve} }
```
A PreResponse + body-mutating sibling to copy from: `tool_call_validation`
(`SupportedStages = {StagePreResponse}`, `MutatesResponseBody()==true`).

Azure's enforce/observe + fail-closed pattern (`plugin.go:80-166`) is the closest
behavioral template:
- decode request → extract text → call client → on client error: fail closed if
  `Blocks(mode)` (return PluginError), else record + pass through.
- on breach: if `Blocks(mode)` → set decision `blocked`, `SetExtras`, return
  `blockError`; else record `reported` and pass through.

---

## 3. Plugin registration (registry / bootstrap)

Single bootstrap site: `pkg/container/modules/plugins.go`, function
`newPluginRegistry(p pluginParams)`.

```go
catalog := []appplugins.Plugin{
    ratelimit.New(redisClient),
    ...
    trustguard.New(p.Adapters, ...),
    azurecontentsafety.New(p.Adapters, p.Logger),  // <-- add bedrock here
}
for _, plugin := range catalog { reg.Register(plugin) }
```

To add the new plugin:
1. import `".../pkg/infra/plugins/bedrockguardrail"`.
2. append `bedrockguardrail.New(p.Adapters, p.Logger)` (plus a bedrock client) to `catalog`.
3. dependencies available in `pluginParams`: `Adapters *adapter.Registry`,
   `Logger *slog.Logger`, `Cache`, `Cfg *config.Config`, `Pricing`, optional `DB`.

`registry.Register` (`pkg/app/plugins/registry.go:47`) validates: non-empty name,
no duplicate, non-empty SupportedStages, valid stages, mandatory⊆supported, and
modes include `ModeEnforce`.

---

## 4. Catalog metadata + SettingsSchema

`pkg/app/plugins/catalog_metadata.go` holds `var pluginCatalogMeta map[string]catalogMeta`.
Group constant already exists: `groupGuardrails = "Guardrails"` (`catalog_metadata.go:26`).
Schema field types in `pkg/app/plugins/catalog.go:28`:
`string, integer, number, boolean, duration, enum, object, array, map`.
`Field` supports nested containers via `Fields` (object), `Item` (array element),
`Value`+`KeyOptions` (map).

The catalog is built in `catalog.go:110 Catalog()`: it reads stages/modes from the
**registered plugin** and merges the hand-authored `schema`/`name`/`group`/`description`
from `pluginCatalogMeta`. A plugin with no metadata still appears under `Other`, so
the metadata entry is required for correct UX.

Sibling entry to copy (`azure_content_safety`, `catalog_metadata.go:1154`) shows
required strings, an enum w/ default, an array-of-enum, and a **map** field:
```go
"azure_content_safety": {
    name: "Azure Content Safety", group: groupGuardrails, description: "...",
    schema: SettingsSchema{ Fields: []Field{
        {Key:"api_key", Type:FieldTypeString, Required:true},
        {Key:"output_type", Type:FieldTypeEnum, Enum:[]string{...}, Default:"..."},
        {Key:"categories", Type:FieldTypeArray, Item:&Field{Type:FieldTypeEnum, Enum:[...]}},
        {Key:"category_severity", Type:FieldTypeMap, KeyOptions:[...], Value:&Field{Type:FieldTypeInteger}},
        {Key:"message", Type:FieldTypeString},
    }},
},
```
For bedrock we will need a nested **object** field (`credentials` with
`aws_region`, `use_role`, `role_arn`, `session_name`, optional static keys),
an **array of enum** (`stages`), and **enum** (`pii_action`, `version`) plus an
`action` object holding `message`. There is no existing object-field example in
the file, but `FieldTypeObject` + `Fields` is the documented mechanism.

---

## 5. Provider-specific prompt/response text extraction (new SDK)

Done through the adapter registry, NOT by sending raw JSON.
`pkg/infra/providers/adapter/`:
1. `format, err := adapter.ResolveAgentFormat(in.Request.Provider, in.Request.SourceFormat, nil)`
   (`format.go:142`) → a `Format` (openai, anthropic, google, bedrock, mistral, …).
2. Request text: `creq, err := p.registry.DecodeRequestFor(in.Request.Body, format)`
   (`registry.go:128`) → `*CanonicalRequest`. Then concatenate `creq.System` +
   each `creq.Messages[i].Content` (verbatim copy of `azurecontentsafety.joinRequestText`,
   `plugin.go:175`).
3. Response text: `cresp, err := p.registry.DecodeResponseFor(in.Response.Body, format)`
   (`registry.go:178`) → `*CanonicalResponse` with `.Content` (and `.ToolCalls`).
4. To re-encode a masked body per provider use the adapter
   `EncodeRequest(*CanonicalRequest)` / `EncodeResponse(*CanonicalResponse)`
   (interfaces in `registry.go:51-63`; per-adapter encoders exist for each format).

Canonical types: `pkg/infra/providers/adapter/canonical.go`
(`CanonicalRequest{System, Messages[]{Role,Content}, ...}`,
`CanonicalResponse{Content, ToolCalls, ...}`).

Guard rails for the Execute guard clauses (mirror siblings): pass through when
`in.Request==nil`, `p.registry==nil`, `Provider==""`, `len(Body)==0`, format
unresolved, decode error/nil, or extracted text is empty.

---

## 6. Bedrock client wrapper to port

Legacy source: `LegacyGateway/pkg/infra/bedrock/client.go` and
`LegacyGateway/pkg/infra/plugins/bedrock_guardrail/{bedrock_guardrail,data}.go`.

### `ApplyGuardrail` call (legacy `bedrock_guardrail.go:151`)
```go
input := &bedrockruntime.ApplyGuardrailInput{
    Content: []types.GuardrailContentBlock{
        &types.GuardrailContentBlockMemberText{Value: types.GuardrailTextBlock{Text: aws.String(text)}},
    },
    GuardrailIdentifier: aws.String(cfg.GuardrailID),
    GuardrailVersion:    aws.String(cfg.Version),     // legacy default "1"; spec default "DRAFT"
    Source:              types.GuardrailContentSourceInput,  // INPUT for prompt; OUTPUT for response
}
output, err := client.ApplyGuardrail(ctx, input)
```

### Response shape (verified via `go doc`, bedrockruntime v1.53.1)
`ApplyGuardrailOutput`: `Action types.GuardrailAction` (`GUARDRAIL_INTERVENED`/`NONE`),
`Assessments []GuardrailAssessment`, `Outputs []GuardrailOutputContent`
(**`.Text` holds the masked/anonymized text**), `Usage`, `ActionReason`, `GuardrailCoverage`.

`GuardrailAssessment` exposes ALL policies the issue requires:
`TopicPolicy`, `ContentPolicy`, `WordPolicy`, `SensitiveInformationPolicy`,
`ContextualGroundingPolicy` (+ `AutomatedReasoningPolicy`).
Action enums (verified):
- Content/Topic block action: `GuardrailContentPolicyActionBlocked = "BLOCKED"`
  (legacy checked `"REJECT"` — **wrong for v2 SDK**; fix to `BLOCKED`).
- PII: `GuardrailSensitiveInformationPolicyActionAnonymized = "ANONYMIZED"` and `...Blocked = "BLOCKED"`.
- `SensitiveInformationPolicy.PiiEntities[]{Action, Match, Type, Detected}` and `Regexes[]`.
- `WordPolicy.{CustomWords, ManagedWordLists}`.
- `ContextualGroundingPolicy.Filters[]` (grounding/relevance, score vs threshold, action).

### Auth paths (legacy `bedrock/client.go`)
- `BuildClient(ctx, accessKey, secretKey, sessionToken, region, useRole, roleARN, sessionName)`.
- Static keys → `loadAWSConfig` with a static `CredentialsProvider`.
- Role assumption → `assumeRole` (STS `AssumeRole` with `RoleArn`+`RoleSessionName`,
  default session `"BedrockClientSession"`), then load config with the temp creds.
- Default region fallback `us-east-1`.

### Client caching to port
Legacy already caches with a `sync.Map` keyed by
`accessKey:secretKey:sessionToken:region:useRole:roleARN:sessionName` plus a
per-key mutex for single-flight. **Bug in legacy to fix**: `muPool.Delete(clientKey)`
is `defer`-ed while the lock is held, racing the single-flight guarantee — rework
to store the built `*bedrockruntime.Client` keyed by credential set, build once,
reuse thereafter. The new plugin should hold the cache on the `Plugin` (or an
injected client wrapper) so clients are reused across requests, not per-request.

NOTE: the legacy `bedrock.Client` interface signature for `BuildClient` has
`accessKey, secretKey, sessionToken, region` but the plugin calls it as
`(accessKey, secretKey, region, sessionToken, ...)` — argument order is
inconsistent in legacy. Define the new wrapper signature cleanly.

---

## 7. AWS SDK availability

Already a direct dependency in the worktree `go.mod` — no new deps needed:
- `github.com/aws/aws-sdk-go-v2 v1.41.9`
- `github.com/aws/aws-sdk-go-v2/config v1.32.20`
- `github.com/aws/aws-sdk-go-v2/service/bedrockruntime v1.53.1`
- `github.com/aws/aws-sdk-go-v2/service/sts v1.42.3`
- (indirect already present: credentials, sso, ssooidc, etc.)

Credential/secret handling: there is **no AWS sibling plugin in the new SDK** yet.
Siblings take credentials directly from the policy `Settings` map (azure `api_key`,
trustguard token), decoded via `mapstructure`. So bedrock credentials should live
under a `credentials` object in Settings (matching the spec), parsed with
`pluginutil.Parse[Settings]`. No central secret store is wired into the plugin SDK.

---

## 8. 403 block response + event record fields

### Required client response (RUN-719)
`403 Forbidden`, body:
```json
{ "error": { "type": "guardrail_blocked", "policy": "topic_policy", "name": "..." } }
```
Implement in a `reject.go` mirroring `azurecontentsafety/reject.go`: build a
`*appplugins.PluginError{StatusCode: http.StatusForbidden, Type:"guardrail_blocked",
Headers:{"Content-Type":["application/json"]}, Body: <marshaled JSON above>}`.
Because `pluginErrorResult` returns `pe.Body` verbatim, the JSON shape is exact.
(Use a fixed operator message — do NOT `fmt.Sprintf(conf.Actions.Message, msg)` as
legacy did; that is a format-string injection bug to fix.)

### Event record fields (issue: id/version, region, matched policy/type/action, latency, decision)
Define `Data` in `data.go` (legacy `BedrockGuardrailData` is the starting point):
```go
type Data struct {
    GuardrailID string `json:"guardrail_id"`
    Version     string `json:"version"`
    Region      string `json:"region"`
    Stage       string `json:"stage"`
    Mode        string `json:"mode"`
    Decision    string `json:"decision"`   // blocked|anonymized|reported|allowed|failed_closed
    Policy      string `json:"policy,omitempty"`      // topic_policy|content_policy|word_policy|sensitive_information|contextual_grounding
    MatchType   string `json:"type,omitempty"`
    Action      string `json:"action,omitempty"`
    Name        string `json:"name,omitempty"`
    LatencyMS   int64  `json:"latency_ms"`
}
```
Record via `event.SetExtras(data)` + `appplugins.SetDecision(in.Event, in.Mode)`.

---

## What to fix vs legacy (consolidated)
1. Client built per request → cache/reuse clients per credential set (fix the
   `muPool.Delete` race too).
2. Raw request body sent as guardrail content → extract real text via adapters.
3. `fmt.Sprintf(conf.Actions.Message, msg)` → fixed message, structured JSON body.
4. Partial policy coverage → add WordPolicy, ContextualGrounding, and PII
   `ANONYMIZED` masking; use correct v2 action constants (`BLOCKED`, not `REJECT`).
5. Content logged at `Info` (with full prompt) → remove or Debug-gate; never log content.
6. Add observe mode (`Blocks(in.Mode)` gating) and PreResponse support (legacy was PreRequest only).
7. Default version `DRAFT` (spec) instead of `"1"`.

---

## Affected areas
- `pkg/infra/plugins/bedrockguardrail/` (new): `plugin.go`, `config.go`, `client.go`, `data.go`, `reject.go`, tests.
- `pkg/container/modules/plugins.go` — register the plugin.
- `pkg/app/plugins/catalog_metadata.go` — add `bedrock_guardrail` entry under `groupGuardrails`.
- `tests/functional/` — add `plugin_bedrock_guardrail_test.go` (mirror azure functional test).
- `go.mod` — no change (AWS SDK already present).

## Approaches
1. **Mirror `azure_content_safety` structure + port the legacy bedrock client wrapper into the plugin package (with caching) and reuse the AWS SDK directly.** (recommended)
   - Pros: matches the canonical sibling 1:1; minimal new abstractions; client cache co-located; testable via an interface seam over `ApplyGuardrail`.
   - Cons: AWS client construction is heavier than azure's plain HTTP; need a mockable seam.
   - Effort: Medium.
2. **Re-create a shared `pkg/infra/bedrock` package (like legacy) and inject a `bedrock.Client` via dig.**
   - Pros: reusable if other bedrock plugins appear; closer to legacy.
   - Cons: extra DI wiring; no current second consumer; over-abstraction for one plugin.
   - Effort: Medium-High.

## Recommendation
Approach 1. Put the AWS client wrapper + per-credential cache inside the plugin
package behind a small interface (e.g. `guardrailClient` with
`ApplyGuardrail(ctx, region, creds, input)`), so unit tests can inject a fake.
Support both PreRequest (Source=INPUT) and PreResponse (Source=OUTPUT). Use the
adapter registry for text extraction and, for PII `anonymize`, re-encode the
`output.Outputs[].Text` back into the provider body via `EncodeRequest`/`EncodeResponse`
and return it through `Result.RequestBody` (PreRequest) or `Result.Body`+`StopUpstream`
(PreResponse).

## Risks
- **PII anonymize re-encoding**: Bedrock returns the masked text as plain
  `Outputs[].Text`. Re-inserting it into the canonical structure is straightforward
  for the *last user message* / response content, but mapping a single masked blob
  back to multi-message canonical requests is lossy. Needs a defined rule (e.g.
  send only the concatenated last user turn to the guardrail, replace that turn).
- **PreResponse response-body mutation** only works via `StopUpstream:true` + `Body`
  (no non-stop response-body apply path). Confirm short-circuiting after upstream
  call is acceptable (it is for `tool_call_validation`).
- **Streaming responses**: `tool_call_validation` passes through when
  `in.Response.Streaming`; PreResponse guardrail on streamed output is not feasible
  here — decide whether to skip streaming or only guard PreRequest for streams.
- **Multiple ApplyGuardrail calls** (PreRequest + PreResponse) double the AWS cost/latency.
- **Bedrock content source for response**: must set `Source = GuardrailContentSourceOutput`
  on PreResponse (verify constant name in v2 SDK).

---

## OPEN QUESTIONS (blocking design)

1. **PII `anonymize` body rewrite scope** — How is the masked
   `output.Outputs[].Text` mapped back into a multi-message
   `CanonicalRequest`/`CanonicalResponse`? Only the last user turn? The whole
   concatenation? *Answer lives in*: `pkg/infra/providers/adapter/canonical.go` +
   per-adapter `EncodeRequest`/`EncodeResponse`; decide a product rule.

2. **`pii_action` semantics vs guardrail config** — Bedrock's anonymize/block is
   configured on the guardrail in AWS; the spec adds a plugin-side `pii_action`
   (`block`/`anonymize`). Does `pii_action` override AWS behavior or just decide how
   TrustGate reacts to the returned `Action`? *Answer*: product decision; code
   reads `assessment.SensitiveInformationPolicy.PiiEntities[].Action`.

3. **Config key shape** — spec uses `action.message` (object) but legacy used
   `actions.message`. Lock the final schema (`action` object vs flat `message`).
   *Answer*: align with `azurecontentsafety` (flat `message`) or keep `action{}`.

4. **Stage gating from `stages` setting** — issue config has a `stages` array, but
   stage selection in TrustGate is policy-level (`MandatoryStages`/`SupportedStages`
   + policy config), applied by the executor. Should the plugin support both
   PreRequest and PreResponse via `SupportedStages` and let the policy choose,
   making the `stages` setting redundant? *Answer lives in*: `pkg/app/plugins/stages.go`
   + `plan.go` (how policy stages map to execution).

5. **Streaming PreResponse** — skip guardrail on `in.Response.Streaming`, or buffer?
   *Answer lives in*: `pkg/app/proxy/forwarder.go` (PreResponse vs PostResponse and
   stream wrapping `wrapStreamWithPostResponse`).

6. **Client cache lifetime/eviction** — unbounded `sync.Map` keyed by full
   credential set could leak under many consumers. Bound it? *Answer*: design choice;
   legacy used unbounded `sync.Map`.

7. **Credential security** — credentials sit in plaintext policy Settings (same as
   azure `api_key`). Confirm acceptable; no secret store seam exists in the plugin SDK.

8. **`scope` (consumer/global)** — issue says scope `consumer|global`. The SDK
   handles scope at policy level (`RuntimeScope`), and a stateless guardrail does not
   need to partition state. Confirm nothing extra is required. *Answer lives in*:
   `pkg/app/plugins/plugin.go` (`RuntimeScope.Subject`).

---

## Ready for Proposal
Yes — the SDK contract, sibling pattern, registration, catalog, text extraction,
AWS surface, and event/403 shapes are fully mapped. Resolve open questions 1–4
(anonymize body-rewrite rule, `pii_action` semantics, config key shape, stage
gating) during `sdd-propose`/`sdd-design`; the rest are confirmations.
