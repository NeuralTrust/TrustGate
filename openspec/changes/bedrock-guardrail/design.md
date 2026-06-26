# Design: Bedrock Guardrail plugin (RUN-719)

Concrete Go design for re-implementing LegacyGateway's `bedrock_guardrail` on the
TrustGate plugin SDK. Mirrors the canonical guardrail sibling `azurecontentsafety`
for enforce/observe + fail-closed, and `tool_call_validation` for PreResponse +
body mutation + degraded pass-through. All eight orchestrator design decisions are
treated as fixed.

Binding: `.agents/AGENT.md` (hexagonal layout, DTOs in the plugin package, HARD
no-comments policy incl. Go doc comments — only the Apache license header is kept,
matching every sibling file) and `golang-pro` (wrapped errors, context propagation,
no data races, mockable seams, `go vet`/`golangci-lint`/`-race` clean).

---

## 1. Chosen approach

**Approach 1 (recommended in exploration):** mirror the `azurecontentsafety` package
1:1, port the legacy AWS client wrapper into the plugin package behind a small
mockable `guardrailClient` seam over `ApplyGuardrail`, and reuse the adapter registry
for text extraction and (for PII anonymize) masked-output re-encoding.

Rejected alternative — Approach 2 (shared `pkg/infra/bedrock` package + dig-injected
`bedrock.Client`): no second consumer exists today; it adds DI wiring and an extra
infra package for one plugin. The cache lives inside the plugin package instead.

### Resolved design risks / open questions

- **Multi-message anonymize mapping (open Q1).** Resolved by making the *evaluated
  span* and the *rewritten span* identical: PreRequest sends **only the last `user`
  turn's `Content`** to `ApplyGuardrail`; PreResponse sends **`CanonicalResponse.Content`**.
  Because the text sent to Bedrock is exactly the span we replace with the masked
  `Outputs[0].Text`, the anonymize re-encode is 1:1 and lossless. Earlier turns are
  not re-scanned on PreRequest (they were scanned on their own inbound requests).
- **OUTPUT source constant (open Q + proposal risk).** Confirmed against vendored
  `bedrockruntime@v1.53.1/types/enums.go`: `GuardrailContentSourceInput = "INPUT"`,
  `GuardrailContentSourceOutput = "OUTPUT"`.
- **Double `ApplyGuardrail` cost.** PreRequest and PreResponse are independent
  policy-selected stages; when both are selected the gateway makes one INPUT call and
  one OUTPUT call at different points in the request lifecycle. Accepted; the
  per-credential client cache amortizes connection/credential setup across both calls
  and across requests. No batching (the stages fire at different times).
- **`pii_action` semantics (open Q2).** TrustGate-side reaction selector, not an AWS
  override (fixed decision 3). Code reads
  `assessment.SensitiveInformationPolicy.{PiiEntities,Regexes}[].Action`.
- **Config key shape (open Q3).** Flat `message`, nested `credentials` object (fixed
  decision 4) — aligned with `azurecontentsafety`.
- **Stage gating (open Q4).** `SupportedStages = {PreRequest, PreResponse}`,
  `MandatoryStages = {}`; selection is policy-level via `EffectiveStages`
  (`pkg/app/plugins/stages.go`). No `stages` Settings field.
- **Streaming (open Q5).** Pass through on `in.Response.Streaming` at PreResponse
  (fixed decision 5), mirroring `tool_call_validation`.
- **Cache lifetime (open Q6).** Unbounded `sync.Map` keyed by a credential
  fingerprint, as in legacy. Bounded eviction is an explicit non-goal.
- **Credential security (open Q7).** Credentials live in policy `Settings`, same as
  azure `api_key`. No secret-store seam exists in the plugin SDK. Content is never
  logged (fixes legacy defect 6).
- **`scope` (open Q8).** Stateless guardrail; scope handled at policy level
  (`RuntimeScope`). No extra plugin state.

No genuinely unresolvable open questions remain.

---

## 2. Package file layout

New package `pkg/infra/plugins/bedrockguardrail/` (slug `bedrock_guardrail`).
One responsibility per file, no comments beyond the license header.

| File | Responsibility |
|------|----------------|
| `plugin.go` | `Plugin` struct, `New(...)`, the nine `appplugins.Plugin` interface methods, `Execute` dispatch, the per-stage `executePreRequest`/`executePreResponse` flows, text-extraction helpers (`lastUserText`, `responseText`), `passThrough`, internal `warn`. |
| `config.go` | `Settings` + `Credentials` structs (`mapstructure` tags), `parseConfig` via `pluginutil.Parse[Settings]`, `applyDefaults`, `validate`, the pii_action/version/region/session-name constants. |
| `client.go` | `awsCredentials` value type + `fingerprint()`, the `guardrailClient` interface seam, `cachedGuardrailClient`, `clientCache` (race-free single-flight build over a `sync.Map`), `buildRuntimeClient` (static-key + STS assume-role auth), `newCachedGuardrailClient`. |
| `assess.go` | `buildApplyInput`, the `finding` + `assessmentResult` types, and `inspect` (walks all five assessment families and classifies block / PII-block / PII-anonymize). |
| `anonymize.go` | `maskedText`, `rewriteRequest`, `rewriteResponse` (decode-side already done; replace span and re-encode via `registry.GetAdapter(format).EncodeRequest/EncodeResponse`), `supportsReencode`. |
| `data.go` | `Data` event struct (`json` tags) + `setExtras(event, data)`. |
| `reject.go` | `blockError(finding) *appplugins.PluginError` + `blockBody(finding) []byte` producing the exact `{"error":{"type":"guardrail_blocked","policy":...,"name":...}}` JSON. |
| `plugin_test.go` | Execute flows with a fake `guardrailClient`. |
| `config_test.go` | `parseConfig`/`applyDefaults`/`validate` table tests. |
| `client_test.go` | `awsCredentials.fingerprint` stability + `clientCache` single-flight/error-delete with an injected fake build func (no real AWS). |
| `assess_test.go` | `inspect` mapping table per policy family + action. |
| `anonymize_test.go` | `rewriteRequest`/`rewriteResponse` round-trip + unsupported-format degraded. |
| `reject_test.go` | exact 403 JSON shape. |

Plus functional test `tests/functional/plugin_bedrock_guardrail_test.go`.

---

## 3. Type and interface signatures

### `plugin.go`

```go
const PluginName = "bedrock_guardrail"

const (
    decisionBlocked      = "blocked"
    decisionAnonymized   = "anonymized"
    decisionReported     = "reported"
    decisionAllowed      = "allowed"
    decisionFailedClosed = "failed_closed"
)

var _ appplugins.Plugin = (*Plugin)(nil)

type Plugin struct {
    registry   *adapter.Registry
    guardrails guardrailClient
    logger     *slog.Logger
}

func New(registry *adapter.Registry, logger *slog.Logger) *Plugin {
    return &Plugin{
        registry:   registry,
        guardrails: newCachedGuardrailClient(),
        logger:     logger,
    }
}

func (p *Plugin) Name() string                  { return PluginName }
func (p *Plugin) MandatoryStages() []policy.Stage { return nil }
func (p *Plugin) SupportedStages() []policy.Stage {
    return []policy.Stage{policy.StagePreRequest, policy.StagePreResponse}
}
func (p *Plugin) SupportedModes() []policy.Mode {
    return []policy.Mode{policy.ModeEnforce, policy.ModeObserve}
}
func (p *Plugin) MutatesRequestBody() bool  { return true }
func (p *Plugin) MutatesResponseBody() bool { return true }
func (p *Plugin) MutatesMetadata() bool     { return false }
func (p *Plugin) ValidateConfig(settings map[string]any) error
func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error)
```

`MandatoryStages` returns `nil` (empty) so the policy chooses stages; the registry
validation (non-empty `SupportedStages`, `mandatory ⊆ supported`, modes include
`ModeEnforce`) passes. A policy that selects no supported stage is rejected by
`ValidateStages` (`ErrNoEffectiveStages`) — intended.

The unexported `guardrails` field IS the mockable seam: same-package tests build
`&Plugin{registry: reg, guardrails: fakeGuardrailClient{...}, logger: ...}` and never
touch AWS.

### `config.go`

```go
const (
    piiActionBlock     = "block"
    piiActionAnonymize = "anonymize"
    defaultVersion     = "DRAFT"
    defaultRegion      = "us-east-1"
    defaultSessionName = "BedrockClientSession"
)

type Settings struct {
    GuardrailID string      `mapstructure:"guardrail_id"`
    Version     string      `mapstructure:"version"`
    PIIAction   string      `mapstructure:"pii_action"`
    Message     string      `mapstructure:"message"`
    Credentials Credentials `mapstructure:"credentials"`
}

type Credentials struct {
    AWSRegion       string `mapstructure:"aws_region"`
    UseRole         bool   `mapstructure:"use_role"`
    RoleARN         string `mapstructure:"role_arn"`
    SessionName     string `mapstructure:"session_name"`
    AccessKeyID     string `mapstructure:"access_key_id"`     // #nosec G101 -- config field name
    SecretAccessKey string `mapstructure:"secret_access_key"` // #nosec G101 -- config field name
    SessionToken    string `mapstructure:"session_token"`     // #nosec G101 -- config field name
}

func parseConfig(settings map[string]any) (Settings, error) // Parse -> applyDefaults -> validate
```

`applyDefaults`: `Version → DRAFT`, `PIIAction → block`, `Credentials.AWSRegion →
us-east-1`, `Credentials.SessionName → BedrockClientSession`.

`validate`:
- `guardrail_id` required.
- `pii_action ∈ {block, anonymize}`.
- if `use_role`: `role_arn` required.
- else: `access_key_id` and `secret_access_key` required (region defaulted).

### `client.go`

```go
type awsCredentials struct {
    region          string
    useRole         bool
    roleARN         string
    sessionName     string
    accessKeyID     string
    secretAccessKey string
    sessionToken    string
}

func credentialsFromConfig(c Credentials) awsCredentials
func (c awsCredentials) fingerprint() string // sha256 hex of the joined tuple

type guardrailClient interface {
    ApplyGuardrail(
        ctx context.Context,
        creds awsCredentials,
        in *bedrockruntime.ApplyGuardrailInput,
    ) (*bedrockruntime.ApplyGuardrailOutput, error)
}

type cacheEntry struct {
    once   sync.Once
    client *bedrockruntime.Client
    err    error
}

type clientCache struct {
    entries sync.Map // fingerprint -> *cacheEntry
    build   func(ctx context.Context, creds awsCredentials) (*bedrockruntime.Client, error)
}

func (c *clientCache) get(ctx context.Context, creds awsCredentials) (*bedrockruntime.Client, error)

type cachedGuardrailClient struct{ cache *clientCache }

func newCachedGuardrailClient() *cachedGuardrailClient // build = buildRuntimeClient
func (g *cachedGuardrailClient) ApplyGuardrail(ctx, creds, in) (*bedrockruntime.ApplyGuardrailOutput, error)

func buildRuntimeClient(ctx context.Context, creds awsCredentials) (*bedrockruntime.Client, error)
```

`clientCache.get` is the **race-free single-flight** that fixes legacy defect 1
(`muPool.Delete` raced inside the held lock). Pattern:

```go
func (c *clientCache) get(ctx context.Context, creds awsCredentials) (*bedrockruntime.Client, error) {
    key := creds.fingerprint()
    v, _ := c.entries.LoadOrStore(key, &cacheEntry{})
    e := v.(*cacheEntry)
    e.once.Do(func() { e.client, e.err = c.build(ctx, creds) })
    if e.err != nil {
        c.entries.Delete(key) // failed build is not cached; next request retries
        return nil, e.err
    }
    return e.client, nil
}
```

`buildRuntimeClient` ports the legacy auth with a clean, fixed argument order
(fixing legacy defect: the inconsistent `BuildClient` call-site arg order):
- static keys → `config.LoadDefaultConfig` with a static `aws.CredentialsProviderFunc`
  and `config.WithRegion`.
- `use_role && role_arn != ""` → STS `AssumeRole` (RoleArn + RoleSessionName, default
  `BedrockClientSession`) using a base config, then `LoadDefaultConfig` with the
  temporary credentials; finally `bedrockruntime.NewFromConfig`.

`fingerprint()` hashes the tuple (sha256 hex) so the cache key does not retain a
plaintext secret concatenation as the map key value.

### `assess.go`

```go
type finding struct {
    policy string // topic_policy|content_policy|word_policy|sensitive_information|contextual_grounding
    name   string
    typ    string
    action string
}

type assessmentResult struct {
    block         *finding // first non-PII BLOCKED finding
    piiBlocked    *finding // first PII entity/regex with action BLOCKED
    piiAnonymized *finding // first PII entity/regex with action ANONYMIZED
    piiFired      bool     // any PII entity/regex with action != NONE
}

func buildApplyInput(cfg Settings, text string, source types.GuardrailContentSource) *bedrockruntime.ApplyGuardrailInput
func inspect(out *bedrockruntime.ApplyGuardrailOutput) assessmentResult
```

### `anonymize.go`

```go
func maskedText(out *bedrockruntime.ApplyGuardrailOutput) (string, bool) // Outputs[0].Text
func supportsReencode(format adapter.Format) bool                        // registry.GetAdapter(format) != err
func rewriteRequest(reg *adapter.Registry, format adapter.Format, creq *adapter.CanonicalRequest, msgIndex int, masked string) ([]byte, bool)
func rewriteResponse(reg *adapter.Registry, format adapter.Format, cresp *adapter.CanonicalResponse, masked string) ([]byte, bool)
```

`rewriteRequest`: `creq.Messages[msgIndex].Content = masked`; `adp, err :=
reg.GetAdapter(format)`; `body, err := adp.EncodeRequest(creq)` → `(body, true)`,
else `(nil, false)`. `rewriteResponse`: `cresp.Content = masked`;
`adp.EncodeResponse(cresp)`. `GetAdapter` is the confirmed exported encoder entry
point (`registry.go:114`), and `EncodeRequest`/`EncodeResponse` are on
`ProviderAdapter` (`registry.go:51-63`), implemented by `BedrockAdapter`
(`bedrock_adapter.go:186,241`) and every other format.

### `data.go`

```go
type Data struct {
    GuardrailID    string `json:"guardrail_id,omitempty"`
    Version        string `json:"version,omitempty"`
    Region         string `json:"region,omitempty"`
    Stage          string `json:"stage,omitempty"`
    Mode           string `json:"mode,omitempty"`
    Decision       string `json:"decision,omitempty"`
    Policy         string `json:"policy,omitempty"`
    MatchType      string `json:"type,omitempty"`
    Action         string `json:"action,omitempty"`
    Name           string `json:"name,omitempty"`
    LatencyMS      int64  `json:"latency_ms,omitempty"`
    Degraded       bool   `json:"degraded,omitempty"`
    DegradedReason string `json:"degraded_reason,omitempty"`
}

func setExtras(event *metrics.EventContext, data *Data) // nil-checks event and data
```

No `input_length`/content fields (fixes legacy defect 6: never record content).

### `reject.go`

```go
const typeGuardrailBlocked = "guardrail_blocked"

func blockError(f finding) *appplugins.PluginError
func blockBody(f finding) []byte
```

```go
func blockError(f finding) *appplugins.PluginError {
    return &appplugins.PluginError{
        StatusCode: http.StatusForbidden,
        Type:       typeGuardrailBlocked,
        Headers:    map[string][]string{"Content-Type": {"application/json"}},
        Body:       blockBody(f),
    }
}
```

`blockBody` marshals `{"error":{"type":"guardrail_blocked","policy":"<f.policy>",
"name":"<f.name>"}}` (the `name` field uses `omitempty`; `type` and `policy` always
present). No `fmt.Sprintf(message, …)` (fixes legacy defect 3).

---

## 4. Execute control flow

```go
func (p *Plugin) Execute(ctx, in) (*appplugins.Result, error) {
    cfg, err := parseConfig(in.Config.Settings)
    if err != nil { return nil, fmt.Errorf("bedrock_guardrail: %w", err) }
    switch in.Stage {
    case policy.StagePreRequest:  return p.executePreRequest(ctx, cfg, in)
    case policy.StagePreResponse: return p.executePreResponse(ctx, cfg, in)
    default:                      return passThrough(), nil
    }
}
```

### PreRequest (`Source = INPUT`)

1. **Guard clauses → passThrough**: `in.Request == nil`, `p.registry == nil`,
   `in.Request.Provider == ""`, `len(in.Request.Body) == 0`.
2. `format, err := adapter.ResolveAgentFormat(provider, sourceFormat, nil)`; on err →
   passThrough.
3. `creq, err := p.registry.DecodeRequestFor(body, format)`; err or nil → passThrough.
4. `text, idx := lastUserText(creq)`; `strings.TrimSpace(text) == ""` → passThrough.
5. `start := time.Now()`; `out, err := p.guardrails.ApplyGuardrail(ctx,
   credentialsFromConfig(cfg.Credentials), buildApplyInput(cfg, text, INPUT))`;
   `latency := time.Since(start)`.
6. **Client/API error** → `p.failOrReport(ctx, in, cfg, latency, err)`:
   - `Blocks(in.Mode)` → `setExtras(failed_closed Data)`, return
     `fmt.Errorf("bedrock_guardrail: apply guardrail: %w", err)` (same fail-closed
     shape as azure; proxy maps via `AsPluginError`).
   - observe → `setExtras(failed_closed Data)`, `SetDecision`, passThrough.
   - Content is never logged; only `plugin`/`stage`/`error` attrs at Warn.
7. `res := inspect(out)`.
8. **Hard block (non-PII)** `res.block != nil` → `p.decide(in, cfg, latency,
   *res.block, INPUT-stage)`:
   - `Blocks(in.Mode)` → `decision=blocked`, `setExtras`, `return blockError(*res.block)`.
   - observe → `decision=reported`, `setExtras`, `SetDecision`, passThrough.
9. **PII** (`SensitiveInformationPolicy`):
   - `pii_action == block`: if `res.piiFired` → block/report exactly as step 8 with the
     `sensitive_information` finding (prefer `piiBlocked`, else `piiAnonymized`, else a
     synthesized fired finding).
   - `pii_action == anonymize`:
     - `res.piiBlocked != nil` → **fall back to block** (Bedrock returned BLOCKED, not
       anonymized) → block/report as step 8.
     - else `res.piiAnonymized != nil`:
       - observe → `decision=reported`, `setExtras`, `SetDecision`, passThrough (no
         mutation in observe).
       - enforce → `masked, ok := maskedText(out)`; if `ok`, `body, ok2 :=
         rewriteRequest(registry, format, creq, idx, masked)`:
         - `ok && ok2` → `decision=anonymized`, `setExtras`, return
           `&appplugins.Result{StatusCode: http.StatusOK, RequestBody: body}`
           (`StopUpstream: false`; executor applies `req.Body = res.RequestBody`).
         - else (no masked text or unsupported/failed re-encode) → **degraded, fail
           closed**: `Data.Degraded=true`, `DegradedReason ∈ {anonymize_no_output,
           anonymize_unsupported_format, anonymize_encode_failed}`, `decision=blocked`,
           `setExtras`, `return blockError(sensitive_information finding)`.
10. **Allow** → `decision=allowed`, `setExtras`, `SetDecision`, passThrough.

### PreResponse (`Source = OUTPUT`)

Same skeleton, with these differences:
- Guards also: `in.Response == nil` → passThrough; `in.Response.Streaming` →
  passThrough (fixed decision 5); `len(in.Response.Body) == 0` → passThrough. Format is
  still resolved from `in.Request` (provider/source format), so `in.Request == nil` →
  passThrough.
- `cresp, err := p.registry.DecodeResponseFor(in.Response.Body, format)`; `text :=
  cresp.Content`; empty → passThrough.
- `buildApplyInput(cfg, text, OUTPUT)`.
- Anonymize enforce success returns `&appplugins.Result{StatusCode: http.StatusOK,
  Body: body, StopUpstream: true}` via `rewriteResponse` (the only response-body apply
  path, mirroring `tool_call_validation/plugin.go:127`).
- A non-`PluginError` failure fails closed only on a blocking stage; returning a plain
  wrapped `error` in enforce is consistent with the proxy's `preResponseBlocks` (502),
  matching azure/`tool_call_validation`.

`Blocks(in.Mode)` (`modes.go:45`) is the single gate distinguishing enforce (may
return `PluginError` / mutate) from observe (record + passThrough only).

### Helpers

```go
func lastUserText(creq *adapter.CanonicalRequest) (string, int) // last role=="user" non-empty Content; (-1) if none
func responseText(cresp *adapter.CanonicalResponse) string      // cresp.Content
func passThrough() *appplugins.Result                            // &appplugins.Result{StatusCode: http.StatusOK}
```

---

## 5. Assessment inspection mapping

`inspect` iterates `out.Assessments` and classifies via the **verified**
`bedrockruntime@v1.53.1/types` fields/constants:

| AWS assessment field | matched sub-item | block condition | `policy` string | `name` | `type` |
|---|---|---|---|---|---|
| `TopicPolicy.Topics[]` (`GuardrailTopic`) | `Action == GuardrailTopicPolicyActionBlocked` | yes → `block` | `topic_policy` | `*Topic.Name` | `string(Topic.Type)` (e.g. `DENY`) |
| `ContentPolicy.Filters[]` (`GuardrailContentFilter`) | `Action == GuardrailContentPolicyActionBlocked` | yes → `block` | `content_policy` | `string(Filter.Type)` | `string(Filter.Type)` |
| `WordPolicy.CustomWords[]` (`GuardrailCustomWord`) | `Action == GuardrailWordPolicyActionBlocked` | yes → `block` | `word_policy` | `*Word.Match` | `custom` |
| `WordPolicy.ManagedWordLists[]` (`GuardrailManagedWord`) | `Action == GuardrailWordPolicyActionBlocked` | yes → `block` | `word_policy` | `*Word.Match` | `string(Word.Type)` |
| `SensitiveInformationPolicy.PiiEntities[]` (`GuardrailPiiEntityFilter`) | `Action ∈ {Blocked, Anonymized}` | PII path | `sensitive_information` | `*Entity.Match` | `string(Entity.Type)` |
| `SensitiveInformationPolicy.Regexes[]` (`GuardrailRegexFilter`) | `Action ∈ {Blocked, Anonymized}` | PII path | `sensitive_information` | `*Regex.Match` (or `*Regex.Name`) | `regex` |
| `ContextualGroundingPolicy.Filters[]` (`GuardrailContextualGroundingFilter`) | `Action == GuardrailContextualGroundingPolicyActionBlocked` | yes → `block` | `contextual_grounding` | — | `string(Filter.Type)` (`GROUNDING`/`RELEVANCE`) |

Constant names (verified, fixes legacy defect 4 — legacy checked `"REJECT"`):
`GuardrailContentPolicyActionBlocked`, `GuardrailTopicPolicyActionBlocked`,
`GuardrailWordPolicyActionBlocked`, `GuardrailContextualGroundingPolicyActionBlocked`,
`GuardrailSensitiveInformationPolicyActionBlocked` / `…Anonymized` / `…None`.

`inspect` records the **first** blocking finding for non-PII families into
`assessmentResult.block`, and the first PII Blocked/Anonymized into
`piiBlocked`/`piiAnonymized` with `piiFired` set when any PII action is not `None`.
`AutomatedReasoningPolicy` is out of scope (the issue lists five families).

All `*string` (`Name`, `Match`) are read via `aws.ToString` to avoid nil deref.

---

## 6. Anonymize re-encode + degraded fallback

- **Encoders (confirmed):** `*adapter.Registry.GetAdapter(format)` →
  `ProviderAdapter`; `EncodeRequest(*CanonicalRequest) ([]byte, error)` and
  `EncodeResponse(*CanonicalResponse) ([]byte, error)` exist on the interface
  (`registry.go:51-63`) and on `BedrockAdapter` (`bedrock_adapter.go:186,241`).
- **Span rule (lossless):** the text sent to Bedrock equals the span we mutate — the
  last `user` turn (PreRequest) / `Content` (PreResponse). `rewriteRequest` sets that
  one message's `Content` to `Outputs[0].Text` then `EncodeRequest`; `rewriteResponse`
  sets `cresp.Content` then `EncodeResponse`.
- **Degraded fallback** (mirrors `tool_call_validation`'s degraded pattern):
  - `maskedText` returns `ok=false` when `len(out.Outputs)==0` or `Outputs[0].Text==nil`.
  - `GetAdapter`/`Encode*` error → re-encode unsupported/failed.
  - enforce → **fail closed**: return `blockError` with `Data.Degraded=true` and a
    `DegradedReason`.
  - observe → `Data.Degraded=true`, `decision=reported`, passThrough.

---

## 7. Registration + catalog metadata diffs

### `pkg/container/modules/plugins.go`

```go
import (
    // …
    "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/bedrockguardrail"
    // …
)

catalog := []appplugins.Plugin{
    // …existing…
    tool_call_validation.New(p.Adapters, openai.NewOpenaiClient(), p.Logger),
    tooltransform.New(p.Adapters),
    trustguard.New(p.Adapters, p.Cfg.TrustGuard.BaseURL, p.Cfg.TrustGuard.Timeout, p.Logger),
    bedrockguardrail.New(p.Adapters, p.Logger), // <- appended
}
```

No new `pluginParams` field. `registry.Register` validations are satisfied
(non-empty `SupportedStages`, `mandatory ⊆ supported`, modes include `ModeEnforce`).

### `pkg/app/plugins/catalog_metadata.go`

Append one entry to `pluginCatalogMeta` (before the closing `}` at line 1158), under
`groupGuardrails`:

```go
"bedrock_guardrail": {
    name:        "AWS Bedrock Guardrail",
    group:       groupGuardrails,
    description: "Apply an AWS Bedrock guardrail to request prompts (PreRequest) and/or responses (PreResponse). Inspects topic, content, word, sensitive-information (PII) and contextual-grounding policies configured on the guardrail; blocks with a 403 or anonymizes PII in place. Streaming responses are passed through.",
    schema: SettingsSchema{
        Fields: []Field{
            {Key: "guardrail_id", Label: "Guardrail ID", Type: FieldTypeString, Required: true,
                Description: "AWS Bedrock guardrail identifier."},
            {Key: "version", Label: "Version", Type: FieldTypeString, Default: "DRAFT",
                Description: "Guardrail version. Defaults to DRAFT."},
            {Key: "pii_action", Label: "PII Action", Type: FieldTypeEnum, Enum: []string{"block", "anonymize"}, Default: "block",
                Description: "How TrustGate reacts when the sensitive-information policy fires."},
            {Key: "message", Label: "Block Message", Type: FieldTypeString,
                Description: "Optional operator message; the 403 body always carries the matched policy and name."},
            {Key: "credentials", Label: "AWS Credentials", Type: FieldTypeObject, Required: true,
                Fields: []Field{
                    {Key: "aws_region", Label: "AWS Region", Type: FieldTypeString, Default: "us-east-1"},
                    {Key: "use_role", Label: "Use IAM Role", Type: FieldTypeBoolean, Default: false},
                    {Key: "role_arn", Label: "Role ARN", Type: FieldTypeString,
                        Description: "Required when Use IAM Role is enabled."},
                    {Key: "session_name", Label: "Session Name", Type: FieldTypeString, Default: "BedrockClientSession"},
                    {Key: "access_key_id", Label: "Access Key ID", Type: FieldTypeString,
                        Description: "Required for static-key auth (Use IAM Role disabled)."},
                    {Key: "secret_access_key", Label: "Secret Access Key", Type: FieldTypeString},
                    {Key: "session_token", Label: "Session Token", Type: FieldTypeString},
                },
            },
        },
    },
},
```

`FieldTypeObject` + `Fields` is the documented nesting mechanism (`catalog.go:43-59`);
stages/modes are read from the registered plugin, so the metadata only supplies
name/group/description/schema.

---

## 8. DI wiring

- Constructor `bedrockguardrail.New(p.Adapters, p.Logger)` — the same two deps azure
  takes; `p.Adapters` and `p.Logger` already exist in `pluginParams`.
- The client cache is constructed **inside** the package (`newCachedGuardrailClient`)
  and held on `Plugin.guardrails`. No dig provider, no new `pluginParams` field, no
  shared infra package.
- **No new env vars.** Region/credentials come from policy `Settings`; the AWS SDK's
  default credential chain is not relied upon (explicit static or assumed creds only),
  consistent with legacy.
- AWS SDK deps already in `go.mod` (`bedrockruntime v1.53.1`, `config v1.32.20`,
  `sts v1.42.3`, `aws-sdk-go-v2 v1.41.9`) — no `go.mod` change.

---

## 9. Test plan

Unit (per file, `bedrockguardrail` package, fake `guardrailClient`):

- **`config_test.go`** — defaults (DRAFT/block/us-east-1/BedrockClientSession);
  validation: missing `guardrail_id`, bad `pii_action`, `use_role` without `role_arn`,
  static auth without keys.
- **`assess_test.go`** — table over each policy family + action mapping to `finding`
  (policy/name/type/action) and the PII classification (`piiBlocked`/`piiAnonymized`/
  `piiFired`); nil-`*string` safety; empty assessments → allow.
- **`anonymize_test.go`** — `maskedText` empty-`Outputs`; `rewriteRequest`/
  `rewriteResponse` round-trip on a supported format (bedrock/openai) and `(nil,false)`
  for a registry miss / encode failure.
- **`reject_test.go`** — `blockBody` exact JSON
  `{"error":{"type":"guardrail_blocked","policy":"topic_policy","name":"…"}}`.
- **`client_test.go`** — `awsCredentials.fingerprint` stability + difference across
  fields; `clientCache.get` single-flight (build invoked once for N concurrent calls,
  run under `-race`) and error-not-cached (failed build deletes the entry) using an
  injected fake `build` func — no real AWS.
- **`plugin_test.go`** — Execute matrix with a fake `guardrailClient`:
  - PreRequest INPUT vs PreResponse OUTPUT (asserts `Source` on the captured input).
  - guard-clause pass-throughs (nil request/response, empty body, streaming response,
    empty extracted text, unresolved format, decode error).
  - non-PII block: enforce → `*PluginError` 403; observe → passThrough + `reported`.
  - PII `block`: fired → 403 (enforce) / reported (observe).
  - PII `anonymize`: ANONYMIZED enforce → `Result.RequestBody`/`Result.Body`+`StopUpstream`
    with masked text; BLOCKED enforce → fall back to 403; observe → reported, no mutation.
  - degraded: unsupported format / empty `Outputs` → enforce fail-closed 403 + Degraded;
    observe → passThrough + Degraded.
  - client error: enforce → error (fail closed); observe → passThrough.
  - `MutatesRequestBody`/`MutatesResponseBody` true; `SupportedStages`/`Modes` correct.

Functional — **`tests/functional/plugin_bedrock_guardrail_test.go`** (`//go:build
functional`), mirroring `plugin_azure_content_safety_test.go`:
- Because Bedrock has no HTTP stub like azure, the functional test injects a fake
  `ApplyGuardrail` seam. Smallest viable approach: a tiny exported test hook in the
  plugin package (build-tagged `//go:build functional` helper, e.g.
  `bedrockguardrail.SetGuardrailClientForTest(p, fake)`) OR a functional-only
  registration override. Preferred: add a `funcopt`-style unexported `newWithClient`
  plus a `//go:build functional` exported shim so the functional harness can register
  a plugin instance whose `guardrails` is a scripted fake keyed on the request text
  (mirrors azure's `flagWord`).
- Cases: benign passes through (upstream hit, decision allowed); topic block → exact
  403 body, upstream NOT hit; observe mode never blocks (upstream hit + reported); PII
  `anonymize` rewrites the forwarded request body with masked text.

`go vet ./… && golangci-lint run && go test -race ./pkg/infra/plugins/bedrockguardrail/…`
must be clean. No content is logged in any path.

---

## 10. Affected files (final)

- `pkg/infra/plugins/bedrockguardrail/` (new): `plugin.go`, `config.go`, `client.go`,
  `assess.go`, `anonymize.go`, `data.go`, `reject.go`, + the six `*_test.go`.
- `pkg/container/modules/plugins.go` — import + append to `catalog`.
- `pkg/app/plugins/catalog_metadata.go` — `bedrock_guardrail` entry under
  `groupGuardrails`.
- `tests/functional/plugin_bedrock_guardrail_test.go` (new).
- `go.mod` — unchanged.
