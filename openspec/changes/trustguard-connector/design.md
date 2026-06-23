# Design: TrustGuard connector plugin — RUN-669

## Technical Approach

A new guardrail plugin `trustguard` (package `pkg/infra/plugins/trustguard/`) that
calls the external TrustGuard service `POST {base_url}/v1/guard` on the request
and/or response leg and, in `enforce` mode, blocks a `block` verdict with a 403
`*appplugins.PluginError`. It composes two established patterns: the
external-guardrail decode-and-block flow of `tool_call_validation` (adapter
`Registry` body→text, `*PluginError` rejection, fail-open) and the raw
`net/http` client of `oauth/provider_client.go` (`*http.Client{Timeout}`,
`NewRequestWithContext`, Bearer auth, `io.LimitReader`, JSON decode). Base URL +
timeout come from env via `pkg/config`, injected through DI; per-policy
`Settings` carry `api_key`, `consumer_id`, `inspect`, optional `base_url`.

## Architecture Decisions

| Decision | Choice | Alternatives rejected | Rationale |
|---|---|---|---|
| Stage gating | Declare `pre_request`+`pre_response` **both Mandatory** and gate inside `Execute` on `cfg.Inspect` × `in.Stage` | Use `SupportedStages` + policy stage selection | Executor runs a plugin only at `EffectiveStages = Mandatory ∪ (selected ∩ Supported)` (stages.go). A single `inspect` field can only reliably gate both legs if `Execute` is always invoked on both. |
| Where base_url/timeout enter | New `config.TrustGuardConfig{BaseURL, Timeout}` in `pkg/config`; DI passes **plain values** to `trustguard.New(reg, baseURL, timeout, logger)` | Pass `*config.Config` or a config struct into `New` | Existing plugin constructors take plain deps (`tool_call_validation.New(adapters, llm, logger)`). Keeps the infra plugin package free of any `pkg/config` import, preserving the hexagonal boundary (infra plugin must not depend on the process config loader). |
| Client param shape | Client owns its `*http.Client{Timeout}` (built in `New`); `Guard(ctx, baseURL, apiKey, body)` takes baseURL+apiKey **per call** | Bake baseURL/apiKey into the client at construction | `api_key` and the optional `base_url` override are **per-policy** Settings, resolved at request time; timeout is process-wide (env). So timeout is construction state, baseURL/apiKey are call args. |
| Catalog group | `groupOther` | New `groupGuardrails` | The nearest analog `tool_call_validation` (also an external guardrail) lives in `groupOther`; reuse avoids changing `groupOrder` and catalog ordering contracts. (Open: a dedicated "Guardrails" group is reasonable future work.) |
| Block transport | Fail-open on any transport error / timeout / non-2xx / empty base_url | Fail-closed | Settled in proposal; `fail_closed` is future work. Recorded via `failed_open` event-extra for alerting. |

## Data Flow

```
pre_request leg (inspect ∈ {request, request_response})
  Request.Body ──DecodeRequestFor──▶ input text ──▶ GuardRequest{direction:"input"}
       │                                                      │
       └────────────────── Execute ◀── client.Guard(POST /v1/guard) ──▶ TrustGuard
                              │
        status=="block" & Blocks(mode) ──▶ *PluginError{403}  (short-circuit, no upstream)
        else ──▶ passThrough + SetExtras

pre_response leg (inspect ∈ {response, request_response}, non-streaming)
  Response.Body ─DecodeResponseFor─▶ output text ─▶ GuardRequest{direction:"output"}
        status=="block" & Blocks(mode) ──▶ *PluginError{403}  (replaces client response)
        streaming ──▶ passThrough (body unavailable, cannot block realtime)
```

## File Changes

| File | Action | Description |
|---|---|---|
| `pkg/infra/plugins/trustguard/plugin.go` | Create | `Plugin` type, `New`, `Name`/stages/modes/capabilities, `ValidateConfig`, `Execute`, `passThrough` helper. |
| `pkg/infra/plugins/trustguard/config.go` | Create | `Settings` struct (mapstructure tags), `inspect` consts, `parseConfig` (Parse→applyDefaults→validate), `selectsStage`. |
| `pkg/infra/plugins/trustguard/client.go` | Create | `client` (raw `net/http`), `newClient(timeout)`, `Guard(ctx, baseURL, apiKey, GuardRequest)`. |
| `pkg/infra/plugins/trustguard/data.go` | Create | `GuardRequest`/`GuardResponse` DTOs + `guardData` event-extras struct + `setExtras`. |
| `pkg/infra/plugins/trustguard/plugin_test.go` | Create | Table-driven `Execute` tests against `httptest.NewServer`. |
| `pkg/infra/plugins/trustguard/config_test.go` | Create | Table-driven config parse/validate tests. |
| `pkg/infra/plugins/trustguard/client_test.go` | Create | `httptest` client tests (success, non-2xx, timeout, bad JSON, headers). |
| `pkg/config/config.go` | Modify | Add `TrustGuardConfig` struct + field, `defaultTrustGuardTimeout`, `getTrustGuardConfig()`, wire into `LoadConfig`. |
| `pkg/container/modules/plugins.go` | Modify | Import `trustguard`; add `Cfg *config.Config` to `pluginParams`; append `trustguard.New(...)` to catalog. |
| `pkg/app/plugins/catalog_metadata.go` | Modify | Add `"trustguard"` entry to `pluginCatalogMeta` (group `groupOther`, hand-authored schema). |
| `pkg/app/plugins/catalog_test.go` | Modify | Optional `TestTrustGuardSchema` mirroring the token schema test. |
| `docs/...` (plugin docs) | Create/Modify | Slug, config, stage/direction matrix, blocking/fail-open, streaming limitation. |

## Interfaces / Contracts

```go
// plugin.go
const PluginName = "trustguard"

type Plugin struct {
    registry      *adapter.Registry
    client        *client
    defaultBaseURL string
    logger        *slog.Logger
}

func New(registry *adapter.Registry, baseURL string, timeout time.Duration, logger *slog.Logger) *Plugin

func (p *Plugin) Name() string                  // "trustguard"
func (p *Plugin) MandatoryStages() []policy.Stage // {pre_request, pre_response}
func (p *Plugin) SupportedStages() []policy.Stage // {pre_request, pre_response}
func (p *Plugin) SupportedModes() []policy.Mode   // {enforce, observe}
func (p *Plugin) MutatesRequestBody() bool        // false
func (p *Plugin) MutatesResponseBody() bool       // false
func (p *Plugin) MutatesMetadata() bool           // false
func (p *Plugin) ValidateConfig(settings map[string]any) error // -> parseConfig
func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error)
```

```go
// config.go
const (
    inspectRequest         = "request"
    inspectResponse        = "response"
    inspectRequestResponse = "request_response"
)

type Settings struct {
    APIKey     string `mapstructure:"api_key"` // #nosec G101 -- config field name
    ConsumerID string `mapstructure:"consumer_id"`
    Inspect    string `mapstructure:"inspect"`
    BaseURL    string `mapstructure:"base_url"`
}

func parseConfig(settings map[string]any) (*Settings, error) // Parse -> applyDefaults(Inspect="request_response") -> validate
func (s *Settings) selectsStage(stage policy.Stage) bool       // inspect × stage matrix
```

`validate`: `api_key` required; `consumer_id` required; `inspect` ∈ the three
enum values (empty allowed → defaulted); `base_url` if set must parse as an
absolute URL with scheme+host.

```go
// data.go
type GuardRequest struct {
    Direction  string          `json:"direction"`
    Protocol   string          `json:"protocol"`
    SessionID  string          `json:"session_id,omitempty"`
    ConsumerID string          `json:"consumer_id,omitempty"`
    Input      GuardInput      `json:"input"`
    Attributes GuardAttributes `json:"attributes,omitempty"`
}
type GuardInput struct {
    Input string `json:"input"`
}
type GuardAttributes struct {
    ContentType string      `json:"content_type,omitempty"`
    Model       *GuardModel `json:"model,omitempty"`
}
type GuardModel struct {
    Name     string `json:"name,omitempty"`
    Provider string `json:"provider,omitempty"`
}

type GuardResponse struct {
    Status             string          `json:"status"`
    TransformedPayload json.RawMessage `json:"transformed_payload,omitempty"`
    Findings           []GuardFinding  `json:"findings,omitempty"`
    TraceID            string          `json:"trace_id,omitempty"`
    RequestID          string          `json:"request_id,omitempty"`
}
type GuardFinding struct {
    Category string `json:"category,omitempty"`
    Action   string `json:"action,omitempty"`
    Score    float64 `json:"score,omitempty"`
}

type guardData struct {
    Direction     string `json:"direction,omitempty"`
    Status        string `json:"status,omitempty"`
    TraceID       string `json:"trace_id,omitempty"`
    RequestID     string `json:"request_id,omitempty"`
    FindingsCount int    `json:"findings_count,omitempty"`
    Decision      string `json:"decision,omitempty"` // blocked|allowed|reported|failed_open|passthrough
    FailedOpen    bool   `json:"failed_open,omitempty"`
}
func setExtras(event *metrics.EventContext, data guardData)
```

```go
// client.go
const guardPath = "/v1/guard"
const maxResponseBytes = 1 << 20

type client struct{ http *http.Client }
func newClient(timeout time.Duration) *client // {Timeout: timeout||defaultTrustGuardTimeout}

// Guard POSTs body to {baseURL}/v1/guard with Authorization: Bearer <apiKey>.
// Returns a transport error for non-2xx status so callers fail open uniformly.
func (c *client) Guard(ctx context.Context, baseURL, apiKey string, body GuardRequest) (GuardResponse, error)
```

```go
// pkg/config/config.go additions
const defaultTrustGuardTimeout = 15 * time.Second

type TrustGuardConfig struct {
    BaseURL string
    Timeout time.Duration
}
// in Config: TrustGuard TrustGuardConfig
func getTrustGuardConfig() TrustGuardConfig {
    return TrustGuardConfig{
        BaseURL: getEnv("TRUSTGUARD_BASE_URL", ""),
        Timeout: getEnvDuration("TRUSTGUARD_TIMEOUT", defaultTrustGuardTimeout),
    }
}
// LoadConfig: TrustGuard: getTrustGuardConfig(),
```

No new `Validate()` rule (empty base URL is valid → plugin passes through + logs).

```go
// pkg/container/modules/plugins.go
type pluginParams struct {
    dig.In
    Cache   cache.Client
    Adapters *adapter.Registry
    Locator embeddingfactory.EmbeddingServiceLocator
    Logger  *slog.Logger
    Pricing appcatalog.PricingResolver
    Cfg     *config.Config // added
}
// in catalog slice:
trustguard.New(p.Adapters, p.Cfg.TrustGuard.BaseURL, p.Cfg.TrustGuard.Timeout, p.Logger),
```

## Execute control flow (pseudocode)

```
cfg, err := parseConfig(in.Config.Settings); if err -> return nil, fmt.Errorf("trustguard: %w", err)
if in.Request == nil -> return passThrough()
if !cfg.selectsStage(in.Stage) -> return passThrough()            // matrix gate

direction := "input" if in.Stage==pre_request else "output"

baseURL := cfg.BaseURL; if baseURL=="" { baseURL = p.defaultBaseURL }
if baseURL == "" -> log.Warn("trustguard base url not configured", direction) ; return passThrough()

if p.registry == nil || in.Request.Provider == "" -> return passThrough()
format, err := adapter.ResolveAgentFormat(in.Request.Provider, in.Request.SourceFormat, nil); if err -> passThrough()

var text string
if direction=="input":
    if len(in.Request.Body)==0 -> passThrough()
    creq, err := registry.DecodeRequestFor(in.Request.Body, format); if err||creq==nil -> passThrough()
    text = joinMessages(creq.System, creq.Messages)   // System + each Message.Content
else: // output
    if in.Response == nil -> passThrough()
    if in.Response.Streaming -> passThrough()          // cannot inspect/block streams
    if len(in.Response.Body)==0 -> passThrough()
    cresp, err := registry.DecodeResponseFor(in.Response.Body, format); if err||cresp==nil -> passThrough()
    text = cresp.Content
if text=="" -> passThrough()

req := GuardRequest{Direction:direction, Protocol:"llm", SessionID:in.Request.SessionID,
                    ConsumerID:cfg.ConsumerID, Input:{Input:text},
                    Attributes:{ContentType:"application/json",
                                Model:{Name:in.Request.RequestedModel, Provider:in.Request.Provider}}}

resp, err := p.client.Guard(ctx, baseURL, cfg.APIKey, req)
if err != nil:                                          // transport/timeout/non-2xx
    log.Warn("trustguard call failed, failing open", err, direction)
    setExtras(in.Event, guardData{Direction:direction, Decision:"failed_open", FailedOpen:true})
    return passThrough()

base := guardData{Direction:direction, Status:resp.Status, TraceID:resp.TraceID,
                  RequestID:resp.RequestID, FindingsCount:len(resp.Findings)}

if resp.Status=="block" && appplugins.Blocks(in.Mode):
    base.Decision = "blocked"; setExtras(in.Event, base)
    return nil, &appplugins.PluginError{StatusCode:403, Type:"trustguard_blocked",
              Message:"request blocked by TrustGuard", Body: blockBody(resp)}

if resp.Status=="block":                                // observe mode
    base.Decision = "reported"
else:
    base.Decision = "allowed"                           // transform/report/"" => allow
setExtras(in.Event, base)
appplugins.SetDecision(in.Event, in.Mode)
return passThrough()
```

`passThrough()` returns `&appplugins.Result{StatusCode: http.StatusOK}`.
`blockBody` marshals `{status, findings, trace_id, request_id}` to JSON
(fail-safe to a short plain message on marshal error).

## Error handling & logging

- All failures **fail open** (return `passThrough`), never a non-`PluginError`
  error except a config parse error in `Execute`/`ValidateConfig`.
- `client.Guard` wraps transport errors and **maps non-2xx to an error**
  (`fmt.Errorf("trustguard: unexpected status %d", code)`) so `Execute` has one
  uniform fail-open branch.
- slog attrs (named, no narration comments): `slog.String("plugin","trustguard")`,
  `slog.String("direction", direction)`, `slog.String("base_url", baseURL)` on
  the unconfigured-base-url warning; `slog.Any("error", err)` +
  `slog.String("direction", direction)` on the call-failed warning. Use
  `p.logger.WarnContext(ctx, ...)`.

## Testing Strategy

| Layer | What | Approach |
|---|---|---|
| Unit (config) | required `api_key`/`consumer_id`, `inspect` enum + default, `base_url` validation, `selectsStage` matrix | table-driven `config_test.go` |
| Unit (client) | 2xx decode, non-2xx → error, transport error, context-timeout, malformed JSON, Bearer+Content-Type headers, path `/v1/guard`, `io.LimitReader` cap | `httptest.NewServer` in `client_test.go` |
| Unit (Execute) | block→403 PluginError (pre_request short-circuit, pre_response replace); observe→reported passThrough; allow statuses (`transform`/`report`/``); streaming passThrough; empty base_url passThrough+warn; transport error fail-open; stage not selected by `inspect`; request body decode → GuardRequest assertion (direction, model, session, consumer) | `httptest.NewServer` fake TrustGuard + real `adapter.NewRegistry()`; assert returned `*PluginError`/`*Result` and captured request body |
| Catalog | metadata entry present, stages+schema | extend `catalog_test.go` |

All tests run under `go test -race`. Fake server captures the request body for
assertions; a slow handler + small `TRUSTGUARD_TIMEOUT` exercises the timeout
fail-open path.

## Migration / Rollout

No migration. Additive and self-contained: removing the `newPluginRegistry`
line, the catalog entry, the `pkg/config` additions, and the package reverts the
change. Empty `TRUSTGUARD_BASE_URL` keeps the plugin inert (passThrough) even if
a policy references it, so deploy is safe before TrustGuard is reachable.

## Open Questions

- [ ] **Catalog group**: ship under `groupOther` (chosen, matches
  `tool_call_validation`) vs. introduce a dedicated `groupGuardrails`. Resolved
  to `groupOther` for minimal blast radius; revisit if product wants a
  Guardrails section.
- [ ] **`input.input` join format for request leg**: concatenation of
  `System` + each `Message.Content` (newline-joined). Chosen as the simplest
  faithful text view; exact separator is an implementation detail validated in
  tests (no blocker).
