# Design: OpenAI moderation guardrail plugin — RUN-717

## Technical Approach

A net-new infra plugin `openai_moderation` under
`pkg/infra/plugins/openaimoderation/`, registered in the catalog and run at
`pre_request` and `pre_response`. It is modeled **file-for-file on `trustguard`**
(`pkg/infra/plugins/trustguard/`), the closest analog: an external-HTTP,
read-only guardrail that inspects both legs and supports `enforce` + `observe`.

The plugin is read-only (`MutatesRequestBody/ResponseBody/Metadata == false`),
returns a pass-through `*appplugins.Result{StatusCode: 200}` on allow, and
returns a `*appplugins.PluginError` as the `error` to short-circuit on block (403
`content_flagged`) or on a moderator outage in enforce mode (502
`moderation_unavailable`). It never uses `Result.StopUpstream`.

Content for moderation is extracted **text-only** through the injected canonical
adapter registry (`*adapter.Registry`): request text = `System` + each
`Messages[].Content`, response text = `CanonicalResponse.Content`, identical to
`trustguard/plugin.go:224-235`. The moderations call uses the shared **pooled,
tuned transport** (`providers.NewHTTPClientPool().Get("openai_moderation", timeout)`)
plus a per-call `context.WithTimeout`, fixing the legacy "no HTTP timeout"
defect and improving on trustguard's bare `&http.Client{Timeout: ...}`.

All Go is written **without comments** (AGENT.md §11 / `go-comments` rule — only
the Apache header) and follows golang-pro: `%w` error wrapping,
`context` propagation with deadlines, no goroutine leaks (single synchronous
round-trip), table-driven `-race` tests, `go vet` / `golangci-lint` clean. The
package exports only `Plugin`, `PluginName`, `New`, and the trace payload type
`ModerationData`; everything else is unexported (one-responsibility-per-file,
AGENT.md §10.1 — the same shape as `trustguard`).

## Package file layout — `pkg/infra/plugins/openaimoderation/`

| File | Responsibility | Key symbols (unexported unless noted) |
|------|----------------|----------------------------------------|
| `plugin.go` | `Plugin` struct, DI `New()`, all interface methods, `Execute` orchestration, `passThrough()` | `PluginName` (const, exported), `Plugin` (exported), `New()` (exported), `Name/MandatoryStages/SupportedStages/SupportedModes/MutatesRequestBody/MutatesResponseBody/MutatesMetadata/ValidateConfig/Execute`, `passThrough`, `warn` |
| `config.go` | `Settings` struct (`mapstructure` tags) + `parseConfig` + `applyDefaults` + `validate` + `selectsStage` | `Settings` (exported, mirrors trustguard), `parseConfig`, `(*Settings).applyDefaults`, `(*Settings).validate`, `(Settings).selectsStage`, stage/default consts |
| `client.go` | Pooled moderations HTTP client: marshal, POST `{base}/v1/moderations`, `Authorization: Bearer`, `io.LimitReader`, status check, typed non-2xx error, unmarshal | `client`, `newClient(timeout)`, `(*client).Moderate(ctx, baseURL, apiKey, req)`, `moderationsPath`, `maxResponseBytes`, `errModeration` (typed) |
| `data.go` | Moderations request/response JSON shapes + event extras + `setExtras(event, data)` | `moderationRequest`, `moderationInput`, `moderationResponse`, `moderationResult`, `ModerationData` (exported), `violation`, `setExtras` |
| `extract.go` | Canonical text extraction for request + response legs | `joinRequestText(*adapter.CanonicalRequest) string`, `responseText(*adapter.CanonicalResponse) string` |
| `reject.go` | `blockError` → 403 `content_flagged` `*PluginError`; `unavailableError` → 502 `moderation_unavailable` `*PluginError` | `blockError(violations)`, `unavailableError()`, `blockBody`, type/message consts |
| `evaluate.go` | Score aggregation + block-rule evaluation (max-per-category across all `results[]`, allow-list, thresholds, `block_on_flagged`) | `aggregate(results)`, `evaluate(cfg, agg) []violation` |
| `plugin_test.go`, `config_test.go`, `client_test.go`, `extract_test.go`, `evaluate_test.go` | Table-driven `-race` tests, one per source file | — |

`client.go`, `data.go`, `extract.go`, `evaluate.go`, `reject.go` hold no
interfaces, so AGENT.md §10.1 is satisfied (same pattern as trustguard's
`client.go` / `data.go` / `reject.go`). `evaluate.go` is split out of `plugin.go`
(unlike trustguard, whose block rule is a single status check) because the
moderation block rule is non-trivial and must be unit-tested in isolation —
one-responsibility-per-file.

## Architecture Decisions

| Decision | Choice | Rejected | Rationale |
|----------|--------|----------|-----------|
| Template plugin | **Copy `trustguard` file-for-file** | Copy `tool_call_validation` (also OpenAI) | trustguard is the exact behavioral analog: external HTTP, read-only, both legs, enforce/observe, fail-path branching. `tool_call_validation` reads `api_key` from a nested `semantic` block and uses the shared `openai.OpenaiClient` (chat-completions, not moderations) — wrong endpoint and wrong config shape. |
| Stage gating | **`MandatoryStages = {}`, `SupportedStages = {pre_request, pre_response}`, plus a `stages []string` settings field gated by `selectsStage`** | trustguard's `MandatoryStages = {both}` + `inspect` enum | Resolved per proposal. `MandatoryStages` empty means `EffectiveStages = policy.Stages ∩ supported` (`stages.go:26-40`) drives invocation; the in-plugin `stages` field (default `[pre_request, pre_response]`) is a self-contained secondary filter matching the Linear config sample verbatim. Both must agree; the default never narrows. Diverges from trustguard (mandatory both) deliberately so a policy can opt a single leg in. |
| HTTP client | **Pooled tuned transport** `providers.NewHTTPClientPool().Get("openai_moderation", timeout)` built once in `newClient`, plus per-call `context.WithTimeout` + `http.NewRequestWithContext` | Bare `&http.Client{Timeout: timeout}` (trustguard) | Fixes legacy defect #1 (no timeout) and improves on trustguard: isolated connection pool, `ResponseHeaderTimeout`, HTTP/2, bounded dial/TLS (`http_client.go:109-131`). The context deadline guarantees the call returns even if the transport's own timeout is misconfigured (no goroutine leak). |
| Base URL source | **Env-only** via `OpenAIModerationConfig{BaseURL, Timeout}`, default `https://api.openai.com` | Per-policy `base_url` settings field (trustguard has one) | The resolved settings schema does not include `base_url`. Default is a real URL (not empty like `TRUSTGUARD_BASE_URL`), so the plugin is active whenever a policy enables it with an `api_key`. An empty `BaseURL` (operator blanked the env) → pass-through with a `warn`, matching trustguard's missing-base-URL guard. |
| `api_key` location | **Policy settings** (`mapstructure:"api_key"` with `// #nosec G101`) | Env var / credential manager | Consistent with trustguard / tool_call_validation. Credential-manager alignment is an explicit non-goal (proposal §Non-goals). |
| Content scope | **Text-only v1** (canonical adapter text) | Per-provider raw-JSON `image_url` extraction | The canonical model exposes `CanonicalMessage.Content` as a flat string and the OpenAI adapter drops `image_url` parts (exploration §4.2). Image moderation needs a per-provider raw extractor that would blow the 400-line budget; deferred fast-follow (proposal DEVIATION). |
| Fail mode on API/non-2xx error | **Fail-CLOSED**: enforce → 502 `moderation_unavailable` (generic body, detail via `slog`); observe → pass-through + record | Fail-open (trustguard) | Moderation is a safety control; an unavailable moderator must not pass unmoderated traffic in enforce. Diverges from trustguard deliberately. Streaming `pre_response` is skipped (cannot 502 a mid-stream body). Fixes legacy defect #4 (raw body leakage): the upstream body is logged, never returned. |
| Multi-input aggregation | **Max-per-category across ALL `results[]`** | legacy `results[0]` only | Fixes legacy defect #6. With one text input there is one result, so behavior is unchanged in the common case; correctness holds if multiple inputs are ever sent. |
| `categories` semantics | **Allow-list**: non-empty → only these categories evaluated; empty → all categories present in the response | legacy dead field | Fixes legacy defect #2 (decoded-but-unused). Precise rule below. |
| `action.type` | **Dropped** (only `action.message`) | keep + validate (legacy) | Fixes legacy defect #3 (validated but unused). |
| Block signalling | **Return `*PluginError` as `error`**; `Body` set verbatim to the spec'd JSON | `Result.StopUpstream` / `Result.Body` | `pluginErrorResult` (`plugin_runner.go:200-217`) emits `pe.Body` verbatim, so the 403/502 shapes reach the client unchanged (exploration §7). |

## Settings struct (`config.go`)

```go
const (
	defaultModel = "omni-moderation-latest"

	stagePreRequest  = "pre_request"
	stagePreResponse = "pre_response"
)

type Settings struct {
	APIKey         string             `mapstructure:"api_key"` // #nosec G101 -- config field name, not a credential
	Model          string             `mapstructure:"model"`
	Stages         []string           `mapstructure:"stages"`
	Categories     []string           `mapstructure:"categories"`
	Thresholds     map[string]float64 `mapstructure:"thresholds"`
	BlockOnFlagged bool               `mapstructure:"block_on_flagged"`
	Action         ActionSettings     `mapstructure:"action"`
}

type ActionSettings struct {
	Message string `mapstructure:"message"`
}
```

`parseConfig` mirrors trustguard exactly: `pluginutil.Parse[Settings](settings)`
→ `applyDefaults()` → `validate()`.

**`applyDefaults`**:

- `Model == ""` → `defaultModel` (`omni-moderation-latest`).
- `len(Stages) == 0` → `[]string{stagePreRequest, stagePreResponse}`.

**`validate`**:

- `strings.TrimSpace(APIKey) == ""` → `fmt.Errorf("openai_moderation: api_key is required")`.
- every `Stages[i] ∈ {pre_request, pre_response}` → else
  `fmt.Errorf("openai_moderation: stages must be pre_request or pre_response")`.
- every `Thresholds[cat]` in `[0, 1]` → else
  `fmt.Errorf("openai_moderation: threshold for %q must be between 0 and 1", cat)`.
- (no requirement on `categories`, `block_on_flagged`, or `action.message`;
  an empty message falls back to a default block message in `reject.go`).

**`selectsStage`** (driven by the `stages` field, like trustguard's `Inspect`):

```go
func (s Settings) selectsStage(stage policy.Stage) bool {
	for _, st := range s.Stages {
		if policy.Stage(st) == stage {
			return true
		}
	}
	return false
}
```

## Plugin contract + DI (`plugin.go`)

```go
const PluginName = "openai_moderation"

type Plugin struct {
	registry *adapter.Registry
	client   *client
	baseURL  string
	logger   *slog.Logger
}

func New(registry *adapter.Registry, baseURL string, timeout time.Duration, logger *slog.Logger) *Plugin {
	return &Plugin{
		registry: registry,
		client:   newClient(timeout),
		baseURL:  baseURL,
		logger:   logger,
	}
}
```

`New` takes the same shape as `trustguard.New(registry, baseURL, timeout, logger)`.
DI in `modules/plugins.go` passes `p.Adapters`, `p.Cfg.OpenAIModeration.BaseURL`,
`p.Cfg.OpenAIModeration.Timeout`, `p.Logger`.

Interface methods:

| Method | Value |
|--------|-------|
| `Name()` | `PluginName` (`"openai_moderation"`) |
| `MandatoryStages()` | `[]policy.Stage{}` (empty) |
| `SupportedStages()` | `{policy.StagePreRequest, policy.StagePreResponse}` |
| `SupportedModes()` | `{policy.ModeEnforce, policy.ModeObserve}` |
| `MutatesRequestBody/ResponseBody/Metadata()` | `false` |
| `ValidateConfig(settings)` | `_, err := parseConfig(settings); return err` |
| `Execute(ctx, in)` | orchestration below |

`SupportedModes` includes `ModeEnforce` (required by `validateDeclaredModes`,
`modes.go:26-43`).

## Execute control flow (`plugin.go` + `evaluate.go`)

```mermaid
sequenceDiagram
    participant Ex as executor
    participant P as openai_moderation
    participant Cl as client (HTTP)
    participant Ev as evaluate.go
    Ex->>P: Execute(ctx, in)
    P->>P: cfg = parseConfig(in.Config.Settings)  (wrap %w on error)
    alt !cfg.selectsStage(in.Stage)
        P-->>Ex: passThrough()
    end
    alt baseURL == "" (env blanked)
        P->>P: warn("base url not configured")
        P-->>Ex: passThrough()
    end
    alt in.Request == nil || registry == nil || Provider == ""
        P-->>Ex: passThrough()
    end
    P->>P: format = ResolveAgentFormat(Provider, SourceFormat, nil)
    alt direction == input
        alt len(Request.Body) == 0
            P-->>Ex: passThrough()
        end
        P->>P: creq = registry.DecodeRequestFor(Request.Body, format)
        P->>P: text = joinRequestText(creq)
    else direction == output
        alt Response == nil || Response.Streaming || len(Response.Body) == 0
            P-->>Ex: passThrough()
        end
        P->>P: cresp = registry.DecodeResponseFor(Response.Body, format)
        P->>P: text = responseText(cresp)
    end
    alt strings.TrimSpace(text) == ""
        P-->>Ex: passThrough()
    end
    P->>Cl: resp = client.Moderate(ctx, baseURL, cfg.APIKey, {model, input:[{type:text,text}]})
    alt Moderate error (transport / non-2xx)
        P->>P: warn(detail) ; setExtras(decision=failed_closed/failed_open)
        alt Blocks(in.Mode)  (enforce)
            P-->>Ex: nil, unavailableError()   (502 moderation_unavailable)
        else observe
            P-->>Ex: passThrough()
        end
    end
    P->>Ev: agg = aggregate(resp.Results)   (max per category across all results[])
    P->>Ev: violations = evaluate(cfg, agg)  (allow-list + thresholds + block_on_flagged)
    alt len(violations) > 0 && Blocks(in.Mode)
        P->>P: setExtras(decision=blocked, data)
        P-->>Ex: nil, blockError(violations)   (403 content_flagged)
    end
    P->>P: setExtras(decision=reported|allowed, data) ; SetDecision(in.Event, in.Mode)
    P-->>Ex: passThrough()
```

`passThrough()` returns `&appplugins.Result{StatusCode: http.StatusOK}` (mirrors
trustguard `plugin.go:237-239`). `warn` is the nil-safe `slog` helper copied from
trustguard `plugin.go:206-211`.

### Direction & request DTO

`direction = "input"` for `pre_request`, `"output"` for `pre_response`
(decides request vs response decode). The moderations request is built
**text-only**:

```go
req := moderationRequest{
	Model: cfg.Model,
	Input: []moderationInput{{Type: "text", Text: text}},
}
```

### Aggregation + block rule (`evaluate.go`)

```go
type aggregated struct {
	scores  map[string]float64
	flagged map[string]bool
}

func aggregate(results []moderationResult) aggregated {
	agg := aggregated{scores: map[string]float64{}, flagged: map[string]bool{}}
	for _, r := range results {
		for cat, score := range r.CategoryScores {
			if score > agg.scores[cat] {
				agg.scores[cat] = score
			}
		}
		for cat, f := range r.Categories {
			if f {
				agg.flagged[cat] = true
			}
		}
	}
	return agg
}
```

`evaluate(cfg, agg) []violation`:

1. **Evaluation set** = `cfg.Categories` (allow-list) when non-empty; otherwise
   the union of keys present in `agg.scores` ∪ `agg.flagged`.
2. For each category `c` in the evaluation set, in deterministic order
   (sorted to keep the 403 body / tests stable):
   - if a threshold `t` is configured for `c` and `agg.scores[c] >= t` →
     append `violation{Category: c, Score: agg.scores[c], Threshold: t}`.
   - else if `cfg.BlockOnFlagged && agg.flagged[c]` → append
     `violation{Category: c, Score: agg.scores[c], Threshold: 0}` (threshold
     omitted from JSON via `omitempty`).
   - a category is reported at most once.
3. Returns the (possibly empty) `[]violation`.

**Block iff** `len(violations) > 0 && appplugins.Blocks(in.Mode)`
(`Blocks(mode) == mode != observe`). Observe never blocks; it records
`decision = reported` when violations exist, `allowed` otherwise.

## Moderations client (`client.go`)

```go
const (
	moderationsPath  = "/v1/moderations"
	maxResponseBytes = 1 << 20
)

type client struct {
	http *http.Client
}

func newClient(timeout time.Duration) *client {
	return &client{http: providers.NewHTTPClientPool().Get(PluginName, timeout)}
}

func (c *client) Moderate(ctx context.Context, baseURL, apiKey string, body moderationRequest) (*moderationResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	payload, err := json.Marshal(body)        // wrap %w
	endpoint := strings.TrimRight(baseURL, "/") + moderationsPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)                // wrap %w
	defer providers.DrainBody(res.Body)
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("openai_moderation: unexpected status %d", res.StatusCode)
	}
	var out moderationResponse
	json.Unmarshal(raw, &out)                 // wrap %w
	return &out, nil
}
```

- Built once via the pooled tuned transport keyed by `PluginName`
  (`"openai_moderation"`). The per-call deadline is layered with
  `context.WithTimeout`; `newClient` stores `timeout` on the struct so
  `Moderate` can apply it (the snippet elides the field for brevity).
- `providers.DrainBody` returns the connection cleanly on every path
  (exploration §3).
- **Non-2xx maps to a typed error carrying only the status code** — the raw
  OpenAI body is **never** propagated upward (fixes legacy defect #4). The
  plugin maps any `Moderate` error to a generic 502 and logs detail via `slog`.

### JSON shapes (`data.go`)

```go
type moderationRequest struct {
	Model string            `json:"model"`
	Input []moderationInput `json:"input"`
}

type moderationInput struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type moderationResponse struct {
	ID      string             `json:"id"`
	Model   string             `json:"model"`
	Results []moderationResult `json:"results"`
}

type moderationResult struct {
	Flagged        bool               `json:"flagged"`
	Categories     map[string]bool    `json:"categories"`
	CategoryScores map[string]float64 `json:"category_scores"`
}
```

## reject.go — block (403) and fail-closed (502)

```go
const (
	typeContentFlagged = "content_flagged"
	typeUnavailable    = "moderation_unavailable"

	defaultBlockMessage = "content blocked by moderation policy"
	unavailableMessage  = "content moderation is temporarily unavailable"
)

func blockError(message string, violations []violation) *appplugins.PluginError {
	return &appplugins.PluginError{
		StatusCode: http.StatusForbidden,
		Type:       typeContentFlagged,
		Message:    blockMessageOr(message),
		Body:       blockBody(violations),
	}
}

func unavailableError() *appplugins.PluginError {
	return &appplugins.PluginError{
		StatusCode: http.StatusBadGateway,
		Type:       typeUnavailable,
		Message:    unavailableMessage,
		Body:       []byte(`{"error":{"type":"moderation_unavailable","message":"content moderation is temporarily unavailable"}}`),
	}
}
```

`blockBody(violations)` marshals exactly the spec'd shape:

```json
{
  "error": {
    "type": "content_flagged",
    "categories": [
      { "category": "hate", "score": 0.91, "threshold": 0.7 }
    ]
  }
}
```

via:

```go
type violation struct {
	Category  string  `json:"category"`
	Score     float64 `json:"score"`
	Threshold float64 `json:"threshold,omitempty"`
}
```

`blockError` receives `cfg.Action.Message` for the `Message` field (falling back
to `defaultBlockMessage` when blank); the 403 **Body** carries the structured
violation list and reaches the client verbatim through `pluginErrorResult`. The
502 body is a fixed generic JSON — no OpenAI detail.

## data.go — event extras

```go
type ModerationData struct {
	Direction        string             `json:"direction,omitempty"`
	Model            string             `json:"model,omitempty"`
	CategoryScores   map[string]float64 `json:"category_scores,omitempty"`
	MaxScore         float64            `json:"max_score,omitempty"`
	MaxScoreCategory string             `json:"max_score_category,omitempty"`
	FlaggedCategories []violation       `json:"flagged_categories,omitempty"`
	FlaggedByOpenAI  bool               `json:"flagged_by_openai,omitempty"`
	Decision         string             `json:"decision,omitempty"`
	FailedClosed     bool               `json:"failed_closed,omitempty"`
}

func setExtras(event *metrics.EventContext, data ModerationData) {
	if event == nil {
		return
	}
	event.SetExtras(data)
}
```

`in.Event` is **nil-checked** (nil when traces disabled, exploration §8).
`max_score`/`max_score_category` are derived from the aggregated scores;
`flagged_by_openai` is `true` if any `agg.flagged[*]` is set. Latency, status,
and mode are recorded by the executor around `Execute` (`executor.go:142-168`)
and are not duplicated here. On the non-block path the plugin also calls
`appplugins.SetDecision(in.Event, in.Mode)`.

## Config / env wiring (`pkg/config/config.go`)

Mirror `TrustGuardConfig`:

```go
const defaultOpenAIModerationTimeout = 15 * time.Second

type OpenAIModerationConfig struct {
	BaseURL string
	Timeout time.Duration
}

func getOpenAIModerationConfig() OpenAIModerationConfig {
	return OpenAIModerationConfig{
		BaseURL: getEnv("OPENAI_MODERATION_BASE_URL", "https://api.openai.com"),
		Timeout: getEnvDuration("OPENAI_MODERATION_TIMEOUT", defaultOpenAIModerationTimeout),
	}
}
```

- Add the field `OpenAIModeration OpenAIModerationConfig` to `Config` (after
  `TrustGuard`).
- Wire `OpenAIModeration: getOpenAIModerationConfig()` into the `LoadConfig`
  struct literal.

`.env.example` (after the TrustGuard block, lines 96-101):

```bash
# OpenAI Moderation Guardrail Configuration
# Base URL of the OpenAI Moderations API used by the openai_moderation plugin.
# api_key is configured per-policy in plugin settings, not here.
OPENAI_MODERATION_BASE_URL=https://api.openai.com
OPENAI_MODERATION_TIMEOUT=15s
```

## Catalog metadata (`pkg/app/plugins/catalog_metadata.go`)

Add `pluginCatalogMeta["openai_moderation"]` (group `groupGuardrails`, already in
`groupOrder`), modeled on the trustguard entry (`:1121-1157`):

```go
"openai_moderation": {
	name:        "OpenAI Moderation",
	group:       groupGuardrails,
	description: "Screen request and/or response text with the OpenAI Moderations API and block content that crosses configured category thresholds. Fails closed (HTTP 502) in enforce mode on any moderator error; observe mode records and passes through. Streaming responses cannot be inspected in realtime. Text-only.",
	schema: SettingsSchema{
		Fields: []Field{
			{Key: "api_key", Label: "API Key", Type: FieldTypeString, Description: "OpenAI credential sent as a Bearer token to the Moderations API.", Required: true},
			{Key: "model", Label: "Model", Type: FieldTypeString, Description: "Moderations model.", Default: "omni-moderation-latest"},
			{Key: "stages", Label: "Stages", Type: FieldTypeArray, Description: "Legs to inspect.", Item: &Field{Key: "stage", Label: "Stage", Type: FieldTypeEnum, Enum: []string{"pre_request", "pre_response"}}},
			{Key: "categories", Label: "Categories", Type: FieldTypeArray, Description: "Allow-list of categories to evaluate. Empty evaluates all categories returned by OpenAI.", Item: &Field{Key: "category", Label: "Category", Type: FieldTypeString}},
			{Key: "thresholds", Label: "Thresholds", Type: FieldTypeMap, Description: "Per-category score threshold (0..1). A score at or above the threshold blocks.", Value: &Field{Key: "threshold", Label: "Threshold", Type: FieldTypeNumber}},
			{Key: "block_on_flagged", Label: "Block On Flagged", Type: FieldTypeBoolean, Description: "Block any category OpenAI marks flagged, even without a configured threshold.", Default: false},
			{Key: "action", Label: "Action", Type: FieldTypeObject, Fields: []Field{
				{Key: "message", Label: "Message", Type: FieldTypeString, Description: "Block message returned to the caller."},
			}},
		},
	},
}
```

## Registration (`pkg/container/modules/plugins.go`)

Add the import and append to the `catalog` slice (no `pluginParams` change — the
deps already exist):

```go
import "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/openaimoderation"

catalog := []appplugins.Plugin{
	// ...existing...
	trustguard.New(p.Adapters, p.Cfg.TrustGuard.BaseURL, p.Cfg.TrustGuard.Timeout, p.Logger),
	openaimoderation.New(p.Adapters, p.Cfg.OpenAIModeration.BaseURL, p.Cfg.OpenAIModeration.Timeout, p.Logger),
}
```

## Affected files

| File | Impact | Notes |
|------|--------|-------|
| `pkg/infra/plugins/openaimoderation/plugin.go` | New | contract + `New` + `Execute` (~150 LOC) |
| `pkg/infra/plugins/openaimoderation/config.go` | New | `Settings` + parse/defaults/validate/selectsStage (~90 LOC) |
| `pkg/infra/plugins/openaimoderation/client.go` | New | pooled client + ctx deadline (~80 LOC) |
| `pkg/infra/plugins/openaimoderation/data.go` | New | JSON shapes + extras (~70 LOC) |
| `pkg/infra/plugins/openaimoderation/extract.go` | New | canonical text (~40 LOC) |
| `pkg/infra/plugins/openaimoderation/evaluate.go` | New | aggregate + block rule (~70 LOC) |
| `pkg/infra/plugins/openaimoderation/reject.go` | New | 403 + 502 builders (~60 LOC) |
| `pkg/infra/plugins/openaimoderation/*_test.go` | New | table-driven `-race` |
| `pkg/app/plugins/catalog_metadata.go` | Modified | new map entry, group `Guardrails` (~40 LOC) |
| `pkg/container/modules/plugins.go` | Modified | import + one register line |
| `pkg/container/modules/plugins_test.go` | Modified | registration + catalog-metadata assertions |
| `pkg/config/config.go` | Modified | `OpenAIModerationConfig` + getter + const + field + wire (~20 LOC) |
| `.env.example` | Modified | two env vars + comment |

## Test plan (table-driven, `-race`)

| File | Layer | Cases |
|------|-------|-------|
| `config_test.go` | Unit | defaults applied (model, stages); api_key required → error; invalid stage → error; threshold <0 / >1 → error; valid threshold accepted; `selectsStage` matrix (pre_request/pre_response/neither) |
| `extract_test.go` | Unit | `joinRequestText`: system + messages joined, blanks skipped; `responseText`: content returned; empty canonical → "" (per provider: OpenAI + Anthropic at minimum, via `ResolveAgentFormat` + `DecodeRequestFor`) |
| `evaluate_test.go` | Unit | `aggregate` max-per-category across multiple `results[]`; flagged OR across results; `evaluate`: threshold crossed → violation; below threshold → none; allow-list restricts evaluated categories; empty allow-list evaluates all; `block_on_flagged=true` flags without threshold; `block_on_flagged=false` ignores flagged-without-threshold; deterministic ordering |
| `client_test.go` | Unit | `httptest.Server`: 200 happy path decodes `results[]`; non-2xx → typed error, **body not leaked**; malformed JSON → error; `Authorization: Bearer` + `Content-Type` headers set; context deadline cancels a slow server (no leak) |
| `plugin_test.go` | Unit | contract (Name/MandatoryStages empty/SupportedStages/SupportedModes/Mutates*); enforce block → 403 `content_flagged` body; observe with violations → pass-through + `decision=reported`; fail-closed enforce (server 5xx) → 502 `moderation_unavailable`, no leaked body; fail-closed observe → pass-through; streaming `pre_response` → skip; stage not selected → skip; empty text → skip; nil request → skip; threshold-vs-flagged precedence |
| `pkg/container/modules/plugins_test.go` | Unit (existing) | `TestNewPluginRegistry_RegistersOpenAIModeration` (registered + `Get` + `Names`); catalog-metadata test: entry exists under a group, non-empty Name/Description/SettingsSchema.Fields/SupportedStages/SupportedModes, field keys = `{api_key, model, stages, categories, thresholds, block_on_flagged, action}` |

All tests run under `go test -race ./...`; `go vet` and `golangci-lint`
(including `unused`) clean — each phase ships its own tests so newly added
unexported symbols are exercised and not flagged dead.

## Phase breakdown (chained PR series, ≤400 changed lines each)

Proposal estimates ~640 non-test LOC + ~600 test LOC + ~60 wiring LOC, well over
the 400-line reviewer budget. Ship as a **stacked / chained PR series** (each PR
based on the previous), not three independent PRs — the feature is user-visible
only at the final phase. Each phase is independently green under `go vet`,
`golangci-lint`, and `go test -race ./...`.

| Phase | Scope | Lines (approx) | Green in isolation | Shippable alone |
|-------|-------|----------------|--------------------|-----------------|
| **P1** | `config.go` (Settings, parse/defaults/validate/selectsStage) + `data.go` (JSON shapes + `ModerationData` + `setExtras`) + `client.go` (pooled client + ctx deadline) + `extract.go` + `config_test.go` + `client_test.go` + `extract_test.go` | ~280 + ~250 test | Yes — tests exercise every new symbol so `unused` passes; package compiles standalone | No (not registered; inert, harmless dead code on main) |
| **P2** | `evaluate.go` (aggregate + block rule) + `reject.go` (403 + 502 builders) + `plugin.go` (contract + `New` + `Execute`) + `evaluate_test.go` + `plugin_test.go` | ~280 + ~300 test | Yes — `Plugin`/`New` exported (not flagged unused); full plugin behavior tested with `httptest` | No (still not registered) |
| **P3** | `pkg/config/config.go` (`OpenAIModerationConfig` + getter + const + field + wire) + `.env.example` + `catalog_metadata.go` entry + `modules/plugins.go` registration + `modules/plugins_test.go` assertions | ~90 + ~40 test | Yes | **Yes — activates the feature**; catalog + registration + env all land together |

Ordering rationale: P1 introduces only leaf code (config/client/data/extract)
exercised by its own tests. P2 introduces `Plugin`/`New`/`Execute` (exported, so
no `unused` failure) and the evaluation/reject logic. P3 is the thin activation
layer (config + catalog + registration + env + module tests) that wires the
plugin into the runtime — kept last and small so the "go-live" diff is trivially
reviewable. If a single chained series is undesirable, P1+P2 can be merged into
one functional-but-unregistered PR and P3 shipped as the activation PR (two PRs),
but the three-way split keeps each diff comfortably under budget.

## Resolved decisions (canonical)

- [x] **Q1 — stage field**: keep both — `MandatoryStages={}` +
  `SupportedStages={pre_request,pre_response}` (SDK) **and** a `stages` settings
  field gated by `selectsStage` (default both), matching the Linear config
  sample. Defaults never narrow; the two mechanisms agree.
- [x] **Q2 — image scope**: **text-only v1**; image moderation deferred
  fast-follow (proposal DEVIATION).
- [x] **Q3 — `categories`**: **allow-list** of categories to evaluate; empty =
  all categories present in the response.
- [x] **Q4 — fail mode**: **fail-CLOSED** — enforce → 502
  `moderation_unavailable` (generic body, detail logged); observe → pass-through
  + record; streaming `pre_response` skipped.
- [x] **Q5 — aggregation**: **max-per-category across all `results[]`** (+
  flagged OR across results).
- [x] **Q6 — credential**: `api_key` in policy settings (`// #nosec G101`);
  credential-manager out of scope.
- [x] **Q7 — streaming**: skip `pre_response` when `in.Response.Streaming`
  (mirrors trustguard `plugin.go:142`).
- [x] **Q8 — default thresholds**: none built-in; a category with no threshold
  blocks only when `block_on_flagged=true` and OpenAI flagged it.

## Open Questions

None blocking. All exploration open questions are resolved above against the
code.
