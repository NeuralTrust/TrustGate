# Exploration: OpenAI Moderation Guardrail plugin (RUN-717)

Re-implements legacy `toxicity_openai` on the new TrustGate plugin SDK. This
document is the source of truth for the proposal/design phases. All paths are
relative to the worktree `/Users/edu/Neuraltrust/TrustGate-openai-moderation-guardrail`
unless prefixed with `LegacyGateway/`.

Recommended plugin slug: **`openai_moderation`**
Recommended package/dir: **`pkg/infra/plugins/openaimoderation/`** (package
`openaimoderation`, mirroring `trustguard`, `modelallowlist`, `prompttemplate`
which drop underscores in the package name while keeping a snake_case slug).
Catalog group: **`Guardrails`** — already exists, no new group needed.

---

## 1. The plugin SDK (`pkg/app/plugins`)

### 1.1 `Plugin` interface — `pkg/app/plugins/plugin.go:35-49`

```go
type Plugin interface {
    Name() string
    MandatoryStages() []policy.Stage
    SupportedStages() []policy.Stage
    SupportedModes() []policy.Mode
    ValidateConfig(settings map[string]any) error
    Execute(ctx context.Context, in ExecInput) (*Result, error)
    MutatesRequestBody() bool
    MutatesResponseBody() bool
    MutatesMetadata() bool
}
```

- `MandatoryStages` ⊆ `SupportedStages` (enforced in `registry.Register`,
  `registry.go:67-74`). Stages the plugin ALWAYS runs on regardless of policy
  config.
- `SupportedStages` is the set a policy may opt into; `EffectiveStages`
  (`stages.go:26-40`) = mandatory ∪ (policy-selected ∩ supported).
- For a guardrail we want operators to choose legs: set
  `SupportedStages = {pre_request, pre_response}` and
  `MandatoryStages = {}` (empty), letting `policy.Stages` drive which legs run.
  (See OPEN QUESTION Q1 about the `stages` config field.)
- `Mutates*` are all `false` for a read-only guardrail (trustguard does this,
  `trustguard/plugin.go:84-88`). They are resolved once on the cold path to
  decide parallel-batch packing (AGENT.md §14.2).

### 1.2 `ExecInput` — `plugin.go:51-62`

```go
type ExecInput struct {
    Stage    policy.Stage
    Mode     policy.Mode
    Config   policy.PluginConfig          // .Settings is map[string]any
    Scope    RuntimeScope
    Request  *infracontext.RequestContext
    Response *infracontext.ResponseContext
    Event    *metrics.EventContext        // NIL when traces disabled → nil-check
}
```

### 1.3 `Result` — `plugin.go:94-100`

```go
type Result struct {
    StatusCode   int
    Body         []byte
    RequestBody  []byte
    Headers      map[string][]string
    StopUpstream bool
}
```

- Read-only guardrails return a "pass-through" result:
  `&Result{StatusCode: http.StatusOK}` (trustguard `passThrough()`,
  `trustguard/plugin.go:237-239`).
- To BLOCK, do NOT use `Result.StopUpstream`; return a `*PluginError` as the
  `error` (see §2.4). The executor/forwarder translate it into the client
  response.

### 1.4 Stage enums — `pkg/domain/policy/plugin.go:17-33`

`StagePreRequest = "pre_request"`, `StagePostRequest`, `StagePreResponse = "pre_response"`,
`StagePostResponse`. Legacy ran only PreRequest; this plugin adds PreResponse.

### 1.5 Mode enums + `Blocks` — `pkg/domain/policy/mode.go:19-23`, `pkg/app/plugins/modes.go`

- `ModeEnforce = "enforce"`, `ModeThrottle = "throttle"`, `ModeObserve = "observe"`.
- `appplugins.Blocks(mode) bool` → `mode != ModeObserve` (`modes.go:45-47`).
- `appplugins.SetDecision(event, mode)` records `"observe"`/`"throttle"`/`"block"`
  (`modes.go:53-69`).
- Every plugin MUST support `ModeEnforce` (validated in `validateDeclaredModes`,
  `modes.go:26-43`). For this plugin: `SupportedModes = {ModeEnforce, ModeObserve}`.
- Drive blocking with `if shouldBlock && appplugins.Blocks(in.Mode) { return nil, blockError(...) }`,
  exactly like trustguard `plugin.go:190-203`.

### 1.6 Registry — `pkg/app/plugins/registry.go:29-35`

`Register`/`Get`/`Validate`/`ValidateStages`/`Names`. Registration validates
stages and modes. Duplicate names rejected.

---

## 2. Exemplary existing plugins

### 2.1 `trustguard` — the closest analog (external HTTP guardrail, both stages, enforce/observe)

`pkg/infra/plugins/trustguard/` — **this is the template to copy.** File layout:

| File | Responsibility |
|---|---|
| `plugin.go` | `Plugin` struct, `New(...)`, all interface methods, `Execute` |
| `config.go` | `Settings` struct (`mapstructure` tags), `parseConfig`, `applyDefaults`, `validate`, `selectsStage` |
| `client.go` | HTTP client + `Guard()` call (marshal, POST, `io.LimitReader`, status check, unmarshal) |
| `data.go` | request/response JSON shapes + event `guardData` + `setExtras(event, data)` |
| `reject.go` | `blockError(resp) *appplugins.PluginError` (403 + JSON body) |
| `plugin_test.go`, `config_test.go`, `client_test.go` | tests |

Key flow in `trustguard/plugin.go:95-204`:
1. `parseConfig(in.Config.Settings)` → typed `Settings`.
2. Gate on stage (`cfg.selectsStage(in.Stage)`), nil request/provider, empty body.
3. Resolve format via `adapter.ResolveAgentFormat(in.Request.Provider, in.Request.SourceFormat, nil)`.
4. Decode body → canonical → extract text (`joinRequestText` for request leg,
   `cresp.Content` for response leg).
5. Build request DTO, call `p.client.Guard(ctx, ...)`.
6. On transport error → **fail open** (`passThrough()` + record `failed_open`).
7. On `status==block && Blocks(mode)` → `return nil, blockError(resp)`.
8. Else record decision via `setExtras` + `SetDecision`, return `passThrough()`.

Config (`trustguard/config.go`): `api_key` field carries
`// #nosec G101 -- config field name, not a credential` on the struct tag line.
Parses via `pluginutil.Parse[Settings](settings)` (`pluginutil/decode.go:38-44`,
mapstructure with `WeaklyTypedInput: true`).

### 2.2 `tool_call_validation` — also calls OpenAI, shows credential-from-settings + shared client

`pkg/infra/plugins/tool_call_validation/` uses `openai.NewOpenaiClient()` (which
internally builds a `providers.NewHTTPClientPool()`), and reads the OpenAI
`api_key` from a nested `semantic` settings block. Registered with the OpenAI
client injected: `tool_call_validation.New(p.Adapters, openai.NewOpenaiClient(), p.Logger)`
(`modules/plugins.go:102`).

### 2.3 `model_allowlist` — guardrail that returns 403 (reject) for reference

`pkg/infra/plugins/modelallowlist/` blocks disallowed models with a 403; good
reference for a pure request-leg guard with reject/substitute behavior.

---

## 3. Shared HTTP client + context deadline

There is **no `httpx` package** in TrustGate (that was the legacy import
`pkg/infra/httpx`). The shared client lives in
**`pkg/infra/providers/http_client.go`**:

- `providers.NewHTTPClientPool()` → `*HTTPClientPool`.
- `pool.Get(key string, timeout time.Duration) *http.Client` — pooled per key,
  with a tuned `*http.Transport` (`newTransport()`, `http_client.go:109-131`:
  dial 10s, TLS 10s, `ResponseHeaderTimeout` 30s, HTTP/2, idle pooling).
- `providers.DefaultHTTPTimeout = 120s` (overridable).
- `providers.DrainBody(r)` to cleanly return connections on error paths.

**Recommendation for the moderation client (fixes legacy "no timeout" defect):**
construct a `providers.NewHTTPClientPool()` once in the plugin constructor, call
`pool.Get("openai_moderation", timeout)`, and additionally bound each call with
`ctx, cancel := context.WithTimeout(ctx, timeout)` + `http.NewRequestWithContext`.
trustguard currently uses a bare `&http.Client{Timeout: timeout}`
(`trustguard/client.go:37-39`) — we improve on that by using the pooled tuned
transport. Timeout/base-URL come from config (see §6, mirror `TrustGuardConfig`).

---

## 4. Provider-aware content extraction (text + image)

### 4.1 Text — solved via the adapter registry

`*adapter.Registry` (`pkg/infra/providers/adapter/registry.go`) is injected into
plugins (`pluginParams.Adapters`, `modules/plugins.go:54`). It exposes:
- `DecodeRequestFor(body, format) (*CanonicalRequest, error)` — `registry.go:128`
- `DecodeResponseFor(body, format) (*CanonicalResponse, error)` — `registry.go:178`
- `ResolveAgentFormat(provider, sourceFormat, opts) (Format, error)` — `format.go:142`

Covers OpenAI/Anthropic/Bedrock/Gemini/Mistral/Groq/DeepSeek/Azure
(`registry.go:93-106`). Request text = `System` + each `Messages[].Content`
(see `trustguard/plugin.go:224-235`); response text = `CanonicalResponse.Content`.

### 4.2 Image — NOT available through the canonical model (key constraint)

`CanonicalMessage.Content` is a flat `string` (`canonical.go:42-47`). The OpenAI
adapter's `contentToString` (`openai_adapter.go:158-182`) extracts only `text`
parts from a content-part array and **silently drops `image_url`**. So the
adapter path gives text only; there is **no existing helper that returns
`image_url`** for moderation.

Implication: to moderate images we must add a small, provider-aware raw-JSON
extractor (e.g. `extract.go`) that pulls `image_url` parts directly from the
request body per provider shape (OpenAI `messages[].content[].image_url.url`,
Anthropic `content[].source`, Bedrock content blocks). The legacy plugin only
handled the single OpenAI `messages[].content[]` shape
(`LegacyGateway/.../toxicity_openai.go:197-209`). See OPEN QUESTION Q2 — strongly
recommend **text-only in v1**, images as a fast-follow, to avoid per-provider
image-shape sprawl.

`RequestContext` / `ResponseContext` fields a plugin receives:
`pkg/infra/context/request_context.go:30-54` (`.Body []byte`, `.Provider`,
`.SourceFormat`, `.RequestedModel`, `.ConsumerType`, `.SessionID`, …) and
`response_context.go:22-35` (`.Body []byte`, `.Streaming`, `.StatusCode`).

---

## 5. Catalog metadata (`pkg/app/plugins/catalog_metadata.go`)

- Groups are consts (`catalog_metadata.go:20-28`): **`groupGuardrails = "Guardrails"`
  already exists** and is in `groupOrder` (`:31-39`). No new group required.
- `catalogMeta{name, group, description, schema}` (`:44-49`); add an entry keyed
  by the slug to the `pluginCatalogMeta` map (`:55`). `trustguard`'s entry
  (`:1121-1157`) is the model to copy.
- `SettingsSchema` / `Field` / `FieldType` defined in `catalog.go:26-64`. Field
  types: string, integer, number, boolean, duration, enum, object, array, map.
- The catalog endpoint reads stages/modes from the live plugin
  (`catalog.go:110-137`) and merges curated metadata; a plugin without metadata
  falls back to `groupOther` (won't crash, but UI would be poor).
- Suggested schema fields: `api_key` (string, required), `model` (string,
  default `omni-moderation-latest`), `thresholds` (map<string→number>),
  `categories` (array<string>), `block_on_flagged` (boolean, default false),
  `action` → `{ message: string }` (object). See Q1 re: `stages` field.

---

## 6. Registration / bootstrap (DI)

- Single place to register: `newPluginRegistry` in
  **`pkg/container/modules/plugins.go:91-105`** — append to the `catalog`
  `[]appplugins.Plugin` slice, e.g.:
  `openaimoderation.New(p.Adapters, p.Cfg.OpenAIModeration.Timeout, p.Logger)`.
- Dependencies available via `pluginParams` (`plugins.go:51-60`): `Adapters
  *adapter.Registry`, `Logger *slog.Logger`, `Cfg *config.Config`, plus cache,
  pricing, DB.
- Config for base-URL/timeout: mirror `TrustGuardConfig`
  (`config.go:244-247` + `getTrustGuardConfig` `config.go:485-490` +
  `defaultTrustGuardTimeout = 15s` `config.go:98`). Add an
  `OpenAIModerationConfig{BaseURL, Timeout}` read from
  `OPENAI_MODERATION_BASE_URL` / `OPENAI_MODERATION_TIMEOUT` (api_key stays in
  policy settings, like trustguard). Document in `.env.example`.
- Module test pattern: add `TestNewPluginRegistry_RegistersOpenAIModeration` and
  a catalog-metadata test mirroring `modules/plugins_test.go:46-83`. Note:
  `pkg/app/plugins/catalog_test.go` `builtinSlugs` (`:29-38`) uses FAKE
  `stagePlugin`s and does NOT enumerate real infra plugins, so it does not need
  editing for a new plugin.

---

## 7. How blocking reaches the client (executor + forwarder)

- `executor.runOne` (`pkg/app/plugins/executor.go:126-177`) calls `Execute`,
  records latency (`SetSLatency`), status, error, and decision span; closes the
  span via `defer event.Publish()`.
- A returned `*PluginError` propagates as `err` up through
  `RunStage` → `forwarder.runPreRequest` (`pkg/app/proxy/plugin_runner.go:50-54`)
  → `pluginErrorResult(pe)` (`plugin_runner.go:200-217`). PreResponse path:
  `runPreResponseGated` (`:66-95`).
- `pluginErrorResult` uses `pe.Body` verbatim if set, else builds a generic
  `{error,message,type}` JSON. So our `blockError` must set `Body` to the spec'd
  shape:
  ```json
  { "error": { "type": "content_flagged",
    "categories": [{ "category": "hate", "score": 0.91, "threshold": 0.7 }] } }
  ```
  with `StatusCode: 403`, `Type: "content_flagged"`.
- `PluginError` shape: `pkg/app/plugins/errors.go:21-27`
  (`StatusCode, Type, Message, Headers, Body`); `AsPluginError` unwraps it.

---

## 8. Event recording / metrics

- `*metrics.EventContext` (`pkg/infra/metrics/event_context.go`): `SetExtras(any)`
  (arbitrary JSON payload → span extras), `SetError`, `SetStatusCode`,
  `SetDecision`, `SetMode`, `SetSLatency`. **Always nil-check** `in.Event`.
- The executor already sets mode, latency, and status around `Execute`
  (`executor.go:142-168`), so the plugin only needs `SetExtras(data)` with the
  per-category scores + decision, plus `appplugins.SetDecision(in.Event, in.Mode)`
  on the non-block path. trustguard's `setExtras` (`trustguard/data.go:79-84`)
  is the pattern.
- Recommended extras payload (re-shaped from legacy `ToxicityOpenaiData`,
  `LegacyGateway/.../data.go`): `model`, `input_count`, per-category
  `category_scores map[string]float64`, `flagged_by_openai bool`, `max_score`,
  `max_score_category`, `flagged_categories [{category,score,threshold}]`,
  `decision`, `latency_ms`. Note: the executor already records latency on the
  span; an explicit `latency_ms` extra is optional/duplicative.

---

## 9. Legacy implementation summary (`LegacyGateway/pkg/infra/plugins/toxicity_openai`)

`toxicity_openai.go` (296 lines) + `data.go`. Behavior:
- PreRequest only. POST `https://api.openai.com/v1/moderations`, model hardcoded
  `omni-moderation-latest` (`:165`).
- Parses request as `{messages:[{role,content:[{type,text,image_url}]}]}` —
  single hardcoded OpenAI multimodal shape (`:45-62`, `:197-209`).
- `extractModerationInputs` builds `[]ModerationInput{type:text|image_url}`.
- One call, uses `Results[0]` only (`:234`); finds max score/category; blocks if
  ANY `category_scores[cat] >= thresholds[cat]` (`:261-269`).
- On block → `PluginError{403, Actions.Message + violation}` (`:286-290`).

### Moderations API JSON shapes (to re-declare in `data.go`)

Request:
```json
{ "model": "omni-moderation-latest",
  "input": [ {"type":"text","text":"..."},
             {"type":"image_url","image_url":{"url":"https://..."}} ] }
```
Response (`OpenAIModerationResponse`, legacy `:75-86`):
```json
{ "id": "...", "model": "...",
  "results": [ { "flagged": true,
                 "categories": {"hate": false, ...},
                 "category_scores": {"hate": 0.01, ...},
                 "category_applied_input_types": {"hate": ["text"], ...} } ] }
```

### Defects to fix (called out in RUN-717)

1. **No HTTP timeout** — legacy falls back to bare `&http.Client{}`
   (`:92-94`). Fix: pooled tuned client + `context.WithTimeout` (§3).
2. **Dead `categories` field** — only `thresholds` drove blocking; `categories`
   was decoded but never used. Fix: make both meaningful (see Q3).
3. **`action.type` validated but never used** — `ValidateConfig` requires
   `Actions.Type` (`:127-129`) but `Execute` only uses `Actions.Message`. Fix:
   drop `action.type`, keep `action.message`.
4. **Error leakage** — non-200 returns `fmt.Errorf("OpenAI API returned error:
   %s", body)` (`:185-187`), surfacing raw OpenAI body upstream. Fix: map to a
   generic **502** to the caller, log detail via slog (see Q4 on fail-open vs
   fail-closed).
5. **Missing observe mode + PreResponse** — add both.
6. Uses only `Results[0]` — with multiple inputs, aggregate across all results
   (max per category). See Q5.

---

## 10. Recommended file layout for the new plugin

```
pkg/infra/plugins/openaimoderation/
  plugin.go        # Plugin, New, interface methods, Execute
  config.go        # Settings, parseConfig, applyDefaults, validate
  client.go        # moderations HTTP client (pooled + ctx deadline)
  data.go          # Moderation req/resp JSON + event extras + setExtras
  extract.go       # provider-aware text (+ optional image) extraction
  reject.go        # blockError -> *PluginError (403 content_flagged body)
  plugin_test.go config_test.go client_test.go extract_test.go
```
Plus: `pkg/app/plugins/catalog_metadata.go` (new map entry, group Guardrails),
`pkg/container/modules/plugins.go` (register), `pkg/config/config.go`
(`OpenAIModerationConfig` + getter + default) and `.env.example`.

Constraints honored: hexagonal layout (plugin in `infra`, SDK in `app`, stage/mode
in `domain`), one-use-case/responsibility-per-file, NO CODE COMMENTS (strip when
porting from legacy), `//go:generate mockery` only where interfaces are introduced.

---

## Approaches (stage selection)

| Approach | Pros | Cons | Effort |
|---|---|---|---|
| A. Policy-native stages (`MandatoryStages={}`, `SupportedStages={pre_request,pre_response}`, driven by `policy.Stages`) | SDK-idiomatic; UI catalog shows supported stages; no redundant config | Diverges from the literal `stages` field in the Linear config sample | Low |
| B. Settings `stages: []string` field (like trustguard's `inspect`) | Matches legacy/Linear config sample verbatim; self-contained | Duplicates the SDK stage mechanism; two sources of truth | Low–Med |

**Recommendation: Approach A**, and treat the `stages` config key as an alias
resolved into policy stages OR drop it — pending Q1.

---

## Recommendation

Copy the `trustguard` structure exactly, swap the external call for OpenAI
Moderations, reuse `*adapter.Registry` for provider-aware **text** extraction,
use the pooled `providers` HTTP client + a context deadline, return a `403
content_flagged` `*PluginError`, support `enforce`+`observe` via
`appplugins.Blocks`, run on `pre_request` and `pre_response`, and record
per-category scores via `Event.SetExtras`. Ship **text-only v1**; defer image
moderation. Map upstream API failures to a generic **502** with detail logged.

**Ready for Proposal: Yes**, once the open questions below are answered.

---

## OPEN QUESTIONS (resolve before proposal/design)

- **Q1 — `stages` config field vs policy stages.** Use SDK-native `policy.Stages`
  (Approach A) and drop `stages` from settings, or keep a `stages` settings field
  to match the Linear config sample? (Recommend: policy-native; remove from
  schema.)
- **Q2 — Image moderation scope.** Text-only v1 (reuse adapter canonical text),
  with image_url moderation as a fast-follow? Or must v1 moderate images, which
  requires a new per-provider raw-JSON image extractor (OpenAI/Anthropic/Bedrock
  shapes differ)? (Recommend: text-only v1.)
- **Q3 — `categories` semantics.** What exactly does `categories` mean now that
  it must be "meaningful"? Options: (a) allow-list restricting which categories
  are evaluated against thresholds; (b) categories that block on `flagged=true`
  even without a threshold; (c) default-threshold list. Need a precise rule.
- **Q4 — Fail-open vs fail-closed on API error/timeout.** RUN-717 says map errors
  to **502** (implies fail-closed), but `trustguard` fails **open**
  (pass-through) on transport errors. Which wins for moderation — block (502) or
  allow-through-and-record? Does the answer differ by mode (observe always
  passes through) or by stage (pre_response cannot 502 a mid-stream response)?
- **Q5 — Multi-input aggregation.** Confirm we aggregate scores across ALL
  Moderations `results[]` (max per category) rather than legacy `results[0]`.
- **Q6 — Credential management.** Read `api_key` from policy settings now (like
  trustguard/tool_call_validation), aligning later with a credential-manager? Is
  there an existing secret-reference mechanism this should use instead of
  plaintext-in-policy?
- **Q7 — Response-leg streaming.** PreResponse cannot inspect streaming responses
  in realtime (trustguard skips when `in.Response.Streaming`,
  `trustguard/plugin.go:142`). Confirm we likewise skip streaming on
  pre_response (and rely on post_response analytics only if needed).
- **Q8 — Default thresholds.** If a category has no configured threshold and
  `block_on_flagged=false`, is it ignored entirely? Any built-in default
  threshold, or purely operator-configured?
