# Design: Budget plugin (token / dollar budget + cost cap) — RUN-696

## Technical Approach

Extend `token_rate_limiter` in place (proposal Approach 1, structured per
Approach 3): keep the slug `token_rate_limiter`, split the growing package into
small single-responsibility files, gate every new feature behind optional config
so existing `window{unit,max}+group_by_header` policies are byte-for-byte
unchanged. Reuse `appcatalog.PricingResolver` (injected via DI) for both the
dollar budget and the stateless cost cap; reuse `adapter.CanonicalUsage` for
usage; reuse the existing fixed-window Lua `recordScript` for both token and
micro-USD counters. Downgrade rewrites the model in `req.Body` during
`pre_request` (single-plugin-batch only) and emits a header via `Result.Headers`.

All Go is written **without comments** (AGENT.md §11) and follows golang-pro
(error wrapping with `%w`, `context` propagation, table-driven `-race` tests).

## Package file layout — `pkg/infra/plugins/tokenratelimit/`

| File | Responsibility | Key symbols (all unexported unless noted) |
|------|----------------|-------------------------------------------|
| `plugin.go` | Plugin contract + `Execute` dispatch + provider guard + DI constructor | `PluginName` (const), `Plugin` (exported), `New(redis, registry, pricing)`, `Name/MandatoryStages/SupportedStages/SupportedModes/ValidateConfig/Execute`, `preRequest`, `postResponse` |
| `config.go` | Full config struct + `parseConfig` + `validate` + legacy back-compat mapping + window-string parsing | `config`, `windowConfig`, `budgetRule`, `aggregateConfig`, `costCapConfig`, `costCeiling`, `customPrice`, `parseConfig`, `(*config).validate`, `(*config).normalize`, `parseWindow(string) (int, error)` |
| `budget.go` | Pre-request budget gate + post-response accrual; per-model + aggregate iteration; token vs micro-USD | `budgetGate`, `accrue`, `selectRule`, `windowsFor` |
| `costcap.go` | Stateless pre-request cost cap: ceiling compare, reject / downgrade / unknown-model | `costCapDecision`, `decision` (struct), `evaluateCeiling` |
| `pricing.go` | Custom overlay → builtin resolver composition; per-token→per-1k; micro-USD scaling | `priceFor(ctx, provider, model) (perTokenIn, perTokenOut float64, found bool)`, `microUSD(usage, in, out) int64`, `per1k(perToken) float64` |
| `keys.go` | Counter key building (`:hdr:`, `:model:`) | `counterKeyPrefix` (const), `aggregateKey`, `modelKey` |
| `glob.go` | Wildcard matcher + most-specific precedence | `globMatch(pattern, s) bool`, `bestMatch[T](m map[string]T, s string) (T, bool)` |
| `data.go` | Trace payload (extended) | `TokenRateLimiterData` (exported) |
| `scripts.go` | Fixed-window Lua (moved out of `plugin.go`, reused as-is) | `recordScript` |

`glob.go` and `keys.go` hold no interfaces; the interface-per-file rule (§10.1)
is unaffected — the package exports only `Plugin` and `TokenRateLimiterData`.

## Architecture Decisions

| Decision | Choice | Rejected | Rationale |
|----------|--------|----------|-----------|
| Slug | Extend `token_rate_limiter` | New `budget` slug | Issue intent; reuse wiring/counter/scope; zero migration |
| Pricing source | Inject `appcatalog.PricingResolver`, custom overlay first | Inject `domain.Repository` | Keep TTLMap+singleflight memoization; one source of truth |
| Slug candidates | Extract `appcatalog.SlugCandidates(...string)` shared by `builder.go` + plugin | Replicate in plugin | DRY; one definition of date-suffix stripping |
| Dollar storage | micro-USD `round(cost_usd*1e6)` int64 in same Lua | float / new script | `INCRBY` is integer-only; no script variant needed |
| Counter unit discriminator | None — `unit` is immutable per `cfgID`, key shape stays back-compat | add `:tok:`/`:usd:` segment | Avoids breaking existing keys; one unit per policy |
| Downgrade channel | Mutate `req.Body` (single-batch) + `Result.Headers` | New `Result.BodyRewrite` channel | Out of scope (proposal); framework change is larger |
| Modes vs behavior | Orthogonal: `policy.Mode` gates, `behavior_on_*` is the action; `observe` forces non-blocking | Map behavior onto Mode | Matches framework; preserves existing `Blocks/Throttles` |

## Config struct(s)

```go
type windowConfig struct {
	Unit string `mapstructure:"unit"`
	Max  int    `mapstructure:"max"`
}

type budgetRule struct {
	Model      string  `mapstructure:"model"`
	Max        float64 `mapstructure:"max"`
	TimeWindow string  `mapstructure:"time_window"`
}

type costCeiling struct {
	MaxInputCostPer1k  float64 `mapstructure:"max_input_cost_per_1k_tokens"`
	MaxOutputCostPer1k float64 `mapstructure:"max_output_cost_per_1k_tokens"`
}

type costCapConfig struct {
	Enabled             bool                    `mapstructure:"enabled"`
	MaxInputCostPer1k   float64                 `mapstructure:"max_input_cost_per_1k_tokens"`
	MaxOutputCostPer1k  float64                 `mapstructure:"max_output_cost_per_1k_tokens"`
	PerModelOverrides   map[string]costCeiling  `mapstructure:"per_model_overrides"`
	BehaviorOnViolation string                  `mapstructure:"behavior_on_violation"`
	DowngradeTo         string                  `mapstructure:"downgrade_to"`
	UnknownModel        string                  `mapstructure:"unknown_model"`
}

type aggregateConfig struct {
	Max        float64 `mapstructure:"max"`
	TimeWindow string  `mapstructure:"time_window"`
}

type customPrice struct {
	Input  float64 `mapstructure:"input"`
	Output float64 `mapstructure:"output"`
}

type config struct {
	Unit                 string                 `mapstructure:"unit"`
	PerModel             bool                   `mapstructure:"per_model"`
	Counting             string                 `mapstructure:"counting"`
	Rules                []budgetRule           `mapstructure:"rules"`
	Aggregate            *aggregateConfig       `mapstructure:"aggregate"`
	BehaviorOnExceeded   string                 `mapstructure:"behavior_on_exceeded"`
	DowngradeTo          string                 `mapstructure:"downgrade_to"`
	StreamUsageInjection bool                   `mapstructure:"stream_usage_injection"`
	CountCacheReads      bool                   `mapstructure:"count_cache_reads"`
	CostCap              *costCapConfig         `mapstructure:"cost_cap"`
	PricingTable         string                 `mapstructure:"pricing_table"`
	CustomPricing        map[string]customPrice `mapstructure:"custom_pricing"`
	Window               windowConfig           `mapstructure:"window"`
	GroupByHeader        string                 `mapstructure:"group_by_header"`
}
```

**Zero-value / back-compat mapping** (`normalize`, run inside `parseConfig`
before `validate`):

- `Unit == ""` → `"tokens"`; `Counting == ""` → `"total"`;
  `PricingTable == ""` → `"builtin"`; `BehaviorOnExceeded == ""` → `"reject"`.
- If `len(Rules)==0 && Aggregate==nil` and legacy `Window.Max>0`: synthesize
  `Aggregate = {Max: float64(Window.Max), TimeWindow: ""}` and keep
  `windowSeconds()` driven by `validUnits[Window.Unit]`. This reproduces today's
  single-window aggregate token budget exactly, including the existing
  `X-Ratelimit-*-Tokens` headers and 429 path.
- `time_window` parsed by `parseWindow`: accepts `"30m"`,`"1h"`,`"1d"`; floor to
  60s, min 1 minute. Empty `time_window` on a synthesized aggregate falls back to
  legacy `windowSeconds()`.

`validate` (table-driven friendly): `unit ∈ {tokens,dollars}`;
`counting ∈ {total,input,output}`; each rule `max>0` and valid `time_window`;
aggregate `max>0`; `behavior_on_exceeded ∈ {reject,throttle,downgrade}` (downgrade
requires non-empty `downgrade_to`); cost_cap `unknown_model ∈
{reject,pass_through,assume_max}`, `behavior_on_violation ∈ {reject,downgrade}`;
at least one of legacy window / rules / aggregate / cost_cap present.

## Execution flow

`Execute` keeps the provider guard (`req==nil || req.Provider==""` → OK) and
dispatches by stage. **pre_request** runs cost cap first, then the budget gate;
**post_response** accrues.

```
pre_request:
  parse+normalize cfg
  if cfg.CostCap.Enabled:
     model := ExtractModel(req.Body)            # fallback req.RequestedModel
     dec := costCapDecision(ctx, cfg, req.Provider, model)
     switch dec.kind:
        reject    -> PluginError{403, model_too_expensive}        # only if Blocks(mode)
        downgrade -> req.Body = OverrideModel(req.Body, dec.target)
                     Result.Headers[X-NeuralTrust-Model-Downgraded] = orig->target
        pass      -> continue
     (observe mode: never reject/rewrite; record decision only)
  budgetGate(ctx, cfg, req):                     # reads Redis counter(s)
     key(s) := aggregateKey + optional modelKey(rule.Model)
     if any counter >= its max:
        Blocks(mode)   -> PluginError{429, *_budget_exceeded, X-Budget-* headers}
        Throttles(mode)-> Throttle(window)
        observe        -> record only
post_response:
  accrue(ctx, cfg, req, resp):
     usage := extractUsage(req, resp)            # streaming: req.Metadata[usage]
     amount := tokens (unit:tokens) | microUSD(usage, perTokenIn, perTokenOut)
     for each active window (aggregate and/or matched per-model rule):
        recordScript.Run(key, amount, windowSec)
```

`req.Provider` and `req.RequestedModel` are guaranteed set before `pre_request`
(forwarder `stampTarget` → `runPreRequest`, AGENT.md §14.1). The downgrade body
rewrite is read downstream by `provider.go` (`body := req.Body` →
`AdaptRequest` → `EnforceModel`).

**`stream_usage_injection` caveat**: the wire-level injection of
`stream_options.include_usage` is owned by the proxy (`provider_stream.go`,
always-on for OpenAI Chat Completions) and the metrics pipeline populates
`req.Metadata[usage]`. The plugin consumes that injected usage for streaming
accrual; the config flag is therefore advisory and the plugin does not itself
mutate the body to opt into stream usage. Wiring the flag through to the proxy
is left out of scope to avoid duplicating platform behavior across packages.

**Mode × behavior**: `observe` (Mode) overrides every `behavior_on_*` →
record-only, no block, no rewrite. `throttle` (Mode) applies only to the budget
gate (delay); cost cap has no throttle and is skipped under throttle/observe for
blocking but still recorded. `enforce` applies the configured `behavior_on_*`.

## Counter keys & Redis

```
aggregate : trl:{cfgID}:{dim}:{subject}[:hdr:{v}]
per-model : trl:{cfgID}:{dim}:{subject}[:hdr:{v}]:model:{slug}
```

`{dim}/{subject}` from `RuntimeScope.Subject()`. Tokens store integer token
counts; dollars store integer **micro-USD** (`round(cost_usd*1e6)`) — same key
shape because `unit` is fixed per `cfgID`. `recordScript` is **reused unchanged**
(integer `INCRBY` + first-write `EXPIRE`); no variant. Window seconds are
**per-rule**: aggregate uses `aggregate.time_window` (or legacy
`windowSeconds()`), each per-model rule uses its own `time_window`. Atomicity:
each counter is one atomic Lua call; the read-side gate is a plain `GET` and is
intentionally lossy (post-response accrual, documented in proposal). Per-model +
aggregate are independent keys updated sequentially in `accrue`.

## Downgrade implementation

- Resolve target via `cfg.DowngradeTo` (budget) or `cfg.CostCap.DowngradeTo`.
- **Same-provider guard**: parse target with `routingdomain.ParseModelRef`; if it
  carries `@provider` and provider != `req.Provider` → cross-provider → fall back
  to **reject**. Bare slug → assume `req.Provider`; confirm priceability via
  `PricingResolver.Resolve(req.Provider, target).Found` (best-effort).
- Rewrite: `req.Body = adapter.OverrideModel(req.Body, target)` (model field name
  is stable across wire formats, so rewriting the source-format body before
  `AdaptRequest` is correct).
- Emit `X-NeuralTrust-Model-Downgraded: <orig>→<new>` via `Result.Headers`
  (merged pre-upstream; works for streams).
- **Single-batch caveat (§14.2)**: `mergeIsolated` merges only Headers+Metadata,
  **not Body**. In a single-plugin batch `runOne` passes the live `req`, so the
  rewrite survives. In a parallel batch the Body rewrite is dropped → downgrade is
  unsafe. Document: do not group this plugin in a parallel `pre_request` batch
  when downgrade is enabled. Headers (the audit signal) survive regardless.

## Pricing

`priceFor` composes: (1) `cfg.CustomPricing` (per-token USD overlay), selected by
`bestMatch` over its glob keys, consulted first; (2) `PricingResolver.Resolve`
over `appcatalog.SlugCandidates(ExtractModel(body), req.RequestedModel)` against
`req.Provider`, returning per-token prices. Cost-cap ceilings are per-1k →
compare `per1k(perToken) = perToken*1000` to the ceiling. Dollar accrual uses
per-token directly: `microUSD = round((in*perTokenIn + out*perTokenOut)*1e6)`.
`count_cache_reads` toggles whether `usage.CacheReadInputTokens` is added to the
input count. **Slug helper**: extract `deploymentCatalogSlug`/`appendModelSlugs`/
`uniqueNonEmptySlugs` from `builder.go` into exported `appcatalog.SlugCandidates`;
refactor `builder.go::pricingSlugs` to call it (no behavior change). Layering:
infra plugin importing `pkg/app/catalog` is consistent with the package already
importing `pkg/app/plugins` and `pkg/infra/metrics`.

## DI wiring

```go
type pluginParams struct {
	dig.In
	Cache    cache.Client
	Adapters *adapter.Registry
	Locator  embeddingfactory.EmbeddingServiceLocator
	Logger   *slog.Logger
	Pricing  appcatalog.PricingResolver
}
```

`tokenratelimit.New(redisClient, p.Adapters, p.Pricing)`. New constructor:
`func New(redisClient *redis.Client, registry *adapter.Registry, pricing appcatalog.PricingResolver) *Plugin`.
`PricingResolver` is already provided by `modules.Catalog`; no import-direction
violation beyond existing precedent.

## Catalog metadata (`catalog_metadata.go`)

Update `token_rate_limiter`: name `"Token & Dollar Budget + Cost Cap"`,
description covering token/dollar budgets and per-model cost cap. Grow
`SettingsSchema.Fields`: keep `window` (object, back-compat) + `group_by_header`;
add `unit` (enum tokens|dollars), `per_model` (boolean), `counting` (enum), `rules`
(array of object{model,max,time_window}), `aggregate` (object{max,time_window}),
`behavior_on_exceeded` (enum), `downgrade_to` (string), `stream_usage_injection`
(boolean), `count_cache_reads` (boolean), `pricing_table` (enum builtin|custom),
`custom_pricing` (map free-form key → object{input,output}), `cost_cap` (object
with the ceilings, `per_model_overrides` map→object, enums). Uses existing
`FieldTypeObject/Array/Map/Enum`. `catalog_test.go` updated for the new tree.

## Wildcard matcher

`globMatch` supports `*` (any run) using a linear two-pointer algorithm (no
regex). `bestMatch[T]` selects among map keys: **exact key wins**; otherwise the
glob match with the **longest non-`*` literal length** wins (most specific).
Used for `rules[].model`, `cost_cap.per_model_overrides`, and `custom_pricing`.

## Data Flow

```
client ─▶ forwarder.Forward
            stampTarget(req)            req.Provider, req.RequestedModel set
            runPreRequest ─▶ executor ─▶ Plugin.Execute(pre)
                                          costcap (PricingResolver) ─▶ OverrideModel(req.Body) / 403
                                          budgetGate (Redis GET) ─▶ 429 + X-Budget-*
            invokeOnce ─▶ provider.go (req.Body ─▶ AdaptRequest ─▶ EnforceModel) ─▶ upstream
upstream ─▶ resp ─▶ post_response ─▶ Plugin.Execute(post)
                                       extractUsage ─▶ priceFor ─▶ recordScript INCRBY (tokens|microUSD)
```

## Testing Strategy

| Layer | What | How |
|-------|------|-----|
| Unit | config validate + back-compat normalize | table-driven, `-race` |
| Unit | glob matcher + `bestMatch` precedence | table-driven |
| Unit | pricing overlay (custom→builtin), per-1k, micro-USD scaling | resolver mock |
| Unit | key building (`:hdr:`,`:model:`) | table-driven |
| Unit | cost-cap decisions (reject/downgrade/unknown ×3) | table-driven |
| Functional | token budget per-model + aggregate; dollar budget; cost cap reject + downgrade; back-compat legacy config; observe/enforce modes | `tests/functional/plugin_token_rate_limiter_test.go` helpers (`setupPolicyRoute`, `createGlobalPolicy`, `createScopedPolicy`, `newUsageUpstream`, `proxyRequest`, `require.Eventually`) |

## Edge cases & decisions

- **Unknown model**: cost cap applies `unknown_model` (reject|pass_through|
  assume_max); dollar accrual records 0 and logs a warn (proposal).
- **Streaming usage**: read `req.Metadata[adapter.MetadataUsageKey]`
  (`*adapter.CanonicalUsage`); `stream_usage_injection` controls whether usage is
  requested/injected upstream.
- **Cache reads**: `count_cache_reads` adds `CacheReadInputTokens` to input.
- **Observe mode**: never blocks/rewrites; records decision + extras only.
- **Validation failure**: `ValidateConfig` rejects at config time; `Execute`
  wraps parse errors with `%w`.

## Migration / Rollout

Additive and config-gated. Existing configs unchanged (normalize synthesizes the
legacy aggregate). Ships as **chained PRs** (config+back-compat → per-model token
→ dollar → cost cap+pricing → downgrade → catalog schema → functional tests);
`sdd-tasks` forecasts the split. Rollback = drop new optional fields/files and
revert `pluginParams`.

## Open Questions (NEW, from real code)

- [ ] **`EnforceModel` vs downgrade**: `provider.go` calls
  `adapter.EnforceModel(body, req.AllowedModels, req.DefaultModel)` after the
  rewrite. If `AllowedModels` is non-empty and the downgrade target is not in it,
  upstream invocation fails `ErrModelNotAllowed`. The cost-cap/budget downgrade
  must verify `target ∈ req.AllowedModels` (when set) and fall back to reject
  otherwise. (`isAllowed` is exact-match; wildcards don't apply here.)
- [ ] **Provider-code parity**: confirm `req.Provider` equals the `providerCode`
  the catalog repo/models.dev uses in `FindModel` (builder uses `served.Provider`)
  — required for both dollar accrual and cost cap to resolve prices.
- [ ] **`builder.go` refactor coordination**: extracting `SlugCandidates` touches
  `app/metrics`; keep it behavior-preserving and covered by existing metrics tests.
