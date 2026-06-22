# Exploration: Budget plugin (token / dollar budget + cost cap) — RUN-696

Unified plugin that extends `token_rate_limiter` with (1) a cumulative budget in
tokens **or** dollars over a window, and (2) a stateless pre-request **cost cap**
on model list price. Absorbs RUN-697 (dollar budget) and RUN-698 (model cost cap).

## Current State

### The existing `token_rate_limiter`
- `pkg/infra/plugins/tokenratelimit/plugin.go` — runs on `pre_request` +
  `post_response` (both mandatory). Pre-request reads a Redis counter and
  rejects (429) / throttles / observes by `policy.Mode`. Post-response extracts
  total tokens from the upstream usage and `INCRBY`s the counter with an
  atomic Lua script (`recordScript`) that sets the window TTL only on first write
  (fixed window, not sliding).
- `pkg/infra/plugins/tokenratelimit/config.go` — config is just
  `window {unit, max}` + `group_by_header`. Units are `second|minute|hour|day`
  (no "1m"/"1h" string form; min granularity = second today). Parsed with
  `pluginutil.Parse[config]` (mapstructure, `WeaklyTypedInput`).
- Counter key: `trl:{configID}:{dimension}:{subject}[:hdr:{headerValue}]` where
  `dimension/subject` come from `RuntimeScope.Subject()` (`global`+gatewayID, or
  `consumer`+consumerID). **There is no per-model sub-keying today** — one window
  for the whole scope.
- Token extraction: streaming reads `req.Metadata[adapter.MetadataUsageKey]`
  (`*adapter.CanonicalUsage`, populated by the stream usage observer);
  non-streaming decodes the response body via
  `registry.DecodeResponseFor(body, format)` → `CanonicalResponse.Usage.TotalTokens`.
  `responseFormat()` prefers `req.SourceFormat` then `req.Provider`.
- Trace payload: `pkg/infra/plugins/tokenratelimit/data.go` (`TokenRateLimiterData`),
  surfaced via `event.SetExtras(...)`.

### Plugin framework
- Contract: `pkg/app/plugins/plugin.go` — `Plugin` interface (`Name`,
  `MandatoryStages`, `SupportedStages`, `SupportedModes`, `ValidateConfig`,
  `Execute`). `ExecInput` carries `Stage, Mode, Config (PluginConfig{ID,Slug,Name,Settings}),
  Scope (RuntimeScope), Request, Response, Event`. `Result{StatusCode, Body,
  Headers, StopUpstream}` is the **only** sanctioned output channel.
- Scope is **derived from `Policy.Global` + resolved consumer**, never from
  config. `RuntimeScope.Subject()` → (`global`|`consumer`, id). The proposed
  config's `"scope": "consumer"|"global"` field does **not** match this model.
- Registration: `pkg/container/modules/plugins.go::newPluginRegistry` builds each
  plugin with its infra deps and `reg.Register(...)`. `pluginParams` (dig.In)
  currently injects `Cache`, `Adapters (*adapter.Registry)`, embedding `Locator`,
  `Logger`. Redis is `p.Cache.RedisClient()`.
- Catalog/JSON-schema for the control plane: `pkg/app/plugins/catalog_metadata.go`
  (hand-authored `SettingsSchema` per slug) + `pkg/app/plugins/catalog.go`
  (`Field`/`FieldType` vocabulary incl. `object`, `array`, `map`, `enum`). Stages
  are read from the plugin, never duplicated. Test: `catalog_test.go`.
- Executor: `pkg/app/plugins/executor.go`. `applyResult` merges `Result.Headers`
  into the response and, on `StopUpstream`, short-circuits with status/body.
  Plugin errors short-circuit via `*PluginError{StatusCode, Message, Headers}`
  (`pkg/app/plugins/errors.go`). Parallel batches run on **isolated clones**;
  `mergeIsolated` merges back **only `Metadata` and `Headers`, NOT `Body`**.
- Modes: `pkg/app/plugins/modes.go` — `Blocks`, `Throttles`, `DecisionForMode`.
  Every plugin must support `enforce`.

### Pricing already exists (key finding)
- `pkg/app/catalog/pricing.go` — `PricingResolver.Resolve(ctx, providerCode, slug)
  → Pricing{ModelLabel, InputPrice, OutputPrice, Found}`. Backed by catalog
  `domain.Repository.FindModel` (Postgres, synced from models.dev via
  `pkg/infra/catalog/modelsdev/client.go` + `pkg/app/catalog/sync.go`), memoized
  in a `TTLMap` (`CatalogModelTTLName`) with singleflight. Provided in DI by
  `pkg/container/modules/catalog.go::Catalog` (`appcatalog.NewPricingResolver`).
- **Prices are per-token USD** (`pkg/app/metrics/builder.go::fillUsageAndCost`
  does `float64(u.InputTokens) * price.InputPrice`). The issue config uses
  per-1k-token units → a ×1000 conversion is required.
- `builder.go::pricingSlugs` already implements robust slug resolution
  (SentModel → response Model → requested ref, each with `-YYYY-MM-DD` suffix
  stripping) and `deploymentCatalogSlug`. This is reusable logic for both the
  budget (dollars) and the cost cap.
- Catalog model schema: `pkg/domain/catalog/catalog.go` (`Model.InputPrice`/
  `OutputPrice` as strings; `Slug`, `ProviderID`, `ContextWindow`, `MaxOutput`).

### Usage normalization across providers
- Centralized in `pkg/infra/providers/adapter/`. `CanonicalUsage{InputTokens,
  OutputTokens, TotalTokens, Cache*, ...}` (`canonical.go`). Each provider adapter
  (`openai_*`, `anthropic_adapter.go`, `bedrock_adapter.go`, `gemini_adapter.go`,
  `mistral_adapter.go`, OpenAI-compatible for Groq/DeepSeek) funnels through
  `newCanonicalUsage(in,out,total)` (nil-on-absence, total = in+out if missing).
  **No per-provider normalization needs reinventing** — decode via
  `registry.DecodeResponseFor` and read `Usage`. Cohere is not a registered
  adapter format here (only the listed 8 formats).

### Model / routing mechanics (relevant to downgrade)
- Forward order (`pkg/app/proxy/forwarder.go::Forward`): `resolveRouting` (sets
  `req.RequestedModel`) → `applyIntentToBody` → `stampConsumerScope` →
  `routeBackend` → **`stampTarget` (sets `req.Provider`/`RegistryID`)** →
  **`runPreRequest`** → invoke. So at `pre_request` `req.Provider` and
  `req.RequestedModel` are set, and the body model is normalized.
- **Backend selection happens BEFORE `pre_request`.** A model rewrite in
  `pre_request` cannot re-route to a different backend; it only changes the model
  field sent to the already-selected backend.
- Model body helpers: `pkg/infra/providers/adapter/model.go` —
  `OverrideModel(body, model)`, `ExtractModel(body)`, `StripModel`, `EnforceModel`.
  `isAllowed` is **exact-match only — no wildcard/glob** (issue uses `claude-opus-*`).
- Response headers from a plugin: returned via `Result.Headers`, merged by
  `executor.applyResult` (works for `X-NeuralTrust-Model-Downgraded`, `X-Budget-*`).

### Tests
- Functional: `tests/functional/plugin_token_rate_limiter_test.go` (build tag
  `functional`) — uses `setupPolicyRoute`, `policyPlugin`, `createGlobalPolicy`,
  `createScopedPolicy`, `newUsageUpstream`, `proxyRequest`, `require.Eventually`
  for the async post_response accrual. Unit: `plugin_test.go`, `config` validation.

## Affected Areas
- `pkg/infra/plugins/tokenratelimit/` (config.go, plugin.go, data.go) — extend in
  place, OR new `pkg/infra/plugins/budget/` package (see Approaches).
- `pkg/app/plugins/catalog_metadata.go` — large schema growth (nested objects,
  arrays, maps for rules/overrides/pricing).
- `pkg/container/modules/plugins.go` — add `PricingResolver` to `pluginParams`
  and pass to the plugin constructor.
- `pkg/infra/providers/adapter/model.go` — wildcard/glob model matching (new) for
  `rules[].model` and `per_model_overrides` keys.
- `tests/functional/` + plugin unit tests + `catalog_test.go`.
- Possibly `pkg/app/plugins` layering note: a plugin in `pkg/infra/plugins`
  importing `pkg/app/catalog` (plugins already import `pkg/app/plugins` and
  `pkg/infra/metrics`, so precedent exists, but confirm with the team).

## Approaches

1. **Extend `token_rate_limiter` in place (same slug)** — add `unit`,
   `per_model`, `counting`, `rules[]`, `aggregate`, `cost_cap`, pricing fields to
   the existing config; keep slug `token_rate_limiter`; make new fields optional
   with back-compat defaults (`unit:tokens`, `per_model:false`, no cost_cap).
   - Pros: one plugin as the issue wants; existing functional wiring, counter,
     Lua script, scope and stream-usage handling reused; existing configs keep
     working if defaults preserve today's behavior; no new catalog slug.
   - Cons: config surface explodes inside one package; `behavior_on_exceeded` /
     downgrade / cost_cap semantics overload a plugin historically about a single
     window; harder to keep files small (AGENT.md favors small files); a single
     `ValidateConfig` becomes complex.
   - Effort: Medium.

2. **New `budget` plugin slug, deprecate/keep `token_rate_limiter`** — new
   `pkg/infra/plugins/budget/` package; copy the Redis counter + usage extraction
   patterns; register a new slug `budget`; leave `token_rate_limiter` as a thin
   alias or untouched for back-compat.
   - Pros: clean separation; freedom to design counter keys (per-model), dollar
     accrual, cost cap without contorting the old plugin; old configs untouched.
   - Cons: code duplication of counter/usage logic; two quota plugins in the
     catalog to explain; "extends token_rate_limiter" intent in the issue is
     looser; migration story for existing token_rate_limiter users.
   - Effort: Medium-High.

3. **Hybrid: shared internal budget package + keep slug** — extract the counter /
   usage / pricing helpers into an internal sub-package reused by the (renamed)
   plugin, register under `token_rate_limiter` (and optionally also `budget`).
   - Pros: small files, testable units, single user-facing slug, room to add a
     `budget` alias later.
   - Cons: most upfront structuring; need to define the internal package boundary.
   - Effort: Medium-High.

## Recommendation
Approach **1 (extend in place)** as the primary, structured per Approach **3**:
keep the `token_rate_limiter` slug for backward compatibility, but split the
growing logic into small files within the package (`config.go`, `costcap.go`,
`budget.go`, `pricing.go`, `keys.go`, `data.go`) to respect the no-large-files /
small-symbol conventions. Reuse `PricingResolver` (inject via `pluginParams`) for
both the dollar budget and the stateless cost cap, and reuse the
`adapter.CanonicalUsage` path for usage. Gate all new behavior behind optional
config so existing single-window token configs are unchanged.

Key design consequences to encode in the proposal:
- **Counter key gains an optional `:model:{model}` segment** when `per_model` /
  `unit:tokens`; dollar mode uses an aggregate (or per-model) cost counter
  (store integer micro-USD to keep the `INCRBY` Lua atomic — Redis counters are
  integers).
- **Cost cap is `pre_request`, stateless**: resolve price via `PricingResolver`
  for `req.Provider` + resolved model, convert per-1k → per-token, compare to the
  ceiling, then reject (403 `model_too_expensive`) or downgrade.
- **Window string form** (`"1h"`, `"1d"`, min 1m) is new vs today's
  `unit:second|minute|hour|day`; the proposal must pick one and keep old configs
  valid.

## Risks
- **Downgrade cannot re-route.** Backend is chosen before `pre_request`
  (`forwarder.go`). A model downgrade only rewrites the outbound model for the
  already-selected backend; cross-provider downgrade (e.g. gpt-5 → claude) will
  not switch backends. Same-provider downgrade (gpt-5→gpt-5-mini, opus→sonnet) is
  the only safe case. Must be scoped/communicated.
- **`Result` cannot mutate the request body, and parallel batches drop `Body`
  changes.** `mergeIsolated` merges only Metadata+Headers. A downgrade that edits
  `req.Body` works only when the plugin runs as a **single-plugin batch**;
  document/guard this, or add a sanctioned body-rewrite channel to `Result`.
- **Post-response counting is lossy by design**: the request that crosses the
  limit still passes; concurrent streams can briefly overshoot (acknowledged in
  the issue). Dollar mode inherits this.
- **No wildcard model matching exists** (`isAllowed` is exact). `claude-opus-*`
  and `per_model_overrides` glob keys need a new matcher.
- **Pricing depends on the catalog DB + models.dev sync.** Unknown models →
  `Pricing{Found:false}`; the `cost_cap.unknown_model` (reject|pass_through|
  assume_max) and dollar-accrual-on-unknown behavior must be defined. Pricing is
  per-token; unit conversion (×1000) and currency (USD only) must be explicit.
- **`scope` config field conflicts** with the framework: scope is derived from
  `Policy.Global`, not config. Either drop `scope` from config or reconcile.
- **Layering**: an infra plugin importing `pkg/app/catalog` — precedent exists
  (plugins import `pkg/app/plugins`) but confirm it's acceptable; alternative is
  injecting the catalog `domain.Repository` directly.
- **Redis cost accrual must stay integer** for the atomic Lua `INCRBY`; floats
  require storing scaled integers (micro-USD).

## Open Questions for the orchestrator
1. **Slug**: extend `token_rate_limiter` in place, or introduce a new `budget`
   slug (with alias/deprecation)? Recommendation: keep slug, split files.
2. **Backward compatibility**: must existing `token_rate_limiter` configs
   (`window{unit,max}` + `group_by_header`) keep working unchanged? (Assume yes.)
3. **Pricing source**: reuse existing `PricingResolver` (catalog DB + models.dev)
   as the single "builtin" table? How do `pricing_table:"custom"` /
   `custom_pricing` overlay on top — per-policy override map merged before lookup?
4. **Counter storage / keying**: confirm per-model key segment and the dollar
   counter as scaled-integer micro-USD in Redis under the same Lua pattern.
5. **Downgrade mechanics**: accept same-provider-only downgrade for v1? Do we add
   a body-rewrite channel to `Result`, or mutate `req.Body` and require the plugin
   to run non-parallel? How is `X-NeuralTrust-Model-Downgraded` emitted on streams?
6. **Window format**: adopt string durations (`"1h"`) with 1-minute floor, or
   keep `unit/max`? Per-rule `time_window` vs single window.
7. **`scope` field**: drop it (use `Policy.Global`) or support an explicit override?
8. **unknown_model & wildcard semantics**: confirm `reject|pass_through|assume_max`
   and that `*` glob matching is in scope (new matcher).
9. **Modes vs `behavior_on_exceeded`/`behavior_on_violation`**: reconcile the
   issue's behavior fields with the framework's `policy.Mode`
   (`enforce|throttle|observe`) — are they the same axis or orthogonal?
10. **Cohere usage**: issue lists Cohere but there is no Cohere adapter format
    registered — is Cohere in scope?

## Ready for Proposal
**Yes** — the architecture is well understood and pricing/usage infrastructure
already exists to build on. Tell the user the heavy lifting (pricing table, usage
normalization, counter pattern) is reusable, but the orchestrator must resolve the
10 open questions above (especially slug strategy, downgrade limits given
pre-routing backend selection, and the `scope`/window/mode reconciliation) before
`sdd-propose`.
