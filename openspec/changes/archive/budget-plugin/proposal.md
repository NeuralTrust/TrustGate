# Proposal: Budget plugin (token / dollar budget + cost cap) — RUN-696

## Why

Spend control is scattered across three planned plugins: cumulative token
budget (RUN-696), dollar budget (RUN-697), and per-model cost cap (RUN-698).
Operators need **one** place to bound consumption per consumer or per gateway.
This change unifies all three by **extending the existing `token_rate_limiter`
plugin in place** rather than shipping three overlapping plugins.

- Linear: **RUN-696** (this change), absorbs **RUN-697** (dollar budget =
  `unit:dollars`) and **RUN-698** (model cost cap = the `cost_cap` block).

## What changes

- **Token budget**, per-model and/or aggregate, over a time window, using
  actual provider-reported usage (`adapter.CanonicalUsage`).
- **Dollar budget** (`unit:dollars`): accrue cost from usage × price; stored as
  scaled-integer **micro-USD** so the atomic Redis `INCRBY` Lua stays integer.
- **Stateless pre-request cost cap**: reject/downgrade by model **list price**
  vs per-1k-token ceilings, with `per_model_overrides` and `unknown_model`
  policy.
- **Model downgrade** (same-provider only) by rewriting the outbound model in
  `req.Body` during `pre_request`; emits `X-NeuralTrust-Model-Downgraded`.
- **Pricing table**: `builtin` reuses `appcatalog.PricingResolver` (catalog DB
  synced from models.dev); `custom` is a per-policy overlay consulted first.
- **Wildcard model matching** (`claude-opus-*`) for rules, overrides, custom
  pricing; exact beats glob, most-specific wins.
- **Extend-in-place + full back-compat**: keep slug `token_rate_limiter`. All
  new fields optional; existing `{window:{unit,max}, group_by_header}` configs
  map to `unit:tokens`, aggregate, single window, `behavior_on_exceeded:reject`
  and keep working unchanged. Catalog name/description updated to reflect
  token+dollar budget + cost cap.

## Scope

### In scope
- Per-model + aggregate token budgets; dollar budgets; stateless cost cap.
- Same-provider downgrade; wildcard matcher; custom pricing overlay.
- Back-compat for all existing `token_rate_limiter` configs.

### Out of scope (non-goals)
- **Cross-provider downgrade routing** — backend is selected before
  `pre_request`; downgrade only rewrites the model on the already-chosen
  backend. Unknown / cross-provider `downgrade_to` → fall back to reject.
- **Cohere** — no registered adapter format (`adapter.Registry`); follow-up.
- **Sliding windows** — fixed-window Lua only.
- **Currencies other than USD**.
- **A new framework `Result` body-rewrite channel** — downgrade uses the
  existing `req.Body` mutation, which only survives a single-plugin batch.

## Config schema (final)

No `scope` field — scope is derived from `Policy.Global` via
`RuntimeScope.Subject()` (global+gatewayID or consumer+consumerID).

```json
{ "unit":"tokens", "per_model":true, "counting":"total",
  "rules":[{"model":"gpt-5","max":100000,"time_window":"1h"},
           {"model":"claude-opus-*","max":200000,"time_window":"1h"}],
  "aggregate":{"max":100.00,"time_window":"1d"},
  "behavior_on_exceeded":"reject", "downgrade_to":"gpt-5-mini",
  "stream_usage_injection":true, "count_cache_reads":false,
  "cost_cap":{"enabled":true,
    "max_input_cost_per_1k_tokens":0.010,"max_output_cost_per_1k_tokens":0.030,
    "per_model_overrides":{"claude-opus-*":{"max_input_cost_per_1k_tokens":0.020,
      "max_output_cost_per_1k_tokens":0.080}},
    "behavior_on_violation":"reject","downgrade_to":"claude-sonnet-4.6",
    "unknown_model":"reject"},
  "pricing_table":"builtin",
  "custom_pricing":{"gpt-5":{"input":0.000010,"output":0.000030}} }
```

- `time_window` strings (`"1h"`,`"1d"`,`"30m"`; min 1 minute, floored to 60s);
  legacy `window{unit:second|minute|hour|day, max}` still accepted.
- `pricing_table:"custom"` + `custom_pricing` = per-token USD overlay consulted
  before the resolver. Cost-cap ceilings are per-1k tokens → convert via
  `price_per_token × 1000`.
- Counter key extends `trl:{cfgID}:{dim}:{subject}[:hdr:{v}]` with optional
  `:model:{slug}` for per-model/per-rule windows.

## Behavior

Order per request:
1. **pre_request — cost cap** (stateless): resolve price (custom overlay →
   resolver, slug-candidate logic from `metrics/builder.go::pricingSlugs`),
   compare per-1k ceilings. Violation → reject `403
   {error:{type:"model_too_expensive",...}}` or downgrade (rewrite model +
   `X-NeuralTrust-Model-Downgraded: <orig>→<new>`). `unknown_model`:
   `reject | pass_through | assume_max`.
2. **pre_request — budget gate**: read Redis counter for scope (+model);
   exceeded → `429` + `X-Budget-*` headers,
   `{error:{type:"token_budget_exceeded"|"dollar_budget_exceeded",...}}`.
3. **post_response — accrual**: extract usage, `INCRBY` the fixed-window
   counter (tokens, or micro-USD for dollars).

Mode vs behavior (orthogonal axes): `policy.Mode` is the framework gate,
`behavior_on_*` is the action when enforcing. `observe` → never block/downgrade,
record only (overrides behavior field); `throttle` → delay (budget only);
`enforce` → apply behavior field. **observe precedence**: observe forces
non-blocking regardless of `behavior_on_*`.

## Capabilities

### New Capabilities
- None (extends existing plugin behavior; no new openspec capability folder).

### Modified Capabilities
- None at the openspec spec level — this is a plugin config/behavior extension
  documented in spec.md within this change.

## Affected areas

| Area | Impact | Description |
|------|--------|-------------|
| `pkg/infra/plugins/tokenratelimit/` | Modified | Split into small files: config, plugin orchestration, budget counter, cost cap, pricing overlay, key building, glob matcher, trace data. |
| `pkg/app/plugins/catalog_metadata.go` | Modified | Grow `SettingsSchema` (nested objects/arrays/maps) + name/description. |
| `pkg/container/modules/plugins.go` | Modified | Inject `appcatalog.PricingResolver` into `pluginParams`, pass to `tokenratelimit.New`. |
| `tests/functional/`, plugin unit tests, `catalog_test.go` | New/Modified | Coverage for budgets, cost cap, downgrade, back-compat. |

Layering note: an infra plugin importing `pkg/app/catalog` is acceptable
(plugins already import `pkg/app/plugins` and `pkg/infra/metrics`; the metrics
builder imports `app/catalog`).

## Risks & mitigations

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Downgrade cannot re-route (backend chosen before `pre_request`). | High | Same-provider only; unknown/cross-provider `downgrade_to` → fall back to reject. Documented constraint. |
| Body rewrite dropped by `mergeIsolated` (Headers+Metadata only) in parallel batches. | Med | Default single-plugin batch preserves the rewrite; document that operators must not group this plugin in a parallel `pre_request` batch when downgrade is enabled. |
| Post-response accrual is lossy (the crossing request still passes; concurrent streams overshoot). | Med | Accepted by design (matches RUN-696); fixed-window semantics documented. |
| Integer dollar scaling. | Low | Store micro-USD (`round(cost_usd×1e6)`); scale the dollar max identically for comparison. |
| Pricing depends on catalog DB + models.dev sync. | Med | `unknown_model` policy for cost cap; dollar mode accrues 0 + warns on unpriced model. |

## Rollback plan

Additive and config-gated. Existing configs are unaffected (defaults preserve
today's behavior). Rollback = remove the new optional config fields / new files
and revert the catalog metadata and `pluginParams` injection; the original
single-window token limiter remains intact.

## Delivery note

This is a **large** change and will exceed the 400-line reviewer budget. It must
ship as **chained PRs** (e.g. config+back-compat → per-model token budget →
dollar budget → cost cap+pricing → downgrade → catalog schema → functional
tests). The `sdd-tasks` phase will forecast the split.

## Success criteria

- [ ] Existing `token_rate_limiter` configs pass unchanged (back-compat tests).
- [ ] Per-model + aggregate token budgets enforce and accrue correctly.
- [ ] Dollar budget accrues via micro-USD and enforces the scaled max.
- [ ] Cost cap rejects/downgrades by per-1k ceiling with overrides + wildcards.
- [ ] Same-provider downgrade rewrites model and emits the header; unknown/
      cross-provider falls back to reject.
- [ ] `observe` mode never blocks; `enforce` applies `behavior_on_*`.
