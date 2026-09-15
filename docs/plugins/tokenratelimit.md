# `tokenratelimit` — Token / Cost Budgets

Catalog slug: `token_rate_limiter`

Caps LLM spend with token or dollar budgets over time windows, either as one
aggregate counter, per-model `rules`, a stateless per-request `cost_cap`, or
the legacy `window` block.

Source:

- `pkg/infra/plugins/tokenratelimit/config.go`
- `pkg/infra/plugins/tokenratelimit/plugin.go`
- `pkg/infra/plugins/tokenratelimit/responses.go`
- `pkg/infra/plugins/llmcost/costcap.go` (`cost_cap` shape)
- `pkg/infra/plugins/llmcost/pricing.go` (`custom_pricing` shape)
- `docs/policies.json` (`Quota` → `token_rate_limiter`)

Stages: `pre_request` + `post_response` (both mandatory).
Protocols: `LLM` only.
Modes: `enforce`, `observe`.

## Configuration fields

| Field | Type | Required | Default | Effect |
|---|---|---|---|---|
| `unit` | enum `tokens` \| `dollars` | no | `tokens` | Whether budgets count provider tokens or USD cost. Dollar budgets cannot use the legacy `window` block. |
| `per_model` | boolean | no | `false` (auto-`true` when `rules` is non-empty) | Key budgets per model. Requires `rules` or a legacy `window`. |
| `counting` | enum `total` \| `input` \| `output` | no | `total` | Which usage figure accrues against the budget. |
| `rules` | array of `{model, max, time_window}` | no* | — | Per-model budgets. `model` (string, required) is a slug or wildcard (e.g. `gpt-4o`, `claude-opus-*`); `max` (number, required, `> 0`; whole number when `unit: tokens`); `time_window` (string like `30m`, `1h`, `1d`; required unless a legacy `window` is set; values `< 60s` are clamped to `60s`). |
| `aggregate` | object `{max, time_window}` | no* | synthesized from legacy `window` when set and `aggregate` is nil | Single catch-all counter. Same `max` / `time_window` semantics as a rule. |
| `behavior_on_exceeded` | enum `reject` \| `downgrade_model` | no | `reject` | Action in `enforce` mode when a budget is exceeded. `downgrade_model` requires `downgrade_to`. |
| `downgrade_to` | string | only with `downgrade_model` | — | Target model for budget downgrades. Must be on the same provider. |
| `count_cache_reads` | boolean | no | `false` | Include Anthropic cache-read input tokens in counted/costed usage. |
| `cost_cap` | object (see below) | no* | — | Stateless per-request price ceiling evaluated at `pre_request`. |
| `custom_pricing` | map `model-pattern → {input, output[, cache_read, cache_write, cache_write_1h]}` | no | — | Per-token USD rates (e.g. `{"gpt-4o": {"input": 0.001, "output": 0.002}}`) consulted before registry pricing and the models.dev catalog. Used for dollar budgets. |
| `window` | legacy object `{unit, max}` | no* | — | Back-compat shorthand. `unit` must be `second` \| `minute` \| `hour` \| `day`; `max` is the token cap. Synthesized into `aggregate` (stays a catch-all alongside `rules`). |
| `group_by_header` | string | no | `""` | Optional header (e.g. `X-User-Id`) that sub-partitions the budget inside the policy scope; otherwise per gateway (global) or per consumer. |

\* At least one of `window`, `rules`, `aggregate`, or an enabled `cost_cap`
must be set.

`cost_cap` (`llmcost.CapConfig`) fields:

| Field | Type | Required | Default | Effect |
|---|---|---|---|---|
| `enabled` | boolean | no | `false` | Gates the whole cost-cap check. |
| `max_input_cost_per_1k_tokens` | number `>= 0` | no | `0` (no ceiling) | Per-1k-token USD input ceiling. |
| `max_output_cost_per_1k_tokens` | number `>= 0` | no | `0` (no ceiling) | Per-1k-token USD output ceiling. |
| `per_model_overrides` | map `pattern → {max_input_cost_per_1k_tokens, max_output_cost_per_1k_tokens}` | no | — | Most-specific pattern wins (exact over wildcard). |
| `behavior_on_violation` | enum `reject` \| `downgrade` | no | `reject` | `downgrade` requires `downgrade_to`. |
| `downgrade_to` | string | only with `downgrade` | — | Cheaper same-provider fallback model. |
| `unknown_model` | enum `reject` \| `pass_through` \| `assume_max` | no | `reject` (fail-closed) | Policy when the model price cannot be resolved. |

Scope: global policies share one budget across the gateway; consumer policies
give each consumer an independent budget.

## Example JSON

Aggregate token budget (1000 tokens/hour):

```json
{
  "unit": "tokens",
  "counting": "total",
  "aggregate": {
    "max": 1000,
    "time_window": "1h"
  }
}
```

Per-model token rules with a downgrade fallback:

```json
{
  "unit": "tokens",
  "counting": "total",
  "per_model": true,
  "rules": [
    { "model": "gpt-4o", "max": 10000, "time_window": "1h" },
    { "model": "gpt-4o-mini", "max": 50000, "time_window": "1h" }
  ],
  "behavior_on_exceeded": "downgrade_model",
  "downgrade_to": "gpt-4o-mini"
}
```

Stateless dollar cost cap with custom pricing:

```json
{
  "unit": "dollars",
  "custom_pricing": {
    "gpt-4o": { "input": 0.001, "output": 0.002 },
    "gpt-4o-mini": { "input": 0.0001, "output": 0.0001 }
  },
  "cost_cap": {
    "enabled": true,
    "max_input_cost_per_1k_tokens": 0.5,
    "max_output_cost_per_1k_tokens": 0.5,
    "behavior_on_violation": "reject",
    "unknown_model": "pass_through"
  }
}
```

Legacy window shorthand (1000 tokens/hour):

```json
{
  "window": { "unit": "hour", "max": 1000 },
  "group_by_header": "X-User-Id"
}
```

Full policy object (Admin API):

```json
{
  "name": "llm-budget",
  "slug": "token_rate_limiter",
  "enabled": true,
  "priority": 10,
  "parallel": false,
  "stages": ["pre_request", "post_response"],
  "settings": {
    "unit": "tokens",
    "counting": "total",
    "aggregate": { "max": 1000, "time_window": "1h" }
  }
}
```

## Behavior

- `pre_request` checks the budget/cost cap before upstream; `post_response`
  accrues actual usage. Requests without a provider short-circuit to `200`
  without charging.
- Budget exceeded in `enforce` mode: `429` with
  `type: token_budget_exceeded` (tokens) or `dollar_budget_exceeded`
  (dollars) plus `X-Budget-Unit/Scope/Window/Limit-Usd/Remaining-Usd/Reset`
  headers. Cost-cap violation: `403 model_too_expensive`, or a transparent
  rewrite to `downgrade_to` (`X-NeuralTrust-Model-Downgraded`) when
  downgrade behavior is configured.
- `observe` mode never rejects; it records the decision for telemetry.
- Fail-closed: invalid config returns an error; unknown-model prices default
  to `reject` unless `unknown_model: pass_through`; Redis/budget errors do
  not silently bypass the gate. See the gateway-plane vs middleware
  discussion in [#519](https://github.com/NeuralTrust/TrustGate/issues/519).
