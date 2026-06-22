# Delta for Budget (token_rate_limiter plugin)

This change extends the existing `token_rate_limiter` plugin in place. The slug
stays `token_rate_limiter`. All new fields are optional; absent fields preserve
today's behavior. Scope is always derived from `Policy.Global` (never config).
Cohere is out of scope.

## ADDED Requirements

### Requirement: Backward compatibility with legacy config

The plugin MUST treat a legacy config of the form
`{window:{unit,max}, group_by_header}` exactly as it behaves today: an aggregate
token budget over a single fixed window that rejects (429) when exceeded under
`enforce`. New fields (`unit`, `per_model`, `rules`, `aggregate`, `cost_cap`,
`pricing_table`, `custom_pricing`, etc.) MUST default such that their absence
is indistinguishable from the pre-change plugin.

#### Scenario: Legacy aggregate window still enforces
- GIVEN a config `{window:{unit:"hour",max:1000}, group_by_header:"X-User"}` and mode `enforce`
- WHEN cumulative tokens for the scope+header value reach 1000 within the window
- THEN the next pre-request MUST be rejected with 429
- AND no per-model or dollar logic is engaged

#### Scenario: Legacy config requires no new fields
- GIVEN a legacy config with only `window` and `group_by_header`
- WHEN `ValidateConfig` runs
- THEN it MUST pass, defaulting `unit:tokens`, aggregate scope, `behavior_on_exceeded:reject`

### Requirement: Aggregate token budget

When `unit:tokens` and not per-model, the plugin MUST accrue total provider-
reported usage into one fixed-window counter for the scope, reject (429) pre-
request when the counter is at or over `max`, and emit `X-Ratelimit-*-Tokens`
headers. Accrual is post-response and lossy: the request that crosses the limit
still passes; the next request is rejected.

#### Scenario: Reject when over and headers present
- GIVEN an aggregate token budget at/over `max` for the scope
- WHEN a new request reaches the budget gate under `enforce`
- THEN it MUST be rejected 429 with `error.type:"token_budget_exceeded"`
- AND `X-Ratelimit-Limit-Tokens`, `X-Ratelimit-Remaining-Tokens`, `X-Ratelimit-Reset-Tokens` MUST be set

#### Scenario: Crossing request passes, next is blocked
- GIVEN the counter is below `max` but a single response will push it over
- WHEN that request completes and usage is accrued post-response
- THEN that request MUST have been allowed
- AND the subsequent request MUST be rejected 429

### Requirement: Per-model token budget

When `per_model:true` with `rules[]`, each rule `{model, max, time_window}` MUST
key a separate counter whose key includes a `:model:{slug}` segment. Wildcard
model patterns (e.g. `claude-opus-*`) MUST match by most-specific-wins with an
exact match preferred over any glob. `counting` MUST select which usage field
accrues: `input`, `output`, or `total`.

#### Scenario: Per-model counter isolation
- GIVEN rules for `gpt-5` (max 100000/1h) and `claude-opus-*` (max 200000/1h)
- WHEN traffic flows to both models
- THEN each MUST accrue into its own `:model:{slug}` counter independently

#### Scenario: Exact beats glob, most-specific wins
- GIVEN rules `claude-opus-*` and `claude-opus-4` and request model `claude-opus-4`
- WHEN selecting the governing rule
- THEN the exact `claude-opus-4` rule MUST be chosen over the glob

#### Scenario: Counting field selection
- GIVEN a rule with `counting:"output"`
- WHEN usage is `{input:500, output:300}`
- THEN the counter MUST increment by 300 only

### Requirement: Dollar budget

When `unit:dollars`, cost MUST be computed as
`input_tokens*input_rate + output_tokens*output_rate`, stored as a scaled
integer in micro-USD so the atomic Redis `INCRBY` stays integer. Dollar budgets
MAY be aggregate or per-model. Over-budget MUST reject 429 with
`error.type:"dollar_budget_exceeded"`. An unknown/unpriced model MUST accrue 0
and emit a warning.

#### Scenario: Cost accrual in micro-USD
- GIVEN rates input $0.000010/tok, output $0.000030/tok and usage `{input:1000, output:500}`
- WHEN the response is accrued
- THEN the counter MUST increase by `round((1000*0.000010 + 500*0.000030)*1e6)` micro-USD

#### Scenario: Over dollar budget rejects
- GIVEN a dollar counter at/over the scaled `max`
- WHEN a new request reaches the budget gate under `enforce`
- THEN it MUST be rejected 429 with `error.type:"dollar_budget_exceeded"`

#### Scenario: Unpriced model accrues zero
- GIVEN a model with no resolvable price
- WHEN its response is accrued in dollar mode
- THEN the counter MUST increase by 0 AND a warning MUST be emitted

### Requirement: Stateless cost cap

When `cost_cap.enabled`, the plugin MUST, BEFORE the budget gate and statelessly
at pre-request, compare the model's list price (per-1k tokens) against
`max_input_cost_per_1k_tokens` / `max_output_cost_per_1k_tokens` (global or the
matching `per_model_overrides` entry). A violation MUST trigger
`behavior_on_violation`: reject 403 `error.type:"model_too_expensive"` (carrying
`input_price`, `output_price`, `max_input`, `max_output`) or downgrade. The
`unknown_model` policy MUST be one of `reject | pass_through | assume_max`.

#### Scenario: Reject over-priced model
- GIVEN a model whose input price per-1k exceeds `max_input_cost_per_1k_tokens` and `behavior_on_violation:reject`
- WHEN the request hits the cost cap pre-request
- THEN it MUST be rejected 403 `model_too_expensive` with the four price fields

#### Scenario: Per-model override applies
- GIVEN `per_model_overrides:{"claude-opus-*":{...higher ceilings...}}`
- WHEN an `claude-opus-4` request is checked
- THEN the override ceilings MUST be used instead of the global ceilings

#### Scenario: Unknown model policy
- GIVEN `unknown_model:"assume_max"` and an unpriced model
- WHEN the cost cap evaluates it
- THEN it MUST be treated as exceeding the ceiling (violation path)
- AND with `pass_through` it MUST be allowed, with `reject` it MUST be rejected 403

#### Scenario: Cost cap runs before budget gate
- GIVEN both cost cap and a budget are configured
- WHEN a request is processed
- THEN the cost cap MUST be evaluated before the budget counter is read

### Requirement: Same-provider model downgrade

When `behavior_on_exceeded:"downgrade_model"` or
`cost_cap.behavior_on_violation:"downgrade"`, the plugin MUST rewrite the
outbound model to `downgrade_to` on the already-selected backend (same provider
only) and emit `X-NeuralTrust-Model-Downgraded: <orig>→<new>`. If `downgrade_to`
implies a different provider or is unknown, the plugin MUST fall back to reject.

#### Scenario: Successful same-provider downgrade
- GIVEN `gpt-5` violates and `downgrade_to:"gpt-5-mini"` (same provider)
- WHEN the request is processed pre-request
- THEN the outbound model MUST be rewritten to `gpt-5-mini`
- AND `X-NeuralTrust-Model-Downgraded: gpt-5→gpt-5-mini` MUST be emitted

#### Scenario: Cross-provider downgrade falls back to reject
- GIVEN a violation and `downgrade_to` resolves to a different provider or is unknown
- WHEN the downgrade is attempted
- THEN the plugin MUST NOT rewrite the model AND MUST reject instead

### Requirement: Pricing table

Pricing MUST be sourced from either `builtin` (catalog / models.dev via
`PricingResolver`) or `custom`. When a per-policy `custom_pricing` overlay is
present, it MUST be consulted first (per-token USD rates), then the resolver.
The same resolved price MUST serve both the dollar budget and the cost cap.

#### Scenario: Custom overlay wins over builtin
- GIVEN `pricing_table:"custom"` with `custom_pricing.gpt-5` and a builtin price for `gpt-5`
- WHEN a `gpt-5` price is resolved
- THEN the `custom_pricing` rates MUST be used

#### Scenario: Builtin fallback
- GIVEN no `custom_pricing` entry for a model
- WHEN its price is resolved
- THEN the `PricingResolver` (catalog/models.dev) value MUST be used

### Requirement: Mode reconciliation

`policy.Mode` and `behavior_on_*` are orthogonal axes. `observe` MUST record only
and never block or downgrade, overriding any `behavior_on_*`. `throttle` MUST
delay (budget only). `enforce` MUST apply the configured behavior field.

#### Scenario: Observe forces non-blocking
- GIVEN mode `observe` and `behavior_on_exceeded:"reject"` with an exceeded budget
- WHEN a request is processed
- THEN it MUST NOT be rejected or downgraded; the event MUST still record the breach

#### Scenario: Enforce applies behavior
- GIVEN mode `enforce` and an exceeded budget with `behavior_on_exceeded:"reject"`
- WHEN a request is processed
- THEN it MUST be rejected 429

### Requirement: Scope derivation

Scope MUST be derived from `Policy.Global`: global policies key by gateway,
otherwise by consumer. There MUST be no config `scope` field; any such field
MUST be ignored/rejected per validation.

#### Scenario: Global vs consumer keying
- GIVEN a global policy
- WHEN a counter key is built
- THEN it MUST use the gateway subject; a non-global policy MUST use the consumer subject

### Requirement: Window parsing

The plugin MUST accept string durations (`"1h"`, `"30m"`, `"1d"`) for
`time_window`, applying a 1-minute floor (anything below 60s is raised to 60s).
The legacy `window.unit` enum (`second|minute|hour|day`) MUST remain valid.

#### Scenario: String duration with floor
- GIVEN `time_window:"30s"`
- WHEN it is parsed
- THEN the effective window MUST be 60s

#### Scenario: Legacy unit still parses
- GIVEN `window:{unit:"day",max:N}`
- WHEN parsed
- THEN it MUST yield a 1-day window

### Requirement: Usage injection and cache-read flags

`stream_usage_injection:true` MUST cause usage to be obtained/injected for
streaming responses so accrual works on streams. `count_cache_reads` (Anthropic)
MUST control whether cache-read input tokens are included in counted/costed
usage: when false they MUST be excluded, when true included.

#### Scenario: Stream usage injection enables streaming accrual
- GIVEN a streaming response and `stream_usage_injection:true`
- WHEN the stream completes
- THEN provider usage MUST be available for post-response accrual

#### Scenario: Cache reads excluded by default
- GIVEN an Anthropic response with cache-read tokens and `count_cache_reads:false`
- WHEN usage is counted/costed
- THEN cache-read input tokens MUST be excluded

### Requirement: Configuration validation

`ValidateConfig` MUST reject invalid configurations, including: `unit` not in
`{tokens,dollars}`; `per_model:true` with no `rules` and no legacy `window`;
`unit:dollars` with no usable pricing source; any `downgrade_*` behavior without
`downgrade_to`; negative or zero `max`; and malformed `time_window`.

#### Scenario: Invalid unit rejected
- GIVEN `unit:"credits"`
- WHEN `ValidateConfig` runs
- THEN it MUST fail

#### Scenario: Per-model without rules rejected
- GIVEN `per_model:true`, no `rules`, and no legacy `window`
- WHEN `ValidateConfig` runs
- THEN it MUST fail

#### Scenario: Dollars without pricing rejected
- GIVEN `unit:"dollars"` with neither builtin pricing nor `custom_pricing` usable
- WHEN `ValidateConfig` runs
- THEN it MUST fail

#### Scenario: Downgrade without target rejected
- GIVEN a `downgrade_*` behavior and no `downgrade_to`
- WHEN `ValidateConfig` runs
- THEN it MUST fail

#### Scenario: Non-positive max and bad window rejected
- GIVEN `max <= 0` or a malformed `time_window`
- WHEN `ValidateConfig` runs
- THEN it MUST fail
