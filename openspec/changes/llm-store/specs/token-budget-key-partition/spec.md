# Delta for token-budget-key-partition

Change `llm-store` (RUN-1763), slice S2 (decision D9). New capability. `token_rate_limiter` (`pkg/infra/plugins/tokenratelimit`) gains a per-key budget: `partition: key`, with UTC calendar windows and hard limits. For a personal key the counter is keyed by its owner, so neither a rotation, a revoke-and-re-create nor the consumer selected for a request resets it. Today the plugin partitions only by `global` or `consumer`, windows are TTL-from-first-write, and a Redis error always fails open through `appplugins.HandleCounterFailure`. Everything below applies only under `partition: key`; a config without `partition` MUST behave byte-for-byte as today.

## ADDED Requirements

### Requirement: `partition` field and the default

The plugin config MUST accept an optional `partition` field whose only value is `key`. Absent, the plugin MUST behave exactly as today: same Redis keys, same subject (`global` or `consumer`), same fail-open, same unpriced handling. Any other value MUST make policy create and update fail with 422.

#### Scenario: Default unchanged

- GIVEN a `token_rate_limiter` config without `partition`, attached to consumer X
- WHEN a request on X spends tokens
- THEN the Redis keys written are the same as before the change (`trl:<cfg>:consumer:<X id>…`), and the existing plugin tests pass unchanged

#### Scenario: A request that names no model

- GIVEN a `partition`-less policy with `rules: [{model: gpt-4o-mini, max: 100, time_window: 1h}]` and a route whose default model is `gpt-4o-mini`
- WHEN a request with no model, `auto` or `pool:<alias>` is served
- THEN it is counted under the model it names, as before, and matches no rule; only a `partition: key` policy counts it against the routed default model

#### Scenario: Unknown partition

- GIVEN a policy with `partition: owner`
- WHEN it is created
- THEN 422, and nothing is stored

### Requirement: The counter subject is the owner, else the auth

`RuntimeScope` and `RequestContext` MUST gain `AuthID` and `OwnerID`, injected by the proxy handler from `authCtx` where it builds `reqCtx`. Under `partition: key` the counter subject MUST be `owner:<owner_id>` when the auth has an owner, and `auth:<auth_id>` otherwise. Keys MUST have the form `trl:<cfg>:key:<subject>[:p:<period>][:model:<slug>]`. The two prefixes MUST keep owner and auth counters apart.

#### Scenario: Two owners, two counters

- GIVEN a global `partition: key` policy and personal keys of `alice` and `bob`
- WHEN each spends 100 tokens on `/store/v1/chat/completions`
- THEN two counters exist, `trl:<cfg>:key:owner:alice…` and `trl:<cfg>:key:owner:bob…`, each at 100

#### Scenario: One owner across consumers

- GIVEN a global `partition: key` policy with a 1000-token budget and `alice`'s key linked to P1 and P2
- WHEN she spends 600 tokens on a request P1 serves and then sends a 500-token request that P2 serves
- THEN both requests count against `trl:<cfg>:key:owner:alice…`, and a further request answers 429

#### Scenario: Application key

- GIVEN a `partition: key` policy attached to application consumer X with application key A
- WHEN A spends 100 tokens on `/<X slug>/v1/chat/completions`
- THEN the counter `trl:<cfg>:key:auth:<A id>…` is at 100

#### Scenario: Rotation keeps the budget

- GIVEN `alice` has spent her whole 1000-token budget
- WHEN her key is rotated and she sends a request with the new secret
- THEN 429

#### Scenario: Revoke and re-create keeps the budget

- GIVEN `alice` has spent her whole 1000-token `calendar_month` budget
- WHEN she revokes her key, creates a new one (new auth id) and sends a request with it in the same month
- THEN 429, because both keys count against `owner:alice`

### Requirement: Requests without an auth pass through uncounted

Under `partition: key`, a request with neither an auth id nor an owner id (the playground, and every request that no API key authenticated: OAuth2, OIDC, mTLS) MUST pass through the plugin without reading or writing Redis, and MUST NOT be rejected by it. Only an API key stamps the auth id and the owner.

#### Scenario: Playground request

- GIVEN a `partition: key` policy with `max: 1` and a playground request with an empty auth id
- WHEN ten such requests are sent
- THEN all ten reach the upstream and no `trl:<cfg>:key:*` key exists in Redis

### Requirement: Calendar windows

`time_window` (in `rules[]` and in `aggregate`) MUST accept `calendar_month` and `calendar_day` in addition to today's `<n>s|m|h|d`. Calendar windows MUST be UTC. The period MUST be part of the key (`p:2006-01` for a month, `p:2006-01-02` for a day), and the key TTL MUST run to the end of the period, with the floor `quotaTTL` (`pkg/infra/ratelimit/store.go`) already applies. Calendar windows MUST be valid only with `partition: key`; using one without it MUST fail validation with 422. `partition: key` with a rolling window (for example `24h`) MUST stay valid.

#### Scenario: Month rollover

- GIVEN a `calendar_month` budget of 1000 tokens, a clock at `2026-10-31T23:59:00Z` and `alice` at 1000 tokens spent
- WHEN she sends a request, and the clock then moves to `2026-11-01T00:00:00Z` and she sends another
- THEN the first gets 429 and the second reaches the upstream, counted under `p:2026-11`

#### Scenario: A stream that crosses the period end

- GIVEN a `calendar_month` budget and a request admitted at `2026-10-31T23:59:58Z` whose response ends at `2026-11-01T00:00:05Z`
- WHEN its usage accrues
- THEN it is charged to `p:2026-10`, the period that admitted it (the request's arrival time, stamped once by the proxy handler), with that counter's TTL floored at 60 s, and `p:2026-11` is untouched

#### Scenario: Day key and TTL

- GIVEN a `calendar_day` budget and a clock at `2026-10-02T18:00:00Z`
- WHEN `alice` spends tokens
- THEN the key contains `p:2026-10-02` and its TTL is at most 6 hours

#### Scenario: Calendar window without partition

- GIVEN a config with `time_window: calendar_month` and no `partition`
- WHEN the policy is created
- THEN 422

#### Scenario: Rolling window with partition

- GIVEN a config with `partition: key` and `time_window: 24h`
- WHEN the policy is created
- THEN 2xx

### Requirement: Config combinations refused under `partition: key`

`custom_pricing`, `group_by_header` or `behavior_on_exceeded: downgrade_model` together with `partition: key` MUST fail validation with 422: a hard limit never serves past the budget on another model.

#### Scenario: Custom pricing

- GIVEN a config with `partition: key` and a `custom_pricing` entry
- WHEN the policy is created
- THEN 422

#### Scenario: Downgrade instead of refusing

- GIVEN a config with `partition: key`, `behavior_on_exceeded: downgrade_model` and `downgrade_to: gpt-4o-mini`
- WHEN the policy is created
- THEN 422

#### Scenario: Group by header

- GIVEN a config with `partition: key` and `group_by_header: X-Team`
- WHEN the policy is created
- THEN 422

### Requirement: Hard limits under `partition: key` in blocking modes

Under `partition: key`, and only when the policy mode blocks (`appplugins.Blocks(mode)`):

1. A Redis error while reading the budget in `budgetGate` MUST reject the request with **503** and `error.type = budget_unavailable`, as an `*appplugins.PluginError`, through a branch local to `budgetGate`. `appplugins.HandleCounterFailure` MUST NOT change, and every other partition and every other counter plugin MUST keep failing open. A Redis error while accruing after the response MUST be logged and MUST NOT change the response already sent.
2. With `unit: dollars`, a request that a budget window applies to (a matching rule or the aggregate), for a model that `llmcost.Resolve` cannot price (catalog and registry rates), MUST be rejected in `budgetGate` with **403** and `error.type = model_unpriced`, before Redis is read and before the upstream is called. A request no window applies to (a rules-only budget without a matching rule, a `cost_cap`-only config) MUST NOT be checked, so `cost_cap.unknown_model` keeps deciding it. The model priced MUST be the one that will be served: when the request names no model (none, `auto`, `pool:<alias>`), the selected route's default model, so such a request is served and charged. With `unit: tokens` no pricing check applies. Without `partition: key`, an unpriced model MUST keep accruing $0 with a warning, as `TestPlugin_DollarBudget_UnpricedModelAccruesZero` pins today.
3. Exceeding the budget MUST return the existing 429 (`token_budget_exceeded` or `dollar_budget_exceeded`) with `error.scope = key`.

In a non-blocking mode the plugin MUST NOT return 503 or 403: it records the decision on the event and lets the request through.

#### Scenario: Redis down

- GIVEN a blocking `partition: key` policy and Redis unreachable
- WHEN `alice` sends a request on `/store/v1/chat/completions`
- THEN 503 `budget_unavailable`, and the upstream is not called
- AND the same outage under a `partition`-less policy on consumer X lets X's request through, as today

#### Scenario: Observe mode never blocks

- GIVEN a `partition: key`, `unit: dollars` policy in observe mode, Redis unreachable, and an unpriced model
- WHEN `alice` requests that model
- THEN the request reaches the upstream, and the event records the decision

#### Scenario: Unpriced model on a dollar budget

- GIVEN a blocking `partition: key`, `unit: dollars` policy and a model with no catalog or registry price
- WHEN `alice` requests that model
- THEN 403 `model_unpriced`, and the upstream is not called

#### Scenario: No budget window applies

- GIVEN a blocking `partition: key`, `unit: dollars` policy whose only rule is `claude-*`
- WHEN `alice` requests an unpriced `gpt-4o-mini`
- THEN the request reaches the upstream, unchecked and uncounted

#### Scenario: Registry rate counts as priced

- GIVEN the same policy and a model priced only by its registry's rates
- WHEN `alice` requests it
- THEN the request reaches the upstream and its cost accrues

#### Scenario: Over budget

- GIVEN `alice` over her `calendar_month` token budget
- WHEN she sends a request
- THEN 429 with `error.type = token_budget_exceeded` and `error.scope = key`

### Requirement: Catalog metadata and docs describe the key partition

The plugin catalog metadata (`pkg/app/plugins/catalog_metadata.go`) and `docs/policies.json` MUST list `partition` (value `key`) and the `calendar_month` / `calendar_day` windows, and MUST state that under `partition: key` the counter is per owner (else per key), the plugin fails closed (503) in blocking modes, rejects unpriced models on dollar budgets (403 `model_unpriced`), refuses `custom_pricing` and `group_by_header`, and lets requests without an auth through uncounted. The existing fail-open sentence MUST stay true for the default partition.

#### Scenario: Catalog lists the field

- GIVEN the catalog entry for `token_rate_limiter`
- WHEN its config schema is read in `pkg/app/plugins/catalog_test.go`
- THEN `partition` is present with the single value `key`, and both calendar windows are documented
