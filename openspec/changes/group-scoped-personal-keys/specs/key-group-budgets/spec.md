# Delta for key-group-budgets

Change `group-scoped-personal-keys` (ENG-2610), slices K6a and K6b (G8). New capability. A directory group's keys are held to a monthly budget on `/store/v1`: the group's total and each member's share, in US dollars of priced cost over the UTC calendar month.

## ADDED Requirements

### Requirement: A budget per gateway and group

A budget MUST be stored per `(gateway_id, group_id)` in `key_group_budgets` (in-code migration `20261022130000_add_key_group_budgets`, deleted with its gateway) with `monthly_limit_usd` (the group's total), `member_monthly_limit_usd` (each member's default), `member_overrides` (by platform user id, replacing the default for that member) and `action` (`alert` | `block`). A null limit MUST mean no limit; a budget MUST set at least one limit or override; every limit MUST be a finite number of dollars, zero or more (zero allows no spend). Anything else MUST answer `ErrInvalidBudget` (422 `validation_failed`).

#### Scenario: A member override replaces the default

- GIVEN a budget with `member_monthly_limit_usd = 1` and `member_overrides = {alice: 5, bob: 0}`
- WHEN the limits of alice, bob and carol are read
- THEN they are 5, 0 and 1

### Requirement: Admin routes

Under `/v1/gateways/{gateway_id}`, with gateway access checked on `auths`:

- `PUT /key-groups/{group_id}/budget` MUST create or replace the whole budget, keep its `created_at`, and answer 200 `{"group_id", "monthly_limit_usd", "member_monthly_limit_usd", "member_overrides", "action", "created_at", "updated_at"}`, an unset limit `null` and no overrides `{}`.
- `DELETE /key-groups/{group_id}/budget` MUST answer 204, or 404 when the group has none.
- `GET /key-groups/budgets` MUST answer 200 `{"items": [...]}` with every budget of the gateway.

PUT and DELETE MUST refuse a service credential (403); GET MUST NOT. A write MUST invalidate the gateway's data on every replica and signal a snapshot recompile.

#### Scenario: Replace keeps the creation time

- GIVEN a budget for `g-eng` created at T
- WHEN it is replaced with only `member_monthly_limit_usd`
- THEN the answer has `monthly_limit_usd: null`, `member_overrides: {}` and `created_at` T

#### Scenario: Service credential

- GIVEN a service credential with `auths` read and write scopes on G
- WHEN it lists, sets and deletes a budget
- THEN the list answers 200 and both writes 403

### Requirement: Every proxy plane holds the group to its budget

The budgets MUST reach every proxy plane: loaded with the gateway's consumer data from Postgres on the full plane and from the config snapshot (`key_group_budgets`) on a DB-less plane, so a request reads no database for them. A budget that cannot be read MUST fail the gateway's data load.

#### Scenario: DB-less plane

- GIVEN a `block` budget whose member limit alice has spent
- WHEN alice's group key calls `/store/v1` on a DB-less proxy
- THEN it answers 429 `budget_exceeded` once the snapshot carries the budget, and 200 once the budget is deleted

### Requirement: Enforcement on `/store/v1`

A `/store/v1` request authenticated with a group key whose group has a budget MUST be held to it, before every admin policy; a personal key with no group, an application key and the MCP Store MUST NOT. Spend MUST be counted in micro-dollars, priced as a `partition: key` dollar budget prices (the model that will be served), on `kgb:<gateway>:<group>:p:<YYYY-MM>` for the group and `kgb:<gateway>:<group>:owner:<owner>:p:<YYYY-MM>` for the member, expiring at the end of the month, a request charged to the month that admitted it. A limit MUST be reached once the spend is at or above it; the group's total MUST be checked first and the first reached applies. Under `block` the request MUST answer 429 with `{"error": {"type": "budget_exceeded", "code": "budget_exceeded", "message", "scope": "group" | "member", "group_id", "window": "calendar_month", "limit_usd", "spent_usd", "resets_at"}}` and the `X-Budget-*` headers, the message naming the group's or the member's limit, and never reach a provider. Under `alert` the request MUST go on and the decision be recorded.

#### Scenario: Member share, then the group's total

- GIVEN a `block` budget of $0.0012 for the group and $0.0005 per member, bob overridden to $0.01, and $0.0008 per request
- WHEN alice calls twice, then bob calls twice
- THEN alice's second call answers 429 with `scope: member`, bob's second with `scope: group`, and the provider is called twice

#### Scenario: Alert

- GIVEN an `alert` budget the group has spent
- WHEN a group key calls `/store/v1`
- THEN the request is served and the stage records `observe`

### Requirement: Failures follow `partition: key`

With the action in place of the policy mode: counters that cannot be read MUST answer 503 `budget_unavailable` with `Retry-After: 5` under `block` and let the request through under `alert`; a charge that cannot be recorded MUST NOT refuse the answer; a model with no price MUST answer 403 `model_unpriced` before any provider call under `block`, and accrue nothing under `alert`. These answers carry `"scope": "key_group"`.

#### Scenario: Redis down

- GIVEN Redis is unreachable
- WHEN a group key with a `block` budget calls, and one with an `alert` budget calls
- THEN the first answers 503 `budget_unavailable` and the second is served

### Requirement: The console hears once per limit and month

The first time a counter reaches its limit in a month, under either action, the proxy MUST post to `CONSOLE_EVENTS_URL`, signed as the personal key events, `{"event": "key_group_budget_reached", "source": "budget", "team_id", "gateway_id", "group_id", "scope", "user_id" (member scope only), "limit_usd", "spent_usd", "period": "YYYY-MM", "action"}`, at most once per gateway, group, scope, member and month across replicas. The post MUST run off the request. A limit already passed when a request reaches the gate (a limit lowered mid-month) MUST be announced then. Without `CONSOLE_EVENTS_URL` limits MUST still be enforced.

#### Scenario: Once

- GIVEN alice's member limit is reached and announced
- WHEN alice keeps calling and is refused
- THEN no second event is sent this month, and one is sent when she reaches it next month
