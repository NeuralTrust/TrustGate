# Design: Group-scoped personal keys for cost attribution (ENG-2610)

## Linked artifacts

- Linear: [ENG-2610](https://linear.app/neuraltrust/issue/ENG-2610/group-scoped-personal-api-keys-for-cost-attribution).
- Proposal (binding): [`proposal.md`](./proposal.md), G1–G8, D1–D11.
- Builds on: [`llm-store`](../llm-store/design.md) (personal keys, personal consumers, links, `partition: key`).
- User documentation: `docs/llm-store.md` (Group keys, Group budgets), `docs/telemetry/otlp-metadata-contract.md`.
- Base: `develop` @ `e8cbaba5`. Conventions: `.agents/AGENTS.md` (hexagonal layers, DI in `pkg/container/modules`, one DTO per file, mockery mocks).

## Technical approach

A group key is an ordinary personal key with two more columns. Everything that keys on the owner keeps working; what changes is where the code needs to tell one of an owner's keys from another:

1. **Storage and lookup.** `auths.group_id` / `group_name`; the owner index includes the group. The repository finds a key by (gateway, owner, group) and lists an owner's keys. The snapshot read model indexes owned keys the same way, so DB-less planes answer the same lookups.
2. **Lifecycle.** The admin create takes the group; self routes by id manage any key of the caller; the personal-key routes and the `PersonalKeys` gRPC service keep meaning "the key with no group".
3. **MCP reach.** The proxy's auth chain builds a personal key's principal; for a group key it adds a `key_group` claim. Two principal methods, `StoreSubject()` and `StoreGroups()`, are what the Store decides access for, and every Store component reads them instead of `Subject` / `Groups`.
4. **Telemetry.** The proxy stamps the key's kind and group next to its id; events and OTLP carry them.
5. **Budgets.** A `key_group_budgets` table, an admin use case and routes, distribution with the gateway's consumer data, and a `key_group_budget` stage that the forwarder joins to a group key's store requests.

## Decisions

| # | Decision | Rejected | Rationale |
|---|---|---|---|
| DD1 | `KeyGroup{ID, Name}` value type with `NormalizeKeyGroup` (trim; name needs id, id needs name; ≤ 256 each). | Two loose strings | One place validates the pair. |
| DD2 | `Repository.FindByOwner` is replaced by `FindByOwnerAndGroup(gw, owner, group)` (`""` = personal key) and `ListByOwner(gw, owner)` (newest first). | Keep `FindByOwner` returning "the" key | It would be ambiguous once an owner has several. |
| DD3 | `UpdateOwner` writes `group_name` only when the row has a `group_id` (`CASE WHEN group_id IS NULL …`); the domain refuses a name for a personal key (`ErrPersonalKey` → 422 `personal_key`). | Let the SQL write it anyway | A personal key must never gain a name without an id. |
| DD4 | Expiry: `NewOwnedAPIKeyAuth(…, expiresAt *time.Time)`; `ExpiryChange{At *time.Time}` with nil receiver = keep, `At == nil` = clear. `PersonalKeyIssuerLifetime` keeps the Store page at 90 days. | A sentinel time for "never" | `nil` already means "no expiry" everywhere else on an auth. |
| DD5 | `Principal.KeyGroup()` reads the `key_group` claim only when `Method == MethodPersonalKey`. | Read it on any principal | An OIDC or session token could otherwise claim a group. |
| DD6 | Group-scoped MCP policies see `OwnerGroups ∪ {GroupName}`; the Store sees `{GroupName}`. | One group set for both | Narrowing the Store reach must not narrow security policies. |
| DD7 | `InstallRequest.GroupScoped` and the configure ticket's `group_scoped` make the installer match grants on the group only, while the install itself stays the owner's. | A synthetic group subject | Installs and vault accounts are per person. |
| DD8 | `trace.Metadata.AuthKind` / `AuthGroupID`, set by `SetAuthKey(kind, groupID)` from the proxy's `AuthContext` (`KeyGroupID` copied from the key in `serveStore`). | Derive at export time | The event builder has no key at hand. |
| DD9 | Budgets ride `consumer.Data` (`SetKeyGroupBudgets`, `KeyGroupBudget(groupID)`), loaded by the data finder through a `keygroup.Reader` option: Postgres on the full plane, the snapshot adapter on DB-less planes. | A per-request read | The store path makes no database call today. |
| DD10 | `key_group_budget` is a `appplugins.Plugin` in `pkg/infra/plugins/tokenratelimit` (it shares the package's counters, pricing, usage decoding and response helpers) that no registry holds. `appproxy.WithGroupBudget(plugin)` compiles a one-entry `NewInertStagePlan` over a private registry with a fixed policy id; `Forward` unions it into the consumer's plan when `Request.KeyGroupBudget != nil`. | Register it; or call it from the handler | Registering exposes it to admins; the handler cannot do post-response or streaming accrual. |
| DD11 | Priority -1: admin policies have priority ≥ 0, so the gate runs first and a refused request costs no guardrail call. | Priority 0 | Ties would order it by slug among admin policies. |
| DD12 | The stage's policy mode is always `enforce`; the plugin maps the budget's action to the mode it reports and blocks with (`block` → enforce, `alert` → observe). | Policy mode from the action | The plan is compiled once, independent of any budget. |
| DD13 | The notice marker is set before the notice is sent (`SETNX`, TTL to month end + 24 h); the send runs off the request (`context.WithoutCancel`, 10 s). | Send then mark | Two replicas crossing at once would both send. |
| DD14 | The console notifier resolves the team from the gateway (`TenantID()`), through `gatewaydomain.Repository` (snapshot-backed on DB-less planes). | Carry the tenant on the request | The tenant is not on the request context. |

## `/store/v1` request flow with a group key

```
auth chain (api key) ─► AuthContext{AuthID, OwnerID, KeyGroupID = auth.GroupID}
proxy handler, store path:
    stampCallerTrace ─► trace: auth.id, auth.kind = personal, auth.group_id
    reqCtx.KeyGroupID = KeyGroupID
    reqCtx.KeyGroupBudget = Data.KeyGroupBudget(KeyGroupID)      in memory, nil when none
    StoreSelector ─► consumer ─► Precheck (plan rate limit)
forwarder:
    policies, plan = groupBudget.extend(req, consumer.Policies, consumer.PolicyPlan)
    pre_request:  key_group_budget (priority -1) ─► consumer policies ─► upstream
    post_response (async, streams included): key_group_budget charges the answer
```

### The stage

| Stage | Behaviour |
|---|---|
| pre_request | Price check (block: unpriced → 403 `model_unpriced`; alert: record, go on). Read every window (`GET`); a read error → block: 503 `budget_unavailable` (failed closed), alert: fail open. The first window at or over its limit (the group's first) is the one answered: block → 429 `budget_exceeded`; alert → decision `observe`. Every window over its limit gets a notice attempt. |
| post_response | Usage and served model from the answer; unpriced → warn, accrue zero. `INCRBY` + `EXPIRE` per window (`recordScript`, TTL to the end of the admitting month). A charge that moves a window from under to at-or-over its limit gets a notice attempt. A write error fails open. |

Windows: the group's total when `monthly_limit_usd` is set, and the member's when `member_overrides[owner]` or `member_monthly_limit_usd` is set. No window → the stage does nothing.

### Counters and markers

| Key | Value | TTL |
|---|---|---|
| `kgb:<gw>:<url-escaped group>:p:<YYYY-MM>` | group's micro-USD this month | to month end |
| `kgb:<gw>:<group>:owner:<url-escaped owner>:p:<YYYY-MM>` | member's micro-USD | to month end |
| `kgb:notified:<gw>:<group>:<scope>:<member or empty>:<YYYY-MM>` | `1` | to month end + 24 h |

## Interfaces / contracts

```go
// pkg/domain/auth
type KeyGroup struct{ ID, Name string }
func NormalizeKeyGroup(g KeyGroup) (KeyGroup, error)
func NewOwnedAPIKeyAuth(gatewayID ids.GatewayID, ownerID string, group KeyGroup, expiresAt *time.Time, now time.Time) (*Auth, error)
FindByOwnerAndGroup(ctx, gatewayID ids.GatewayID, ownerID, groupID string) (*Auth, error)
ListByOwner(ctx, gatewayID ids.GatewayID, ownerID string) ([]*Auth, error)

// pkg/app/auth
type ExpiryChange struct{ At *time.Time }
PersonalKeys.Create(ctx, gw, owner, group domain.KeyGroup, expiresAt *time.Time)
PersonalKeys.Rotate(ctx, gw, ownerID, expiry *ExpiryChange)
PersonalKeys.List / RotateKey(…, id, expiry) / RevokeKey(…, id)

// pkg/domain/identity
const ClaimKeyGroup = "key_group"
func (p *Principal) KeyGroup() string
func (p *Principal) StoreSubject() string
func (p *Principal) StoreGroups() []string

// pkg/domain/keygroup
type Budget struct{ GatewayID; GroupID; MonthlyLimitUSD, MemberMonthlyLimitUSD *float64; MemberOverrides map[string]float64; Action string; CreatedAt, UpdatedAt time.Time }
type Reader interface{ ListByGateway(ctx, gw) ([]*Budget, error) }
type Repository interface{ Reader; List(ctx, page, size); Upsert(ctx, *Budget) (*Budget, error); Delete(ctx, gw, groupID) error }
type Reached struct{ GatewayID; GroupID, Scope, UserID string; LimitUSD, SpentUSD float64; Period, Action string }
type Notifier interface{ Notify(ctx, Reached) error }

// pkg/app/keygroup
type Budgets interface{ List; Set(ctx, SetBudgetInput) (*Budget, error); Delete }

// pkg/infra/plugins/tokenratelimit
func NewGroupBudget(redis *redis.Client, registry *adapter.Registry, pricing appcatalog.PricingResolver, notifier keygroup.Notifier, logger *slog.Logger) *GroupBudget

// pkg/app/proxy
func WithGroupBudget(plugin appplugins.Plugin) ForwarderOption

// pkg/infra/console
func NewKeyGroupBudgetEvents(endpoint, secret string, gateways GatewayFinder, client *http.Client) (*KeyGroupBudgetEvents, error)
```

### Migrations

| Migration | Up | Down |
|---|---|---|
| `20261022120000_add_auth_key_group` | Add `group_id`, `group_name`; create `auths_gateway_owner_group_uniq`; drop `auths_gateway_owner_uniq`. Lock timeout as the LLM Store migrations. | Delete group keys' `consumer_auth` rows and the keys; recreate the old index; drop the columns. |
| `20261022130000_add_key_group_budgets` | Create `key_group_budgets` (PK `(gateway_id, group_id)`, FK `gateways` cascade, `CHECK action`). | Drop it. |

### Admin wire

| Route | Request | Response |
|---|---|---|
| `PUT /v1/gateways/{gw}/key-groups/{group_id}/budget` | `{"monthly_limit_usd"?: number\|null, "member_monthly_limit_usd"?: number\|null, "member_overrides"?: {"<user>": number}, "action": "alert"\|"block"}` | 200 `BudgetResponse` |
| `DELETE …/key-groups/{group_id}/budget` | — | 204 / 404 |
| `GET …/key-groups/budgets` | — | 200 `{"items": [BudgetResponse]}` |

`BudgetResponse`: `{"group_id", "monthly_limit_usd": number|null, "member_monthly_limit_usd": number|null, "member_overrides": {}, "action", "created_at", "updated_at"}`.

### Console event

`POST CONSOLE_EVENTS_URL`, headers `X-TrustGate-Timestamp` and `X-TrustGate-Signature: v1=hex(HMAC-SHA256(SERVER_SECRET_KEY, "trustgate.console-events.v1." + timestamp + "." + body))`:

```json
{"event": "key_group_budget_reached", "source": "budget", "team_id": "…", "gateway_id": "…", "group_id": "…",
 "scope": "group" | "member", "user_id": "… (member only)", "limit_usd": 0.0, "spent_usd": 0.0, "period": "YYYY-MM", "action": "alert" | "block"}
```

## Testing strategy

| Level | What |
|---|---|
| Domain | `KeyGroup` normalisation, `SetGroupName`, expiry bounds, `Budget` validation, `GroupLimit` / `MemberLimit` (override replaces default). |
| App | `PersonalKeys` group create, list, by-id rotate/revoke on another owner's key (404), `never_expires`; `Budgets` set/delete announce; Store mode, scoper and installer for a group key. |
| Infra | Codec round trip of group fields and `key_group_budgets`; compiler and snapshot adapters; `GroupBudget` (counters per month, group-first, overrides, alert, one notice per limit and month, lowered limit, Redis down, unpriced); console notifier (signature, body, no team). |
| HTTP | Handlers and DTOs; admin router (service credential refused on budget writes and self routes); proxy handler hands the group's budget to the forwarder. |
| Forwarder | A blocking budget refuses once spent without reaching the provider; the consumer's policies are not modified. |
| Postgres (`PG_TEST_URL`) | Migrations (twice, up and down), auth repository per (owner, group), budget repository upsert / list / delete / FK. |
| Functional | Group key lifecycle; MCP Store as the group; budget routes; enforcement on a full proxy (member and group scopes, personal key not held, console event once, signature) and on a DB-less proxy (budget via snapshot, cleared via snapshot). |
