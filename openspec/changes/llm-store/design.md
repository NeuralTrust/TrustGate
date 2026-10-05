# Design: LLM Store — personal keys on personal LLM consumers (RUN-1763)

## Linked artifacts

- Linear: [RUN-1763](https://linear.app/neuraltrust/issue/RUN-1763). Related: ENG-1710, ENG-1704.
- Proposal (binding): [`proposal.md`](./proposal.md), B1–B9, D1–D14, option C. This design replaces the "exactly one consumer per key" revision: the move transaction, the `FOR NO KEY UPDATE` locking, the create-and-attach transaction and the single-consumer index are gone.
- Exploration: [`exploration.md`](./exploration.md) (S0, S1, S2, S6 apply as written).
- Base: `develop` @ `1ea70e06`. Line numbers are HEAD. Conventions: `.agents/AGENTS.md` (hexagonal layers, DI in `pkg/container/modules`, one DTO per file, one use case per file, no narrative comments, mockery mocks) and golang-pro (`%w` wrapping, `ctx` first and propagated, immutable shared state, `-race`).
- `tasks.md` predates option C; regenerate it with `sdd-tasks` from this file.

Resolutions encoded here:

| # | Resolution | Where |
|---|---|---|
| R1 | `partition: key` counts per `owner_id` when the auth has one, else per auth id | DD8 |
| R2 | `partition: key` fails closed (503) on Redis read errors in blocking modes; observe mode passes | DD9 |
| R3 | Personal keys need `expires_at ≤ now + 90 d`. Rotate keeps the auth id and links and may move the expiry to `≤ now + 90 d` | DD11 |
| R4 | Admin consumer responses keep listing every auth id in `auth_ids`; `auth_links` stay snapshot-only | D7 |
| R5 | Hybrid gateways are out of v1: `/store/v1/*` → 404; creating a personal consumer or a personal key → 422 | DD3, DD5 |
| R6 | The `auth_key` TTL map is cleared by `InvalidateGatewayDataEvent`, closing the cross-process lag after rotate and revoke | DD15 |

## Technical approach

A personal consumer is an ordinary LLM consumer with `audience = personal`. A personal key is an ordinary `api_key` auth with `owner_id`, linked through `consumer_auth` to every personal consumer the app granted to its owner, and each link carries `level`, `priority` and `granted_at`. On `/store/v1/*` the auth middleware authenticates the key by hash and attaches the principal without a consumer. The proxy handler reads the key's pre-sorted links from `Data`, and a new `StoreSelector` use case runs the existing routing resolver per linked consumer, applies the per-provider substitution of `user`-level links and picks the first consumer that admits the request. The forwarder then serves the request through that consumer, with a candidate filter that keeps substituted providers out, so LB, fallback and policies run unchanged. New: two consumer/auth columns, three `consumer_auth` columns, one partial unique index, one in-memory index and two use cases. No new tables, proto messages, gRPC methods or TTL maps.

## Decisions

Proposal decisions are D#. Design-level decisions are DD#.

| # | Decision | Rejected | Rationale |
|---|---|---|---|
| DD1 (B1) | `Consumer.Audience` holds `""` for application and `"personal"` for personal. `ParseAudience` maps `"application"` to `""`. The repo writes `AudienceName()` and canonicalises on scan. | Storing `"application"` in memory | `omitempty` keeps existing consumers byte-identical with one in-memory form. |
| DD2 (B5) | Link attributes are three nullable `consumer_auth` columns, read into `Consumer.AuthLinks map[ids.AuthID]AuthLink` (`json:"auth_links,omitempty"`) only for rows with `level IS NOT NULL`. `granted_at` is the tie-break. | A `rank` integer (the app would have to renumber on every grant change); a separate table (B2 forbids new tables) | `granted_at` is stable and already exists app-side (`createdAt`). A map keyed by auth id needs no ordering on the wire. `ids.AuthID` implements `TextMarshaler` (`ids.go:96-104`), so it is a valid JSON map key. |
| DD3 (D1, R5) | Order in the middleware branch: hybrid → 404, `Data` → 500, no active personal consumer → 404, then the key. All three run before any key lookup. | Letting `HybridGatewayGuardMiddleware` answer 421 | A hosted proxy and a hybrid DP answer the same way (R5). OSS pays one string compare. |
| DD4 (D2) | `Data` gains `storeLinks map[ids.AuthID][]StoreLink` and `personal int` (active personal consumers), built in `NewData`. Each slice is sorted once by `(level rank, priority, granted_at, consumer id)`. Inactive personal consumers are left out, as `indexBySlug` leaves out inactive consumers. An auth id in `AuthIDs` with no `AuthLinks` entry is skipped. | Sorting per request; including inactive consumers | `Data` is immutable after `NewData`, so readers share the slices without a lock. A link change rebuilds `Data` on the same event. |
| DD5 (R5) | `appconsumer.Creator` refuses `audience = personal` on a hybrid gateway with 422 `ErrHybridPersonal`. `PersonalKeys.Create` refuses a hybrid gateway too. | Gating only `/store/v1` | Nothing personal is created where it can never be served. |
| DD6 (D4) | Attach of an owned key to a personal consumer is an upsert of one row in the existing `AttachAuth` transaction (consumer row lock as today, `repository.go:413`). `AttachAuth` gains `link *AuthLink`: `nil` keeps today's `ON CONFLICT DO NOTHING`; non-nil writes the columns with `ON CONFLICT (consumer_id, auth_id) DO UPDATE SET level, priority, granted_at`. | A move transaction; locking the auth row | Links are independent rows under option C; no invariant spans two of them. |
| DD7 (D4) | `associator.AttachAuth(ctx, gatewayID, consumerID, authID, link *AuthLink)`. Personal consumer + owned key: `link` required and `link.Validate()` (level known, `priority ≥ 0`, `granted_at` non-zero), priority defaulted to 1 by the DTO. Application consumer: `link` must be nil (422). Audience mismatch: 422 (`ValidateAuthConfig`). | Defaulting `granted_at` to now | A re-attach without it would reorder the user's consumers silently. |
| DD8 (D9, R1) | `partition: key` → dimension `owner` with subject `OwnerID` when set, else dimension `auth` with subject `AuthID`. With neither (playground), nothing is read or counted. A `partition: key` policy attached to consumer A counts only the requests A serves; a global one counts the owner whatever consumer serves. | Auth id only | A revoke followed by a new key keeps the owner's spend. |
| DD9 (D9, R2) | 503 `budget_unavailable` and 403 `model_unpriced` apply only when `partition: key` and `appplugins.Blocks(mode)` (`modes.go:59`). A ctx the caller cancelled keeps today's path. Post-response accrual errors keep log-and-pass. | Changing `HandleCounterFailure` (`counter_failure.go:73`) | Fail-closed stays local to the new partition. |
| DD10 (D7) | `authdomain.ErrOwnedKey` wraps a new `commonerrors.ErrManagedByOwner`. `httpio.MapDomainError` maps it to 422 `owned_key`. | Wrapping `ErrValidation` (`validation_failed`) | A stable code the app can branch on. |
| DD11 (D8, R3) | `authdomain.ValidateOwnedExpiry(at, now)` requires `now < at ≤ now + 90 d`. Create requires `expires_at`. Rotate takes an optional `expires_at`: absent keeps the current one, present must pass the cap. | A required `expires_at` on rotate | Rotation never clears the expiry. |
| DD12 (D11) | `dataFinder.loadAuths` (`data_finder.go:349`) skips the auth ids of personal consumers, so `rc.Auths` is empty for them. | Loading them | `rc.Auths` is read only by slug-path resolution and MCP (`api_key_resolver.go:45`, `auth.go:196`, `auth_chain.go:188`, `oauth/connect.go:636`). It saves an O(links) `FindByIDs` and a clone per `Data` rebuild. |
| DD13 (D11) | `pathResolver.load` (`path_resolver.go:145`) treats a personal consumer as no match. | Leaving it | Otherwise OAuth metadata discovery resolves personal consumers by slug. |
| DD14 (D7) | `RotateInput.OwnerID`: when the existing auth is owned, it must equal `existing.OwnerID`, else `ErrOwnedKey`. The admin handler passes `""` (→ 422); `PersonalKeys` passes the caller. The updater refuses owned keys outright. | Duplicating the rotator | Cache eviction, invalidation and `Signal` stay in one place. |
| DD15 (R6) | `InvalidateGatewayDataEventSubscriber` (`invalidate_gateway_data_event_subscriber.go:44-90`) gets `authKeyCache` = `AuthKeyTTLName` and clears it, as it clears `authCache`. | Leaving the ≤ 5 min lag | A rotated personal secret would keep resolving on other full-plane replicas, and the auth id still has its links. |
| DD16 (D13) | The selector lives in `pkg/app/proxy` (it needs `approuting.Resolver`, `appcatalog.ModelListing` and the request intent; `pkg/app/routing` imports `pkg/app/consumer`, so it cannot live there). It reuses one candidate pipeline extracted from `forwarder.resolveRouting` (`routing.go:47-91`) into `candidatePipeline`, so the selector and the forwarder never drift. | A copy of the pipeline in the selector | One place for Resolve → capability → files → listing. |
| DD17 (D13) | In the store, the listing check drops a deferring candidate whose provider catalog answers `VerdictAbsent`, with **no** "keep all when empty" fallback. The slug path keeps its fallback (`routing.go:115-117`). | The fallback in the store | The fallback exists because the slug consumer is fixed. In the store it would let an Anthropic registry without an allow-list capture `gpt-*` (worked example, `gpt-4.1` must be 403). |
| DD18 (D13) | Admission uses **primary** candidates only: `routingdomain.Candidate.FallbackOnly()` (true when every source is `fallback`; `sourceFallback` moves to `routingdomain.SourceFallback`). The selected consumer still forwards with its fallback candidates. | Admitting through fallback | A's DeepSeek fallback must not make A serve `deepseek-chat`. |
| DD19 (D13) | Substitution is a candidate filter, `Keep func(routingdomain.Candidate) bool`, set only for a `group`/`all` link when the substituted provider set is non-empty. `ForwardInput.Keep` and `ListModelsInput.Keep` apply it after `Resolve`; when `Keep` is set the forwarder resolves even for a zero intent, and `nonCandidateRoutes` (`routing.go:455-475`) then excludes substituted LB routes and fallback backends. Empty after `Keep` → `ErrModelDenied`. Slug path: `Keep == nil`, byte-identical. | A filtered copy of the consumer | No synthetic consumer; LB key and policies stay the real consumer's. |

## `/store/v1/*` request flow

`…/store/v1/chat/completions` with `X-AG-API-Key` or `Authorization`.

| # | Step | Code (after) | Warm | Cold / miss |
|---|---|---|---|---|
| 1 | Gateway from host / `X-AG-Gateway-Slug` | `gatewayResolver.Resolve` (`auth.go:58`) | TTL get | snapshot map (DB-less), 1 PG (full) |
| 2 | Path → slug `store` → `serveStore` | `ResolveProxyPath` (`proxy_path_resolver.go:69-78`), `route.ConsumerSlug == domainconsumer.StoreSlug` | string ops | — |
| 3 | `gw.ServedByHybridDataPlane()` → **404** | `gateway.go:125` | field read | — |
| 4 | Gateway `Data` → **500** on error | `dataFinder.FindByGateway` (`auth.go:69`) | TTL get | today's load + `storeLinks` build, O(personal links) |
| 5 | `!data.HasPersonalConsumers()` → **404** | new | int compare | — |
| 6 | Raw key, empty → **401** | `resolver.APIKeyFromRequest` | header read | — |
| 7 | SHA-256 → auth. `ErrNotFound`/`ErrExpired` → **401**, other → **500** | `APIKeyFinder.FindByAPIKey` (`key_finder.go:47-62`) | 1 hash + TTL get | snapshot `authsByAPIKeyHash` (DB-less), 1 PG (full) |
| 8 | `Enabled ∧ Type == api_key ∧ IsOwned() ∧ GatewayID == gw.ID` → else **401** | `storeKeyResolver.Resolve` | O(1) | — |
| 9 | `attach` with `Principal{Subject: owner_id, Method: api_key}`, `AuthContext{AuthID, OwnerID}`, no consumer | `auth.go:169` (`rc == nil` skips the consumer locals) | ctx values | — |
| 10 | Handler: `route.ConsumerSlug == StoreSlug` → `handleStore`; `links := data.StoreLinks(authCtx.AuthID)` | `proxy_handler.go:139` | 1 map get | — |
| 11 | `/models` → `StoreModels.List/Get` → 200 | new `store_models.go` | in-memory + catalog cache | catalog load |
| 12 | Build `reqCtx`, `StoreSelector.Select` → consumer + `Keep`, or **403** `model_not_allowed` / **400** `invalid_model` | new `store_selector.go` | one `Resolve` per effective link | catalog listing load |
| 13 | `authCtx.ConsumerID`, `stampConsumerTrace`, method check, end user, then `Forward` with `Keep` | `proxy_handler.go:150-195` (shared tail) | as today | — |
| 14 | Registries, ModelPolicies, LB `gw:consumerID`, fallback, policies | unchanged (`load_balancer_cache.go:58-59`, `plansFor` `data_finder.go:179-188`) | unchanged | — |
| 15 | `token_rate_limiter` `partition: key` | `Plugin.Execute` | 1 Redis GET per window pre, 1 EVAL post | — |

A warm request costs 0 DB, 0 gRPC and 0 Redis beyond the budget counter. Staleness: an attach, detach or revoke rewrites `consumer_auth`/`auths`, which rebuilds `Data` on the next snapshot apply (DB-less, `ClearAllTTLMaps`, `config_sync_data.go:111-115`) or on `InvalidateGatewayDataEvent` (full plane, which also clears `auth_key`, DD15).

## Consumer selection (D13)

`StoreSelector.Select(ctx, StoreSelectInput{Links, Data, Request})`:

1. **Substituted providers.** `S` = the lower-cased `Registry.Provider()` of every primary registry (`rc.Registries`) of every `user`-level link.
2. **Effective links.** For a `user` link, `Keep = nil`. For a `group`/`all` link with `S` non-empty, `Keep(c) = provider(c) ∉ S`. A link whose consumer has no primary registry passing `Keep` is dropped.
3. **Intent.** `parseIntent(reqCtx)` (`routing.go:198-209`); an invalid reference → 400 as today.
4. **Admission per effective link.** `candidatePipeline(ctx, intent, needed, rc, data)` = `Resolve` → `Keep` → capability filter → files filter → for a short model, the listing check of DD17. A resolver error means "does not admit". The link admits when at least one candidate with `!FallbackOnly()` remains, and, for a zero intent, at least one such candidate has a `Default`.
5. **Specificity** (qualified and short-model intents; 0 for every other kind), best over the admitting primary candidates: `0` the model is a literal entry of `Allowed`; `1` it matches a glob of `Allowed` (`modelmatch.MatchAny`); `2` `Allowed == nil` (passed the listing check, or no check for a qualified intent, as today).
6. **Order.** Links are already sorted by `(level, priority, granted_at, consumer id)` (DD4). Among admitting links, pick the minimum of `(level rank, priority, specificity, granted_at, consumer id)`. None → `ErrNoStoreConsumer` (wraps `routingdomain.ErrModelDenied` → 403 `model_not_allowed`).
7. Return `StoreSelection{Link, Keep}`.

| Intent kind (`intent.go`) | Admission | Specificity |
|---|---|---|
| empty | a primary candidate with a `Default` | — (level, priority, age) |
| `auto` | `resolveAuto` succeeds with a primary candidate | — |
| `pool:<alias>` | the consumer's LB pool alias matches and a member survives `Keep` | — |
| `@provider/model` | `resolveQualified` succeeds with a primary candidate | 0 / 1 / 2 |
| short model, incl. bare `provider/model` | `resolveShortModel` succeeds and a primary candidate survives DD17 | 0 / 1 / 2 |

Cost: one `Resolve` per effective link (all in-memory maps and slices), one listing lookup per deferring candidate (cached `CatalogListingTTLName`). The selector holds no state and is safe for concurrent use.

### Worked example as a table test (`store_selector_test.go`, and end to end in PR 15)

Links of Ana: A `group` p1 (OpenAI, no allow-list, fallback DeepSeek), B `group` p1 (Anthropic, no allow-list), C `group` p1 (Anthropic `["opus-5.5"]`), D `user` p1 (OpenAI `["gpt6"]`, default `gpt6`), granted A < B < C < D. Listing fake: OpenAI lists `gpt-4.1`, `gpt6`; Anthropic lists `opus-5.5`, `opus-4.8`. `S = {openai}`, so A is not effective.

| Model | Expected |
|---|---|
| `gpt-4.1` | `ErrModelDenied` (403) |
| `gpt6` | D |
| `opus-5.5` | C (specificity 0 < 2) |
| `opus-4.8` | B |
| empty | D |
| `@openai/gpt-4.1` | `ErrModelDenied` |
| `auto` | D |
| without D: `gpt-4.1` | A, and `Keep == nil`; A's fallback candidate DeepSeek is in the forward set |
| without D: `deepseek-chat` | `ErrModelDenied` (fallback never admits) |
| B priority 0, C priority 1: `opus-5.5` | B (priority before specificity) |

## Interfaces / contracts

```go
// pkg/common/errors
var ErrManagedByOwner = errors.New("managed by its owner")

// pkg/domain/consumer
type Audience string
const (
	AudienceApplication Audience = "application"
	AudiencePersonal    Audience = "personal"
)
func ParseAudience(s string) (Audience, error)
func (c *Consumer) IsPersonal() bool
func (c *Consumer) AudienceName() Audience

type GrantLevel string
const (
	GrantLevelUser  GrantLevel = "user"
	GrantLevelGroup GrantLevel = "group"
	GrantLevelAll   GrantLevel = "all"
)
const DefaultGrantPriority = 1
func ParseGrantLevel(s string) (GrantLevel, error)
func (l GrantLevel) Rank() int // user 0, group 1, all 2
type AuthLink struct {
	Level     GrantLevel `json:"level"`
	Priority  int        `json:"priority"`
	GrantedAt time.Time  `json:"granted_at"`
}
func (l AuthLink) Validate() error

Consumer.Audience  Audience                  `json:"audience,omitempty"`
Consumer.AuthLinks map[ids.AuthID]AuthLink   `json:"auth_links,omitempty"`
CreateParams.Audience Audience; RehydrateParams.Audience Audience; RehydrateParams.AuthLinks map[ids.AuthID]AuthLink
var (
	ErrInvalidAudience       = fmt.Errorf("consumer: invalid audience: %w", commonerrors.ErrValidation)
	ErrAudienceImmutable     = fmt.Errorf("consumer: audience cannot change: %w", commonerrors.ErrValidation)
	ErrAudienceMismatch      = fmt.Errorf("consumer: auth does not match the consumer audience: %w", commonerrors.ErrValidation)
	ErrPersonalAuthsBulk     = fmt.Errorf("consumer: a personal consumer's auths change only by attach and detach: %w", commonerrors.ErrValidation)
	ErrHybridPersonal        = fmt.Errorf("consumer: personal consumers are unavailable on hybrid gateways: %w", commonerrors.ErrValidation)
	ErrPersonalNoDefault     = fmt.Errorf("consumer: a personal consumer needs a default model on at least one registry: %w", commonerrors.ErrValidation)
	ErrInvalidAuthLink       = fmt.Errorf("consumer: invalid auth link: %w", commonerrors.ErrValidation)
)
Associator (repo port): AttachAuth(ctx context.Context, consumerID ids.ConsumerID, authID ids.AuthID, link *AuthLink) error

// pkg/domain/routing
const SourceFallback = "fallback"
func (c Candidate) FallbackOnly() bool

// pkg/domain/auth
Auth.OwnerID string `json:"owner_id,omitempty"`
func (a *Auth) IsOwned() bool
const MaxOwnedKeyLifetime = 90 * 24 * time.Hour
func NewOwnedAPIKeyAuth(gatewayID ids.GatewayID, ownerID string, expiresAt, now time.Time) (*Auth, error)
func ValidateOwnedExpiry(expiresAt, now time.Time) error
var (
	ErrOwnedKeyExists = fmt.Errorf("auth: a personal key already exists for this owner: %w", commonerrors.ErrAlreadyExists)
	ErrOwnedKey       = fmt.Errorf("auth: owned_key: %w", commonerrors.ErrManagedByOwner)
	ErrOwnedExpiry    = fmt.Errorf("auth: expires_at must be in the future and within 90 days: %w", commonerrors.ErrValidation)
)
ListFilter.ExcludeOwned bool; ListFilter.OwnerID string
Repository: FindByOwner(ctx context.Context, gatewayID ids.GatewayID, ownerID string) (*Auth, error)

// pkg/app/auth
AuthContext.OwnerID string
RotateInput.OwnerID string
type PersonalKeys interface {
	Get(ctx context.Context, gatewayID ids.GatewayID, ownerID string) (*PersonalKey, error)
	Create(ctx context.Context, gatewayID ids.GatewayID, ownerID string, expiresAt time.Time) (*PersonalKey, error)
	Rotate(ctx context.Context, gatewayID ids.GatewayID, ownerID string, expiresAt *time.Time) (*PersonalKey, error)
	Revoke(ctx context.Context, gatewayID ids.GatewayID, ownerID string) error
}
type PersonalKey struct{ Auth *domain.Auth; ConsumerIDs []ids.ConsumerID; RawKey string }
func NewPersonalKeys(repo domain.Repository, consumers consumerdomain.Reader, gateways gatewaydomain.Repository,
	rotator Rotator, deleter Deleter, manager *cache.TTLMapManager, publisher cache.EventPublisher,
	logger *slog.Logger, signaler configsyncport.SnapshotSignaler, now func() time.Time) PersonalKeys

// pkg/app/consumer
type StoreLink struct {
	Consumer *RoutableConsumer
	Link     domain.AuthLink
}
func (d *Data) HasPersonalConsumers() bool
func (d *Data) StoreLinks(id ids.AuthID) []StoreLink // shared, sorted; callers must not mutate
Associator: AttachAuth(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, authID ids.AuthID, link *domain.AuthLink) error
var ErrStoreKeyRejected = errors.New("store: key rejected")
type StoreKeyResolver interface {
	Resolve(ctx context.Context, gatewayID ids.GatewayID, rawKey string) (*authdomain.Auth, error)
}
func NewStoreKeyResolver(apiKeys appauth.APIKeyFinder) StoreKeyResolver

// pkg/app/proxy
type CandidateFilter func(routingdomain.Candidate) bool
ForwardInput.Keep    CandidateFilter
ListModelsInput.Keep CandidateFilter
var ErrNoStoreConsumer = fmt.Errorf("store: no consumer admits the request: %w", routingdomain.ErrModelDenied)
type StoreSelectInput struct {
	Links   []appconsumer.StoreLink
	Data    *appconsumer.Data
	Request *infracontext.RequestContext
}
type StoreSelection struct {
	Link appconsumer.StoreLink
	Keep CandidateFilter
}
type StoreSelector interface {
	Select(ctx context.Context, in StoreSelectInput) (*StoreSelection, error)
}
func NewStoreSelector(resolver approuting.Resolver, listing appcatalog.ModelListing, logger *slog.Logger) StoreSelector
type StoreModelsInput struct {
	Links []appconsumer.StoreLink
	Data  *appconsumer.Data
}
type StoreModels interface {
	List(ctx context.Context, in StoreModelsInput) (*ModelsList, error)
	Get(ctx context.Context, in StoreModelsInput, id string) (*ModelCard, error)
}
func NewStoreModels(lister ModelsLister) StoreModels

// pkg/app/plugins, pkg/infra/context
RuntimeScope.AuthID string; RuntimeScope.OwnerID string
func (s RuntimeScope) Key() (dimension, id string, ok bool)
RequestContext.AuthID string; RequestContext.OwnerID string

// pkg/api/middleware/auth.go
func NewAuthMiddleware(identityResolver resolver.IdentityResolver, dataFinder appconsumer.DataFinder,
	gatewayResolver resolver.GatewayResolver, storeKeys appconsumer.StoreKeyResolver, logger *slog.Logger) *AuthMiddleware
func (m *AuthMiddleware) serveStore(c *fiber.Ctx, gw *gatewaydomain.Gateway, data *appconsumer.Data, route resolver.ProxyRoute) error

// pkg/api/handler/http/proxy
func (h *ForwardedHandler) WithStore(selector appproxy.StoreSelector, models appproxy.StoreModels) *ForwardedHandler
```

`StoreKeyResolver.Resolve` wraps infra errors with `fmt.Errorf("store: find api key: %w", err)`; `ErrNotFound` (which includes `ErrExpired`) and every failed check become `ErrStoreKeyRejected`. `StoreSelector` and `StoreModels` take `ctx` first and hold no mutable state. `StoreModels.List` calls `ModelsLister.List` once per effective link with `Keep` = the link's substitution filter combined with `!FallbackOnly()`, then deduplicates by id and sorts, as `collect` does (`list_models.go:89-121`). The substitution helper `storeScope(links) []scopedLink` is shared by the selector and `StoreModels` (one file, `store_scope.go`).

### Migrations (in-code, one transaction each, idempotent; template `20260922120000_add_auth_expires_at.go`)

```sql
-- 20261002120000_add_consumer_audience  (up)
ALTER TABLE consumers ADD COLUMN IF NOT EXISTS audience TEXT NOT NULL DEFAULT 'application';
ALTER TABLE consumers DROP CONSTRAINT IF EXISTS consumers_audience_check;
ALTER TABLE consumers ADD CONSTRAINT consumers_audience_check CHECK (audience IN ('application', 'personal'));
-- down
ALTER TABLE consumers DROP CONSTRAINT IF EXISTS consumers_audience_check;
ALTER TABLE consumers DROP COLUMN IF EXISTS audience;

-- 20261002120100_add_auth_owner  (up)
ALTER TABLE auths ADD COLUMN IF NOT EXISTS owner_id TEXT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS auths_gateway_owner_uniq ON auths (gateway_id, owner_id) WHERE owner_id IS NOT NULL;
-- down
DROP INDEX IF EXISTS auths_gateway_owner_uniq;
ALTER TABLE auths DROP COLUMN IF EXISTS owner_id;

-- 20261002120200_add_consumer_auth_grant  (up)
ALTER TABLE consumer_auth ADD COLUMN IF NOT EXISTS level TEXT NULL;
ALTER TABLE consumer_auth ADD COLUMN IF NOT EXISTS priority INTEGER NULL;
ALTER TABLE consumer_auth ADD COLUMN IF NOT EXISTS granted_at TIMESTAMPTZ NULL;
ALTER TABLE consumer_auth DROP CONSTRAINT IF EXISTS consumer_auth_grant_check;
ALTER TABLE consumer_auth ADD CONSTRAINT consumer_auth_grant_check CHECK (
	(level IS NULL AND priority IS NULL AND granted_at IS NULL)
	OR (level IN ('user', 'group', 'all') AND priority >= 0 AND granted_at IS NOT NULL));
-- down
ALTER TABLE consumer_auth DROP CONSTRAINT IF EXISTS consumer_auth_grant_check;
ALTER TABLE consumer_auth DROP COLUMN IF EXISTS granted_at;
ALTER TABLE consumer_auth DROP COLUMN IF EXISTS priority;
ALTER TABLE consumer_auth DROP COLUMN IF EXISTS level;
```

All adds are nullable or constant-default, so there is no rewrite; the CHECKs scan existing rows once (all `NULL` for `consumer_auth`). `personal ⇒ LLM`, the default-model rule and "personal links only on owned keys" are domain rules, not SQL.

### Repository SQL deltas

| Repo | Change |
|---|---|
| consumer (`pkg/infra/repository/consumer/repository.go`) | `consumerSelectColumns` (`:50-58`) + `c.audience` + `COALESCE((SELECT json_object_agg(ca.auth_id, json_build_object('level', ca.level, 'priority', ca.priority, 'granted_at', ca.granted_at)) FROM consumer_auth ca WHERE ca.consumer_id = c.id AND ca.level IS NOT NULL), '{}')::jsonb AS auth_links`. `INSERT` (`:118`) + `audience`. `scanConsumer` (`:732`) → `ParseAudience`, `AuthLinks`. `Update` never writes `audience`. `AttachAuth(…, link)` (`:413-431`): `link == nil` keeps today's insert; otherwise `INSERT … (consumer_id, auth_id, level, priority, granted_at) … ON CONFLICT (consumer_id, auth_id) DO UPDATE SET level = EXCLUDED.level, priority = EXCLUDED.priority, granted_at = EXCLUDED.granted_at`. `replaceAuthLinks` unchanged (application consumers only, D5). |
| auth (`pkg/infra/repository/auth/repository.go`) | One `authColumns` const replaces the six SELECT copies (`:140-288`) and adds `owner_id`. `INSERT` (`:73-80`) adds `owner_id` (`NULLIF($n,'')`); a 23505 on `auths_gateway_owner_uniq` → `ErrOwnedKeyExists`. `UPDATE` (`:96-107`) unchanged, so it never writes `owner_id`. `scanAuth` (`:320-332`). List/count add `AND ($k::boolean IS NOT TRUE OR owner_id IS NULL) AND ($m = '' OR owner_id = $m)`. `FindByOwner`: `WHERE gateway_id = $1 AND owner_id = $2`. |
| snapshot adapters (`pkg/runtimeconfig/snapshot/adapters/{auth,consumer}_repository.go`) | `FindByOwner` scans the gateway's auths in the snapshot. `AttachAuth` keeps the adapters' read-only error. |

### Snapshot and admin wire (JSON inside the existing proto `bytes json`, so no proto change)

| Entity | Snapshot | Admin API |
|---|---|---|
| `Consumer` | `"audience":"personal"` and `"auth_links":{…}` only on personal consumers (`omitempty`). Existing consumers are byte-identical. | `ConsumerResponse.Audience string json:"audience"`. `CreateConsumerRequest.Audience string json:"audience,omitempty"`. `UpdateConsumerRequest.Audience *string` (different → 422). `auth_ids` unchanged; `auth_links` not exposed (R4). |
| `Auth` | `"owner_id"` only on owned keys. `buildAuths` (`snapshot.go:254-265`) indexes owned keys by hash with no change. | `AuthResponse.OwnerID string json:"owner_id,omitempty"`. `GET /auths` excludes owned keys; `?owner_id=<sub>` lists one owner's key. |
| `AttachAuthRequest` (new, `consumer/request/attach_auth_request.go`) | — | `{level?: "user"\|"group"\|"all", priority?: int (default 1), granted_at?: RFC 3339}`. Empty body = today. |
| `PersonalKeyResponse` (new) | — | `{id, consumer_ids ([] when unlinked), key (create and rotate only), key_prefix, key_suffix, expires_at, enabled, created_at, updated_at}` |

### Self-only endpoints (D8)

Under `/:gateway_id/store` (`admin_router.go:227`, `RequireGatewayAccess(ResourceRegistries)`) plus `RequireInteractiveIdentity()` (`admin_authz.go:108`). The owner is always `callerSubject(c)` (`requests_handler.go:212`).

| Route | Body | Success | Failures |
|---|---|---|---|
| `GET /principal/llm-key` | — | 200 | 404 no key |
| `POST /principal/llm-key` | `{expires_at}` | 201, raw key once, no links | 409 exists, 422 expiry / hybrid, 403 service credential |
| `POST /principal/llm-key/rotate` | `{expires_at?}` | 200, same id and links, new secret | 404, 422 expiry |
| `DELETE /principal/llm-key` | — | 204 | 404 |

`PersonalKeys.Create`: `ValidateOwnedExpiry` → gateway not hybrid → `FindByOwner` pre-check (409) → `NewOwnedAPIKeyAuth` → `repo.Save` (409 on the race, through the unique index) → `AuthTTLName` / `AuthKeyTTLName` set, `invalidation.GatewayData`, `Signal` (the side effects of `creator.go:78-84`). Rotate is `FindByOwner` → `Rotator.Rotate{Expiry, OwnerID}` (links untouched). Revoke is `FindByOwner` → `Deleter.Delete`, which detaches every link (`guard.go:101`). `Get` adds `consumers.ListByAuthID` ids.

### Budgets (`pkg/infra/plugins/tokenratelimit`)

| Item | Rule |
|---|---|
| Config | `Partition string mapstructure:"partition"`: `""` (today) or `key`. `calendar_month` / `calendar_day` (UTC) valid in `rules[].time_window` and `aggregate.time_window` only with `key`. With `key`, `custom_pricing` and `group_by_header` → validation error. |
| Subject | `in.Scope.Key()` (DD8). `ok == false` → pass, nothing read or counted. |
| Keys | `trl:<policy>:key:owner:<owner_id>` or `trl:<policy>:key:auth:<auth_id>`, then `[:p:<2006-01 \| 2006-01-02>]`, then `[:model:<slug>]`. |
| TTL | Period end minus now, floor of `quotaTTL` (`pkg/infra/ratelimit/store.go:258-264`; layout `meter.go:46,357`). `Plugin.now func() time.Time`. |
| Plumbing | `AuthContext.OwnerID` → `reqCtx.AuthID/OwnerID` at `proxy_handler.go:174-175` → `scopeFromRequest` (`executor.go:443`). Never from a header. |
| Redis read error | `key` and `Blocks(mode)` → `*appplugins.PluginError{503, "budget_unavailable"}` from `budgetGate` (`budget.go:201-213`). Otherwise fail-open as today. |
| Unpriced | `key`, `unit: dollars`, `Blocks(mode)` → `llmcost.Resolve` with registry rates (`pricing.go:151`) not found → 403 `model_unpriced` in `budgetGate`, only when a window applies and before the Redis read. |
| Over budget | Existing 429 (`responses.go:72-85`), `error.scope = key`. |

### Telemetry (S1)

`Metadata.AuthID` + `SetAuthID` (`trace.go:27`) → `Event.AuthID json:"auth_id,omitempty"` (`event.go:23`) → `builder.go:68-84` → OTLP `trustgate.auth.id` (`mapping.go:70-74,202-206`). `stampConsumerTrace(c, rc, authCtx)` (`proxy_handler.go:154,419`); on the store path it runs after selection, so `consumer.id` is the selected consumer. `/store/v1/models` stamps no consumer. Contract: `docs/telemetry/otlp-metadata-contract.md:52-56`.

### Snapshot metrics (S6)

New `pkg/app/configsnapshot/snapshot_metrics.go` with `otel.Meter("trustgate/configsnapshot")` (as `tenant_caps_metrics.go:29`): `trustgate.configsnapshot.encoded_bytes{flavour=catalog|global|scoped}` and `trustgate.configsnapshot.entities{kind=auths|owned_auths|personal_consumers|personal_links}`, recorded on publish only (`dispatcher.go:241-266`), never on a dedup.

## Error codes

| Surface | Condition | Status / `error` |
|---|---|---|
| `/store/v1/*` | hybrid gateway; no active personal consumer | 404 `not_found` |
| `/store/v1/*` | no key; unknown, expired, disabled, non-`api_key`, unowned, other gateway | 401 `unauthenticated` |
| `/store/v1/*` | nothing effective admits the request (N = 0 included) | 403 `model_not_allowed` |
| `/store/v1/*` | invalid model reference, unknown pool alias everywhere | 400 `invalid_model` |
| `/store/v1/*` | `Data` load or key lookup infra error | 500 `internal_error` |
| `/store/v1/models` | nothing effective | 200 `{"object":"list","data":[]}` |
| any LLM path, `partition: key` | over budget / Redis down (blocking) / unpriced (dollars, blocking) | 429 / 503 `budget_unavailable` / 403 `model_unpriced` |
| `/<slug>/v1/*` | expired key (S0); personal consumer slug; personal key on an application slug | 401 / 404 / 401 |
| MCP plane | owned key | 401 |
| Admin consumers | invalid or changed `audience`; `personal` on non-LLM; personal without a default; `PUT auths` on personal; audience mismatch; link fields missing, invalid, or sent for an application link; personal on hybrid | 422 `validation_failed` |
| Admin `/auths/:id` | `PUT` or `rotate` on an owned key | 422 `owned_key` |
| `…/principal/llm-key` | service credential / exists / bad expiry or hybrid / no key | 403 / 409 `already_exists` / 422 / 404 |
| Policy write | `calendar_*` without `key`; `key` with `custom_pricing` or `group_by_header`; unknown `partition` | existing invalid-config mapping |

Note on the unknown pool alias: the selector maps "every effective link refused the alias" to the first resolver error seen, so a pool alias no consumer defines keeps today's 400 and a known alias with no surviving member is 403.

## File changes (chained PRs into `develop`, ≤ ~400 changed lines each; generated mocks and swagger in their own commit)

| PR | Slice | Files (Action) | Est. lines (code / test) | Depends |
|---|---|---|---|---|
| 1 | S0 + S1 | `pkg/api/resolver/api_key_resolver.go` (M: `now`, skip `IsExpired` at `:45`). `pkg/api/middleware/auth.go` (M: `apiKeyAttachedElsewhere(…, now)` `:196`). `pkg/infra/cache/subscriber/invalidate_gateway_data_event_subscriber.go` (M: DD15). `pkg/infra/trace/trace.go`, `pkg/infra/metrics/events/event.go`, `pkg/app/metrics/builder.go`, `pkg/infra/telemetry/otlp/mapping.go`, `proxy_handler.go` (M: auth id). Tests incl. `invalidate_gateway_data_event_subscriber_test.go`. `docs/telemetry/otlp-metadata-contract.md`, release note | 55 / 175 | — |
| 2 | S3a data model | `migrations/20261002120000_add_consumer_audience.go`, `migrations/20261002120100_add_auth_owner.go` (C). `pkg/domain/consumer/{consumer,audience,errors}.go` (M/C). `pkg/domain/auth/{auth,errors,repository}.go` (M). `pkg/infra/repository/{consumer,auth}/repository.go` (M). `adapters/auth_repository.go` (M). Tests: domain, `codec_test.go` golden bytes, `compiler_test.go` (owned key ships), `tests/functional/repositories/{auth,consumer}` | 230 / 160 | — |
| 3 | S3b consumer rules | `consumer.go` `Validate` (personal ⇒ LLM, default model), `auth_rules.go` (D3). `pkg/app/consumer/{creator,updater,associator}.go` (M: audience, immutability, D5, hybrid with a gateway dep, default kept on registry detach). Consumer `request/{create,update}_consumer_request.go`, `response/consumer_response.go` (M). `modules/consumer.go` (M). Tests | 120 / 200 | 2 |
| 4 | S3c auth rules | `list_auth_handler.go` (M: `ExcludeOwned`, `?owner_id`), `response/auth_response.go` (M). `pkg/app/auth/{updater,rotator}.go` (M: DD14). `pkg/app/policy/warnings.go:285` (M). `pkg/common/errors/errors.go`, `httpio/errors.go` (M: `owned_key`). Tests | 90 / 150 | 2 |
| 5 | S3d link columns | `migrations/20261002120200_add_consumer_auth_grant.go` (C). `pkg/domain/consumer/auth_link.go` (C), `consumer.go` (M: `AuthLinks`, rehydrate). `pkg/domain/consumer/repository.go` (M: `AttachAuth` port). `pkg/infra/repository/consumer/repository.go` (M: `auth_links` select, upsert). `adapters/consumer_repository.go` (M). Tests: `auth_link_test.go`, codec golden (application consumer unchanged, personal round trip), PG: CHECK, upsert, `auth_links` read | 120 / 170 | 2 |
| 6 | S3e attach API | `consumer/request/attach_auth_request.go` (C). `association_handler.go` (M: optional body). `pkg/app/consumer/associator.go` (M: DD7). Mocks regen. Tests: handler matrix (empty body, link on application → 422, missing level → 422, priority default), associator, PG re-attach updates priority, links to other consumers untouched | 100 / 160 | 3, 5 |
| 7 | S2a partition | `pkg/app/auth/context.go`, `pkg/infra/context/request_context.go`, `pkg/app/plugins/{plugin,executor}.go`, `proxy_handler.go:174-175` (M). `tokenratelimit/{config,keys,budget,plugin}.go` (M). Tests: config matrix, key layout, owner vs auth subject, playground pass-through, rollovers with a fake clock | 120 / 190 | — |
| 8 | S2b hard limits | `tokenratelimit/{budget,plugin,responses,config}.go` (M). `catalog_metadata.go:142-273`, `docs/policies.json:112` (M). Tests: closed miniredis → 503 enforce / pass observe / default partition fail-open; unpriced → 403; schema | 100 / 165 | 7 |
| 9 | S4a use case | `pkg/app/auth/personal_keys.go` (C). `modules/auth.go` (M). Tests: caps, 409 pre-check and race (unique index → `ErrOwnedKeyExists`), hybrid, rotate keeps id and links and evicts the old hash, revoke detaches all links | 120 / 140 | 2, 4 |
| 10 | S4b HTTP | `pkg/api/handler/http/store/llm_key_handler.go` (C). `store/request/{create_llm_key,rotate_llm_key}_request.go`, `store/response/personal_key_response.go` (C). `admin_router.go:225-247`, `modules/{store,server_admin}.go` (M). Tests: handler (caller-only, service credential 403, codes), `docs/openapi_test.go`; swagger gen apart | 130 / 170 | 9 |
| 11 | S5a `Data` | `consumer_data.go` (M: `storeLinks`, `HasPersonalConsumers`, `StoreLinks`, `indexBySlug` skip). `data_finder.go:349` (M: DD12). D11: `auth.go:196` skip personal, `auth_chain.go:370`, `api_key_consumers.go:156`, `path_resolver.go:145` (M). Tests: ordering (level, priority, granted_at, id), inactive left out, N = 0, `-race` concurrent readers, MCP 401 | 90 / 200 | 5 |
| 12 | S5b branch | `pkg/app/consumer/store_key_resolver.go` (C). `auth.go:56-101,161-182` (M: `serveStore`, `attach` with `rc == nil`). `modules/consumer.go` in `provideConsumerServices` (both planes, `core_data.go:106`) (M). Tests: resolver 401 matrix, 404 order with a finder fake asserting zero calls (hybrid, no personal consumer), principal and `OwnerID` in ctx, application key → 401 | 100 / 180 | 11 |
| 13 | S5c selector | `pkg/app/proxy/{store_selector,store_scope}.go` (C). `pkg/app/proxy/routing.go` (M: extract `candidatePipeline`, `listingAbsent` without fallback for the store). `pkg/domain/routing/candidate.go` (M: `SourceFallback`, `FallbackOnly`), `pkg/app/routing/resolver.go` (M: use the domain const). Tests: worked-example table, every intent kind, priority vs specificity, pool alias errors, N = 0, benchmark with N = 10 | 150 / 220 | 11 |
| 14 | S5d handler | `proxy_handler.go` (M: `handleStore`, shared forward tail, `WithStore`). `pkg/app/proxy/forwarder.go`, `routing.go` (M: `ForwardInput.Keep`, resolve when set). `list_models.go` (M: `ListModelsInput.Keep`), `store_models.go` (C). `modules/proxy.go` (M). Tests: handler store path (models union, 403, `ConsumerID` and trace stamped after selection), forwarder never routes a substituted LB route or fallback, slug path unchanged with `Keep == nil` | 110 / 180 | 12, 13 |
| 15 | S5e functional | `tests/functional/llm_store_test.go` (C): worked example end to end (chat and `/store/v1/models`), A's fallback serves only A's requests, attach/detach/priority change re-selects with the same key, revoke → 401, application key on store → 401, personal key on `/<slug>/v1` and MCP → 401, no personal consumer → 404, hybrid → 404, second create → 409, rotate keeps id and links, `partition: key` 429 across two consumers. DB-less variant through `TestDBLessDataPlane`. `docs/llm-store.md` (C) | 0 / 320 + 50 docs | 6, 8, 10, 14 |
| 16 | S6 metrics | `snapshot_metrics.go` (C), `dispatcher.go:231-319` (M). Tests: manual reader, once per publish, none on a dedup, `personal_links` count | 75 / 65 | 5 |

About 4,600 hand-written lines. PRs 1, 2 and 7 start from `develop` in parallel; 3, 4 and 5 fan out from 2; 11 needs only 5.

## Testing strategy

| Layer | What | How |
|---|---|---|
| Unit: domain | `ParseAudience`, personal ⇒ LLM, default-model rule, `ParseGrantLevel`, `AuthLink.Validate`, `ValidateAuthConfig` matrix, `ValidateOwnedExpiry` edges (now, +90 d, +90 d +1 s), `Candidate.FallbackOnly`, golden JSON bytes for application entities | table tests |
| Unit: use cases | associator link validation and upsert; updater 422s; creator hybrid and default; rotator/updater DD14; `PersonalKeys`; `StoreKeyResolver`; `StoreSelector` (worked example, every intent kind, ordering keys one at a time); `StoreModels` union and dedupe | `mockery --with-expecter` mocks for `Resolver` and `ModelListing`, `cache.NewTTLMapManager`, injected clock |
| Unit: `Data` / handler / middleware / forwarder | link index build and order, inactive left out, `bySlug` skip, 404 order with a `fakeDataFinder` asserting no call, store path in the handler, `Keep` excluding LB routes and fallback, D11 rejections, DD15 subscriber clears `auth_key` | `go test -race`; concurrent readers on one `Data` |
| Unit: plugin | subject choice (R1), calendar keys and TTL, 503 enforce / pass observe (R2), 403 unpriced, config rejections | miniredis (`plugin_test.go:36-49`), `mr.Close()` for the outage |
| Integration (`PG_TEST_URL`) | three migrations up/down twice; partial unique index; `consumer_auth_grant_check`; `ExcludeOwned`/`OwnerID`; `Update` never writes `owner_id`/`audience`; attach upsert updates a link and leaves the key's other links; `auth_links` read; concurrent create ×2 → one key | `tests/functional/repositories/*`, `make test-repositories` |
| Functional (`-tags functional`) | PR 10 handler flow, PR 15 end to end on both planes with a seeded catalog listing | admin JWT with `user_id` (`setup_test.go:128` key), provider stub from `proxy_e2e_test.go` |

Before each push: `make test`, `go test -race ./pkg/...`, `go vet -tags functional ./...`, `make test-repositories`, then the CI functional check.

## Migration / rollout

1. DataCore D1 in prod before PR 1 deploys (events carry `auth_id`).
2. TrustGate on every plane (admin, proxy, MCP, DB-less DPs) before the app creates any personal consumer. An older DP ignores `audience`/`owner_id`/`auth_links` and would serve a personal consumer at `/<slug>/v1`.
3. The app ships `LlmStoreGrant`, the reconcile (sending `{level, priority, granted_at}` on attach) and the Portal (ENG-1710/1704).
4. No flag: inert until a personal consumer exists. S0 is the only behaviour change (release note).

Rollback: as in the proposal (disable `partition: key` policies; `UPDATE consumers SET active = false WHERE audience = 'personal'`; optional cleanup of owned keys). The columns may stay.

## Open questions

| # | Question | Default taken |
|---|---|---|
| Q1 | A key with no links → 403 `model_not_allowed` on chat and an empty `/models`, rather than 401 (proposal OQ1). | 403 / empty list. |
| Q2 | Substitution counts `user`-level primary registries only, not their fallback backends (OQ2). | Primary only. |
| Q3 | `VerdictUnknown` lets a registry without an allow-list admit any short model (OQ3). | Accept; document in `docs/llm-store.md`. |
| Q4 | If a gateway becomes hybrid after personal consumers exist, they stay and `/store/v1` answers 404. Should the entitlement re-stamp deactivate them? | No; the app cleans up. |
| Q5 | PO sign-off on the 503 (R2). | Assumed. |
