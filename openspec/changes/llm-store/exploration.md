# Exploration: llm-store (RUN-1763)

> Only S0, S1, S2 and S6 below still apply. S3, S4 and S5 (the synthetic store consumer, `owner_groups`, grants in `store_grants`, the per-key view cache) are superseded by option C in [`proposal.md`](./proposal.md): real personal consumers, one personal key linked to each of them, and per-request selection on the data plane.

SDD phase: **explore**. Branch `feat/llm-store` cut from `origin/develop` @ `1ea70e06` (HEAD == origin/develop at exploration time). Date: 2026-10-02. TrustGate slices S0–S6 only; DataCore D1/D2 are a separate PR.

The Decision section of the issue is binding and is not re-opened here: Store flow for models, a synthetic LLM Store consumer at `/store/v1/*`, one personal `api_key` auth per user per gateway with `owner_id`/`owner_groups` riding the snapshot, grants in `store_grants`/`store_access_policies` with a `plane` column, the effective view computed and cached on the DP per key until the next snapshot, the snapshot as the only CP↔DP channel, no new tables, OSS unchanged, no Roles. Evidence from the older dossier (`cce30c93`) was re-verified at `1ea70e06`; line numbers below are HEAD.

## Exploration: TrustGate (Go)

### Current State

#### S0. Proxy API-key resolver ignores expiry

- `APIKeyIdentityResolver.Resolve` (`pkg/api/resolver/api_key_resolver.go:32`) hashes once (`:44`) and scans `rc.Auths`, accepting `a.Enabled && a.Type == TypeAPIKey && a.KeyHash == hash` (`:45-46`). No `ExpiresAt` check. Returns `AuthContext{Principal{Subject: a.Name, Method: api_key}, AuthID: a.ID, …}` (`:55-66`); no match → 401 if the consumer has an api_key attached (`:68`), else 403 (`:71`). Struct is empty (`:26`), wired at `pkg/container/modules/api.go:196`.
- `Auth.IsExpired(now)` (`pkg/domain/auth/auth.go:122`) has exactly one non-test caller: `key_finder.live` (`pkg/app/auth/key_finder.go:72-79`, `time.Now().UTC()` inline at `:76`). No clock injection anywhere in `pkg/api/resolver` or `pkg/app/auth`.
- `apiKeyAttachedElsewhere` (`pkg/api/middleware/auth.go:196`) scans every consumer for an enabled hash match, also without expiry → an expired key attached elsewhere answers 403 instead of 401.
- Snapshot side: the compiler ships every auth row, expired included (`compiler.go:462-463` bulk, `:725` per gateway); `readmodel.buildAuths` indexes `TypeAPIKey && Enabled && KeyHash != ""` regardless of expiry (`pkg/runtimeconfig/snapshot/readmodel/snapshot.go:254-265`). Postgres `FindByAPIKeyHash` filters `enabled` only (`pkg/infra/repository/auth/repository.go:156-160`).
- Tests: `pkg/api/resolver/api_key_resolver_test.go` (`:73`, `:91`, `:102`) — no expiry case; expiry cases exist only for the finder (`key_finder_test.go:87,104,123`).

#### S1. Telemetry has no auth id; principal subject is the key name

- `stampConsumerTrace(c, rc)` (`pkg/api/handler/http/proxy/proxy_handler.go:419-431`) sets consumer id/name and `SetPrincipalIdentity(p.Subject, p.Method, p.Email())` from the context principal. `authCtx` (with `AuthID`) is in hand one line above (`:149`) but is not passed.
- Trace metadata `pkg/infra/trace/trace.go:27` (`ConsumerID/Name` `:30-31`, `PrincipalSubject/Method/Email` `:43-45`; `SetPrincipalIdentity` `:150` ignores empty values). Event `pkg/infra/metrics/events/event.go:23` (`PrincipalSubject…` `:30-32`, `Consumer` `:40`) — no `auth_id`. Builder copies meta at `pkg/app/metrics/builder.go:68-84`. OTLP constants `pkg/infra/telemetry/otlp/mapping.go:70-74` (`trustgate.consumer.id`, `trustgate.principal.subject`, …), emitted `:202-206`. Contract doc `docs/telemetry/otlp-metadata-contract.md:52-56`.
- `principal_subject` = owner id for personal keys falls out for free if the store resolver builds `Principal{Subject: auth.OwnerID}`: the stamp reads the principal from context.
- Tests: `pkg/app/metrics/builder_principal_method_test.go:35`, `pkg/infra/telemetry/otlp/mapping_test.go:325`, `proxy_handler_test.go`.

#### S2. `token_rate_limiter` has no owner partition, rolling TTL windows, fails open

- Files: `pkg/infra/plugins/tokenratelimit/{config,keys,budget,plugin,responses,scripts,data}.go`.
- Config (`config.go:58-71`): `Unit` (tokens|dollars `:28-29`), `Rules[]{Model,Max,TimeWindow}` (`:47`), `Aggregate{Max,TimeWindow}` (`:53`), `CustomPricing` (`:68`), `GroupByHeader` (`:70`). No partition field. `validate()` `:110-189`; `parseWindow` `:191-224` accepts `s|m|h|d` only, floor 60 s.
- Keys (`keys.go:17-27`): `trl:<cfgID>:<dimension>:<subject>[:hdr:<v>]` + `:model:<slug>`; no period component. Window = TTL set on first write (`scripts.go:19`, `EXPIRE` when `TTL == -1`) → fixed-from-first-spend, not calendar.
- Scope: `RuntimeScope{GatewayID, ConsumerID, Global}` (`pkg/app/plugins/plugin.go:248`), `Subject()` (`:257`) → `global`|`consumer`; built by `scopeFromRequest` (`executor.go:443`, called `:187`, `:390`) from `RequestContext` (`pkg/infra/context/request_context.go:52`), which has **no** auth id / owner. The proxy handler builds `reqCtx` at `proxy_handler.go:174-175` and copies only `PlaygroundVerified` from `authCtx` — the injection point.
- Flow: `Execute` (`plugin.go:82`; early 200 when `Provider == ""` `:83`; `in.Scope.Subject()` `:92`; key base `:96`) → `preRequest` (`:108`; `modelFor` `budget.go:159`; cost cap `:121`) → `budgetGate` (`budget.go:171`; Redis `Get` `:201`; on error `counterUnavailable` `:213` → `appplugins.HandleCounterFailure` `pkg/app/plugins/counter_failure.go:73`, always fail-open) → `handleExceeded` (`:259`) → `budgetExceededError` 429 (`responses.go:72-85`). Post: `accrue` (`budget.go:347`), dollars `accrueDollars` (`:410`) prices with `llmcost.Resolve` (`:431`); **unpriced → warn + accrue $0** (`:432-444`), pinned by `TestPlugin_DollarBudget_UnpricedModelAccruesZero` (`plugin_budget_test.go:165`).
- Status mapping: `*appplugins.PluginError{StatusCode, Type, Body}` (`pkg/app/plugins/errors.go:41`) → `pluginErrorResult` (`pkg/app/proxy/plugin_runner.go:58,312`). A non-`PluginError` fails open in non-blocking modes (`executor.go:397`), so 503/403 must be `PluginError`s. 403-with-JSON template: `llmcost.CostCapError` (`pkg/infra/plugins/llmcost/costcap.go:194`).
- Calendar-period pattern to copy: `pkg/app/ratelimit/meter.go:46` (`monthWindowLayout = "2006-01"`), `:357` `quotaWindow(now)`; `pkg/infra/ratelimit/store.go:35` (period in key), `:258-264` `quotaTTL` (TTL to period end, floor).
- Pricing resolution: `llmcost.Resolve(ctx, resolver, custom, registryRates, provider, models...)` (`pkg/infra/plugins/llmcost/pricing.go:151`; custom `:153`, registry `:158`, catalog `:168-190`).
- Catalog/docs to update: `pkg/app/plugins/catalog_metadata.go:142-273` (description says fail-open `:145`), `docs/policies.json:112`, `docs/telemetry/otlp-metadata-contract.md:328-360`.
- Tests: `plugin_test.go` (scope `:186-253`, fail-open `:332-380`), `config_test.go:111,320`, `keys_test.go:23,63`, `plugin_budget_test.go:85,165`, `pkg/app/plugins/catalog_test.go:225-289`, miniredis helpers `plugin_test.go:36-49`.

#### S3. Data model, snapshot, admin exclusion

- **Auth**: `Auth` (`pkg/domain/auth/auth.go:99-118`) has tagged JSON (`id`, `gateway_id`, `name`, `type`, `enabled`, `config`, `expires_at,omitempty` `:115`); `KeyHash`/`KeyPrefix`/`KeySuffix`/`RawKey` are `json:"-"`. `NewAPIKeyAuth` `:150`, `SetExpiry` `:172`, `RotateAPIKey` `:196`. Port `pkg/domain/auth/repository.go:27-37` (`ListFilter{GatewayID, Search, Type, Enabled, Page, Sort}`; `List`, `FindByAPIKeyHash`, `ListEnabledByGatewayAndType`, …). Postgres: 12-column SELECT repeated at `repository.go:140,156,177,210,241,288`, INSERT `:73-80`, UPDATE `:96-107`, `scanAuth` `:320-332`, all writes inside `withMarkedTx` (`:54`, outbox marker). ADD COLUMN template: `migrations/20260922120000_add_auth_expires_at.go:37,43`. Latest migrations share `20261001120000` → use `20261002…`.
- **Store tables**: `store_grants` PK `(gateway_id, catalog_code, registry_id)` with nil-uuid default (`migrations/20260908120000_add_store_grants.go:36-48`); `store_access_policies` PK `(gateway_id, principal_type, principal_id)` (`20260908140000_add_store_access_policies.go:35-42`). `ON CONFLICT` targets: `pkg/infra/repository/storeaccess/grants_repository.go:90`, `policies_repository.go:73`.
- **Grant domain** (`pkg/domain/storeaccess/grant.go`): `Grant{GatewayID, CatalogCode, RegistryID, Groups, Users}` (`:55`), `Validate` requires `CatalogCode` (`:93`), **hand-written wire form** `grantJSON` + `MarshalJSON`/`UnmarshalJSON` (`:101-138`) — a new field that is not added there is silently dropped from the snapshot. `Allows(groups, subject)` (`:148`) is reusable as-is. `Set`/`Index` (`:262/:271`) index by code and registry, no plane.
- **Store policy domain** (`pkg/domain/storeaccess/policy.go:44`): no JSON tags, no marshaller → a new field rides as `"Plane"`. `PolicySet.Mode(subject, groups)` (`:144-163`): **the user's own policy wins outright (an explicit `none` included); otherwise the most permissive group wins** (`modeRank` `:166`: open 2 > curated 1 > none 0); otherwise `""`. Fallback chain (`pkg/app/store/mode.go:70-82,124`): token claim `store_access` → `gw.StoreMode()` (metadata `store_mode`, `pkg/domain/gateway/gateway.go:60-97`, default curated) → curated; lookup error fails closed to curated (`:74-76`).
- **MCP-catalog coupling**: `grantService.Set` (`pkg/app/store/grants.go:75-110`) checks `catalog.GetByCode` (`:80`, MCP catalog, `CatalogReader` `installer.go:64`) and instance membership (`:84-89`). MCP readers of grants/policies (all would see llm rows if readers are not plane-filtered): `installer.go:438,446,473,515`, `scoper.go:184,202`, `registry_reader.go`, `pkg/app/mcp/store_tool.go`, `pkg/api/handler/http/store/{grants,policies}_handler.go`. Registry deletion already cleans grants by registry (`pkg/app/registry/deleter.go:101` → `grants_repository.go:116`), which covers llm grants for free.
- **Snapshot**: proto carries `Auth{bytes json; string key_hash}` (`snapshot.proto:97`), `StoreGrant{bytes json}` (`:83`), `StorePolicy{bytes json}` (`:89`); codec encodes/decodes domain JSON (`pkg/infra/configsnapshot/codec.go:92-115`, `:172-199`) → **no proto change** for new JSON-tagged fields. DP clones are JSON round-trips (`adapters/adapters.go:46-56`). Read model: `StoreGrantsByGateway` `:164`, `StorePoliciesByGateway` `:158`, `AuthByAPIKeyHash` `:475`, `AuthsEnabledByGatewayAndType` `:497`. `omitempty` on new fields keeps every existing entity byte-identical (no fleet-wide version churn), as `mcp_wide` did.
- **Admin exclusion**: the compiler reads auths through the same `List` (`compiler.go:462,725`, `auth_reader.go:23`) → filtering owned keys in the repo's default `List` would **drop them from the snapshot**. The exclusion must be an opt-in filter set by the handler. Routes `admin_router.go:250-256`; list handler `pkg/api/handler/http/auth/list_auth_handler.go:61-93`; `AuthResponse` `response/auth_response.go:26`. Pickers/attach that must refuse owned keys: `pkg/app/consumer/associator.go:118` → `authInGateway` `:253`; `pkg/app/consumer/updater.go:189-199`; `pkg/app/policy/warnings.go:285` (api-key reach). OSS frontend uses only `/auths` CRUD + attach (`frontend/src/components/entities/{consumers-view,auth-view}.tsx`).

#### S4. Self-only principal endpoints

- Store group: `gw.Group("/:gateway_id/store", RequireGatewayAccess(ResourceRegistries))` (`pkg/server/router/admin_router.go:227`) under `AdminAuth.Middleware()` (`:168`); principal routes `:243-246`; wiring `pkg/container/modules/store.go:193` (`NewPrincipalHandler`).
- Self-only pattern: `ConnectLink` (`pkg/api/handler/http/store/principal_handler.go:229`) → `caller := callerSubject(c); if caller == "" || caller != principalSub` → `ErrForbidden` (`:252-254`); same in `ConfigureLink` (`:319`). `callerSubject` (`requests_handler.go:212`) reads `UserIDContextKey`, set by `StoreAdminIdentity` (`pkg/api/middleware/admin_identity.go:77-80`) from the console JWT (`admin_auth.go:140`, `Subject = claims.UserID`) or a service token (`:110`). `RequireInteractiveIdentity()` (`admin_authz.go:108`) rejects service credentials.
- **No trusted group source on the admin plane**: the console JWT carries subject/email only; existing Store calls take groups from the request body (`request` `Install.Groups` `:33`, `ConfigureLink.Groups` `:63`).
- Key lifecycle to reuse: `pkg/app/auth/{creator,rotator,deleter}.go` — each sets/deletes `AuthTTLName` + `AuthKeyTTLName`, publishes `invalidation.GatewayData`, and calls `signaler.Signal` (creator `:78-84`, rotator `:112-118`, deleter `:78-84`).

#### S5. No LLM entry on the Store; key → consumer is path-first

- **Path**: `ResolveProxyPath` (`pkg/api/resolver/proxy_path_resolver.go:69-78`) cuts the first segment → `/store/v1/chat/completions` parses as slug `store`, chat capability. Consumer slugs are exactly 8 alphanumerics (`pkg/domain/consumer/slug.go:23,52`) → no collision.
- **Auth middleware** (`pkg/api/middleware/auth.go:56-101`): gateway (`:58`, host or `X-AG-Gateway-Slug`, `gateway_resolver.go:32,104,151`) → path (`:65`) → `dataFinder.FindByGateway` (`:69`) → `data.MatchSlug` (`:73`, 404 on miss; **the store branch slots here**) → `resolver.Resolve` (`:78`) → overwrite gateway/consumer ids (`:89-91`) → `consumerAdmitsCaller` (`:92`) → `attach` (`:169-194`: locals + `WithAuthContext`, `WithPrincipal`, `WithAuthID`, `WithData`, `WithConsumer`). Auth is a global `app.Use` (`pkg/server/router/proxy_router.go:74-75`; chain `pkg/container/modules/server_proxy.go:48-57`), so a separate route group would have to be registered before it.
- **Hash lookup that already exists**: `APIKeyFinder.FindByAPIKey` (`pkg/app/auth/key_finder.go:47-62`; `auth_key` TTL 5 min, cleared on snapshot apply; repo = snapshot `AuthByAPIKeyHash` on DB-less via `adapters/auth_repository.go:57`, Postgres on full; expiry in `live`; **no negative cache**). Precedent with explicit gateway check: `pkg/app/consumer/api_key_consumers.go:156-164` (`!Enabled || Type != api_key || GatewayID != gatewayID`). The MCP plane trusts `auth.GatewayID` without comparing to the host (`auth_chain.go:370-383`, `mcp_auth.go:70`) — the global index spans tenants, so the store path must compare.
- **Handler**: `resolveConsumer` (`proxy_handler.go:358-388`) prefers `ConsumerFromContext` (so the middleware can hand it the view), rejects `Type != LLM && != ""` (`:381`), then `isAuthorizedForConsumer` (`:455-487`) requires `consumerHasAuth(rc, authCtx.AuthID)` over `rc.Consumer.AuthIDs`. `/v1/models` → `handleModels` (`:170,390`) → `pkg/app/proxy/list_models.go:89-124`, driven only by `rc` + `Data`.
- **Synthetic consumer pattern**: `pkg/domain/consumer/store.go:22-72` (`StoreSlug = "store"`, MCP sentinel `570e570e-…`, `IsStoreConsumer` by ID `:42`, `BuildStoreConsumer` `Type: TypeMCP`). `IsStoreConsumer` drives MCP-only behaviour (`identity.go:66` sign-in, `rpc_dispatcher.go:152,184,219`, `credentials.go:586`, `oauth/connect.go:554`, admin list `list_consumer_handler.go:145-175`) → the LLM Store needs **its own sentinel**; reusing the MCP one would light those paths.
- **Data load** (`pkg/app/consumer/data_finder.go:101-157`): `loadBackends` (`:284-308`) loads only registries referenced by consumers; `loadPolicies` (`:321`) splits `everywhere` (global) / `onMCP` (global + MCP-wide) / `byConsumer`; `loadAuths` (`:349`) only consumers' auth ids. `plansFor` (`:179-188`) gives non-MCP consumers `inertPolicies` + `NewInertStagePlan` (`pkg/app/plugins/plan.go:52`); `PolicyPlan` must never be nil for non-MCP (`consumer_data.go:33-41`). MCP `StoreConsumer` built at `:148-154` from `onMCP`. `Data` (`consumer_data.go:54-60`) is cached per gateway in `ConsumerDataTTLName` (1 h), flushed by `ClearAllTTLMaps` on every snapshot apply (`pkg/container/modules/config_sync_data.go:111-115`; `pkg/runtimeconfig/sync/worker.go:140-169`) and on the full plane by `InvalidateGatewayDataEvent` (`pkg/infra/cache/subscriber/invalidate_gateway_data_event_subscriber.go:61-90`). Registry port has no `ListByGateway` (`pkg/domain/registry/repository.go:31-40`); `List(ListFilter{GatewayID})` works on both planes (`adapters/registry_repository.go:75`). DI: `NewDataFinder` (`data_finder.go:49`, `modules/consumer.go:89`); `storeaccess.Reader`/`PolicyReader` are bound on both planes (`modules/core_data.go:89-94`, `modules/store.go:54,79`).
- **Narrowing surface**: routing reads `rc.Registries` + `rc.Consumer.ModelPolicies` (`pkg/domain/consumer/consumer.go:75`; `model_policy.go:26-31,93`) in `pkg/app/routing/resolver.go:62-127`; provider enforcement `adapter.EnforceModel` (`pkg/app/proxy/provider.go:364,601,740`); zero-intent stamps `ModelPolicies.For(bk.ID)` (`routing.go:516-531`). ModelPolicies live on the **domain consumer**, so a view needs its own cloned `*domain.Consumer`.
- **LB trap (confirmed)**: `loadBalancerCache.For` keys `gatewayID:consumerID` (`pkg/app/proxy/load_balancer_cache.go:58-59,169`), pools `…:pool:<alias>` (`:65-69,173`); zero intent returns nil candidates (`routing.go:60-61`) and `nonCandidateRoutes(nil)` excludes nothing (`:455-463`) → every view under one sentinel would share the first view's LB. Pool ID = key (`:82`); health keys are per registry. LBs close on evict (`modules/cache.go:71-76`); full-plane invalidation drops `gw:` prefix (`subscriber :74`).
- **Snapshot version on the DP**: `ConfigStore.Version()` (`pkg/runtimeconfig/sync/configsync.go:29-36`); per-version cache precedent `adapters/playground_keys.go:29-68`. But since `Data` is rebuilt after every apply, a cache **inside `Data`** is keyed by snapshot version implicitly.

#### S6. Snapshot size is only logged

- Publish: `dispatcher.compile` (`pkg/app/configsnapshot/dispatcher.go:278-319`) encodes catalog once (`:286`) and per scope (`:296-300`); publish under mutex `:241-266` with the log "published config snapshot" (version, duration, bytes `:261-265`). Raw bytes in `raw` / `scoped[scope].Raw` (`:231`).
- Metrics: OTel global meter only (`pkg/infra/o11y/otel.go:114`); closest pattern `pkg/app/configsnapshot/tenant_caps_metrics.go:29` (`otel.Meter("trustgate/configsnapshot")`); struct-of-instruments `pkg/app/ratelimit/metrics.go:41`. Tests: `dispatcher_test.go` (`TestDispatch_BroadcastsOnceThenDedupsIdenticalData`).

### Affected Areas

| Slice | Path | Why |
|---|---|---|
| S0 | `pkg/api/resolver/api_key_resolver.go:45-46` (+ `_test.go`) | skip expired keys (→ 401 via `:68`) |
| S0 | `pkg/api/middleware/auth.go:196-213` | same expiry skip so an expired key never yields 403 |
| S0 | `CHANGELOG`/release note | OSS-visible: expired admin keys now rejected on `/<slug>/v1/*` |
| S1 | `pkg/infra/trace/trace.go`, `pkg/infra/metrics/events/event.go`, `pkg/app/metrics/builder.go`, `pkg/infra/telemetry/otlp/mapping.go`, `proxy_handler.go:154,419-431`, `docs/telemetry/otlp-metadata-contract.md` | `AuthID` field → `trustgate.auth.id` |
| S2 | `tokenratelimit/{config,keys,budget,plugin,responses}.go`, `pkg/app/plugins/plugin.go:248-257`, `executor.go:443`, `pkg/infra/context/request_context.go:52`, `proxy_handler.go:174`, `catalog_metadata.go:142-273`, `docs/policies.json` | owner partition, calendar windows, fail-closed, `model_unpriced`, reject `custom_pricing` |
| S3 | `migrations/2026100212xxxx_add_auth_owner.go`, `…_add_store_plane.go` | `auths.owner_id`, `owner_groups`, partial unique `(gateway_id, owner_id) WHERE owner_id IS NOT NULL`; `plane` + `models` on grants, `plane` on policies, PK swaps |
| S3 | `pkg/domain/auth/{auth,repository}.go`, `pkg/infra/repository/auth/repository.go` | fields, `ListFilter.ExcludeOwned`, `FindByOwner(gw, owner)` |
| S3 | `pkg/domain/storeaccess/{grant,policy}.go`, `pkg/infra/repository/storeaccess/*`, `pkg/app/store/{grants,policies}.go` | `Plane`, `Models`, plane-filtered readers, llm grant validation (registry exists, `TypeLLM`, model globs) |
| S3 | `pkg/runtimeconfig/snapshot/readmodel/snapshot.go`, `adapters/store_grant_reader.go` | split grants/policies by plane |
| S3 | `list_auth_handler.go`, `associator.go:253`, `consumer/updater.go:199`, `policy/warnings.go:285` | exclude / refuse owned keys |
| S4 | `pkg/app/store/model_key.go` (new), `pkg/api/handler/http/store/model_key_handler.go` (new) + `request/`, `response/` DTOs, `admin_router.go:243-247`, `modules/store.go` | GET/POST/DELETE (+ rotate) self-only; PUT groups |
| S5 | `pkg/domain/consumer/llm_store.go` (new) | sentinel id, `TypeLLM`, `IsLLMStoreConsumer` |
| S5 | `pkg/app/consumer/llm_store.go` (new), `data_finder.go:101-157,284`, `consumer_data.go:54-60` | per-gateway LLM index built at load; per-key view cache in `Data` |
| S5 | `pkg/api/middleware/auth.go:73` | `/store/*` branch: key → auth → checks → view → `attach` |
| S5 | `pkg/app/consumer/consumer_data.go:26` + `load_balancer_cache.go:58-73,169-175` | `RoutableConsumer.BalancerKey` (view fingerprint) in LB key |
| S6 | `pkg/app/configsnapshot/dispatcher.go:231-266`, new `snapshot_metrics.go` | bytes per flavour + entity counts |

### Approaches

#### S5-K: key → auth on `/store/v1`

1. **K1 — `APIKeyFinder.FindByAPIKey` + explicit checks** (`Enabled`, `Type`, `OwnerID != ""`, `GatewayID == resolved gateway`, expiry in `live`), mirroring `api_key_consumers.go:156-164`.
   - Pros: matches the issue's request path (snapshot `authsByAPIKeyHash` on DB-less, Postgres on full); zero new ports; warm hit is one TTLMap get.
   - Cons: full plane has no negative cache (every unknown key = one Postgres query) and the `auth_key` cache is not evicted cross-process (`invalidate_gateway_data_event_subscriber.go` never touches `AuthKeyTTLName`) → a revoked key lives ≤ 5 min on another full-plane proxy. Mitigated by refusing `/store/*` with 404 **before** the lookup when the gateway has no LLM store (always true in OSS).
   - Effort: S.
2. **K2 — owned keys indexed inside `Data`** at load (`ListEnabledByGatewayAndType(gw, api_key)` filtered by `OwnerID != ""`, map by hash).
   - Pros: zero DB per request on both planes, gateway-scoped by construction, revocation follows `Data` invalidation (immediate cross-process on full plane).
   - Cons: diverges from the issue's stated path; every `Data` rebuild clones all of the gateway's api keys (JSON round-trip on DB-less).
   - Effort: S.

#### S5-V: where the per-key view lives

1. **V1 — inside `Data`** (`sync.Map` keyed by `auth_id`, plus the gateway's precomputed LLM index: llm grants, llm `PolicySet`, LLM registries, store plan).
   - Pros: `Data` is rebuilt after every apply and dropped by the full-plane gateway event, so "(auth_id, snapshot version)" holds without storing a version, no new TTLMap registration, no subscriber changes; bounded by keys of one gateway.
   - Cons: `Data` gains a mutable field (needs sync; `Data` is shared).
   - Effort: S.
2. **V2 — named TTLMap `llm_store_view` keyed `gw:auth_id`.**
   - Pros: same idiom as other caches.
   - Cons: must also be added to `ClearAllTTLMaps` consumers (automatic), the full-plane subscriber (`DeleteByPrefix`), `gateway/deleter.go:65-66` and `invalidate_registry_cache_event_subscriber.go:47-48` — four places to forget.
   - Effort: S/M.

#### S5-LB: LB keyed by view

1. **LB1 — `RoutableConsumer.BalancerKey`** = hash of the view's sorted registry ids; `loadBalancerCacheKey` appends it when set (keep the `gw:` prefix). Views with the same registry set share one LB → LB count bounded by distinct grant shapes, not users. Effort: S (~20 lines).
2. **LB2 — refuse zero/`auto`/`pool:` intents on `/store/v1`** (400) so the LB is never reached. Smaller, but changes client semantics vs `/<slug>/v1`.

#### S3-G: how an llm grant is keyed

1. **G1 — PK `(gateway_id, plane, catalog_code, registry_id)`, llm rows `catalog_code = ''`, `registry_id` required**; `Validate` branches on plane. Readers default to `plane = mcp`.
2. **G2 — keep PK, put a sentinel code (`llm`) in `catalog_code`.** No PK change, but every MCP reader that indexes by code sees a fake code unless filtered; fails open.

#### Mode precedence for the llm plane

1. **M1 — reuse `PolicySet.Mode` unchanged per plane** (own policy wins, incl. `none`; groups most permissive; else gateway default) and read "None wins" as "an explicit user `none` wins"; under `none` the view is empty (unlike MCP, where `none` keeps grants, `scoper.go:184-202`).
2. **M2 — add a strict variant where any group `none` beats other groups.** Matches the literal spec, diverges from the MCP Access page semantics the console already renders.

### Recommendation

K1 (gated by "gateway has an LLM store") + V1 + LB1 + G1 + M1: each is the smallest change that keeps OSS byte-identical and the warm request at 0 DB / 0 gRPC; M1 needs a one-line product confirmation (open question 1). Ship as chained PRs: S0+S1 → S3 → S2 → S4 → S5 → S6.

### Risks

- **Snapshot starvation**: excluding owned keys in `auth.Repository.List` drops them from every snapshot (`compiler.go:462,725`). The filter must be opt-in.
- **Grant wire form**: `Plane`/`Models` not added to `grantJSON` (`grant.go:101-138`) are silently lost on the DP. Codec round-trip test required (`codec_test.go`, `TestGrantJSONRoundTrip`).
- **MCP readers see llm rows** unless `ListByGateway`/`ListPoliciesByGateway` default to `plane = mcp` (installer, scoper, registry_reader, store_tool, handlers). Fail-closed default is the reader, not each caller.
- **PK swap** on two live tables: `ON CONFLICT` targets (`grants_repository.go:90`, `policies_repository.go:73`) change in the same PR; Down must delete llm rows before restoring the old PK.
- **Sentinel reuse**: using the MCP Store id for the LLM Store lights MCP-only paths keyed on `IsStoreConsumer`.
- **LB leak** if `BalancerKey` is forgotten on any view (zero intent shares the first caller's registry set).
- **Group source**: groups on a self-only endpoint would let a user assert their own groups (privilege escalation). `owner_groups` must come only from a non-human identity (open question 3).
- **Fail-closed scope creep**: `HandleCounterFailure` is shared by every counter plugin; the 503 must be a local branch under `partition=owner`, not a change to the helper. PO ack required (issue open question).
- **Every key write recompiles and flushes all DP caches** (`config_sync_data.go:111-115`); S6 makes the cost visible, it does not reduce it.
- **Full-plane `auth_key` not evicted cross-process** (subscriber gap); harmless in OSS (no personal keys), relevant for any full-plane commercial deploy.
- **Release note** for S0: OSS admin keys with past `expires_at` start failing on `/<slug>/v1/*`.

### Code vs issue

- "Policies attached to the Store" has no storage: `consumer_policy.consumer_id` has an FK to `consumers` and the Store is not persisted. Today only gateway-wide placements reach a synthetic consumer. v1 = `everywhere` (globals) through `plansFor`'s non-MCP branch; MCP-wide must **not** reach it.
- "Groups combine by union; explicit None wins" vs `PolicySet.Mode`: groups combine by most-permissive (a group `none` loses), the user's own policy wins outright. See M1/M2.
- MCP `none` keeps explicit grants (`gateway.go:74-77`, `scoper.go:184-202`); the LLM spec wants `none` to reach nothing.
- The issue lists `/auths` + pickers; code also refuses via `associator.authInGateway` and `consumer/updater.go:199` — both need the owned-key check or a user key could be attached to an application consumer.
- `RoutableConsumer` has no `InstanceOf`/`Backends`; ModelPolicies live on `domain.Consumer`.

### Open questions (with the answer the code suggests)

1. **"None wins" among groups?** Code: `PolicySet.Mode` → user `none` wins, group `none` loses to any other group. Recommend M1 (reuse) unless product needs group-`none` precedence.
2. **Gateway default for the llm plane — where?** No table allowed. Code precedent: gateway metadata `store_mode` (`gateway.go:60-97`). Use a second key (e.g. `llm_store_mode`), default `curated` (= grants only). Rides the snapshot with the gateway.
3. **Who calls `PUT …/model-key/groups`?** The console JWT carries no groups (`admin_auth.go:140`), so a self-only PUT would let users assert groups. Recommend: service/platform identity only (`RequireGatewayAccess(ResourceAuths)` scope `auths:write`, reject `AdminIdentityHuman`), body `{principal_sub, groups}`; POST creates the key with `owner_groups = null` until the first reconcile.
4. **What does `open` mean on llm?** All enabled `TypeLLM` registries of the gateway, no ModelPolicies (all models); needs `registryRepo.List(GatewayID)` at `Data` load because `loadBackends` only loads consumer-referenced registries (`data_finder.go:284-308`).
5. **Curated view shape?** Union of `Grant.Allows(owner_groups, owner_id)` llm grants; `ModelPolicies[reg].Allowed` = union of `models` globs, any grant with `models = null` → all models (no entry). Validate globs with `ModelPolicy.validate` (`model_policy.go:66`) at write time.
6. **Which PK for llm grants?** G1. Registry-level, `catalog_code = ''`; registry delete cleanup already works (`registry/deleter.go:101`).
7. **One key per user enforcement?** Partial unique index `(gateway_id, owner_id) WHERE owner_id IS NOT NULL` (an index, not a table) + `FindByOwner` for GET; POST on an existing key → 409, rotate keeps id (`RotateAPIKey` `auth.go:196`).
8. **Principal method for personal keys?** Keep `api_key` (MCP `PrincipalInert` rule unaffected; LLM never gates on groups today), `Subject = owner_id`, `Claims[groups] = owner_groups` so group-gated LLM policies stay possible later.
9. **`partition=owner` on a request without owner** (application key, playground)? `Subject()` errors on empty id (`plugin.go:257`) and non-`PluginError` fails open (`executor.go:397`). Recommend explicit pass-through (no counting) for owner-less requests, since store policies are globals that also run on every LLM consumer.
10. **Calendar window syntax?** `parseWindow` has no month (`config.go:191-224`). Add `calendar_month` / `calendar_day` values valid only with `partition=owner`; period in key + TTL to period end (`ratelimit/store.go:258-264`).
11. **Admin `GET/PUT/DELETE /auths/:id` on owned keys?** List excludes them; recommend 404 on get/update/rotate, allow delete as admin revocation (open for product).
12. **Hybrid gateways?** Out of v1: 404 on `/store/*` when `gw.ServedByHybridDataPlane()` (`gateway.go:125`).
13. **Admin consumer list** shows the MCP Store synthetic row (`list_consumer_handler.go:157`). Recommend not listing the LLM Store in v1 (console scope).

### LOC estimate (production + tests, excluding generated swagger/mocks)

| Slice | Prod | Tests |
|---|---|---|
| S0 | ~10 | ~50 |
| S1 | ~40 | ~70 |
| S2 | ~180 | ~240 |
| S3 | ~420 | ~380 |
| S4 | ~350 | ~320 |
| S5 | ~380 | ~420 |
| S6 | ~60 | ~60 |
| **Total** | **~1,440** | **~1,540** (≈3,000) |

Well over the 400-line review budget: chained PRs.

### Ready for Proposal

Yes. Open questions 1–3 are product/security confirmations with a code-derived default; the rest are answered above.
