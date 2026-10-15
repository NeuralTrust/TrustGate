# Proposal: LLM Store — personal keys on personal LLM consumers (RUN-1763)

Linear: [RUN-1763](https://linear.app/neuraltrust/issue/RUN-1763). Related: ENG-1710 (Access admin UI), ENG-1704 (employee Portal). Repo: TrustGate (Go), base `develop` @ `1ea70e06`. Slices S0–S6 only; DataCore D1/D2 ship separately.
Evidence: [`exploration.md`](./exploration.md) (S0, S1, S2, S6 still apply as written). This proposal encodes the binding **option C**: one personal key attached to **every** personal consumer the user has a grant for, and the data plane picks the consumer per request. It replaces the "exactly one personal consumer per key" revision. `design.md`, `specs/` and `tasks.md` follow this file.

## Intent

Employees call models through `…/store/v1/<rest>` with a **personal key**. The key leads to all of the user's personal consumers on that gateway. For each request the data plane picks one of them by grant level, priority, how specifically it allows the requested model, and grant age. The chosen consumer then serves the request through its normal registries, ModelPolicies, load balancer, fallback and policies. Admins shape access by creating **personal LLM consumers** and granting them to users, groups or everyone in the app (Prisma). TrustGate stores only the result: which consumers the key is attached to, and each link's level, priority and grant time.

## Binding design (user-agreed, option C)

| # | Rule |
|---|---|
| B1 | New column `consumers.audience text NOT NULL DEFAULT 'application'` (`application` / `personal`). `personal` is valid only for `TypeLLM`. A personal consumer is configured like any LLM consumer (registries, ModelPolicies, policies, budget). It must have a concrete default model on at least one of its registries (422). |
| B2 | Assignments of consumers to users, groups or everyone live in the app (Prisma `LlmStoreGrant`, below). **TrustGate gets no new tables and never reads assignments.** A key attached to a consumer *is* the authorisation. |
| B3 | **One personal key per user per gateway.** It is a normal `auths` row (`type = api_key`) with a new nullable `owner_id` (platform user id = token `sub`). Partial unique index `(gateway_id, owner_id) WHERE owner_id IS NOT NULL`: a second create → 409. |
| B4 | The key is attached through `consumer_auth` to **all** of the user's personal consumers of that gateway (N ≥ 0). The consumers **complement** each other; none is exclusive. The app reconcile attaches and detaches. There is no move operation, no exactly-one rule and no move transaction. |
| B5 | Each link of a personal key carries `level` (`user` / `group` / `all`), `priority` (int, default 1, from the grant) and `granted_at` (the grant's creation time, the stable tie-break). They are three nullable `consumer_auth` columns, and the snapshot carries them on the personal consumer as `auth_links` (`omitempty`). Application links are unchanged and leave the columns `NULL`. |
| B6 | Request on `/store/v1/*`: hybrid gateway → 404 before any key lookup. A gateway without active personal consumers → 404 for every caller but a personal key of that gateway, which goes on to the handler (403 `no_model_access`). Then SHA-256 → `APIKeyFinder` → auth (enabled, `api_key`, owner set, same gateway, not expired → else 401) → the key's links through an in-memory index built in consumer `Data` → consumer selection (B7) → the normal LLM path. O(1) to the links, in memory, no extra calls. |
| B7 | **Selection.** A `user`-level link **substitutes** `group`/`all` links **per provider**: for every provider that some `user`-level consumer of the key has a registry for, the `group`/`all` consumers' registries of that provider are ignored for this user. Among the remaining consumers that admit the request (the existing routing resolver per consumer, for every intent kind, with the catalog listing filter on short models), order = level (`user` < `group` < `all`) → priority (lower first) → match specificity (exact allow-list entry > glob > registry without an allow-list) → oldest grant. First wins; none → 403 `model_not_allowed`. No model → the first consumer by level, priority and age that has a default model. |
| B8 | `/store/v1/models` returns the union of the models of the key's effective consumers after substitution. |
| B9 | `/store/v1` accepts **only** owned keys. Application keys keep working on `/<slug>/v1` only. MCP Store unchanged. The snapshot is the only CP ↔ DP channel: no new gRPC, no DP-side Redis/DB lookups for keys. Same OSS binary, unchanged by default (nothing personal exists without the app). No Roles. |

### Out-of-repo dependency: app-side assignment (ENG-1710 / ENG-1704)

| Prisma `LlmStoreGrant` | Notes |
|---|---|
| `teamId`, `gatewayId`, `consumerId` | `consumerId` = a personal consumer of that gateway |
| `principalType` `USER` \| `GROUP` \| `ALL` | `USER` unique per (gateway, user); `ALL` unique per (team, gateway) |
| `userId?`, `groupId?` (FK `DirectoryGroup`) | set according to `principalType` |
| `priority` int, default 1 | sent as the link's `priority` |
| `createdBy`, `createdAt` | `createdAt` sent as the link's `granted_at` |

The app reconcile runs on key create, grant changes and group-membership changes. For each grant that reaches the user (`USER`, any of their groups, `ALL`) it attaches the user's key to the grant's consumer with `{level, priority, granted_at}` (`level` = `principalType` lower-cased). It detaches the key from consumers no grant reaches any more. On offboarding it revokes the key. Precedence is applied by the data plane (B7), not by the app.

## Scope

| Slice | What ships |
|---|---|
| **S0** Expiry + key cache | `APIKeyIdentityResolver.Resolve` (`pkg/api/resolver/api_key_resolver.go:45-46`) and `apiKeyAttachedElsewhere` (`pkg/api/middleware/auth.go:196`) skip `Auth.IsExpired(now)` keys. An expired key gets 401, never 403. The clock is injected. **Release note:** OSS application keys with a past `expires_at` stop working on `/<slug>/v1/*`. Also: `InvalidateGatewayDataEventSubscriber` clears the `auth_key` TTL map, so a rotated or revoked secret stops resolving on every full-plane replica at the next event (today ≤ 5 min lag). |
| **S1** Telemetry | `AuthID` on trace metadata → event `auth_id` → OTLP `trustgate.auth.id` (`trace.go:27`, `event.go:23`, `builder.go:68-84`, `otlp/mapping.go:70-74,202-206`). `stampConsumerTrace` (`proxy_handler.go:419`) receives `authCtx`. On `/store/v1` the principal is `Subject = owner_id`, so `principal_subject = owner_id` falls out of the existing stamp. Contract doc `docs/telemetry/otlp-metadata-contract.md:52-56`. |
| **S2** Budgets | `token_rate_limiter` gains `partition: key`: the counter is keyed by `owner_id` when the auth has one, else by auth id. Hard limits only under `partition: key` (D9). Calendar windows `calendar_month` / `calendar_day` (UTC) are valid only with `partition: key`. |
| **S3** Data model + admin rules | Migrations, domain, repository, DTOs and snapshot for `consumers.audience`, `auths.owner_id` and the three `consumer_auth` link columns. Validations (D3–D6). Admin `/auths` hides owned keys through an opt-in handler filter (D7). Admin attach takes the link attributes (D4). |
| **S4** Self-only key endpoints | Create / get / rotate / revoke the caller's own key (D8). Create attaches nothing; the app reconcile attaches. Admin revoke through the existing `DELETE /auths/:id`. |
| **S5** `/store/v1/*` | Routing branch, key → links, consumer selection, union model listing (D1, D2, D10, D13, D14). Personal keys are rejected everywhere else (D11). |
| **S6** Snapshot metric | Encoded bytes per flavour and entity counts (`auths`, `owned_auths`, `personal_consumers`, `personal_links`) on publish (`dispatcher.go:241-266`, pattern `tenant_caps_metrics.go:29`). |

Hybrid gateways are out of v1: `/store/v1/*` → 404 and creating a personal consumer → 422.

### Data model (columns and one index; no new tables)

| Table | Change | Wire form (snapshot JSON) |
|---|---|---|
| `consumers` | `audience text NOT NULL DEFAULT 'application'`, `CHECK (audience IN ('application','personal'))` | `"audience":"personal"` only when personal (`omitempty`). Existing consumers stay byte-identical. |
| `auths` | `owner_id text NULL`. Partial unique index `auths_gateway_owner_uniq (gateway_id, owner_id) WHERE owner_id IS NOT NULL`. | `owner_id,omitempty`. Application keys stay byte-identical. |
| `consumer_auth` | `level text NULL`, `priority integer NULL`, `granted_at timestamptz NULL`. One CHECK: all three `NULL` (application link), or `level IN ('user','group','all') AND priority >= 0 AND granted_at IS NOT NULL` (personal link). | On the consumer: `"auth_links":{"<auth_id>":{"level":"group","priority":1,"granted_at":"…"}}`, only for personal links (`omitempty`). `auth_ids` unchanged. |

Migrations are in-code (`20261005…`), idempotent, and one transaction each (template `20260922120000_add_auth_expires_at.go`). All are nullable or constant-default column adds, so there is no table rewrite. `consumer_auth` keeps its PK `(consumer_id, auth_id)`, `auth_id` RESTRICT (`20260617180000`) and same-gateway trigger (`20260622120000:40-42,67-70`).

## Decisions

| # | Topic | Decision | Rejected (why) |
|---|---|---|---|
| D1 | `/store/v1` routing | In `AuthMiddleware` (`auth.go:56-101`), after `ResolveProxyPath` and `FindByGateway`: slug `store` → the store branch instead of `MatchSlug`. `store` cannot collide: consumer slugs are exactly 8 alphanumerics (`slug.go:23,52`). Hybrid gateway → 404 *before any key lookup*. `Data` with **no active personal consumer** → the same 404 (today's `MatchSlug` miss, so OSS stays byte-identical) for every caller but a personal key of the gateway, which goes on to 403 `no_model_access`; the key lookup's miss cache keeps repeated unknown-key probes off Postgres. | A route group before the global `app.Use` auth (`proxy_router.go:74-75`): it duplicates the chain. |
| D2 | Key → links | `APIKeyFinder.FindByAPIKey` (`key_finder.go:47-62`, expiry in `live`). Checks: `Enabled`, `Type == api_key`, `OwnerID != ""`, `GatewayID == resolved gateway` (the global hash index spans tenants; precedent `api_key_consumers.go:156-164`) → else 401. Then `Data.StoreLinks(auth.ID)`: a `map[AuthID][]StoreLink` built in `NewData` over **active** personal consumers from their `auth_links`, each slice pre-sorted by level, priority, `granted_at`, consumer id. An empty slice is valid (N = 0). | Indexing owned keys by hash inside `Data`: diverges from B6. A scan over every consumer's `AuthIDs`: O(keys). |
| D3 | Audience rules (domain) | `Consumer.Validate` (`consumer.go:212`): `personal` ⇒ `Type == TypeLLM` and a concrete (non-glob) `ModelPolicies[r].Default` for at least one `r` in `RegistryIDs`. `audience` is set at create and **immutable** (422 on change). `ValidateAuthConfig` (`auth_rules.go:37`, today a no-op): a personal consumer accepts only owned keys, an application consumer only unowned ones → 422. | A mutable audience: switching it would strand attached keys of the wrong kind. |
| D4 | Attach of an owned key | Admin `POST /consumers/:id/auths/:auth_id` takes an optional body `{level, priority, granted_at}`, as `AttachRegistry` takes `{weight}` (`association_handler.go:57-90`). Owned key on a personal consumer: `level` and `granted_at` required, `priority` defaults to 1 → else 422. The write is an upsert of that one link (`ON CONFLICT (consumer_id, auth_id) DO UPDATE`), so the reconcile re-sends changed priorities on the same call. Links to other consumers are untouched. Application key, or link fields on an application consumer → today's behaviour, and link fields there → 422. Detach is today's `DetachAuth`. | A move (exactly one link): replaced by option C. A bulk "set all links of a key" endpoint: more surface, and the reconcile diffs per grant anyway. |
| D5 | Personal consumers and bulk `auths` | Create never takes `auths`, for any audience: keys arrive only through attach. `PUT /consumers/:id` with `auths` on a personal consumer (`[]` included) → 422, because `replaceAuthLinks` (`repository.go:244-275`) would otherwise drop every user's link and its attributes. | Letting `replaceAuthLinks` preserve personal links: hidden semantics. |
| D6 | Consumer delete | Unchanged: `consumer_auth` cascades. The owned keys survive with their other links. | Deleting owned keys with the consumer: a user would lose their key on an admin reshuffle. |
| D7 | Owned keys on the admin plane | `GET /auths` excludes them through an opt-in `ListFilter.ExcludeOwned` that **only the list handler** sets (`list_auth_handler.go:61-93`). `?owner_id=<sub>` lists one owner's key, for the reconcile and offboarding. The compiler keeps reading the unfiltered `List` (`compiler.go:462,725`). `GET /auths/:id` works (shows `owner_id`, never the secret). `PUT` and `POST rotate` on an owned key → 422 `owned_key`. `DELETE` is the admin revoke (the deleter already detaches, `guard.go:101`). `Update` never writes `owner_id`. `policy/warnings.go:285` api-key reach skips owned keys. | Repo-level exclusion: starves the snapshot. |
| D8 | Self-only endpoints (S4) | Under `/:gateway_id/store` (`admin_router.go:227`, `RequireGatewayAccess(ResourceRegistries)`) plus `RequireInteractiveIdentity()` (`admin_authz.go:108`). Owner = `callerSubject(c)` (`requests_handler.go:212`) only. `GET /principal/llm-key` (200 with `consumer_ids` / 404), `POST /principal/llm-key` `{expires_at}` (201, raw key once, attached to nothing; 409 if one exists), `POST /principal/llm-key/rotate` `{expires_at?}` (200, **same auth id and links**, new secret), `DELETE /principal/llm-key` (204). `now < expires_at ≤ now + 90 d` → else 422. Hybrid gateway → 422. | A `consumer_id` on create: the app attaches to N consumers through D4. A `principal_sub` in the body: lets a caller act for others. |
| D9 | `partition: key` hard limits | Only under `partition: key` and `appplugins.Blocks(mode)`: Redis read error → **503** `budget_unavailable` (local branch in `budgetGate`, `budget.go:171,213`; `HandleCounterFailure` stays fail-open); dollar budget on an unpriced model → **403** `model_unpriced`; `custom_pricing` / `group_by_header` with `partition: key` → config error; over budget → existing 429. Counter subject `owner:<owner_id>` when set, else `auth:<auth_id>`, so rotation and revoke-and-re-create keep the spend. | Changing `HandleCounterFailure`: fail-closed creep into every counter plugin. |
| D10 | Principal on `/store/v1` | `Principal{Subject: owner_id, Method: api_key}`, `AuthContext{AuthID, OwnerID}`; `ConsumerID` is set once the handler selects the consumer. The middleware attaches no consumer; the handler takes the store path when the route slug is `store`. | A new principal method: it would touch the MCP `PrincipalInert` rules. |
| D11 | Personal keys elsewhere | **Rejected.** `/<slug>/v1`: `indexBySlug` (`consumer_data.go:124`) skips personal consumers (404); `apiKeyAttachedElsewhere` skips them (personal key on an application slug → 401). MCP: `chainIdentityResolver.resolveAPIKey` (`auth_chain.go:370`) and `apiKeyConsumers.ForAPIKey` (`api_key_consumers.go:148`) treat `IsOwned()` as unknown → 401. | Allowing them on `/<slug>/v1`: two entry points for one grant. |
| D12 | Load balancer, fallback, policies | Unchanged per consumer. The selected consumer's LB key is `gw:consumerID` (`load_balancer_cache.go:58-59`), shared by every user it serves. Its policies are its attached ones plus gateway globals (`plansFor`, `data_finder.go:179-188`). Its fallback applies only when it serves the request. | — |
| D13 | Consumer selection | New use case `appproxy.StoreSelector` (B7). Per effective link it runs the existing pipeline: `Resolver.Resolve` (`pkg/app/routing/resolver.go`), substitution filter, capability filter, and on short models the catalog listing check per candidate (`filterCandidatesByProviderListing` semantics, `pkg/app/proxy/routing.go:94-119`). A consumer admits only through its **primary** registries; fallback backends never admit. The chosen consumer and its candidates, already filtered by substitution, go to the forwarder (`ForwardInput.Resolved`), so the forwarder never routes a substituted provider, fallback included. | Merging all consumers into one synthetic consumer: loses per-consumer LB, fallback and policies. Letting the app compute one effective consumer: option C rejects it. |
| D14 | `/store/v1/models` | New use case `appproxy.StoreModels`: the union over effective links of today's `modelsLister` output restricted to kept primary candidates (`ListModelsInput.Keep`), deduplicated and sorted. Every listed model is one that some consumer admits. | Listing fallback backends: they would list models the selector refuses. |

## Request path

```
…/store/v1/chat/completions   (X-AG-API-Key / Authorization)
auth middleware: gateway (host) ─► ResolveProxyPath ─► FindByGateway (cached Data)
  slug == "store"?
   ├─ no  ─► today's flow (+S0 expiry; personal consumers not in bySlug)
   └─ yes ─► hybrid gateway, or no active personal consumer and not a personal key of the gateway ─► 404
             APIKeyFinder.FindByAPIKey(sha256)           snapshot index / in-proc TTL
             enabled ∧ api_key ∧ owner_id ∧ gw match ∧ !expired ─► else 401
             attach(principal{sub=owner_id}, auth id)    no consumer yet
proxy handler (store path):
             links = Data.StoreLinks(auth id)            O(1), pre-sorted, N ≥ 0
             /models ─► StoreModels (union after substitution)
             else StoreSelector(links, intent) ─► consumer + candidates ─► 403 model_not_allowed if none
             ─► forwarder: registries + ModelPolicies + LB(gw:consumer) + fallback, minus substituted
             ─► consumer + global policies (token_rate_limiter partition=key) ─► upstream
```

Warm request on DB-less: 0 DB, 0 gRPC, 0 Redis beyond the budget counter. An attach, detach or revoke takes effect on the next snapshot apply (DB-less) or on `InvalidateGatewayDataEvent` (full plane). The links live in `Data`, so a stale `auth_key` entry cannot route through a link that is gone, and S0 clears that cache on the same event.

### Worked example (binding test scenario)

Ana's key is linked to A (`group`, OpenAI registry without allow-list, fallback DeepSeek), B (`group`, Anthropic without allow-list), C (`group`, Anthropic allow-list `opus-5.5`) and D (`user`, OpenAI allow-list `gpt6`, default `gpt6`). All priority 1. The catalog lists both providers' models. D substitutes OpenAI, so A has no primary registry left and is not effective.

| Request | Result | Why |
|---|---|---|
| `gpt-4.1` | 403 `model_not_allowed` | D does not allow it; A's OpenAI is substituted; the Anthropic catalog does not list it |
| `gpt6` | D | exact entry |
| `opus-5.5` | C | C exact beats B without allow-list at equal level and priority |
| `opus-4.8` | B | only B admits it |
| no model | D | first by level with a default model (`gpt6`) |

Without D, `gpt-4.1` goes to A, and A's DeepSeek fallback applies only to that request. `deepseek-chat` is refused (403): A does not admit it through its fallback.

## Error codes (new or changed)

| Surface | Condition | Status |
|---|---|---|
| `/store/v1/*` | hybrid gateway; gateway has no active personal consumer and the key is not a personal key of it; the Files API (with a valid key) | 404 `not_found` |
| `/store/v1/*` | no key, or the key is unknown, expired, disabled, unowned or from another gateway | 401 |
| `/store/v1/*` | a valid personal key with no links: its owner has no model access | 403 `no_model_access` |
| `/store/v1/*` | no effective consumer admits the request | 403 `model_not_allowed` |
| `/store/v1/models` | key with no links, or nothing effective | 200 with an empty list |
| `/store/v1/*` | invalid model reference / unknown pool alias | 400 `invalid_model` (today's mapping) |
| `/store/v1/*` | `partition: key`: over budget / Redis down / unpriced (dollars) | 429 / 503 / 403 |
| `/<slug>/v1/*` | expired key (S0); personal key | 401 |
| MCP plane | personal key | 401 |
| `POST /principal/llm-key` | key exists / bad expiry or hybrid gateway / service credential | 409 / 422 / 403 |
| Admin consumers | `audience` change; `personal` on non-LLM; personal without a default model; `auths` bulk on personal; owned↔application attach mismatch; missing or invalid link fields | 422 |
| Admin `/auths/:id` | `PUT` / `rotate` on an owned key | 422 `owned_key` |
| Admin registries | delete, or detach from a personal consumer, of the registry holding its last primary default | 422 |

## Out of scope

- Console and Portal UI, Prisma `LlmStoreGrant` and the reconcile (ENG-1710, ENG-1704). DataCore D1/D2.
- Personal keys on MCP. Group or owner budgets beyond `partition: key`. Self-service in OSS. Hybrid gateways.
- The Files API on `/store/v1`: file operations would run on the registry's shared credential across users, so v1 answers the unknown-route 404.
- Playground on personal consumers: they are not slug-routable (D11). Admins test with their own personal key.
- Reducing recompile/flush cost per key or link write (S6 measures it).

## Deviations from RUN-1763 (the issue still describes the synthetic design)

| Issue says | This proposal |
|---|---|
| Synthetic LLM Store consumer with a computed effective view | **Real personal consumers** (`audience = personal`), selected per request by the DP. No sentinel, no view cache. |
| `plane` (and `models`) on `store_grants` / `store_access_policies`, `llm_store_mode` metadata | **No change to store tables or gateway metadata.** MCP Store untouched. |
| `owner_groups` on `auths`, `PUT …/model-key/groups` | **Dropped.** The app resolves groups and sends one link per grant, with its level and priority. |
| Grants and policies by user/group in TrustGate | **Assignments in app Prisma.** TrustGate stores only links and their ordering attributes. |
| `partition: owner` | `partition: key`, counted per `owner_id` when set. |

## Delivery (chained PRs into `develop`, ≤ ~400 changed lines each)

| PR | Slice | Content | Est. lines | Depends |
|---|---|---|---|---|
| 1 | S0 + S1 | Expiry skip, `auth_key` cross-process eviction, `trustgate.auth.id`, release note | ~230 | — |
| 2 | S3a | `audience` + `owner_id` migrations, domain, repos, list filter, `FindByOwner`, `omitempty` wire + golden codec tests, compiler test | ~390 | — |
| 3 | S3b | Consumer rules: personal ⇒ LLM, default model, immutability, bulk `auths` 422, hybrid 422, DTO `audience` | ~320 | 2 |
| 4 | S3c | Auth admin rules: `/auths` filter and `?owner_id`, `owned_key` 422, rotator owner check, warnings | ~240 | 2 |
| 5 | S3d | `consumer_auth` link columns: migration, `AuthLink`, repo read (`auth_links`) and upsert, golden wire tests | ~290 | 2 |
| 6 | S3e | Attach with link attributes: request DTO, associator validation, audience mismatch, PG tests | ~260 | 3, 5 |
| 7 | S2a | `partition: key`, `AuthID`/`OwnerID` plumbing, calendar windows | ~310 | — |
| 8 | S2b | Hard limits (D9), catalog and docs | ~265 | 7 |
| 9 | S4a | `appauth.PersonalKeys` use case, caps, 409 on the unique index | ~260 | 2, 4 |
| 10 | S4b | Self-only HTTP routes and DTOs (`make docs` in its own commit) | ~300 | 9 |
| 11 | S5a | `Data.StoreLinks`, `HasPersonalConsumers`, `bySlug` skip, D11 rejections | ~290 | 5 |
| 12 | S5b | Middleware store branch + `StoreKeyResolver` | ~280 | 11 |
| 13 | S5c | `StoreSelector`: substitution, admission per intent kind, specificity, ordering, default model | ~370 | 11 |
| 14 | S5d | Handler store path, `ForwardInput.Keep`, `StoreModels` union | ~290 | 12, 13 |
| 15 | S5e | Functional tests (worked example, both planes) + `docs/llm-store.md` | ~370 | 6, 8, 10, 14 |
| 16 | S6 | Snapshot size and entity-count metrics | ~140 | 5 |

About 4,600 lines in total. PRs 1, 2 and 7 can start in parallel. `sdd-tasks` confirms the sizes.

## Rollout

1. DataCore D1 in prod before PR 1 deploys (events start carrying `auth_id`).
2. TrustGate on **every plane** (admin, proxy, MCP, DB-less DPs) before the app creates any personal consumer. An older DP ignores `audience`/`owner_id`/`auth_links` and would serve a personal consumer at its `/<slug>/v1` with its owned keys (D11 not enforced).
3. The app ships `LlmStoreGrant` + reconcile + Portal (ENG-1710/1704).
4. No flag: inert until a personal consumer exists, which is always the case in OSS. S0 is the only behaviour change for existing deployments (release note).

## Rollback

| Step | Action |
|---|---|
| 1 | Disable or delete `token_rate_limiter` policies with `partition: key` (an older binary rejects the config and the `calendar_*` windows). |
| 2 | Stop personal access before an older binary serves it at `/<slug>/v1`: `UPDATE consumers SET active = false WHERE audience = 'personal';` |
| 3 | Optional cleanup: `DELETE FROM consumer_auth WHERE auth_id IN (SELECT id FROM auths WHERE owner_id IS NOT NULL); DELETE FROM auths WHERE owner_id IS NOT NULL;` |
| 4 | Columns may stay: older binaries ignore them. S0 alone is a revert. |

## Risks

| Risk | Mitigation |
|---|---|
| Snapshot starvation if owned keys are filtered in the repo `List` | Opt-in filter in the handler only. Compiler test. |
| An old DP serves personal consumers by slug | Rollout step 2 (whole fleet first). Rollback step 2. |
| Snapshot growth: ~405 B per key, plus ~150 B per link (`auth_ids` entry + `auth_links` entry). A user with N grants costs N links. Every key or link write recompiles and flushes DP caches | S6 metric (`personal_links`). 250 ms debounce. Follow-up if the metric shows pressure. |
| A deferring registry (no allow-list) captures another provider's models when the catalog has no authoritative listing for its provider (`VerdictUnknown`) | Listing check per candidate with no "keep all" fallback in the store. Documented; admins add allow-lists on such registries. |
| Selection cost grows with N | One `Resolve` per effective link, all in memory; N is the user's grant count (single digits expected). Benchmark in PR 13. |
| TrustGate trusts the app for attachment | Self-service create attaches nothing; attach needs admin consumer rights. JWTs are minted server-side by the app only. |
| Fail-closed scope creep | The 503 branch is local to `partition: key`. |

## Success criteria

- An expired application key → 401 on `/<slug>/v1/*`. Application keys otherwise work unchanged.
- The worked example passes end to end on a DB-less and a full-plane proxy, including `/store/v1/models` = `gpt6` plus the Anthropic models.
- Attaching or detaching a link, or changing its priority, changes the selection after the next snapshot, with the same key. A revoke → 401.
- Application keys on `/store/v1` → 401. Personal keys on `/<slug>/v1` and on MCP → 401. A gateway without personal consumers → 404.
- A second `POST /principal/llm-key` → 409. Rotate keeps the auth id and links and kills the old secret on every replica at the next event.
- `partition: key`: 429 over budget, 503 with Redis down, 403 `model_unpriced`.
- Events carry `trustgate.auth.id`, `principal_subject = owner_id` and `consumer.id` = the selected consumer. Snapshot metrics are emitted per publish.
- OSS: snapshot bytes for existing entities are identical, and `/auths`, `auth_ids` and attach/detach without a body are unchanged for application keys. `go test -race ./...` and `go vet -tags functional ./...` are green.

## Open questions

| # | Question | Default taken here |
|---|---|---|
| OQ1 | A key with no links authenticates and gets 403 `model_not_allowed` (models: empty list). Should it be 401 instead? | 403: N = 0 is a valid state of option C, and 401 would tell the Portal the key is broken. |
| OQ2 | Substitution counts only the **primary** registries of `user`-level consumers, not their fallback backends. | Primary only: a fallback is resilience, not a grant. |
| OQ3 | With `VerdictUnknown` (catalog not loaded, or provider listing not authoritative) a registry without an allow-list admits any short model. | Accept, as the slug path does; document it. |
| OQ4 | PO sign-off on the fail-closed 503 under `partition: key`. | Assumed yes. |
| OQ5 | Admin `GET /consumers/:id` on a large personal consumer returns every owned key id in `auth_ids` (not `auth_links`). | Keep. |
