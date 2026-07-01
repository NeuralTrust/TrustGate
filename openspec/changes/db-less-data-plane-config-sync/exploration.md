# Exploration: DB-less data plane with pull-based config sync (TrustGate) — ENG-950

Port the TrustGuard DB-less data-plane config-sync mechanism (ENG-942, PR #268) to
TrustGate. Make the **proxy** and **mcp** planes DB-less: no Postgres. They pull a
compiled, content-hash-versioned, multi-gateway read-model snapshot (State-of-the-World)
from the admin plane over HTTP+ETag, notified by Redis Streams, and serve every config
read from an in-memory snapshot behind an `atomic.Pointer`, with an encrypted
last-known-good (LKG) copy on disk. Redis stays (sessions, OAuth flow state, rate limits,
semantic cache, playground traces, current Pub/Sub invalidation).

All file:line references below are from the worktree
`/Users/edu/Neuraltrust/TrustGate-eng-950-db-less-config-sync` unless prefixed
`TrustGuard:` (reference impl at `/Users/edu/Neuraltrust/TrustGuard-db-less-config-sync`,
READ-ONLY).

---

## 1. Current state — architecture map (verified against code)

### Plane selection & shared DI graph
- Entry `cmd/trustgate/main.go`: plane chosen by `argv[1]` — `admin`/`proxy`/`mcp`/`run`
  (default `proxy`) via `serverType()` (`main.go:119-124`). Servers 8080/8081/8082 wired
  by `ServerAdmin`/`ServerProxy`/`ServerMCP` modules.
- **All planes share ONE DI graph.** `container.New(modules.All()...)` (`main.go:65`) builds
  the full graph; `modules.All()` lists 20 modules including `Core`, `Cache`, `Gateway`,
  `Registry`, `Role`, `Consumer`, `Catalog`, `Policy`, `Plugins`, `Auth`, `MCP`, etc.
  (`pkg/container/modules/modules.go:19-43`).
- **Every plane runs migrations + needs Postgres today.** `main.go:70` unconditionally
  `c.Invoke(runMigrations)` (which calls `mgr.ApplyPending`), and `Core` provides
  `database.NewConnectionProvider` (`pkg/container/modules/core.go:50`). So proxy/mcp boot
  requires a live Postgres today. Confirmed by `config.Validate()` requiring
  `DB_HOST`/`DB_USER`/`DB_NAME` unconditionally (`pkg/config/config.go:523-530`).

### Proxy hot path
- `pkg/api/middleware/auth.go` `AuthMiddleware.Middleware()`:
  `gatewayResolver.Resolve(c)` → `dataFinder.FindByGateway(ctx, gw.ID)` →
  `data.MatchSlug(route.ConsumerSlug)` → `resolver.Resolve` → OIDC role resolution via
  `roleResolver.ResolveOIDCRoles(ctx, data.Roles, claims)` (`auth.go:58-121`). The gateway
  resolver ultimately calls `gateway.Finder.FindBySlug` (`pkg/app/gateway/finder.go:69`).
- `pkg/app/consumer/data_finder.go` `dataFinder.load()` is the **central runtime view**
  builder (`data_finder.go:105-148`): ~5 reads per gateway (consumers, roles, registries,
  policies, auths), TTL-cached (`cache.ConsumerDataTTLName`) with `singleflight`. Builds
  `[]RoutableConsumer{Consumer, Registries, FallbackBackends, Policies, PolicyPlan, Auths}`
  and `Roles`; `PolicyPlan` is a precomputed `appplugins.StagePlan`
  (`data_finder.go:150-155`).
- Then `pkg/app/proxy/forwarder.go` → `pkg/app/plugins/executor.go`.

### MCP hot path
- `pkg/api/middleware/mcp_auth.go` `MCPAuthMiddleware.Middleware()`:
  `resolver.Resolve(c)` (mTLS > bearer > API key) → `gateways.FindByID(ctx, identity.GatewayID)`
  → `dataFinder.FindByGateway(ctx, identity.GatewayID)` (`mcp_auth.go:61-78`). Same
  `DataFinder` + `gateway.Finder` as proxy, plus per-user credential resolution (vault) —
  see §6.

### Per-entity finders (Postgres + TTL cache)
- `pkg/app/gateway/finder.go` (`FindByID`, `FindBySlug` with negative-cache `slugMiss`),
  `pkg/app/registry/finder.go`, `pkg/app/policy/finder.go`, `pkg/app/auth/finder.go`,
  `pkg/app/auth/key_finder.go` (`FindByAPIKey` → `repo.FindByAPIKeyHash`),
  `pkg/app/role/finder.go`. Each wraps `domain.Repository` + a `cache.TTLMap` and enforces
  gateway scoping (`scopeToGateway` returns `domain.ErrNotFound` cross-gateway).
- Repos are pgx v5-backed in `pkg/infra/repository/*`; domain repo interfaces in
  `pkg/domain/*/repository.go`.

### Redis (go-redis v8 v8.11.5 — same major as TrustGuard, `pkg/infra/cache/client.go:28`)
- Sessions: `pkg/container/modules/session.go:29-30` → `sessionrepo.NewRepository(cc.RedisClient())`.
- OAuth connect/flow state: `pkg/container/modules/mcp.go:78-83` → `infraoauth.NewConnectStore(cc.RedisClient())`.
- Rate limits & semantic cache: `pkg/container/modules/plugins.go:84-101`
  (`ratelimit.New(redisClient)`, `tokenratelimit`, `pertoolratelimit`,
  `semantic.NewStore(..., Redis: redisClient)`, `semanticcache.New(store,...)`).
- Playground traces: `pkg/container/modules/telemetry.go:55-60` → `playground.NewStore(cc.RedisClient(), ...)`.
- Config invalidation Pub/Sub: `pkg/infra/cache/redis_event_publisher.go:54`
  (`RedisClient().Publish` to channel `gateway_events`); subscribers registered by
  `StartCacheEventListener` (`pkg/container/modules/cache_events.go:44-64`), invoked at
  `main.go:74`.

### Telemetry / Kafka
- `pkg/container/modules/telemetry.go`: exporter factory registers a **Kafka** template
  (`kafka.NewKafkaTemplate(logger, cfg.Kafka)`, `telemetry.go:63-67`) + OTLP; default
  pipeline uses Kafka topic (`telemetry.go:85-96`) only when `cfg.Telemetry.Enabled`.
  Telemetry is **Redis + Kafka, never Postgres**. `config.Validate()` requires
  `KAFKA_BROKERS` unconditionally (`config.go:535-536`).

**Correction to the head-start map:** `modules.All()` lists **20** modules (not ~22).
`Plugins` already declares `DB *database.Connection` as **`optional:"true"`** and guards it
with `poolOrNil` (`plugins.go:62,127-132`) — the Postgres pool is only used by the
**pgvector** semantic-cache backend; the default `SEMANTIC_CACHE_VECTOR_STORE=redis`
(`plugins.go:120-125`) means plugins already tolerate a nil DB. Everything else in the map
is confirmed.

---

## 2. Config entities read on the DP + domain types + multi-gateway indexing

The snapshot read model (mirror of `TrustGuard: internal/configsnapshot/readmodel/snapshot.go`)
must hold every entity the proxy/mcp hot path reads, indexed by **gateway id AND slug**.

| Entity | Domain type | Read via (hot path) | Indexes the DP needs |
|---|---|---|---|
| Gateway | `pkg/domain/gateway` `Gateway` | `gateway.Finder.FindBySlug` (proxy), `FindByID` (mcp) | `byID map[GatewayID]*Gateway`, `bySlug map[string]GatewayID` (NormalizeSlug) |
| Consumer | `pkg/domain/consumer` `Consumer` | `consumer.Repository.ListByGateway` (DataFinder) | `consumersByGateway map[GatewayID][]*Consumer`, `byID`, `activeBySlug` (for `FindActiveBySlug`) |
| Registry (backend) | `pkg/domain/registry` `Registry` (holds `MCPTarget.Auth`, encrypted creds) | `registry.Repository.FindByIDs(gw, ids)` (DataFinder), `registry.Finder.FindByID` | `registriesByGateway map[GatewayID]map[RegistryID]*Registry` |
| Policy | `pkg/domain/policy` `Policy` (`IsGlobal()`, `ConsumerIDs`, `Slug`) | `policy.Repository.ListByGateway` (DataFinder) | `policiesByGateway map[GatewayID][]*Policy`, `byID` |
| Auth | `pkg/domain/auth` `Auth` (`KeyHash`, `Type`, `Enabled`, `GatewayID`) | `auth.Repository.FindByIDs(gw, ids)` (DataFinder), `FindByAPIKeyHash` (key_finder), `FindByID` | `authsByGateway`, `byID`, `byAPIKeyHash map[string]*Auth`, plus `ListEnabledByGatewayAndType`/`FindEnabledByTypes` indexes |
| Role | `pkg/domain/role` `Role` (`RegistryIDs`, `GatewayID`) | `role.Repository.ListByGateway` (DataFinder), `role.Finder.FindByID` | `rolesByGateway map[GatewayID][]*Role`, `byID` |
| Catalog model (pricing) | `pkg/domain/catalog` `Model` (`DisplayName`, `InputPrice`, `OutputPrice`) | `catalog.Repository.FindModel(providerCode, slug)` via `PricingResolver` (costcap, tokenratelimit) | `modelsByProviderSlug map[string]*Model` (global, not per-gateway) — see §6 open Q |

`DataFinder.load()` composition logic (`data_finder.go:105-358`) — fallback chains
(`fallbackChainOf`), pool exclusion (`poolRegistryIDs`), global-vs-consumer policy merge
(`composePolicies`), role→registry id expansion (`appendRoleRegistryIDs`), and
`StagePlan` precompute (`buildPolicyPlan`) — is **pure in-memory logic over the entities
above**. It should be preserved unchanged; only the underlying `Repository` reads are
swapped to snapshot-backed adapters. The multi-gateway snapshot must therefore key
consumers/registries/policies/auths/roles **by `GatewayID`**, and gateways additionally
**by slug** (proxy) — exactly the multi-gateway generalization of TrustGuard's
single-collector-per-gateway index.

---

## 3. Finder/Repository interfaces to reimplement as snapshot-backed adapters

Adapters must satisfy the **exact domain `Repository` interfaces** the finders already
depend on (so `DataFinder` and every `*.Finder` are unchanged), resolving reads from the
`readmodel.Snapshot` and returning `domain.ErrNotFound` on miss; all write methods return
`configsync.ErrReadOnly`. This mirrors `TrustGuard: internal/configsnapshot/adapters/*`.

**Read methods actually exercised on the DP hot path are the priority; write methods are
stubbed read-only.** Interfaces + methods:

1. `consumer.Repository` (`pkg/domain/consumer/repository.go:31-52`)
   - Hot: `ListByGateway`, `FindByID`, `FindActiveBySlug`, `ListByAuthID`
   - Read-only stubs: `Save`, `Update`, `Delete`, `List`, `Attach/Detach{Registry,Role,Auth,Policy}`, `DetachRegistryIfUnreferenced`
2. `registry.Repository` (`pkg/domain/registry/repository.go:31-38`)
   - Hot: `FindByIDs`, `FindByID` — stubs: `Save`, `Update`, `Delete`, `List`
3. `policy.Repository` (`pkg/domain/policy/repository.go:31-40`)
   - Hot: `ListByGateway`, `FindByID`, `FindByIDs` — stubs: `Save`, `Update`, `SetGlobal`, `Delete`, `List`
4. `auth.Repository` (`pkg/domain/auth/repository.go:31-41`)
   - Hot: `FindByAPIKeyHash`, `FindByIDs`, `FindByID`, `FindEnabledByTypes`, `ListEnabledByGatewayAndType`
   - stubs: `Save`, `Update`, `Delete`, `List`
5. `role.Repository` (`pkg/domain/role/repository.go:31-42`)
   - Hot: `ListByGateway`, `FindByID`, `FindByIDs` — stubs: `Save`, `Update`, `Delete`, `List`, `Attach/Detach*`
6. `gateway.Repository` (`pkg/domain/gateway/repository.go:30-38`)
   - Hot: `FindBySlug`, `FindByID`, `FindByDomain` — stubs: `Save`, `Update`, `Delete`, `List`
7. `catalog.Repository` (`pkg/domain/catalog/catalog.go:52-58`)
   - Hot: `FindModel`, `ListModelsByProviderCode` — stubs: `UpsertProvider`, `UpsertModel`
     (only if catalog is embedded — see §6)

> Design choice: swap **`domain.Repository` bindings** (one adapter per interface). This
> keeps the app-layer `*.Finder`/`DataFinder`/`PricingResolver` and their TTL caches
> intact — the DP still benefits from the finder-level caches on top of the snapshot,
> exactly as today. (Alternative: swap the `*.Finder` layer instead — rejected because it
> would duplicate more surface and lose the existing cache/scoping behavior.)

Supporting core (mirror `TrustGuard: internal/configsync/*`) to copy into **`pkg/configsync/`**:
`configsync.go` (interfaces `ConfigFetcher`, `ConfigStore[T]`, `ChangeNotifier`, `Crypto`,
`SnapshotCodec[T]`, `Versioned[T]`), `http_fetcher.go`, `memory_store.go` (atomic pointer),
`aesgcm_crypto.go`, `redis_notifier.go` (go-redis v8 Streams), `lkg.go`, `worker.go`,
`readiness.go`, `errors.go` (`ErrReadOnly`, `ErrIntegrity`, `ErrLKGCorrupt`). Plus
snapshot infra: `pkg/infra/configsnapshot/` (proto + `codec.go`),
`pkg/configsnapshot/readmodel/snapshot.go` (multi-gateway `Data`/`Snapshot`/`Build`),
`pkg/configsnapshot/adapters/*` (the adapters above).

---

## 4. Write-set — admin use cases that must `Signal()` a version bump

Mirror `TrustGuard: internal/app/configsyncport/port.go` (`SnapshotSignaler.Signal(ctx)`),
injected into every admin write use case and called **after a successful commit**. In
TrustGate these are the use cases that call `repo.Save/Update/Delete/Attach/Detach/SetGlobal`.
Add `configsyncport.SnapshotSignaler` (nil = no-op on the DP graph) next to the existing
Pub/Sub `events.go` invalidation.

| Domain | Use cases (files) that must Signal() |
|---|---|
| gateway | `creator.go`, `updater.go`, `deleter.go` |
| registry | `creator.go`, `updater.go`, `deleter.go` |
| consumer | `creator.go`, `updater.go`, `deleter.go`, `associator.go` (Attach/Detach registry, role, auth, policy) |
| policy | `creator.go`, `updater.go`, `deleter.go`, `duplicator.go`, `scoper.go` (SetGlobal) |
| auth | `creator.go`, `updater.go`, `deleter.go` |
| role | `creator.go`, `updater.go`, `deleter.go`, `associator.go` |
| catalog | `sync.go` (models.dev sync), `provider_auth.go`, `mcp_servers.go` — **only if catalog is embedded in the snapshot** (§6) |

The signal is served by the control-plane `Recompiler` (debounced) →
`Holder` (atomic encoded snapshot) → `RedisStreamNotifier.Publish(version)`
(mirror `TrustGuard: internal/app/configsnapshot/{recompiler,holder,publisher}.go`).

---

## 5. DI split plan (proxy+mcp skip Postgres/migrations, keep Redis)

TrustGuard expresses plane divergence as a **distinct module set**, not a `dig.Decorate`
override, because dig resolves the original provider first (which would force the pool to
build) — `TrustGuard: internal/container/modules/modules.go:9-36`. Replicate:

**A. Make `modules.All()` plane-aware.** Today `main.go:65` calls `modules.All()` before
`serverType()` is known and unconditionally runs migrations. Change to pass the plane + a
DB-less flag (`CONFIG_SYNC_DATA_PLANE_ENABLED`) into module selection, and gate
`runMigrations`/`StartCacheEventListener`/`StartCatalogSync` accordingly.

**B. Two module graphs:**
- **DB-less DP graph (proxy/mcp + flag on):** `CoreData` (config + logger + Redis +
  crypto, **no** `database.NewConnectionProvider`/`MigrationsManager`), `Cache`,
  `CacheEvents` (Pub/Sub coexists), `Session`, `Telemetry` (Kafka+Redis), `Auth`,
  `Policy`, `Plugins` (DB nil-tolerant already), `LoadBalancer`, `Gateway`, `Registry`,
  `Role`, `Consumer`, `Catalog`, `Providers`, `Proxy`, `MCP`, `ServerProxy`/`ServerMCP`,
  plus new **`ConfigSyncData`** (store, codec, crypto, HTTP fetcher, Redis-stream notifier,
  LKG, `Worker`). In this graph the **`domain.Repository` providers come from
  `pkg/configsnapshot/adapters`** instead of `pkg/infra/repository/*` — i.e. the
  `Gateway/Registry/Role/Consumer/Policy/Auth/Catalog` modules must provide the
  snapshot-backed adapter (parameterized by plane) so they never take `*database.Connection`.
- **Control/admin/run graph (unchanged + additive):** existing Postgres graph plus new
  **`ControlConfigSync`** (compiler over live repos, holder, recompiler,
  `SnapshotVersionPublisher` implementing `configsyncport.SnapshotSignaler`, snapshot HTTP
  handler + `config_sync_auth` middleware).

**C. Modules that currently hard-require `*database.Connection`** and must be split so the
DP variant provides a snapshot adapter instead (all verified):
`pkg/container/modules/{gateway.go:30, registry.go:28, auth.go:27, policy.go:27, role.go:27,
consumer.go:27, catalog.go:36, mcp.go:49}`. `plugins.go` already optional. `session.go`,
`telemetry.go`, `providers.go`, `cache*.go` need **no** change (Redis/HTTP only).

**D. Wire the `Worker`** (`configsync.Worker[*readmodel.Snapshot]`) start in the proxy/mcp
run funcs (`main.go` `runProxy`/`runMCP`), analogous to TrustGuard's `runDataDBLess`:
`go worker.Run(ctx)` before/alongside `srv.Run()`, and gate readiness on first successful
converge or LKG restore.

**E. Config** (`pkg/config/config.go`): add `ConfigSyncConfig` (mirror
`TrustGuard: internal/config/config.go` — `CONFIG_SYNC_DATA_PLANE_ENABLED`,
`CONFIG_SYNC_SNAPSHOT_URL`, `CONFIG_SYNC_TOKEN`, `CONFIG_SYNC_STREAM_KEY`,
`CONFIG_SYNC_LKG_PATH`, `CONFIG_SYNC_LKG_KEY` (base64 32-byte AES-256),
`CONFIG_SYNC_POLL_INTERVAL`, `CONFIG_SYNC_RECOMPILE_DEBOUNCE`, instance id). Make
`Validate()` **plane-aware**: skip `DB_HOST/DB_USER/DB_NAME` when DB-less DP, require
`CONFIG_SYNC_*` instead. Keep `KAFKA_BROKERS`/`REDIS_HOST` required on the DP.

---

## 6. Resolved open questions

### Q1 — Vault / per-user OAuth tokens on the DB-less MCP plane
**Where:** read on the MCP hot path in `credentialResolver.forwarded` →
`r.vault.Find(ctx, gatewayID, principal.Subject, provider)` (`pkg/app/mcp/credentials.go:125`)
and **written** during refresh via `r.vault.Upsert` (`credentials.go:174`). Also written by
the OAuth connect flow `pkg/app/oauth/connect.go` (consent callback). Interface is 4 methods
(`Upsert`, `Find`, `ListByPrincipal`, `Delete` — `pkg/domain/vault/credential.go:92-97`),
values already encrypted via `vaultdomain.Encrypter` (`core.go:56-60`), backed by Postgres
(`mcp.go:49-53` `vaultrepo.NewRepository(conn, cipher)`).

Vault is **runtime-mutable per-user state, not config** → it cannot live in the compiled
snapshot.

**Recommendation:** implement a **Redis-backed `vaultdomain.Repository`** for the MCP DP
(keyed `vault:{gatewayID}:{principalSub}:{provider}`, storing the already-encrypted blob),
and bind it in the DB-less MCP module instead of `vaultrepo.NewRepository(conn, ...)`. This
keeps the locked "Postgres removed" invariant, reuses the existing `Encrypter`, and Redis is
already a hard MCP dependency (connect store, STS cache, sessions). Durability is graceful:
the code already treats `vaultdomain.ErrNotFound` as "re-consent" (`credentials.go:126-127`,
`180-182`), so a lost Redis entry degrades to a normal consent prompt, not an outage. Pair
with Redis persistence (AOF) in prod.

**Least-invasive fallback (only if the team wants Postgres-grade durability for refresh
tokens):** a **narrow Postgres carve-out on the MCP plane for vault only** (keep
`*database.Connection` + the `20260610130000_add_vault_credentials` migration solely for the
`vault_credentials` table; all *config* still snapshot-backed). This is smaller code-wise but
**contradicts the locked "Postgres removed on proxy/mcp" decision**, so it should be a
conscious exception, not the default. Prefer the Redis-backed repo for v1.

### Q2 — Catalog / pricing
**Where:** `PricingResolver.Resolve` → `catalog.Repository.FindModel(providerCode, slug)`
(`pkg/app/catalog/pricing.go:88-89`), injected into `costcap` and `tokenratelimit` plugins
(`pkg/container/modules/plugins.go:60,96-97`; callers under
`pkg/infra/plugins/{costcap,llmcost,tokenratelimit}`). Catalog is **global** (not
per-gateway), populated on admin boot from models.dev (`StartCatalogSync`, `main.go:79`),
Postgres-backed (`catalog.go:36-37`).

**Recommendation for v1: embed catalog pricing in the same SotW snapshot** as a separate
top-level section (`Data.CatalogModels []catalog.Model`) and provide a snapshot-backed
`catalog.Repository` adapter (`FindModel`/`ListModelsByProviderCode`). Rationale: keeps **one
distributed artifact, one pull mechanism, one LKG**; costcap/tokenratelimit are only active
when a policy configures them, so pricing must still be available DB-less. Only pricing
fields are needed (`DisplayName`, `InputPrice`, `OutputPrice`), so payload is bounded and
ETag/304 means DPs download it only on change.
**Trade-off:** a models.dev catalog refresh bumps the global snapshot version (fleet-wide
re-pull). Since catalog sync is infrequent (admin boot), this churn is acceptable for v1. If
catalog churn later proves noisy, split catalog into a **second snapshot/endpoint** — note
this as a deferred option, not v1.

### Q3 — Snapshot granularity
`DataFinder` is per-gateway and the DP resolves by gateway slug/id at request time, so both a
fleet-wide and a per-gateway snapshot are technically workable.
**Recommendation: fleet-wide State-of-the-World, indexed by gateway id AND slug** (the
multi-gateway generalization of TrustGuard's single global snapshot with a per-gateway
index). One endpoint, one version, one LKG, one worker — simplest to ship and matches the
reference impl.
**Trade-off:** any single gateway's config change bumps the one global version, so all DPs
re-pull the whole fleet snapshot even for an unrelated gateway. For expected fleet sizes this
is fine (same behavior TrustGuard shipped). Per-gateway snapshots would shrink blast radius
but multiply endpoints, versioning, notification keys and LKG files — **defer to a later
iteration**.

### Q4 — Sessions / OAuth flow state / rate-limit counters / semantic cache
All already Redis-backed and **unaffected** by removing Postgres:
- Sessions: `pkg/container/modules/session.go:29-30`.
- OAuth flow/connect state: `pkg/container/modules/mcp.go:78-83`
  (`infraoauth.NewConnectStore(cc.RedisClient())`); STS exchange cache in the same module.
- Rate limits: `pkg/container/modules/plugins.go:95-98` (`ratelimit`, `tokenratelimit`,
  `pertoolratelimit` over `redisClient`).
- Semantic cache: `pkg/container/modules/plugins.go:85-101` (`semantic.NewStore(Redis: ...)`,
  default `SEMANTIC_CACHE_VECTOR_STORE=redis`; only the optional **pgvector** backend uses
  the pool via the already-optional `DB`).
- Playground traces: `pkg/container/modules/telemetry.go:55-60`.
- Current config-invalidation Pub/Sub (channel `gateway_events`):
  `pkg/infra/cache/redis_event_publisher.go:54`, subscribers `cache_events.go:44-64`. Redis
  Streams config-sync **coexists** with this and eventually replaces it.

### Q5 — Kafka / telemetry on the DP
Proxy/mcp already emit telemetry via **Kafka + Redis**, never Postgres
(`pkg/container/modules/telemetry.go:63-97`). `KAFKA_BROKERS` is required today
(`config.go:535-536`) and the metrics worker starts on proxy/mcp/run
(`main.go:89-116`). The DB-less DP still emits telemetry unchanged; it just drops Postgres.
**Env the DB-less DP truly needs:** `REDIS_*`, `KAFKA_BROKERS` (+ `TELEMETRY_*` when
telemetry enabled), `SERVER_SECRET_KEY`/STS keys (MCP), `GATEWAY_BASE_DOMAIN`, and the new
`CONFIG_SYNC_*` set; it must **not** require `DB_*`.

---

## Approaches

1. **Port TrustGuard core verbatim into `pkg/configsync/` + snapshot adapters + plane-split
   DI (recommended).** Copy the agnostic core, build a multi-gateway read model, swap
   `domain.Repository` bindings on the DP graph, add `configsyncport.Signal()` to write use
   cases, add `Control/DataConfigSync` modules, plane-aware config + main wiring. Vault →
   Redis; catalog embedded in snapshot.
   - Pros: proven shape (ENG-942), one artifact/pull/LKG, finders + caches untouched, honors
     locked decisions.
   - Cons: broad DI surgery (8 modules split), touches ~20 write use cases for Signal(),
     new proto/codec for the multi-gateway model.
   - Effort: **High** (but well-bounded by the reference impl).

2. **Feature-flagged in-place (`dig.Decorate` overrides on the DP).** Rejected: dig resolves
   the original provider first, forcing the Postgres pool to build (documented in
   `TrustGuard: modules.go:9-16`). Not viable.

## Recommendation
Approach 1. Keep the DP `domain.Repository` swap (not the finder swap) so `DataFinder`, all
`*.Finder`s, `PricingResolver` and their TTL caches are unchanged. Fleet-wide SotW indexed by
gateway id + slug; vault on Redis; catalog embedded in the snapshot for v1.

## Risks
- **Secret material in the snapshot.** Registry entities carry credentials
  (`registryrepo.NewRepository(conn, enc)` decrypts on read) and `Auth` carries `KeyHash`;
  the compiled snapshot therefore contains sensitive data. Transport auth
  (`CONFIG_SYNC_TOKEN` + `config_sync_auth` middleware) and encrypted LKG at rest
  (AES-256-GCM) are **mandatory**, not optional. Confirm the codec never logs bodies.
- **Multi-gateway index correctness.** Slug normalization (`gateway.NormalizeSlug`) and
  gateway-scoping semantics (`scopeToGateway` → `ErrNotFound`) must be reproduced exactly in
  adapters, or the DP will leak/deny cross-gateway resources differently than Postgres.
- **`StagePlan` precompute parity.** `DataFinder.buildPolicyPlan` must run identically over
  snapshot-sourced policies; ensure the plugin `Registry` is available on the DP graph
  (it is — `Plugins` module stays).
- **Vault durability if Redis-backed** (mitigated by consent re-flow; document AOF).
- **Catalog version churn** from models.dev refreshes bumping the global snapshot (accepted
  for v1; splittable later).
- **Boot ordering / readiness:** DP must serve `503`/hold traffic until first converge or LKG
  restore; ensure migrations are fully skipped (`main.go:70`) on the DB-less graph.

## Ready for Proposal
**Yes.** Scope, entity map, interface list, write-set, DI split and all five open questions
are resolved with file:line grounding. Next phase: `sdd-propose`.
