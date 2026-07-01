# Proposal: DB-less data plane with pull-based config sync (TrustGate) — ENG-950

## Why

Today **every** TrustGate plane — `admin`, `proxy`, `mcp`, `run` — boots against
a live Postgres: `main.go` unconditionally runs migrations
(`c.Invoke(runMigrations)`), the `Core` module provides
`database.NewConnectionProvider`, and `config.Validate()` requires
`DB_HOST`/`DB_USER`/`DB_NAME` for all planes. This couples the latency-critical
proxy and MCP data planes (DPs) to database availability, schema migrations, and
a shared connection pool they do not need at request time. The DP hot path only
ever *reads* config (gateways, consumers, registries, policies, auths, roles,
pricing) — it never writes it.

TrustGuard already solved this for its own DP in **ENG-942 (PR #268)**: the data
plane runs **DB-less**, pulling a compiled, content-hash-versioned, read-model
snapshot ("State-of-the-World", SotW) from the admin plane over **HTTP + ETag**
(protobuf body), getting change notifications via **Redis Streams**, serving all
config reads from an in-memory snapshot behind an `atomic.Pointer`, and keeping
an encrypted **last-known-good (LKG)** copy on disk (AES-256-GCM) for cold-start
resilience. That architecture — Redis Streams over pub/sub for at-least-once
delivery, HTTP+ETag over gRPC for cache-friendly transport, encrypted LKG for
degraded-mode boot, and an agnostic transport core — is the locked design; its
rationale lives in **ENG-942**.

This change **ports that mechanism to TrustGate** so the `proxy` and `mcp`
planes become DB-less. Redis **stays** on the DP (sessions, OAuth flow state,
rate-limit counters, semantic cache, playground traces, and the existing config
pub/sub). Kafka/telemetry are unchanged (never Postgres). The result: proxy and
MCP boot and serve with **no Postgres dependency**, only `REDIS_*`,
`KAFKA_BROKERS`, and the new `CONFIG_SYNC_*` env.

- Linear: **ENG-950** — *Port TrustGuard DB-less pull-based config-sync to
  TrustGate (proxy + mcp planes)*.
- Origin / reference: **ENG-942** (TrustGuard, PR #268) — locked architecture
  decisions and rationale. Completed impl mirrored from
  `/Users/edu/Neuraltrust/TrustGuard-db-less-config-sync` (read-only reference).

## What changes

- **Agnostic config-sync core copied into `pkg/configsync/`** (mirror
  `TrustGuard: internal/configsync/*`): interfaces (`ConfigFetcher`,
  `ConfigStore[T]`, `ChangeNotifier`, `Crypto`, `SnapshotCodec[T]`,
  `Versioned[T]`), `http_fetcher.go` (HTTP+ETag), `memory_store.go`
  (`atomic.Pointer` swap), `aesgcm_crypto.go` (AES-256-GCM), `redis_notifier.go`
  (go-redis v8 Streams — same major as today, `pkg/infra/cache/client.go`),
  `lkg.go` (encrypted disk LKG), `worker.go` (converge loop), `readiness.go`,
  `errors.go` (`ErrReadOnly`, `ErrIntegrity`, `ErrLKGCorrupt`).
- **Multi-gateway read model** `pkg/configsnapshot/readmodel/snapshot.go`
  (generalizing TrustGuard's single-gateway snapshot): a fleet-wide SotW holding
  every entity the DP hot path reads, **indexed by gateway id AND slug**
  (gateways `byID`+`bySlug`; consumers/registries/policies/auths/roles keyed by
  `GatewayID`; catalog models global by provider+slug). Plus snapshot infra
  `pkg/infra/configsnapshot/` (proto + `codec.go`).
- **Snapshot-backed repository adapters** `pkg/configsnapshot/adapters/*`
  implementing the **exact** `domain.Repository` interfaces the finders already
  depend on (`gateway`, `registry`, `policy`, `auth`, `role`, `consumer`,
  `catalog`). Reads resolve from `readmodel.Snapshot` and return
  `domain.ErrNotFound` on miss; **all write methods return
  `configsync.ErrReadOnly`**. `DataFinder`, every `*.Finder`, `PricingResolver`,
  and their TTL caches stay **unchanged** — only the `domain.Repository` binding
  is swapped on the DP graph.
- **Control-plane recompiler + snapshot server** (mirror
  `TrustGuard: internal/app/configsnapshot/{recompiler,holder,publisher}.go`):
  a debounced `Recompiler` that builds the SotW over the live repos, a `Holder`
  (atomic encoded snapshot), a `RedisStreamNotifier.Publish(version)`, and an
  HTTP snapshot handler guarded by a `config_sync_auth` middleware
  (`CONFIG_SYNC_TOKEN`). Exposed via a new **`ControlConfigSync`** module on the
  admin/run graph.
- **Write-set `Signal()`** (mirror
  `TrustGuard: internal/app/configsyncport/port.go`): add a
  `configsyncport.SnapshotSignaler` (nil = no-op) invoked **after a successful
  commit** in every admin write use case, alongside the existing `gateway_events`
  pub/sub invalidation. Write set: gateway `creator/updater/deleter`; registry
  `creator/updater/deleter`; consumer `creator/updater/deleter/associator`;
  policy `creator/updater/deleter/duplicator/scoper`; auth
  `creator/updater/deleter`; role `creator/updater/deleter/associator`; catalog
  `sync/provider_auth/mcp_servers`.
- **Plane-aware DI split** (a **distinct DB-less module set**, NOT
  `dig.Decorate` — dig would resolve the original provider first and force the
  pgx pool to build; documented in `TrustGuard: modules.go`). `modules.All()`
  becomes plane-aware; on the DB-less DP graph (`proxy`/`mcp` + flag):
  - a `CoreData` module (config + logger + Redis + crypto, **no**
    `database.NewConnectionProvider` / `MigrationsManager` / pgx pool);
  - `gateway/registry/role/consumer/policy/auth/catalog` modules bind the
    **snapshot-backed adapters** instead of the pgx repos, so they never take
    `*database.Connection`;
  - a new **`ConfigSyncData`** module (store, codec, crypto, HTTP fetcher,
    Redis-stream notifier, LKG, `Worker`);
  - **migrations, `StartCacheEventListener`, `StartCatalogSync`, and the pgx
    pool are skipped**; Redis/Kafka/session/telemetry/plugins modules are
    unchanged (`Plugins` already tolerates a nil DB via its `optional:"true"`
    pool + `poolOrNil`; default `SEMANTIC_CACHE_VECTOR_STORE=redis`).
- **Worker start + readiness** in `runProxy`/`runMCP` (`main.go`, analogous to
  TrustGuard's `runDataDBLess`): `go worker.Run(ctx)` alongside `srv.Run()`, with
  readiness gated on first successful converge **or** LKG restore (serve `503`
  until then).
- **Vault / per-user OAuth tokens on the DB-less MCP plane** → **Redis-backed
  `vaultdomain.Repository`** (keyed `vault:{gatewayID}:{principalSub}:{provider}`,
  storing the already-encrypted blob via the existing `vaultdomain.Encrypter`),
  bound in the DB-less MCP module instead of `vaultrepo.NewRepository(conn, …)`.
  Vault is runtime-mutable per-user state, not config, so it cannot live in the
  compiled snapshot; Redis is already a hard MCP dependency, and a lost entry
  degrades gracefully to a normal re-consent (`ErrNotFound`).
- **Catalog pricing embedded in the same SotW snapshot** for v1
  (`Data.CatalogModels`), served by the snapshot-backed `catalog.Repository`
  adapter — one artifact, one pull, one LKG. Only pricing fields
  (`DisplayName`, `InputPrice`, `OutputPrice`) are carried.
- **Config**: add `ConfigSyncConfig` (mirror TrustGuard) —
  `CONFIG_SYNC_DATA_PLANE_ENABLED`, `CONFIG_SYNC_SNAPSHOT_URL`,
  `CONFIG_SYNC_TOKEN`, `CONFIG_SYNC_STREAM_KEY`, `CONFIG_SYNC_LKG_PATH`,
  `CONFIG_SYNC_LKG_KEY` (base64 32-byte AES-256), `CONFIG_SYNC_POLL_INTERVAL`,
  `CONFIG_SYNC_RECOMPILE_DEBOUNCE`, instance id — and make `Validate()`
  **plane-aware**: DB-less DP skips `DB_*` and requires `CONFIG_SYNC_*`; keeps
  `REDIS_HOST`/`KAFKA_BROKERS` required.

## Scope

### In scope

- Copy the TrustGuard agnostic core into `pkg/configsync/` and snapshot infra
  into `pkg/infra/configsnapshot/`, adapted to TrustGate package layout.
- A **multi-gateway** read model indexed by gateway id + slug, covering
  gateways, consumers, registries, policies, auths, roles, and catalog pricing.
- Snapshot-backed `domain.Repository` adapters (read-only; writes →
  `configsync.ErrReadOnly`) for all seven domains, preserving `DataFinder` /
  `*.Finder` / `PricingResolver` / TTL-cache behavior and gateway-scoping
  (`scopeToGateway` → `ErrNotFound`) and slug normalization
  (`gateway.NormalizeSlug`) exactly.
- Control-plane recompiler + holder + Redis-stream publisher + authenticated
  HTTP snapshot endpoint (`ControlConfigSync` module on admin/run).
- `configsyncport.SnapshotSignaler.Signal()` wired into the full admin write set
  after commit (nil no-op on the DP graph).
- Plane-aware `modules.All()` + `CoreData` + `ConfigSyncData` modules; DB-less DP
  graph skips migrations, cache-event listener, catalog sync, and the pgx pool.
- `Worker` start + readiness gating in `runProxy`/`runMCP`.
- Redis-backed `vaultdomain.Repository` for the DB-less MCP plane.
- `ConfigSyncConfig` + plane-aware `Validate()`.
- Encrypted LKG at rest (AES-256-GCM) and transport auth (`CONFIG_SYNC_TOKEN` +
  `config_sync_auth` middleware) as **mandatory** (the snapshot carries secret
  material — registry creds, `Auth.KeyHash`).
- Unit tests mirroring TrustGuard (core round-trips, codec, adapters, read-model
  indexing/scoping, worker converge/LKG restore, plane-aware `Validate()`).

### Out of scope (non-goals / documented limitations)

- **Removing Postgres from `admin`/`run`.** The admin/control plane keeps
  Postgres — it is the source of truth the recompiler reads. Only `proxy`/`mcp`
  become DB-less.
- **Removing Redis from the DP.** Redis stays (sessions, OAuth flow state, rate
  limits, semantic cache, playground traces, current config pub/sub). The Redis
  Streams config-sync **coexists** with the existing `gateway_events` pub/sub;
  fully retiring pub/sub is a later cleanup.
- **Per-gateway snapshots.** v1 ships a single fleet-wide SotW; any one gateway's
  change bumps the global version and all DPs re-pull. Per-gateway snapshots
  (smaller blast radius, more endpoints/versions/LKG) are deferred.
- **Splitting catalog into its own snapshot/endpoint.** Catalog pricing is
  embedded in the SotW for v1; a models.dev refresh bumps the global version
  (accepted churn). A separate catalog snapshot is a deferred option.
- **Postgres-grade durability for MCP refresh tokens.** v1 uses Redis for vault;
  a narrow Postgres carve-out for `vault_credentials` only is a documented
  fallback that contradicts the locked "no Postgres on DP" decision and is **not**
  the default. Pair Redis with AOF persistence in prod.
- **New product behavior.** This is an infrastructure/topology change; the DP's
  request-time semantics (composition, `StagePlan` precompute, scoping) are
  preserved, not extended.

## Phased delivery (400-line PR budget → chained PRs)

Each phase is independently shippable and reviewable; phases are chained (each PR
targets the previous slice's branch). This maps directly to what `sdd-tasks`
should expand.

| Phase | Slice | Notes |
|---|---|---|
| **P1** | Agnostic core in `pkg/configsync/*` (interfaces, http_fetcher, memory_store, aesgcm_crypto, redis_notifier, lkg, worker, readiness, errors) + `pkg/infra/configsnapshot/` proto + codec. | Pure port from TrustGuard; no TrustGate wiring yet. Unit-tested in isolation (round-trip, crypto, codec, notifier). |
| **P2** | Multi-gateway `readmodel.Snapshot`/`Data`/`Build` + snapshot-backed `domain.Repository` adapters in `pkg/configsnapshot/adapters/*` (reads → snapshot, writes → `ErrReadOnly`). | The correctness heart: reproduce indexing, slug normalization, and gateway scoping exactly. Table-driven adapter tests vs the pgx behavior. No DI change yet. |
| **P3** | `ConfigSyncConfig` + plane-aware `Validate()` (DP skips `DB_*`, requires `CONFIG_SYNC_*`). | Small, isolated config slice; unblocks both graphs. |
| **P4** | Control-plane `ControlConfigSync` module: compiler over live repos + `Holder` + `Recompiler` (debounced) + `RedisStreamNotifier` + authenticated HTTP snapshot handler; wire `configsyncport.Signal()` into the admin write set. | Additive on the existing Postgres graph; nil `SnapshotSignaler` = no-op elsewhere. Watch the write-set line count — may split (gateway/registry/consumer vs policy/auth/role/catalog). |
| **P5** | DB-less DP DI: plane-aware `modules.All()`, `CoreData` module, snapshot-adapter bindings for the 8 DB-coupled modules, `ConfigSyncData` module, skip migrations/cache-event-listener/catalog-sync/pgx pool, `Worker` start + readiness in `runProxy`/`runMCP`. | The heaviest wiring slice; the DP first boots DB-less here. Likely split proxy vs mcp if over budget. |
| **P6** | Redis-backed `vaultdomain.Repository` for the DB-less MCP plane. | MCP-only; isolates the per-user credential store from the config path. |

If P4 or P5 exceed the budget, split along the module/domain boundaries noted.

## Affected areas

| Area | Impact | Description |
|---|---|---|
| `pkg/configsync/*` | New | Agnostic transport core (mirror `TrustGuard: internal/configsync/*`). |
| `pkg/infra/configsnapshot/` | New | Snapshot proto + `codec.go`. |
| `pkg/configsnapshot/readmodel/snapshot.go` | New | Multi-gateway SotW read model (`Data`/`Snapshot`/`Build`), id+slug indexes, embedded catalog. |
| `pkg/configsnapshot/adapters/*` | New | Snapshot-backed `domain.Repository` implementations (read-only; writes → `ErrReadOnly`). |
| `pkg/app/configsnapshot/{recompiler,holder,publisher}.go` | New | Control-plane compile/hold/publish (mirror TrustGuard). |
| `pkg/app/configsyncport/port.go` | New | `SnapshotSignaler` interface (nil no-op on DP). |
| Admin write use cases (`pkg/app/{gateway,registry,consumer,policy,auth,role,catalog}/*`) | Modified | `Signal()` after commit in creator/updater/deleter/associator/duplicator/scoper/sync. |
| `pkg/container/modules/modules.go` + `main.go` | Modified | Plane-aware module selection; gate `runMigrations`/`StartCacheEventListener`/`StartCatalogSync`; start `Worker` + readiness in `runProxy`/`runMCP`. |
| `pkg/container/modules/{core,gateway,registry,auth,policy,role,consumer,catalog,mcp}.go` | Modified/New | Split into `CoreData` + snapshot-adapter bindings on the DB-less graph; new `ControlConfigSync` + `ConfigSyncData` modules. |
| `pkg/infra/repository/vault` (Redis variant) | New | Redis-backed `vaultdomain.Repository` for DB-less MCP. |
| `pkg/config/config.go` | Modified | `ConfigSyncConfig` + plane-aware `Validate()`. |
| `pkg/api/middleware/config_sync_auth.go` | New | Bearer (`CONFIG_SYNC_TOKEN`) guard on the snapshot endpoint. |
| `*_test.go` (core, codec, adapters, read model, worker, config) | New | Mirror TrustGuard's test suite; `go test -race ./...`. |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| **Secret material in the snapshot** — registry entities carry decrypted creds; `Auth` carries `KeyHash`. | High | Transport auth (`CONFIG_SYNC_TOKEN` + `config_sync_auth`) and encrypted LKG (AES-256-GCM) are **mandatory**; assert the codec never logs bodies. |
| **Multi-gateway index / scoping divergence** — DP leaks or denies cross-gateway resources differently than Postgres. | High | Reproduce `NormalizeSlug` + `scopeToGateway` → `ErrNotFound` exactly in adapters; table-driven parity tests against pgx behavior. |
| **`StagePlan` precompute drift** — `DataFinder.buildPolicyPlan` over snapshot-sourced policies differs. | Med | Keep `DataFinder`/finders untouched; ensure the plugin `Registry` stays on the DP graph (`Plugins` module unchanged); compose-parity tests. |
| **Boot ordering / readiness** — DP serves traffic before first converge, or migrations run on the DB-less graph. | Med | Gate readiness on first converge **or** LKG restore (serve `503`); assert `runMigrations` and the pgx pool are fully skipped on the DB-less graph. |
| **Vault durability on Redis** — a lost entry drops a refresh token. | Med | Graceful degrade to re-consent (`ErrNotFound` already handled); document/enable Redis AOF in prod; Postgres carve-out is the documented fallback. |
| **Catalog version churn** — a models.dev refresh bumps the global snapshot fleet-wide. | Low | Accepted for v1 (catalog sync is infrequent, admin-boot); splittable into a second snapshot later. |
| **DI regression** — a DB-less module accidentally pulls `*database.Connection`. | Med | Distinct module set (no `dig.Decorate`); a boot smoke test that `proxy`/`mcp` start with `DB_*` unset. |
| **PR review budget** — DI + write-set slices are large. | Med | Chained PRs per the phase table; split P4/P5 along domain/module lines if over 400 lines. |

## Rollback plan

The DB-less DP is **gated behind `CONFIG_SYNC_DATA_PLANE_ENABLED`** and plane
selection. With the flag off, `modules.All()` returns the existing Postgres graph
unchanged and `proxy`/`mcp` boot exactly as today — so the change is
config-reversible without a code revert. On the control side, `ControlConfigSync`
and `Signal()` are additive: the `SnapshotSignaler` is nil (no-op) unless the
control module is present, and the existing `gateway_events` pub/sub invalidation
is untouched, so the admin plane behaves identically whether or not the snapshot
server is wired. No destructive schema migration is introduced (the DP simply
stops using Postgres). Per-phase, each chained PR reverts independently: P1–P3
are inert additions (no runtime wiring), P4 is additive-and-nil-guarded on admin,
and P5/P6 only take effect when the flag selects the DB-less graph.

## Success criteria (mapped to ENG-950)

- [ ] `proxy` and `mcp` boot and serve with **no Postgres** — `DB_*` unset, only
      `REDIS_*`, `KAFKA_BROKERS`, and `CONFIG_SYNC_*` required; `runMigrations`
      and the pgx pool are skipped on the DB-less graph.
- [ ] The DP resolves all config reads (gateway by slug/id, consumers,
      registries, policies, auths, roles, pricing) from the in-memory snapshot;
      `DataFinder`/`*.Finder`/`PricingResolver` and their TTL caches are
      unchanged; write methods return `configsync.ErrReadOnly`.
- [ ] Admin writes bump the snapshot version via `Signal()`; the DP converges
      over Redis Streams + HTTP+ETag and hot-swaps the in-memory snapshot
      (`atomic.Pointer`).
- [ ] Cold start restores the encrypted LKG when the admin plane is unreachable;
      readiness is gated on first converge or LKG restore (serve `503` until
      ready).
- [ ] Multi-gateway indexing + slug normalization + gateway scoping match the
      Postgres behavior (parity tests green).
- [ ] MCP per-user OAuth credentials resolve via the Redis-backed vault repo;
      missing entry degrades to re-consent.
- [ ] Snapshot transport is authenticated and the LKG is AES-256-GCM encrypted;
      no secret bodies are logged.
- [ ] `go test -race ./...` green across the new packages.
