# Design: DB-less data plane with pull-based config sync (TrustGate) — ENG-950

## Technical Approach

Port the TrustGuard ENG-942 mechanism into TrustGate's `pkg/` layout. Copy the
project-agnostic transport core verbatim into `pkg/configsync/` and generalize
TrustGuard's single-collector snapshot into a **multi-gateway** State-of-the-World
read model in `pkg/configsnapshot/`. The proxy and mcp planes become DB-less by
resolving every `domain.Repository` from an in-memory snapshot behind
`atomic.Pointer`; `DataFinder`, all `*.Finder`s, `PricingResolver` and their TTL
caches stay **unchanged** — only the repository binding is swapped on the DB-less
DI graph. The admin/run graph gains a `ControlConfigSync` module (compiler over
the live pgx repos + debounced recompiler + Redis-Stream publisher + authed HTTP
endpoint) and a `Signal()` hook wired into every write use case. Plane divergence
is a **distinct module set**, never `dig.Decorate` (dig resolves the original
provider first, forcing the pgx pool to build — proven in
`TrustGuard: modules.go`). All Go code ports **without comments** per
`.agents/AGENT.md §11` (strip TrustGuard's doc comments during the port).

This maps to specs `control-plane-snapshot`, `data-plane-config-sync`,
`db-less-data-plane`, and `mcp-vault-redis`.

## Architecture Decisions

| Decision | Choice | Alternatives rejected | Rationale |
|---|---|---|---|
| Swap layer | Bind snapshot-backed `domain.Repository` per interface | Swap the `*.Finder` layer | Keeps `DataFinder`/finders/`PricingResolver` + TTL caches intact; smaller surface; scoping stays where it lives today. |
| Plane DI | Distinct DB-less module set via plane-aware `modules.All(plane, dbless)` | `dig.Decorate` overrides on DP | dig resolves the original pgx provider first → pool builds; documented non-viable in `TrustGuard: modules.go`. |
| Snapshot granularity | Fleet-wide SotW indexed by gateway id **and** normalized slug | Per-gateway snapshots | One endpoint/version/LKG/worker; matches reference. Blast radius accepted for v1 (locked). |
| Multi-gateway index | `bySlug map[string]GatewayID` + `xByGateway map[GatewayID][]…` + id/hash lookups | Reuse TrustGuard tenant+gateway keying verbatim | TrustGate routes by gateway slug (proxy) / id (mcp), not tenant/collector; generalize the index, drop `ambiguousGateways`. |
| Wire format | protobuf + `proto.MarshalOptions{Deterministic:true}`; version = hex SHA-256 = ETag | JSON / gob | Deterministic bytes → stable content hash; identical config never bumps version. Mirrors `infra/configsnapshot/codec.go`. |
| Catalog pricing | Embed in same SotW (`Data.CatalogModels`), global index | Second snapshot/endpoint | One artifact/pull/LKG; pricing needed DB-less for costcap/tokenratelimit. Catalog churn accepted for v1. |
| Vault (MCP) | Redis-backed `vaultdomain.Repository`, encrypted blob at rest | Snapshot / Postgres carve-out | Vault is runtime-mutable per-user state, not config; Redis already a hard MCP dep; miss degrades to re-consent. |
| LKG at rest | AES-256-GCM mandatory; transport bearer mandatory | Optional | Snapshot carries secrets (registry creds, `Auth.KeyHash`). Fail-closed auth middleware. |

## Data Flow

```
CONTROL/ADMIN plane (Postgres)                         DB-LESS DP (proxy/mcp)
  write use case commit                                  Worker.Run(ctx)
        │ Signal(ctx)                                       │ restoreLKG (AES-GCM)
        ▼                                                   │ notifier.Tail
  SnapshotVersionPublisher ──► Recompiler (debounce 2s)     ▼
        │ Compile(live repos)                            Converge:
        │ Encode(protobuf) → SHA-256                      fetch(If-None-Match:etag)
        │ if version != published:                        ├─ 304 → keep current
        │   Holder.Set(raw,ver)                           └─ 200 → verify sha==etag
        │   notifier.Publish(ver) ─ Redis Stream ───────►    decode → Build(Data)
        ▼                                                    store.Swap(atomic.Ptr)
  GET /internal/config/snapshot  ◄── HTTP+ETag ────────      persist LKG
  (config_sync_auth bearer) 200/304/503                      │
                                                             ▼
                                          snapshot-backed domain.Repository
                                          → DataFinder / *.Finder (TTL cache)
                                          → proxy/mcp hot path (unchanged)
```

Watch loop (Redis Streams `XREAD BLOCK`) + backstop poll (`POLL_INTERVAL`) both
call `Converge`; a single `convergeMu` serializes swaps.

## File Changes

Module path: `github.com/NeuralTrust/TrustGate/...`. `[port]` = strip-comment copy
from TrustGuard `internal/*` → TrustGate `pkg/*`.

| File | Action | Description |
|---|---|---|
| `pkg/configsync/configsync.go` | Create `[port]` | Interfaces `Versioned[T]`, `ConfigFetcher`, `ConfigStore[T]`, `ChangeNotifier`, `Crypto`, `SnapshotCodec[T]`. |
| `pkg/configsync/{http_fetcher,memory_store,aesgcm_crypto,redis_notifier,lkg,worker,readiness,errors}.go` | Create `[port]` | HTTP+ETag fetcher (send `X-Instance-Id`/`X-Applied-Version`); `atomic.Pointer` store; AES-256-GCM; go-redis **v8** Stream notifier (`Tail`/`Watch`/`Publish`); encrypted LKG; generic `Worker[T]`; `ReadinessCheck[T]`; `ErrReadOnly`/`ErrIntegrity`/`ErrLKGCorrupt`/`ErrNotReady`. |
| `pkg/infra/configsnapshot/proto/snapshot.proto` + `snapshot.pb.go` | Create | Messages: `Snapshot{version, gateways, consumers, registries, policies, auths, roles, catalog_models}` + nested (see Interfaces). `//go:generate protoc` directive only. |
| `pkg/infra/configsnapshot/codec.go` | Create | `Codec` implementing `SnapshotCodec[*readmodel.Snapshot]`: `toProto`/`fromProto`, deterministic marshal, SHA-256 `Version`. Only place importing both proto + domain. Never logs bodies. |
| `pkg/configsnapshot/readmodel/snapshot.go` | Create | Multi-gateway `Data` + immutable `Snapshot` + `Build(Data)`: `gatewaysByID`, `gatewaysBySlug` (`NormalizeSlug`), `gatewaysByDomain`, `consumersByGateway`+`byID`+`activeBySlug`, `registriesByGateway map[GW]map[RegID]`, `policiesByGateway`+`byID`, `authsByGateway`+`byID`+`byAPIKeyHash`+enabled-by-type, `rolesByGateway`+`byID`, `catalogByProviderSlug`. |
| `pkg/configsnapshot/adapters/{gateway,consumer,registry,policy,auth,role,catalog}_repository.go` | Create | One adapter per `domain.Repository`; reads from `store.Load()` snapshot, `scopeToGateway`→`domain.ErrNotFound`, deep-clone mutable returns; every write → `configsync.ErrReadOnly`. |
| `pkg/configsnapshot/adapters/adapters.go` | Create | `snapshotFrom(store)` helper + shared clone utilities. |
| `pkg/app/configsnapshot/{compiler,holder,recompiler,publisher}.go` | Create `[port]` | Compiler over live gateway/consumer/registry/policy/auth/role/catalog readers → sorted `Data`; `Holder` (atomic); debounced `Recompiler` (publish-on-change, retry-on-fail); `SnapshotVersionPublisher` (`Signal(ctx)` no-op when signaler nil). |
| `pkg/app/configsyncport/port.go` | Create `[port]` | `SnapshotSignaler` interface (`Signal(ctx)`). |
| `pkg/api/handler/http/configsnapshot/handler.go` | Create `[port]` | `Handler.Get`: 200+ETag / 304 / 503; logs pull headers only. |
| `pkg/api/middleware/config_sync_auth.go` | Create `[port]` | Constant-time SHA-256 bearer check vs `CONFIG_SYNC_TOKEN`; fail-closed when unset. |
| `pkg/infra/repository/vault/redis_repository.go` | Create | Redis `vaultdomain.Repository`; key `vault:{gatewayID}:{principalSub}:{provider}`; stores already-encrypted blob (JSON); `Find`/`Upsert`/`ListByPrincipal`/`Delete`; miss → `vaultdomain.ErrNotFound`. |
| `pkg/config/config.go` | Modify | `ConfigSyncConfig` (fields below) + `getConfigSyncConfig()`; plane-aware `Validate()`. |
| `pkg/container/modules/modules.go` | Modify | `All(plane string, dbless bool) []container.Option` → DB-less DP set vs full+ControlConfigSync set. |
| `pkg/container/modules/core_data.go` | Create | DB-less core: config/logger/redis/crypto, `provideNilConnection` (`func() *database.Connection { return nil }`), snapshot-adapter repo bindings for the 8 domains. |
| `pkg/container/modules/config_sync_data.go` | Create | DP half: `MemoryStore`, `Codec`, `AESGCMCrypto`, `HTTPFetcher`, `RedisStreamNotifier`, `LKGStore`, `Worker` (not started here). |
| `pkg/container/modules/control_config_sync.go` | Create | CP half: `Compiler` (via `compilerReaders dig.In`), `Holder`, `Codec`, notifier, `Recompiler`, `SnapshotVersionPublisher`→`SnapshotSignaler`, auth middleware, snapshot `Handler`. |
| `pkg/container/modules/{gateway,registry,auth,policy,role,consumer,catalog,mcp}.go` | Modify | Keep Postgres bindings on control graph; snapshot-adapter variants live in `core_data.go` for the DB-less graph (these modules excluded from DB-less set). MCP: bind Redis vault repo when DB-less. |
| `pkg/server/router/*` | Modify | Register snapshot endpoint on admin/run router; register `config_sync_auth` on that route only. |
| `cmd/trustgate/main.go` | Modify | Plane-aware `modules.All(plane, dbless)`; gate `runMigrations`/`StartCacheEventListener`/`StartCatalogSync`; DB-less `runProxy`/`runMCP` start `Worker`; `runAdmin`/`runAll` start `Recompiler` (eager `Signal()`); nil-safe `closeResources`. |
| `*_test.go` across new packages | Create `[port+new]` | Core, codec, adapters, readmodel, worker, config; DI smoke; functional parity. |

## Interfaces / Contracts

Snapshot proto (new entities; TrustGate-specific, replaces tenant/collector shape):

```proto
message Snapshot {
  string version = 1;
  repeated Gateway gateways = 2;
  repeated Consumer consumers = 3;
  repeated Registry registries = 4;
  repeated Policy policies = 5;
  repeated Auth auths = 6;
  repeated Role roles = 7;
  repeated CatalogModel catalog_models = 8;
}
// Gateway{id, slug, domain, ...}; Consumer{id, gateway_id, slug, active,
// registry_ids, role_ids, auth_ids, policy_ids, fallback...};
// Registry{id, gateway_id, ... , mcp_target{auth}}; Policy{id, gateway_id, slug,
// is_global, consumer_ids, config(structpb)}; Auth{id, gateway_id, key_hash,
// type, enabled}; Role{id, gateway_id, registry_ids};
// CatalogModel{provider_code, slug, display_name, input_price, output_price}.
```

Read model (multi-gateway generalization; `NormalizeSlug` + `scopeToGateway`):

```go
type Data struct {
    Version    string
    Gateways   []gatewaydomain.Gateway
    Consumers  []consumerdomain.Consumer
    Registries []registrydomain.Registry
    Policies   []policydomain.Policy
    Auths      []authdomain.Auth
    Roles      []roledomain.Role
    CatalogModels []catalogdomain.Model
}
func Build(data Data) *Snapshot            // indexes by id + normalized slug
func (s *Snapshot) GatewayBySlug(slug string) (*gatewaydomain.Gateway, bool)
func (s *Snapshot) ConsumersByGateway(id ids.GatewayID) []*consumerdomain.Consumer
func (s *Snapshot) AuthByAPIKeyHash(hash string) (*authdomain.Auth, bool)
// … one accessor per hot-path lookup listed in exploration §2
```

Adapter shape (mirrors `adapters/policy_repository.go`; one per domain):

```go
func NewGatewayRepository(store configsync.ConfigStore[*readmodel.Snapshot]) gatewaydomain.Repository
func (r *gatewayRepository) FindBySlug(_ context.Context, slug string) (*gatewaydomain.Gateway, error) {
    snap, ok := snapshotFrom(r.store)   // ErrNotFound if no snapshot yet
    g, ok := snap.GatewayBySlug(slug)   // ErrNotFound on miss
    clone := *g; return &clone, nil     // deep-clone mutable returns
}
func (r *gatewayRepository) Save(context.Context, *gatewaydomain.Gateway) error { return configsync.ErrReadOnly }
```

Config (mirror TrustGuard `ConfigSyncConfig` + `Validate`):

```go
type ConfigSyncConfig struct {
    DataPlaneEnabled  bool          // CONFIG_SYNC_DATA_PLANE_ENABLED (DB-less master flag)
    Token             string        // CONFIG_SYNC_TOKEN
    SnapshotURL       string        // CONFIG_SYNC_SNAPSHOT_URL
    StreamKey         string        // CONFIG_SYNC_STREAM_KEY
    StreamMaxLen      int64         // CONFIG_SYNC_STREAM_MAXLEN
    LKGPath           string        // CONFIG_SYNC_LKG_PATH
    LKGKey            string        // CONFIG_SYNC_LKG_KEY (base64 → 32 bytes)
    PollInterval      time.Duration // CONFIG_SYNC_POLL_INTERVAL
    RecompileDebounce time.Duration // CONFIG_SYNC_RECOMPILE_DEBOUNCE
    InstanceID        string        // CONFIG_SYNC_INSTANCE_ID
}
```

`Config.Validate()` becomes plane-aware: when proxy/mcp **and**
`DataPlaneEnabled`, skip `DB_HOST`/`DB_USER`/`DB_NAME` and instead require the
`CONFIG_SYNC_*` set (token, well-formed URL, LKG path, base64 32-byte key,
positive poll, non-empty stream key, `StreamMaxLen >= 1`). `REDIS_HOST` and
`KAFKA_BROKERS` stay required on the DP.

## Write-set `Signal()` call sites

`configsyncport.SnapshotSignaler` injected into each use case; `Signal(ctx)` after
successful commit, alongside the existing `gateway_events` pub/sub. Nil-safe:
DB-less graph never constructs these use cases.

| Domain | Files |
|---|---|
| gateway | `creator.go`, `updater.go`, `deleter.go` |
| registry | `creator.go`, `updater.go`, `deleter.go` |
| consumer | `creator.go`, `updater.go`, `deleter.go`, `associator.go` |
| policy | `creator.go`, `updater.go`, `deleter.go`, `duplicator.go`, `scoper.go` |
| auth | `creator.go`, `updater.go`, `deleter.go` |
| role | `creator.go`, `updater.go`, `deleter.go`, `associator.go` |
| catalog | `sync.go`, `provider_auth.go`, `mcp_servers.go` |

## DI split mechanics

`main.go` computes `(plane, dbless)` from `serverType()` + `cfg.ConfigSync.DataPlaneEnabled`
and calls `container.New(modules.All(plane, dbless)...)`.

- **DB-less DP set** (`(proxy|mcp) && dbless`): `CoreData`, `Cache`, `CacheEvents`,
  `Session`, `Telemetry`, `Auth`, `Policy`, `Plugins`, `LoadBalancer`, `Providers`,
  `Proxy`, `MCP` (Redis vault), `ServerProxy`/`ServerMCP`, `ConfigSyncData`. The 8
  DB-coupled domains resolve via `CoreData`'s snapshot-adapter bindings (never take
  `*database.Connection`). `provideNilConnection` supplies `func() *database.Connection { return nil }`
  so `optional:"true"` consumers (Plugins) stay resolvable without a pool.
- **Control/admin/run set**: existing 20-module Postgres graph **+** `ControlConfigSync`.
- **Gates** in `main.go`: `runMigrations`, `StartCacheEventListener`, `StartCatalogSync`
  skipped on DB-less; `Worker.Run(ctx)` started in `runProxy`/`runMCP` (goroutine +
  join on shutdown, mirror `startConfigSyncWorker`); `Recompiler.Run` + eager
  `Signal()` started in `runAdmin`/`runAll` (mirror `startRecompiler`). `/readyz`
  gated by `configsync.ReadinessCheck(store)` → 503 until first converge or LKG.
- `closeResources` gains nil-checks so a nil `*database.Connection` doesn't panic.

## Vault-on-Redis design

`vaultrepo.NewRedisRepository(rc *redis.Client, cipher vaultdomain.Encrypter)`
implements the 4-method `vaultdomain.Repository`. Key
`vault:{gatewayID}:{principalSub}:{provider}` holds the credential JSON with
`AccessToken`/`RefreshToken` **already encrypted** by the existing `Encrypter`
(unchanged at rest guarantee). `ListByPrincipal` scans
`vault:{gatewayID}:{principalSub}:*`. No TTL (tokens persist until refresh/delete);
rely on Redis AOF in prod for durability. `Find` miss → `vaultdomain.ErrNotFound`,
which `credentials.go` already treats as re-consent. Bound in the DB-less MCP
module in place of `vaultrepo.NewRepository(conn, cipher)`.

## Testing Strategy

| Layer | What | Approach |
|---|---|---|
| Unit (core) | store swap, worker converge/304/integrity-mismatch/LKG-restore, backoff, notifier tail/watch/publish, AES-GCM round-trip, readiness | `[port]` TrustGuard suite; `-race`; fake fetcher/notifier |
| Unit (codec) | encode→decode round-trip, **determinism** (same `Data` → same bytes → same SHA), unknown-field tolerance, secret fields never logged | table-driven `codec_test.go` |
| Unit (readmodel) | id+slug indexing, `NormalizeSlug`, `activeBySlug`, `byAPIKeyHash`, per-gateway grouping | table-driven |
| Unit (adapters) | read parity vs pgx (`scopeToGateway`→`ErrNotFound`, cross-gateway deny, clone isolation), all writes → `ErrReadOnly` | table-driven per adapter |
| Unit (compiler) | walk all gateways, sorted deterministic `Data`, `ErrNotFound` tolerance | fakes |
| Unit (config) | plane-aware `Validate` (DP skips `DB_*`, requires `CONFIG_SYNC_*`; base64/32-byte key; URL) | table-driven |
| DI smoke | `proxy`/`mcp` DB-less graph builds with `DB_*` unset; control graph builds `ControlConfigSync` | minimal `container.New`+`WithModule` (per AGENT.md §9) |
| Functional | admin write → `Signal` → publish → DP converges → hot-path parity (gateway-by-slug, consumer, policy plan) vs Postgres; MCP vault re-consist over Redis | end-to-end with fake admin endpoint + real codec |

All under `go test -race ./...`; `go vet` + `golangci-lint` clean (golang-pro workflow).

## Migration / Rollout

No schema migration (DP simply stops using Postgres). Gated by
`CONFIG_SYNC_DATA_PLANE_ENABLED` + plane selection: flag off → existing Postgres
graph unchanged. `ControlConfigSync` + `Signal()` are additive and nil-guarded on
admin. Phased chained PRs P1–P6 (proposal table); each reverts independently.

## Open Questions

- [ ] **Proto field IDs / package name** for the multi-gateway snapshot — finalize
  at P1 (`snapshot.proto`, `option go_package`). No blocker; codec is the only importer.
- [ ] **Registry `MCPTarget.Auth` encrypted-cred fidelity** — confirm the pgx
  registry repo decrypts on read so the compiled snapshot carries the same
  decrypted form the DP expects (mandates transport auth + encrypted LKG). Verify
  during P2 codec/adapter parity tests.
- [ ] **Catalog `FindModel` provider-code normalization** — reproduce
  `PricingResolver` provider/slug keying exactly in the global catalog index.
  Resolve from `pkg/app/catalog/pricing.go` at P2.
