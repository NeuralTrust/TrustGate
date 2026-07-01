# Tasks: DB-less data plane with pull-based config sync (TrustGate) — ENG-950

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~7000 excl. generated `.pb.go` (~1400 generated) |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | 8 stacked slices P1→P8 (split heavy P1/P2/P4/P6 into a/b) |
| Delivery strategy | ask-on-risk |
| Chain strategy | feature-branch-chain |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: feature-branch-chain
400-line budget risk: High

### Per-phase forecast (additions+deletions, excl. generated `snapshot.pb.go`)

| Phase | Slice | Est. lines | Budget |
|---|---|---|---|
| P1 | Agnostic core + proto + codec | ~1900 | 🔴 over |
| P2 | Multi-gateway readmodel + adapters | ~1400 | 🔴 over |
| P3 | ConfigSyncConfig + plane-aware Validate | ~280 | ✅ under |
| P4 | CP compiler/holder/recompiler/publisher + authed endpoint | ~1600 | 🔴 over |
| P5 | Write-set `Signal()` hooks | ~380 | 🟡 near |
| P6 | Plane-aware DI + CoreData + main.go DB-less boot + readiness | ~800 | 🔴 over |
| P7 | Vault-on-Redis (MCP) | ~320 | 🟡 near |
| P8 | Functional test(s) + docs | ~400 | 🟡 near |
| **Total** | | **~7080** | (+~1400 generated) |

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | P1a core + P1b proto/codec | PR 1–2 | base = feat/eng-950…; each green alone |
| 2 | P2a readmodel + P2b adapters | PR 3–4 | base = prev PR branch |
| 3 | P3 config | PR 5 | base = prev PR branch; small, unblocks both graphs |
| 4 | P4a compile/hold/recompile/publish + P4b endpoint/mw/router | PR 6–7 | base = prev PR branch; additive on Postgres graph |
| 5 | P5 write-set Signal() | PR 8 | base = prev PR branch; nil no-op elsewhere |
| 6 | P6a DI/CoreData/ConfigSyncData + P6b main.go boot/readiness | PR 9–10 | base = prev PR branch; DP first boots DB-less |
| 7 | P7 vault-on-Redis | PR 11 | base = prev PR branch; MCP-only |
| 8 | P8 functional + docs | PR 12 | base = prev PR branch; only tracker merges to main |

Port strips TrustGuard comments (`.agents/AGENT.md §11`). Every phase: `go build ./...`, `go vet ./...`, `golangci-lint run`, `go test -race ./...` green. Recommendation: feature-branch-chain; single-PR + `size:exception` acceptable (ENG-942 precedent) — see summary.

## Phase 1: Agnostic core + snapshot proto + codec

Covers: data-plane-config-sync (atomic swap, LKG persistence/integrity, notify/converge mechanics), config-sync-security (LKG at rest, no-body logging), deterministic content-hash version.

- [x] 1.1 Port `pkg/configsync/configsync.go` (interfaces `Versioned[T]`, `ConfigFetcher`, `ConfigStore[T]`, `ChangeNotifier`, `Crypto`, `SnapshotCodec[T]`) + `errors.go` (`ErrReadOnly`, `ErrIntegrity`, `ErrLKGCorrupt`, `ErrNotReady`) from `TrustGuard: internal/configsync/*`, comments stripped.
- [x] 1.2 Port `pkg/configsync/{memory_store,aesgcm_crypto,readiness}.go` (`atomic.Pointer` store, AES-256-GCM crypto, `ReadinessCheck[T]`).
- [x] 1.3 Port `pkg/configsync/{http_fetcher,redis_notifier}.go` (HTTP+ETag fetcher sending `X-Instance-Id`/`X-Applied-Version` + bearer; go-redis **v8** Stream `Tail`/`Watch`/`Publish`, matching `pkg/infra/cache/client.go`).
- [x] 1.4 Port `pkg/configsync/{lkg,worker}.go` (encrypted disk LKG; generic `Worker[T]` converge loop: restoreLKG → capture last-id → fetch → 304/200 → verify sha==etag → swap → persist LKG; backstop poll).
- [x] 1.5 Create `pkg/infra/configsnapshot/proto/snapshot.proto` (messages `Snapshot{version,gateways,consumers,registries,policies,auths,roles,catalog_models}` + nested per design Interfaces) with `option go_package` + `//go:generate` directive; run **buf/protoc** to generate `snapshot.pb.go`.
- [x] 1.6 Create `pkg/infra/configsnapshot/codec.go` (`SnapshotCodec[*readmodel.Snapshot]`: `toProto`/`fromProto`, `proto.MarshalOptions{Deterministic:true}`, hex SHA-256 `Version`; never logs bodies) — stub `readmodel` types resolved in P2.
- [x] 1.7 Port core tests `pkg/configsync/*_test.go` (store swap; worker converge/304/integrity-mismatch/LKG-restore/backoff; notifier tail/watch/publish; AES-GCM round-trip; readiness) with fake fetcher/notifier; `-race`.
- [x] 1.8 Add `pkg/infra/configsnapshot/codec_test.go` (encode→decode round-trip, **determinism** same `Data`→same bytes→same SHA, unknown-field tolerance, secret fields never logged).

QA satisfied: LKG encrypted-at-rest + tamper-detected; atomic swap; no snapshot body in logs; deterministic version. Depends on: none.

## Phase 2: Multi-gateway read model + snapshot-backed adapters

Covers: db-less-data-plane (config read parity, gateway-scoped isolation, read-only write rejection, pricing from embedded catalog).

- [x] 2.1 Create `pkg/configsnapshot/readmodel/snapshot.go`: `Data` struct (Version + Gateways/Consumers/Registries/Policies/Auths/Roles/CatalogModels) + immutable `Snapshot` + `Build(Data)` building `gatewaysByID`, `gatewaysBySlug` (`gateway.NormalizeSlug`), `gatewaysByDomain`, `consumersByGateway`+`byID`+`activeBySlug`, `registriesByGateway map[GW]map[RegID]`, `policiesByGateway`+`byID`, `authsByGateway`+`byID`+`byAPIKeyHash`+enabled-by-type, `rolesByGateway`+`byID`, `catalogByProviderSlug`; one accessor per hot-path lookup (exploration §2).
- [x] 2.2 Wire `codec.go` `toProto`/`fromProto` to the real `readmodel` types; confirm registry `MCPTarget.Auth` decrypted-cred fidelity (design Open Q) in codec test.
- [x] 2.3 Create `pkg/configsnapshot/adapters/adapters.go` (`snapshotFrom(store)` → `ErrNotFound` if no snapshot; shared deep-clone helpers).
- [x] 2.4 Create `pkg/configsnapshot/adapters/gateway_repository.go` (`FindBySlug`/`FindByID`/`FindByDomain` from snapshot, clone; writes → `configsync.ErrReadOnly`).
- [x] 2.5 Create `consumer_repository.go` (`ListByGateway`/`FindByID`/`FindActiveBySlug`/`ListByAuthID`; all mutators → `ErrReadOnly`).
- [x] 2.6 Create `registry_repository.go` + `policy_repository.go` (`FindByIDs`/`FindByID`; `ListByGateway`/`FindByID`/`FindByIDs`; writes → `ErrReadOnly`).
- [x] 2.7 Create `auth_repository.go` + `role_repository.go` (`FindByAPIKeyHash`/`FindByIDs`/`FindByID`/`FindEnabledByTypes`/`ListEnabledByGatewayAndType`; role reads; writes → `ErrReadOnly`).
- [x] 2.8 Create `catalog_repository.go` (`FindModel`/`ListModelsByProviderCode`; reproduce `PricingResolver` provider/slug keying from `pkg/app/catalog/pricing.go`, design Open Q).
- [x] 2.9 Add `readmodel/snapshot_test.go` (id+slug indexing, `NormalizeSlug`, `activeBySlug`, `byAPIKeyHash`, per-gateway grouping) + `adapters/*_test.go` table-driven parity: `scopeToGateway`→`ErrNotFound`, cross-gateway deny, clone isolation, all writes → `ErrReadOnly`.

QA satisfied: read parity, gateway scoping, read-only writes, DB-less pricing. Depends on: P1.

## Phase 3: ConfigSyncConfig + plane-aware Validate

Covers: db-less-data-plane (boot without Postgres — env contract).

- [x] 3.1 In `pkg/config/config.go` add `ConfigSyncConfig` (fields per design: `DataPlaneEnabled`, `Token`, `SnapshotURL`, `StreamKey`, `StreamMaxLen`, `LKGPath`, `LKGKey`, `PollInterval`, `RecompileDebounce`, `InstanceID`) + `getConfigSyncConfig()` reading `CONFIG_SYNC_*`; wire into `LoadConfig`.
- [x] 3.2 Make `Config.Validate()` plane-aware: when `(proxy|mcp)` **and** `DataPlaneEnabled`, skip `DB_HOST`/`DB_USER`/`DB_NAME` and require `CONFIG_SYNC_*` (token, well-formed URL, LKG path, base64 32-byte key, positive poll, non-empty stream key, `StreamMaxLen>=1`); keep `REDIS_HOST`/`KAFKA_BROKERS` required.
- [x] 3.3 Add `pkg/config/config_test.go` cases: DB-less DP skips `DB_*`, requires `CONFIG_SYNC_*`; base64/32-byte key + URL validation; Redis/Kafka still required; Postgres graph unchanged.
- [x] 3.4 Add the `CONFIG_SYNC_*` set to `.env.example`.

QA satisfied: proxy/mcp env contract (`DB_*` unset OK; Redis/Kafka still required). Depends on: none (parallel to P1/P2).

## Phase 4: Control-plane snapshot server

Covers: control-plane-snapshot (compilation/versioning, authed HTTP endpoint+ETag, version bumps to Redis Stream), config-sync-security (transport auth fail-closed, no-body logging).

- [x] 4.1 Port `pkg/app/configsnapshot/compiler.go` (walk all gateways over live gateway/consumer/registry/policy/auth/role/catalog readers → sorted deterministic `readmodel.Data`; `ErrNotFound` tolerance).
- [x] 4.2 Port `pkg/app/configsnapshot/{holder,publisher}.go` (`Holder` atomic encoded snapshot; `SnapshotVersionPublisher` — `Signal(ctx)` no-op when signaler nil).
- [x] 4.3 Port `pkg/app/configsnapshot/recompiler.go` (debounced `RecompileDebounce`; publish-on-change via `RedisStreamNotifier.Publish(version)`; retry-on-fail; publish failure non-fatal).
- [x] 4.4 Port `pkg/api/handler/http/configsnapshot/handler.go` (`Handler.Get`: `200`+ETag / `304` on `If-None-Match`==version / `503`; logs pull headers only, never body).
- [x] 4.5 Port `pkg/api/middleware/config_sync_auth.go` (constant-time SHA-256 bearer vs `CONFIG_SYNC_TOKEN`; fail-closed when unset) and register on the snapshot route only in `pkg/server/router/*`.
- [x] 4.6 Create `pkg/container/modules/control_config_sync.go` (`Compiler` via `compilerReaders dig.In`, `Holder`, `Codec`, notifier, `Recompiler`, `SnapshotVersionPublisher`→`SnapshotSignaler`, auth middleware, `Handler`); add to admin/run module set in `modules.go`.
- [x] 4.7 Port tests: `compiler_test.go` (sorted deterministic Data, `ErrNotFound` tolerance, fakes), `holder_test.go`, `recompiler_test.go` (bursts coalesce, publish-on-change), `publisher_test.go`, `handler_test.go` (200/304/503), `config_sync_auth_test.go` (missing/invalid/unset-token rejection).

QA satisfied: version stable/changes, bursts coalesce, ETag 200/304, version→Redis Stream, publish-failure non-fatal, fail-closed auth, no body logged. Depends on: P1 (codec/notifier), P2 (readmodel), P3 (config).

## Phase 5: Write-set `Signal()` hooks

Covers: control-plane-snapshot (admin writes signal a version bump).

- [ ] 5.1 Port `pkg/app/configsyncport/port.go` (`SnapshotSignaler` interface `Signal(ctx)`).
- [ ] 5.2 Inject `configsyncport.SnapshotSignaler` (nil-safe) and call `Signal(ctx)` after successful commit — alongside existing `gateway_events` pub/sub — in gateway `creator/updater/deleter`, registry `creator/updater/deleter`, consumer `creator/updater/deleter/associator`.
- [ ] 5.3 Same for policy `creator/updater/deleter/duplicator/scoper`, auth `creator/updater/deleter`, role `creator/updater/deleter/associator`, catalog `sync/provider_auth/mcp_servers`.
- [ ] 5.4 Update the affected use-case constructors/DI providers to accept the (optional) signaler; add/extend tests: successful write signals once, failed write does not signal, nil signaler is a no-op.

QA satisfied: successful write triggers one signal; failed write no signal; nil no-op. Depends on: P4 (publisher implements `SnapshotSignaler`).

## Phase 6: Plane-aware DI + DB-less boot + readiness

Covers: db-less-data-plane (boot without Postgres, config-read wiring), data-plane-config-sync (readiness gating, cold-start/notify worker wiring).

- [ ] 6.1 Create `pkg/container/modules/core_data.go` (DB-less core: config/logger/redis/crypto, `provideNilConnection func() *database.Connection { return nil }`, snapshot-adapter bindings for gateway/registry/role/consumer/policy/auth/catalog — never take `*database.Connection`).
- [ ] 6.2 Create `pkg/container/modules/config_sync_data.go` (`MemoryStore`, `Codec`, `AESGCMCrypto`, `HTTPFetcher`, `RedisStreamNotifier`, `LKGStore`, `Worker` — not started here).
- [ ] 6.3 Change `pkg/container/modules/modules.go` to `All(plane string, dbless bool) []container.Option`: DB-less DP set (CoreData + Cache/CacheEvents/Session/Telemetry/Auth/Policy/Plugins/LoadBalancer/Providers/Proxy/MCP/Server*/ConfigSyncData) vs full Postgres set + `ControlConfigSync`; exclude the 8 pgx domain modules from the DB-less set.
- [ ] 6.4 In `cmd/trustgate/main.go` compute `(plane, dbless)` from `serverType()`+`cfg.ConfigSync.DataPlaneEnabled`; gate `runMigrations`/`StartCacheEventListener`/`StartCatalogSync` off on DB-less; nil-safe `closeResources`.
- [ ] 6.5 In `runProxy`/`runMCP` start `go worker.Run(ctx)` (join on shutdown, mirror `startConfigSyncWorker`); wire `/readyz` to `configsync.ReadinessCheck(store)` → `503` until first converge or LKG restore. In `runAdmin`/`runAll` start `Recompiler.Run` + eager `Signal()`.
- [ ] 6.6 Add DI smoke tests (per `.agents/AGENT.md §9`): `proxy`/`mcp` DB-less graph builds with `DB_*` unset (no `*database.Connection` pulled); control graph builds `ControlConfigSync`.

QA satisfied: boot no-Postgres (migrations/pool skipped), readiness 503→ready, notify/cold-start worker running. Depends on: P1–P5.

## Phase 7: Vault-on-Redis (DB-less MCP)

Covers: mcp-vault-redis (Redis-backed vault, credential-exchange DB-less, missing→re-consent).

- [ ] 7.1 Create `pkg/infra/repository/vault/redis_repository.go`: `NewRedisRepository(rc *redis.Client, cipher vaultdomain.Encrypter)` implementing `vaultdomain.Repository` — key `vault:{gatewayID}:{principalSub}:{provider}`; `Find`/`Upsert`/`ListByPrincipal` (scan `vault:{gw}:{sub}:*`)/`Delete`; store already-encrypted blob (JSON); no TTL; miss → `vaultdomain.ErrNotFound`.
- [ ] 7.2 Bind the Redis vault repo in the DB-less MCP module (`pkg/container/modules/mcp.go`) in place of `vaultrepo.NewRepository(conn, cipher)`.
- [ ] 7.3 Add `redis_repository_test.go` (miniredis/fake): upsert→find round-trip, value stored encrypted (raw value is ciphertext), `ListByPrincipal`, delete, missing → `ErrNotFound`→re-consent.

QA satisfied: MCP OAuth creds via Redis vault; encrypted at rest; missing→re-consent. Depends on: P6 (DB-less MCP graph).

## Phase 8: Functional test(s) + docs

Covers: cross-cutting end-to-end parity; config-sync-security (no body logged) assertion.

- [ ] 8.1 Add functional test: admin write → `Signal` → publish → DP converges (fake admin endpoint + real codec/notifier) → hot-path parity vs Postgres (gateway-by-slug, consumer, precomputed policy plan); assert no snapshot body in logs.
- [ ] 8.2 Add MCP vault re-consist functional check over Redis (upsert on connect flow → forwarded resolve → refresh persists).
- [ ] 8.3 Update `.agents/AGENT.md` (plane-aware DI, DB-less env contract, `CONFIG_SYNC_*`, buf proto-gen note) and archive the OpenSpec change.

QA satisfied: end-to-end converge + parity + secret-safety. Depends on: P1–P7.
