# Tasks: Extend the semantic_cache plugin — RUN-699

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~2200–2500 across 7 PRs (≈900 prod + ≈1400 test/wiring/mocks) |
| 400-line budget risk | Medium-High — the 5 design phases do NOT all fit 400; P1 and P4 are split |
| Chained PRs recommended | Yes (7: P1a, P1b, P2, P3, P4a, P4b, P5) |
| Suggested split | P1a → P1b → P2 → P3 → P4a → P4b → P5 (strict chain) |
| Delivery strategy | ask-on-risk (stop before P2 cross-consumer slice and before P5 migration) |
| Chain strategy | feature-branch-chain off `feat/extend-semantic-cache` |
| Riskiest phases | **P2** (cross-consumer cache leakage), **P5** (pgvector migration + 1536-only column) |

Decision needed before apply: **No** — the split below targets ≤400/PR. Two
human-review gates are recommended anyway (see "Delivery gates").
Chained PRs recommended: Yes
Chain strategy: feature-branch-chain
400-line budget risk: Medium-High

### Per-phase line estimate

| Phase | Files | Prod | Test/wiring/mocks | Total | Fits 400 |
|-------|-------|------|-------------------|-------|----------|
| P1a | `config.go`, `plugin.go` (header+bypass+status gate+optional key), `data.go` | ~190 | ~190 | ~380 | Yes |
| P1b | `catalog_metadata.go`, `catalog_test.go` | ~95 | ~95 | ~190 | Yes |
| P2 | `plugin.go` (`partitionKey`+streaming+tools gates), `data.go`, `plugin_test.go` | ~130 | ~240 | ~370 | Yes |
| P3 | `factory.go`, `memory_store.go` (semantic), `modules/plugins.go`, `memory_store_test.go` | ~210 | ~180 | ~390 | Yes |
| P4a | `store.go` (interface+redis exact), `memory_store.go` (exact), `plugin.go` (`exactKey`/`normalize`), mocks, `store_test.go` | ~120 | ~250 | ~370 | Yes |
| P4b | `plugin.go` (mode dispatch in pre/post), `plugin_test.go` | ~130 | ~250 | ~380 | Yes |
| P5 | `pgvector_store.go`, `migrations/20260623120000_add_semantic_cache_pgvector.go`(+test), `factory.go` (pgvector case), `modules/plugins.go` (pool) | ~250 | ~110 | ~360 | Yes |

Recommendation: **feature-branch-chain** off a tracker branch
`feat/extend-semantic-cache`. PR #1 (P1a) base = `develop`; each later PR base =
the previous slice's branch, so every child diff stays ≤~400 lines and the chain
lands in order. The two design phases that overflow the budget are split:

- **P1 → P1a + P1b**: config/plugin/data churn is the largest slice; the catalog
  schema + its assertion test ship as a small, independent follow-up (per the
  proposal's "split P1 config-vs-catalog" note). P1b can technically merge before
  P1a is exercised, but keep it after so the catalog schema never advertises a
  field the plugin does not yet read.
- **P4 → P4a + P4b**: P4a lands the exact-match storage seam (interface methods +
  both backend implementations + key derivation + mocks + store-level tests) with
  the plugin still semantic-only; P4b wires the `exact`/`both` dispatch into
  `plugin.go` with its full mode matrix. This keeps the interface change and the
  control-flow change reviewable in isolation and each ≤400.

(Alternative: 5 independent PRs off `develop` — rejected. The phases are strictly
dependent — P4 needs P3's factory, P2 needs P1a's config — so independent PRs
would force constant rebases. Prefer the chain.)

### Delivery gates (ask-on-risk)

- **Before P2 merges**: request human review of the partition-isolation test
  matrix (`Scenario: Consumer scope isolates consumers` + empty-consumer
  pass-through). Cross-consumer leakage is the High risk in `proposal.md`.
- **Before P5 merges**: request human review of the migration (extension
  availability + `vector(1536)` fixed dimension) and confirm the pgvector backend
  is inert unless `vector_store: pgvector` is configured.

### Seam adjustments vs design.md (intentional)

- **The `Store` interface extension (`GetExact`/`PutExact`) lands in P4a, not
  P3.** `design.md`'s phase table places it in P3, but the prompt's phasing (and
  budget) put the exact-match capability wholly in P4. P3 ships only the factory +
  `in_memory` semantic backend + DI; `MemoryStore` implements just the existing
  three methods in P3 and gains the exact methods in P4a alongside `RedisStore`.
  This keeps P3 a pure backend-pluggability slice and the mock regeneration
  (interface change) confined to P4a.
- **`factory.go`'s `pgvector` case lands in P5, not P3.** P3's `NewStore` handles
  `redis` + `in_memory` only; adding the `pgvector` branch in P3 would reference a
  non-existent `NewPgvectorStore` and break the build. The branch ships with the
  backend it selects (P5).
- **The literal `X-Cache: MISS` mechanism is verified, not just asserted.** Design
  open-question 4 (does `mergeProviderResponse` preserve a pre-seeded `X-Cache`)
  is resolved in P1a by reading `executor.go`/`forwarder.go` before relying on the
  no-executor-change path; if the header is clobbered, P1a adds the MISS header in
  `post_response` instead and the forecast for P1a holds.
- **Exact Redis prefix is `sc_exact:`** (fully disjoint from the RediSearch
  `PREFIX "semantic_cache:"`), resolving design open-question 5 — `semantic_cache_exact:`
  is a string-superset of the index prefix and WOULD be indexed. Decided here so
  P4a writes the disjoint prefix from the start.

## Phase 1a: Config surface + back-compat + header + storing gate (no partition/store/mode change)

- [x] 1a.1 Rewrite `pkg/infra/plugins/semanticcache/config.go` `config` struct to
      add `TTLSeconds int (ttl_seconds)`, `Scope string`, `Mode string`,
      `VectorStore string`, `EmbeddingProvider`/`EmbeddingModel string`,
      `CacheOnlyOnStatus []int`, `BypassHeader string`, `SkipIfToolsPresent *bool`,
      `SkipIfStreaming bool`, keeping legacy `TTL string` and nested
      `Embedding embeddingConfig`. Add the const block from `design.md` (`modeExact`/
      `modeSemantic`/`modeBoth`, `scopeConsumer`/`scopeGlobal`, `storeRedis`/
      `storePgvector`/`storeInMemory`, `defaultTTLSeconds=86400`, `defaultBypassHeader`).
- [x] 1a.2 Add precedence accessors to `config.go`: `resolvedTTL()`, `provider()`,
      `model()`, `mode()`, `scope()`, `vectorStore()`, `bypassHeader()`,
      `skipIfTools()`, `cacheableStatus(code int)`; keep `embeddingDomainConfig()`
      sourcing `APIKey` from the nested struct. Delete `parsedTTL()`.
- [x] 1a.3 Make `applyDefaults()` seed only `SimilarityThreshold` (rest default via
      accessors so an empty config behaves like today). Rewrite `validate()` to be
      lenient: range-check `SimilarityThreshold` in `(0,1]`, validate `TTL` only when
      set and `TTLSeconds==0`, reject negative `TTLSeconds`, add `validateEnum` helper
      and enum-check `mode`/`scope`/`vector_store` (empty allowed). **Remove** the
      `embedding.api_key is required` check.
- [x] 1a.4 In `plugin.go`, fold the bypass predicate: add
      `func (p *Plugin) bypassed(req, cfg) bool` covering legacy `Cache-Control:
      no-cache` (existing `noCache`) + configured `cfg.bypassHeader()` present.
      (`skip_if_streaming` request side joins this in P2.) Call it first in `Execute`
      and short-circuit: pre_request → `missResult()`, other stages → `passThrough()`.
- [x] 1a.5 Add `missResult()` returning literal `X-Cache: MISS` + `X-Cache-Status: MISS`
      headers with `StopUpstream:false`; add literal `X-Cache: HIT` to the existing hit
      `Result.Headers` in `preRequest` (alongside `X-Cache-Status`/`X-Cache-Similarity`).
      Return `missResult()` (not bare `passThrough`) on every pre_request miss leg.
- [x] 1a.6 Replace the inline 2xx check in `postResponse` with
      `cfg.cacheableStatus(resp.StatusCode)`; record `SkipReason="status"` in extras
      when it blocks storing. Switch the TTL call from `cfg.parsedTTL()` to
      `cfg.resolvedTTL()` and embedding provider/model reads from `cfg.provider()`/
      `cfg.model()`.
- [x] 1a.7 In `data.go`, add `omitempty` fields `Mode`, `Scope`, `VectorStore`,
      `MatchType`, `Bypassed`, `SkipReason` to `SemanticCacheData` (additive; existing
      consumers unaffected).
- [x] 1a.8 Resolve design open-question 4: read `executor.go` (`applyResults` header
      merge) + `forwarder.go` (`baseHeaders` snapshot, `finalizeBody`) to confirm a
      `StopUpstream:false` pre_request `Result.Headers` survives onto the forwarded
      response. If clobbered, set `X-Cache: MISS` in `postResponse` instead.

### Phase 1a tests (`config_test.go`, `plugin_test.go`)

- [x] 1a.9 `config_test.go` table: legacy `ttl:"1h"` only → 3600s; `ttl_seconds:3600`
      + `ttl:"1h"` → seconds win; nested embedding only → provider/model from nested;
      flattened + nested → flattened win; missing `api_key` → valid; `similarity_threshold:1.5`
      → error; bad `mode`/`scope`/`vector_store` → error; empty config → defaults
      (assert `resolvedTTL`, `provider`, `model`, `mode`, `scope`, `vectorStore`,
      `skipIfTools`, `cacheableStatus`).
- [x] 1a.10 `plugin_test.go` rows: bypass via `cfg.bypassHeader()` present → no
      lookup/store + MISS; `Cache-Control: no-cache` still bypasses; hit returns
      `X-Cache: HIT` (+ legacy headers); miss returns `X-Cache: MISS`; `cache_only_on_status:[200]`
      blocks a `201`/`500` store, allows `200`.

**Verify**: `go build ./... ; go vet ./pkg/infra/plugins/semanticcache/... ; go test -race ./pkg/infra/plugins/semanticcache/...`.
**Rollback**: revert `config.go`/`plugin.go`/`data.go` + test rows; no store/partition touched.

## Phase 1b: Catalog metadata

- [x] 1b.1 In `pkg/app/plugins/catalog_metadata.go` `"semantic_cache"` entry: drop
      `embedding.Required` and `api_key.Required`; add fields `mode`
      (`FieldTypeEnum [exact,semantic,both]` default `"semantic"`), `scope`
      (`FieldTypeEnum [consumer,global]` default `"consumer"`, mirroring the
      `per_tool_rate_limiter` `scope` precedent), `vector_store`
      (`FieldTypeEnum [redis,pgvector,in_memory]` default `"redis"`), `ttl_seconds`
      (`FieldTypeInteger`), `embedding_provider`/`embedding_model` (`FieldTypeString`),
      `cache_only_on_status` (`FieldTypeArray` item `FieldTypeInteger` default `[200]`),
      `bypass_header` (`FieldTypeString` default `"X-Cache-Bypass"`),
      `skip_if_tools_present` (`FieldTypeBoolean` default `true`), `skip_if_streaming`
      (`FieldTypeBoolean` default `false`).
- [x] 1b.2 Extend `pkg/app/plugins/catalog_test.go` to assert the new field
      keys/types/enums/defaults and that `embedding` is no longer `Required`.

**Verify**: `go test -race ./pkg/app/plugins/... -run Catalog ; go vet ./pkg/app/plugins/...`.
**Rollback**: revert the catalog entry additions + test rows; plugin behaviour unchanged.

## Phase 2: Scope partitioning + streaming + tools gates

- [x] 2.1 In `plugin.go` add `partitionKey(cfg *config, scope appplugins.RuntimeScope,
      req *infracontext.RequestContext) (string, bool)` and `registryNamespace(req)`
      per `design.md`: `global` → `registry+"|g:"+scope.GatewayID`; default
      (`consumer`) → `registry+"|c:"+scope.ConsumerID`; empty subject id → `("",false)`
      (pass-through). Read ids from `in.Scope`, registry from `req` (`RegistryID`,
      gateway fallback).
- [x] 2.2 Replace both `scopeID(in.Request)` call sites (`preRequest` Lookup,
      `postResponse` Store) with the `partitionKey` result; delete `scopeID`. On
      `ok==false` record `Degraded:true, DegradedReason:"no_partition"` and return
      `missResult()` (pre) / `passThrough()` (post). Thread `partition` through both
      stage handlers' signatures.
- [x] 2.3 Add the `skip_if_streaming` request-side gate into `bypassed`
      (`cfg.SkipIfStreaming && p.requestWantsStream(req)`); add
      `requestWantsStream(req)` decoding the canonical request `Stream` flag with a
      generic `"stream":true` fallback (mirror the forwarder's `DetectStream`).
- [x] 2.4 Add the `skip_if_streaming` response-side gate in `postResponse`:
      `cfg.SkipIfStreaming && resp.Streaming` → pass-through, `SkipReason="streaming"`.
- [x] 2.5 Add the `skip_if_tools_present` gates: serve-side in `preRequest`
      (`cfg.skipIfTools()` and request canonical `Tools` non-empty → MISS, no serve,
      `SkipReason="tools_present"`); store-side in `postResponse` (request `Tools`
      non-empty OR response `ToolCalls` non-empty OR `FinishReason=="tool_calls"` →
      pass-through). Reuse `p.registry.DecodeRequestFor`/`DecodeResponseFor`; decode
      failure is fail-open (treated as "no tools").
- [x] 2.6 Populate `data.go` extras `Scope`, `SkipReason` on the new gate/partition
      paths.

### Phase 2 tests (`plugin_test.go`)

- [x] 2.7 Partition matrix: `scope:consumer` two different `ConsumerID`s → distinct
      partitions, B never reads A's body; empty `ConsumerID` → `ok=false` →
      pass-through + MISS; `scope:global` two requests same `GatewayID` → shared
      partition; two registries same consumer → distinct partitions; empty registry →
      gateway fallback.
- [x] 2.8 Streaming gate: `skip_if_streaming:true` + request `stream=true` → no
      lookup/store; `+ resp.Streaming` → no store; `false` → today's behaviour.
- [x] 2.9 Tools gate: `skip_if_tools_present:true` request with `Tools` → hit not
      served + store skipped; response `ToolCalls`/`FinishReason=="tool_calls"` →
      store skipped; default-true survives explicit `false` via the `*bool` pointer.

**Verify**: `go vet ./pkg/infra/plugins/semanticcache/... ; go test -race ./pkg/infra/plugins/semanticcache/...`.
**Rollback**: revert `plugin.go`/`data.go` + test rows; P1a config surface unaffected.
**Gate**: human review of consumer-isolation tests before merge (High risk).

## Phase 3: Store factory + in_memory backend + DI wiring (redis default unchanged)

- [x] 3.1 Create `pkg/infra/cache/semantic/factory.go`: `Deps{Redis *redis.Client,
      Pool *pgxpool.Pool, Logger *slog.Logger}` and `NewStore(kind string, deps Deps)
      (Store, error)` handling `""`/`"redis"` (nil client → error, else `NewRedisStore`)
      and `"in_memory"` (`NewMemoryStore`); `"pgvector"` and unknown kinds → error for
      now (pgvector case added in P5).
- [x] 3.2 Create `pkg/infra/cache/semantic/memory_store.go`: `MemoryStore` (mutex +
      `vec map[string][]memVector{vector,response,expiry}`), `NewMemoryStore(logger)`,
      and the existing-interface methods only — `EnsureIndex` (no-op), `Store` (append
      with `expiry=now+TTL`), `Lookup` (brute-force cosine `dot/(‖a‖·‖b‖)` over live
      entries, top-K desc, lazy + opportunistic TTL sweep). `var _ Store = (*MemoryStore)(nil)`.
- [x] 3.3 In `pkg/container/modules/plugins.go`: add `DB *database.Connection` to
      `pluginParams`; add `vectorStoreKind()` (env `SEMANTIC_CACHE_VECTOR_STORE`,
      default `redis`) and `poolOrNil(p.DB)` guard; build the store via
      `semantic.NewStore(p.vectorStoreKind(), semantic.Deps{Redis: redisClient,
      Pool: poolOrNil(p.DB), Logger: p.Logger})` (error-propagated) and pass it to
      `semanticcache.New`. `redis` default keeps the existing graph byte-identical.
- [x] 3.4 Resolve design open-question 2: confirm a minimal test container
      (`container.New` + selective modules, AGENT.md §9) tolerates the new optional
      `pluginParams.DB`; if dig requires it, make the field `optional:"true"`.

### Phase 3 tests (`memory_store_test.go`, factory rows)

- [x] 3.5 `factory_test.go`/rows: `NewStore` selects redis (nil deps → error) /
      in_memory; `"pgvector"` and unknown kind → error.
- [x] 3.6 `memory_store_test.go`: `Store`+`Lookup` cosine top-K ordering;
      TTL eviction (entry gone after `ttl` elapses); empty-rule lookup → no candidates.

**Verify**: `go build ./... ; go vet ./pkg/infra/cache/semantic/... ./pkg/container/modules/... ; go test -race ./pkg/infra/cache/semantic/...`.
**Rollback**: delete `factory.go`/`memory_store.go`, revert `plugins.go` to `NewRedisStore`; interface unchanged so no mock churn.

## Phase 4a: Exact-match storage seam (interface + redis + in_memory + keys)

- [x] 4a.1 In `store.go` extend `Store` with `GetExact(ctx, ruleID, key string)
      (string, bool, error)` and `PutExact(ctx, ruleID, key, response string,
      ttl time.Duration) error`. Add `const exactKeyPrefix = "sc_exact:"` (disjoint
      from `keyPrefix="semantic_cache:"`, resolving open-question 5).
- [x] 4a.2 Implement `RedisStore.GetExact` (`GET exactKeyPrefix+hashID(ruleID)+":"+key`,
      `redis.Nil`/error → `("",false,nil)`) and `RedisStore.PutExact`
      (`SET ... EX ttl`, error wrapped `%w`).
- [x] 4a.3 Implement `MemoryStore.GetExact`/`PutExact` over an
      `exact map[string]memEntry{value,expiry}` keyed by the composite, TTL-filtered
      on read.
- [x] 4a.4 In `plugin.go` add `exactKey(partition, text string) string`
      (`sha256(partition+"\x00"+normalize(text))`) and `normalize(s)` (lower-case +
      `strings.Fields` whitespace collapse).
- [x] 4a.5 Regenerate the store mock: `go generate ./pkg/infra/cache/semantic/...`
      (updates `mocks/store_mock.go` with the two new methods). Do not hand-edit.

### Phase 4a tests (`store_test.go`, `memory_store_test.go`)

- [x] 4a.6 `RedisStore` exact round-trip (miniredis or existing redis test harness):
      put→get hit, missing key → `("",false,nil)`, disjoint prefix never collides with
      a vector `HSET` key under `semantic_cache:`.
- [x] 4a.7 `MemoryStore` exact round-trip + TTL expiry; `exactKey` is
      case/whitespace-insensitive and partition-separated (`a|b` vs `a` + `|b` differ).

**Verify**: `go generate ./pkg/infra/cache/semantic/... ; go vet ./pkg/infra/cache/semantic/... ./pkg/infra/plugins/semanticcache/... ; go test -race ./pkg/infra/cache/semantic/...`.
**Rollback**: revert interface + both impls + `exactKey`/`normalize` + regenerated mock + test rows; plugin still semantic-only (P4b not yet merged), so no behaviour change.

## Phase 4b: Mode dispatch (exact / semantic / both) in plugin.go

- [x] 4b.1 In `preRequest` dispatch on `cfg.mode()`: `exact`/`both` → `store.GetExact(
      ctx, partition, exactKey(partition,text))` first; hit in enforce → serve via
      `hitResult(body, 0, exact=true)` (`MatchType:"exact"`, no `X-Cache-Similarity`);
      `exact` miss → `missResult()`; `both`/`semantic` → fall through to the existing
      embedding `Lookup` path (`MatchType:"semantic"`). Observe mode never serves.
- [x] 4b.2 Add `hitResult(body []byte, similarity float64, exact bool) *Result`
      emitting `X-Cache: HIT`/`X-Cache-Status: HIT` always and `X-Cache-Similarity`
      only when `!exact`; replace the inline hit `Result` from P1a.
- [x] 4b.3 In `postResponse` store per mode: `exact`/`both` → `store.PutExact(...)`;
      `semantic`/`both` → existing `store.Store(...)`. In `both`, a `PutExact` failure
      must not block the semantic store and vice-versa; each failure is a `Degraded`
      trace, never a request failure. Keep exact path embedding-free (no locator call).
- [x] 4b.4 Ensure index/embedding acquisition stays inside the semantic-only branches
      so `mode:exact` needs neither (move the `ensureIndex`/`GetService` calls out of
      `Execute`'s unconditional preamble into the semantic paths).
- [x] 4b.5 Set `data.go` `Mode` and `MatchType` extras on hit/store legs.

### Phase 4b tests (`plugin_test.go`)

- [x] 4b.6 `exact` mode: normalized-message hit returns HIT with NO embedding
      computed (assert the fake creator's `Generate` is never called); near-miss text →
      MISS.
- [x] 4b.7 `semantic` mode: threshold boundary (`0.97 ≥ 0.95` serves; `0.90` misses).
- [x] 4b.8 `both` mode: no exact match but semantic above threshold → exact miss +
      semantic hit; store writes BOTH keys; one store failure (exact or semantic) does
      not fail the request. Extend the existing `fakeStore` double with
      `GetExact`/`PutExact`.

**Verify**: `go vet ./pkg/infra/plugins/semanticcache/... ; go test -race ./pkg/infra/plugins/semanticcache/...`.
**Rollback**: revert the dispatch in `plugin.go` + test rows; P4a store methods remain as unused-but-compilable interface surface.

## Phase 5: pgvector backend + DB migration (inert unless configured)

- [x] 5.1 Create `pkg/infra/cache/semantic/pgvector_store.go`: `PgvectorStore{pool
      *pgxpool.Pool, logger, ensured atomic.Bool, mu sync.Mutex}`,
      `NewPgvectorStore(pool, logger)`, `var _ Store = (*PgvectorStore)(nil)`.
      `EnsureIndex` validates column dim once (no DDL — migration owns it); `Lookup`
      runs `SELECT response, 1-(embedding<=>$1) ... WHERE rule_id=$2 AND expires_at>now()
      ORDER BY embedding<=>$1 LIMIT $3` mapping rows → `Candidate`; `Store` inserts
      `(rule_id,embedding,response,expires_at)`; `GetExact`/`PutExact` over
      `semantic_cache_exact (rule_id,key,response,expires_at)`. Every query error /
      missing extension → degrade (`nil` / `("",false,nil)`), never fail traffic.
- [x] 5.2 Add the `"pgvector"` case to `factory.go` `NewStore` (nil `Pool` → error,
      else `NewPgvectorStore`).
- [x] 5.3 SEAM ADJUSTMENT (review fix): the pgvector schema is created LAZILY by the
      store (`PgvectorStore.ensureSchema`, run once on first use), NOT by a boot
      migration. A mandatory `database.RegisterMigration` running
      `CREATE EXTENSION IF NOT EXISTS vector` on every boot would abort startup for
      every Postgres deployment (including redis-default ones) where the extension or
      `CREATE EXTENSION` privilege is absent. `ensureSchema` runs the same idempotent
      DDL (`CREATE EXTENSION IF NOT EXISTS vector`; `semantic_cache_entries` with
      `embedding vector(1536)`, rule/`ivfflat vector_cosine_ops (lists=100)`/expires
      indexes; `semantic_cache_exact` PK `(rule_id,key)` + expiry index) only when
      `pgvector` is the configured backend, and degrades (no-op) on failure so traffic
      is never affected. Mirrors `RedisStore.EnsureIndex`'s lazy `FT.CREATE`.
- [x] 5.4 Resolve design open-question 3: validate-and-degrade on non-1536 dimension —
      `EnsureIndex`/`Store` reject a mismatched `len(emb.Value)` by degrading to
      pass-through and tracing it; document 1536-only for the pgvector backend in the
      migration/code (no parametric column for v1).
- [x] 5.5 In `pkg/container/modules/plugins.go` confirm `poolOrNil(p.DB)` feeds the
      factory so the pgvector branch resolves; admin/minimal graphs without
      `*database.Connection` stay nil-safe.

### Phase 5 tests

- [x] 5.6 SEAM ADJUSTMENT: no boot-migration test (no migration). The schema DDL is
      asserted indirectly via the store; pure DB-free unit tests cover the rest.
- [x] 5.7 `pgvector_store_test.go` (DB-free): `vectorLiteral` formatting; `EnsureIndex`
      1536 dimension guard; `Store` dimension-mismatch/nil-embedding degrade; exact
      get/put degrade without a pool. Live-DB coverage is deferred (no PG_TEST_URL
      harness in-repo).

**Verify**: `go build ./... ; go vet ./... ; go test -race ./pkg/infra/cache/semantic/... ; PG_TEST_URL=... go test -race ./pkg/infra/cache/semantic/... ./pkg/infra/database/migrations/...`.
**Rollback**: revert the pgvector file + factory case + `plugins.go` pool line; revert the migration (down is clean and the backend is inert unless `vector_store: pgvector`).
**Gate**: human review of the migration + 1536-only constraint before merge.

## Final verification (run before the last PR merges)

- [ ] V.1 `go build ./...`
- [ ] V.2 `go vet ./...`
- [ ] V.3 `golangci-lint run ./pkg/infra/plugins/semanticcache/... ./pkg/infra/cache/semantic/... ./pkg/app/plugins/... ./pkg/container/modules/... ./pkg/infra/database/migrations/...`
- [ ] V.4 `go test -race ./pkg/infra/plugins/semanticcache/... ./pkg/infra/cache/semantic/... ./pkg/app/plugins/...`
- [ ] V.5 `PG_TEST_URL=... go test -race ./pkg/infra/database/migrations/... ./pkg/infra/cache/semantic/...` (P5, env-gated)
- [ ] V.6 Confirm the pre-commit comment-strip hook leaves no comments (AGENT.md §11.1);
      only the Apache license header + `//go:generate`/`// #nosec` directives survive.
- [ ] V.7 Cross-check every `proposal.md` success criterion is covered by a P1a–P5 test
      (config back-compat, partition isolation, X-Cache headers, four gates, optional
      credentials, vector_store selection, mode behaviours, catalog parity).
