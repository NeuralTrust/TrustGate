# Exploration: ENG-3112 — layered config snapshots (fragment compile and fragment pull)

Read against TrustGate `feat/eng-3112-layered-config-snapshots` at `5862832d`, which is stacked on
TrustGate#1273 (shared catalog, reuse of unchanged scopes, gzip). The parent issue ENG-3111 holds the
measurements: compile takes seconds, while publish → applied takes a fraction of a second.

## 1. What a compile reads, and what dirties it

### Outbox
- `config_snapshot_outbox(seq BIGSERIAL, created_at)` has no payload
  (`pkg/infra/database/migrations/20260630000000_config_snapshot_outbox.go`). A marker means "something
  changed", never what changed.
- Writers go through a per-repository `withMarkedTx(ctx, fn)`, which runs `fn` and then `AppendTx` in the
  same transaction. There are 45 call sites:

  | Repository | Call sites |
  |---|---|
  | consumer | 12 |
  | auth | 8 |
  | gateway | 7 |
  | policy | 5 |
  | registry | 4 |
  | catalog | 4 |
  | storeaccess everyone | 4 |
  | storeaccess grants | 4 |
  | keygroup budgets | 3 |
  | storeaccess policies | 3 |
  | consumer registry prune | 1 |

  Two writers call `AppendTx` directly: `registry/secrets.go:411` and `sessionrevocation/repository.go:66`.
  About 30 app-layer sites call `Signal`.
- Can each writer name the gateway it dirties?
  - Most methods take a `gatewayID`, or the row carries `gateway_id`. The storeaccess, keygroup and
    sessionrevocation domain types all carry `GatewayID`.
  - Some methods only know a child id, for example `consumer.DetachAuth(consumerID, authID)` and
    `DetachPolicy`. Those need `RETURNING gateway_id`, or a lookup inside the transaction.
  - Catalog writes are **shared**: they dirty the catalog fragment and nothing else.
  - Registry secret rotation (`secrets.go:411`) can touch registries of several gateways.
- **Resolution:** add a nullable `gateway_id` column, plus a `kind` column (`gateway | catalog | shared`),
  to the outbox. A NULL gateway with kind `gateway` means "unknown", and the replica falls back to a full
  compile. The change is additive and safe even if a writer is missed.

### `CompileAll` (`compiler.go:311`)
- **Per gateway:** `listGateways`, then `collectGateways` (`:621`). That normally means `collectAllBulk`
  (`:656`): eight paged full-table scans (consumers, registries, policies, auths, store grants, store
  policies, store everyone, key-group budgets), grouped by `GatewayID`. On corrupt data it falls back to
  `collectGatewaysEach` / `collectGateway` (`:864`, `:891`), which run per-gateway `ListByGateway`
  queries. **A per-gateway read path already exists**, and incremental compile reuses it for dirty
  gateways.
- **Shared, read on every compile:**
  - `listTenantCaps` (`:399`): no outbox marker; best effort with a last-good fallback.
  - `listSessionRevocations` (`:473`): stamped with the **full list into every scope** (`:539`).
  - `collectCatalogData`.
  - Playground keys and `usageEnforcement`: static process config.
- Where the compile time actually goes (bulk scans, JSON marshal of every entity in `toProto`,
  `readmodel.Build` per scope, sha256) is **not measured**. #1273 already removes the concatenation and
  per-scope catalog hashing. A timing breakdown should be the first task.

## 2. Determinism and byte identity

- `sortData` (`compiler.go:1094`) sorts each entity slice **globally by entity id**. Consumers are sorted
  by consumer id across all gateways, not grouped by gateway.
- `Codec.Encode` is deterministic proto marshal. Repeated fields come out in field-number order
  (`snapshot.proto` `Snapshot` fields 1–18, no maps), and the elements of each field are in slice order.
  Since #1273, served bytes are `tenantEncode || catalogEncode`, with fields 8 and 9 appended last.
- **Concatenating per-gateway fragments is not byte-identical.** It interleaves fields per gateway and
  changes element order, so every version would change and old and new replicas would disagree during a
  rollout. Proto would still decode to an equivalent message, and `readmodel.Build` is order-insensitive
  for every index:
  - Consumers are re-sorted by recency (`readmodel/snapshot.go:266`).
  - Registries and policies are re-sorted (`:312`).
  - The remaining indexes are keyed maps: slug, domain and key hash are unique.
- **Byte-identical alternative (preferred for Phase 1): an element-level cache.** Cache each entity's
  encoded proto element (tag + length + `{json, key_hash}`) by entity id, grouped by gateway. To assemble
  a blob, run a k-way merge of the cached element runs per field, in the same order `sortData` gives,
  and add the shared scalars and repeated fields. The result is byte-for-byte `Encode(full)`, so versions
  match old replicas and the protocol does not change. A dirty gateway re-reads its rows and re-encodes
  only its own elements; clean gateways cost a `memcpy`.
  - Watch `toProto` admission (`admitConsumers` / `validateConsumerSmartRouting`, which uses an owners
    map over *all* registries). It must be recomputed for a dirty gateway's consumers. A cross-gateway
    registry reference already fails validation.

## 3. Cross-replica consistency

- Each admin replica compiles. Peers learn of a write only through a Redis `SnapshotDirtyEvent{}` with
  no payload (`pkg/infra/cache/event/snapshot_dirty_event.go:22`), and react with a full compile.
- `dispatch` drains the markers it observed with `DeleteSeqs` (`dispatcher.go:257,329`). So replica A
  can delete markers before replica B reads them. That is harmless today, because B compiles everything.
  **With incremental compile it would lose dirty info.**
- **Resolution:**
  - Stop deleting markers per cycle. Each replica keeps an in-memory cursor over the outbox and the rows
    age out through the existing retention prune (`PruneOlderThan`: 24 h / 10k rows).
  - Re-scan a short lookback window and dedupe by seq. A seq is assigned at INSERT but committed later,
    so a lower seq can become visible after a higher one.
  - Carry the dirty `gateway_id`s in the pub/sub event as well, for latency. The outbox remains the
    source of truth.
  - At boot, after an LKG restore, or after an unknown marker, run a full compile.
  - Keep the existing backstop (5 min) as a full compile that also **compares** the incremental output
    against the full one and logs/counts drift.
- LKG (`lkg.go` `persist`) already persists only the scopes whose version changed. Restore loads blobs
  without fragments, so the first compile after a restore is a full one.

## 4. Data plane and Phase 2

- `Worker.Converge` (`pkg/runtimeconfig/sync/worker.go:156`) fetches the whole blob with `GetSnapshot`,
  checks `sha256(body) == version`, decodes, swaps, persists the LKG file and sends an Ack. The Sync
  stream sends `VersionNotice{version}`.
- `Hello` already negotiates capabilities: `accepts_usage = 3` and `accepts_usage_changes = 4`
  (`service.go:149-156`). That is the precedent for an `accepts_layered` flag.
- **Phase 2 proposal:**
  - Add `GetManifest(scope)`, returning `{version, repeated FragmentRef{digest, kind, size}}`.
  - Add `GetFragments(digests)`, streaming chunks with gzip, as in #1273.
  - The layered layout is the concatenation of per-gateway fragments plus shared and catalog fragments,
    ordered by kind and then gateway id. It is not byte-identical to v1, so it has its own version:
    `sha256(manifest)`.
  - The admin serves v1 (element-merged blob) to old planes and the manifest to planes that set
    `accepts_layered`. Notices carry the version that matches each stream's capability.
  - The data plane keeps the fragments of the last applied manifest, so cache size equals snapshot size.
    It verifies each fragment digest, then decodes the concatenation, which works because proto merges
    repeated fields.
- Hybrid customer planes on old builds keep v1 untouched.

## Approaches

| Approach | Byte-identical | DB work per write | CPU per write | Protocol change | Rollout risk |
|---|---|---|---|---|---|
| A. Cache per-gateway `readmodel.Data`, full encode | yes | 1 gateway | full JSON + proto encode of everything (~seconds?) | none | low |
| **B. Element-level encoded cache plus k-way merge (Phase 1)** | **yes** | **1 gateway** | **re-encode 1 gateway, memcpy the rest, sha** | **none** | **low** |
| C. Per-gateway fragments concatenated (v2 layout) | no | 1 gateway | concatenation + sha | version scheme changes | old/new replicas disagree on versions mid-rollout |
| D. Manifest plus fragment pull (Phase 2, on top of B) | v1 unchanged, v2 new | 1 gateway | as B, plus manifest | new RPCs + Hello flag | old planes unaffected |

Recommendation: **B for Phase 1**, then **D for Phase 2**. C only becomes acceptable as the v2 layout
behind the capability flag.

## Risks

- A writer that dirties a gateway without naming it means stale config until the drift check. Mitigated
  by NULL → full compile, the backstop compare, and a test that walks every `withMarkedTx` site.
- Tenant caps change with no outbox marker. They are re-read every cycle, as today, and a change
  re-stamps every scope's caps.
- A session revocation change dirties every scope, because the full list is stamped into each one. That
  is acceptable, because reassembly is cheap.
- The k-way merge must reproduce `sortData` exactly, including stable-sort tie-breaks. Guard it with a
  randomized equivalence test between incremental and full output.
- Element cache memory is about the size of one global snapshot plus maps (tens of MB at most).

## Open questions (for propose/design)

1. The compile time breakdown: decide whether to add a timing log or spans first.
2. A lookback window for the outbox cursor, versus a `pg_snapshot_xmin`-based visibility watermark.
3. Whether Phase 2's v2 version should be `sha256(manifest)` or `sha256(concat)`. Manifest is cheaper;
   concat keeps one verification path.
