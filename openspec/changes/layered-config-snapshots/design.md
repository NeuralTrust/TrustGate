# Design: Layered config snapshots (fragment compile and fragment pull)

Inputs: [`proposal.md`](./proposal.md), [`exploration.md`](./exploration.md),
specs `snapshot-compile-telemetry`, `snapshot-dirty-tracking`,
`snapshot-fragment-compile`, `snapshot-layered-pull` (written in parallel).
Base: TrustGate `feat/eng-3112-layered-config-snapshots` @ `5862832d`, which is
stacked on TrustGate#1273 (shared catalog, reuse of unchanged scopes, gzip).
Linear: ENG-3112 (parent ENG-3111).

## Technical Approach

Today a write leads to `Dispatcher.dispatch` running `Compiler.CompileAll`. That
reads every gateway with eight bulk scans, builds the read model per scope,
`toProto` JSON-encodes every entity, and then proto-marshals and hashes each
scope. A compile takes seconds at our size, almost all of the propagation latency.

Phase 1 replaces that with an **encoded-element cache**:

- Each entity's wire bytes (proto tag + length + payload) are cached, grouped by
  gateway.
- A write marks its gateway dirty in the outbox. Only dirty gateways are
  re-read, through the existing per-gateway path (`collectGateway`), and
  re-encoded.
- The global and scoped blobs are **assembled** by merging the cached runs in
  `sortData` order.

The result is byte-for-byte what `Codec.Encode` produces today, so versions,
the wire protocol, LKG rows and data planes are untouched. A full compile
rebuilds the same cache from the bulk read, so there is a single assembly path.

Phase 2 adds an opt-in layered protocol on top of the same cache:

- Each gateway's cached run is serialised as a self-contained proto fragment,
  content-addressed by sha256.
- A data plane that advertises `accepts_layered` pulls a manifest plus only the
  fragments it is missing.
- Everyone else keeps `GetSnapshot`.

## Architecture Decisions

| # | Decision | Alternatives rejected | Rationale |
|---|---|---|---|
| D1 | Cache encoded **elements** per entity, grouped by gateway; assemble with a per-field ordered merge (approach B) | A: cache `readmodel.Data` per gateway and fully re-encode. C: concatenate per-gateway fragments as the only layout | A still JSON-encodes and marshals every entity on every compile (the suspected bulk of the compile time). C changes every version, so old and new replicas disagree mid-rollout and every data plane refetches. B is byte-identical, which makes rollout risk-free. |
| D2 | Wire knowledge (tags, field order, element encoding, admission) lives in `pkg/infra/configsnapshot` behind an app-layer port `FragmentEncoder` | Put the merge in `pkg/app/configsnapshot` | The codec owns the wire format (`codec.go`). Byte identity must be proven next to `toProto`, and the app layer should not know proto field numbers (hexagonal rule in `.agents/AGENTS.md`). |
| D3 | Outbox markers gain nullable `gateway_id UUID` and `kind TEXT` (`gateway`, `catalog`, `all`). NULL kind, or `gateway` with NULL id, means `all` | Separate dirty table; payload in the Redis event | Additive and transactional with the write, like today. Rows from old replicas or unmigrated writers have NULL kind, so they fail safe into a full compile. |
| D4 | The Redis `SnapshotDirtyEvent` stays payload-free; it only wakes peers | Carry dirty ids in the event as a fast path | The outbox read is one indexed query (`seq > $1`), so a second source of truth would add cross-version decode risk for no measurable latency gain. |
| D5 | Per-replica in-memory **cursor** with gap tracking and expiry replaces `Pending` + `DeleteSeqs`. Rows age out only through `PruneOlderThan` | Keep `DeleteSeqs`; `pg_snapshot_xmin` watermark | Deleting rows makes peers lose the dirty set (exploration §3). Gap tracking handles a lower seq committing after a higher one without an xid column. Expired gaps stay in a bounded `late` set that is re-read every cycle, so a transaction slower than the gap expiry is published on the next cycle, not at the backstop; a prune past the cursor forces an immediate full compile. |
| D6 | The dispatch loop compiles **immediately** on a signal. Signals during a compile fold into the one-slot trigger and run right after ("compile while dirty"). Debounce applies only in legacy mode | Adaptive debounce; fixed interval; leader replica | Latency is the hard requirement (ENG-3111). A compile now costs milliseconds, so back-to-back compiles are cheap and every replica can afford them. |
| D7 | Full compile at boot, after LKG restore, on any `all` marker, when the prune passes the cursor, on cache-integrity errors, and on the backstop tick (5 min). The backstop also **compares** against the incremental state | Trust the incremental state alone | Markers can be missed (unmigrated writer, external DB edits, time-based revocation expiry, tenant caps without markers). A periodic full compile bounds staleness to the backstop interval, as today. |
| D8 | Shared inputs (tenant caps, session revocations, playground keys, usage enforcement) are re-read every cycle and stamped at assembly. The catalog is re-read only on a `catalog` marker or a full compile | Track caps and revocations as dirty kinds | Caps have no marker. Revocations change with time (`since = now - TTL`, `compiler.go:477`). Both are one indexed query each, and stage telemetry will show whether that holds. |
| D9 | Consumer admission (`admitConsumers` / `validateConsumerSmartRouting`) runs per gateway inside the fragment encoder | Validate against the full registry set | `validateConsumerSmartRouting` only accepts registries whose owner equals `c.GatewayID` (`routing_admission.go:131-142`). The outcome depends only on the consumer's own gateway, so per-gateway admission is exactly equivalent for global and scoped snapshots. |
| D10 | `CONFIG_SYNC_INCREMENTAL_COMPILE` (default `false`) switches between the new path and today's `CompileAll` + `Encode` | Ship always-on | Instant rollback without an image change. Equivalence tests run both paths. |
| D11 | New code never calls `DeleteSeqs`, whichever mode is on | Delete only in legacy mode | Flipping the switch is a rolling restart. If legacy replicas still deleted rows, incremental peers would lose markers during that window. |
| D12 | Phase 2 version = `"m1:" + hex(sha256(digest₁‖…‖digestₙ))` over raw 32-byte fragment digests, in manifest order | `sha256(concat bytes)` | Each fragment is verified by its own digest, so hashing the manifest is equivalent and avoids hashing about 8 MB per apply. The prefix keeps v1 and v2 versions from colliding in logs and acks. |
| D13 | Phase 2 notices carry the version that matches each connection's capability (hub stores `layered` per conn) | One version for everyone | Old planes compare v1 versions; layered planes compare manifest versions. |

## Data Flow

### Phase 1

    admin write ──tx──▶ repo.withGatewayMarkedTx(gw, fn)
                          │  INSERT outbox(seq, gateway_id=gw, kind='gateway')
                          ▼ commit
                      Signal() ──▶ local trigger (cap 1) + Redis SnapshotDirtyEvent ──▶ peers' trigger

    Dispatcher.Run (each replica, one goroutine):
      trigger ─▶ dispatch():
        markers, minSeq := outbox.ReadSince(cursor.lowWater)        # seq > lowWater
        cursor.Observe(markers, minSeq) ─▶ dirty{gateways, catalog, all}
        all? ─▶ full: bulk collect ─▶ encoder.Rebuild(all gateways)
        else ─▶ for gw in dirty: FindByID + collectGateway ─▶ encoder.Put(gw, data) | encoder.Delete(gw)
                catalog dirty ─▶ collectCatalog ─▶ encoder.PutCatalog
        caps, revocations := listTenantCaps(), listSessionRevocations()
        out := encoder.Assemble(Shared{caps, revocations, playgroundKeys, usage})
        holder.SetPartitioned / broadcast changed scopes / LKG persist   (unchanged)
        cursor.Commit()                                                  # only after success
      ticker(backstop) ─▶ full compile + drift compare

### Phase 2

    DP Hello{accepts_layered} ──▶ hub conn.layered = true
    publish ──▶ hub.BroadcastScope(scope, Versions{Blob, Manifest}) ──▶ notice{version: Manifest, layered: true}
    DP worker ──GetManifest(applied)──▶ {version, refs[digest,size]} | not_modified
              ──GetFragments(missing digests)──▶ stream chunks (gzip)
              verify sha256(fragment)==digest; recompute manifest version; concat; Decode; swap; ack

## Byte-identity argument

`Codec.Encode` is `proto.MarshalOptions{Deterministic: true}.Marshal(toProto(data))`
(`codec.go:46-59`). For `snapshotpb.Snapshot`:

1. **Field order.** protobuf-go marshals a generated message's populated known
   fields in ascending field-number order. `Deterministic` only changes map
   ordering, and `Snapshot` has no maps (`snapshot.proto:23-74`). Unknown
   fields are never set on encode. So
   `Encode = f1 ‖ f2 ‖ … ‖ f18`, where each `fN` is the encoding of field N, or
   empty when the field is unset or empty.
2. **Repeated message fields** (2–6, 10, 12–16, 18) encode as
   `⊕ over elements e, in slice order, of tag(N, LEN) ‖ varint(len(m(e))) ‖ m(e)`,
   where `m(e)` is the element message's own deterministic encoding (for example
   `Consumer{json}`, or `Auth{json, key_hash}` with `key_hash` omitted when
   empty). Each element encodes independently of its neighbours, so caching
   `elem(N, e) = tag ‖ len ‖ m(e)` and concatenating reproduces the field.
3. **Scalars.** `version` (1) is the empty string in every compile, because
   `CompileAll` never sets `Data.Version`, so it is omitted. Assembly asserts
   this. `usage_enforcement` (17) is emitted as `tag(17, VARINT) ‖ 0x01` only
   when true, and assembly places it **between 16 and 18**.
4. **Element order** is `sortData` (`compiler.go:1094-1157`). Every comparator
   is a total order on unique keys:
   - fields 2–6 by entity id (primary keys);
   - grants `(gateway, catalog_code, registry_id)`, budgets `(gateway, group_id)`
     and revocations `(gateway, org, subject)`, all primary keys;
   - store policies `(gateway, principal_type, principal_id)`;
   - Everyone at most one per gateway;
   - tenant caps by tenant, deduplicated by `stampTenantCaps`;
   - playground keys `(kid, pem)`.

   Since the keys are unique, `SliceStable` is insertion-order independent. The
   order of a filtered subset (hosted gateways for global, one gateway for a
   scope) is the restriction of that total order. Each gateway's run is sorted
   with the same comparator, so a k-way merge of the runs reproduces the
   global order exactly. Fields whose first key is the gateway (12, 13, 15, 16,
   18) reduce to concatenating runs in gateway-id order, because `GatewayID`
   compares by `String()` in `sortData`, the same order as field 2.
5. **Catalog.** Since #1273 the served bytes are
   `tenantEncode ‖ catalogEncode`, with fields 8 and 9 only in the catalog
   part. The assembler builds the tenant part (all fields except 8 and 9) and
   keeps #1273's shared catalog slice (`ScopedSnapshot{Raw, Catalog}`).
6. **Admission** (D9) and `attachSharedOAuth` are per registry, consumer and
   gateway, so the per-gateway encoding of a consumer is identical whether it
   came from the bulk or the per-gateway read.
7. **Corrupt rows.** `collectGateways` drops a gateway whose persisted config is
   corrupt, and a dirty gateway that reads as corrupt is removed from the cache
   in the same way. Any other read error aborts the cycle, keeps the previous
   cache, and leaves the cursor uncommitted so the cycle retries.

Points 1–4 are enforced by a randomized equivalence test (Testing).

## Interfaces / Contracts

```go
// pkg/app/configsyncport (ports)
type MarkerKind string
const (
    MarkerGateway MarkerKind = "gateway"
    MarkerCatalog MarkerKind = "catalog"
    MarkerAll     MarkerKind = "all"
)
type Marker struct {
    Seq       int64
    GatewayID ids.GatewayID // zero when Kind != MarkerGateway
    Kind      MarkerKind    // NULL kind or a NULL id with kind gateway reads as MarkerAll
}
type OutboxRepository interface {
    ReadSince(ctx context.Context, afterSeq int64) (markers []Marker, minSeq int64, err error)
    PruneOlderThan(ctx context.Context, cutoff time.Time, keepMax int) (int64, error)
    PendingCount(ctx context.Context) (int64, error) // boot log only
}

// pkg/app/configsnapshot (port, implemented in pkg/infra/configsnapshot)
type FragmentEncoder interface {
    Put(gw gatewaydomain.Gateway, data readmodel.Data) error // encode + admit + replace the gateway's runs
    Delete(id ids.GatewayID)
    PutCatalog(data readmodel.Data) error
    Rebuild(gateways []gatewaydomain.Gateway, data map[ids.GatewayID]*readmodel.Data, catalog readmodel.Data) error
    Assemble(shared SharedInputs) (Assembled, error)
}
type SharedInputs struct {
    TenantCaps         map[string]ratelimitdomain.TenantCaps
    SessionRevocations []readmodel.SessionRevocation
    PlaygroundKeys     []readmodel.VerificationKey
    UsageEnforcement   bool
}
type Assembled struct {
    Global   []byte            // tenant part only; the catalog is in Catalog
    Scoped   map[string][]byte // gateway id → tenant part
    Catalog  []byte
    Hosted   []ids.GatewayID   // phase 2: manifest order
}
```

**Cache structure** (infra, owned by the dispatcher goroutine, no locks):

```go
type gatewayRuns struct {
    hosted bool                 // !ServedByOwnDataPlane()
    tenant string
    runs   [numFields][]element // per proto field, sorted by the sortData comparator
    tenantBytes []byte          // phase 1: assembled scoped tenant part (reused when unchanged)
}
type element struct {
    key   string                // sortData key of the element (entity id, or the composite key joined)
    bytes []byte                // tag ‖ len ‖ m(e); never mutated after build
}
type cache struct {
    gateways map[ids.GatewayID]*gatewayRuns
    catalog  []byte             // #1273 shared slice
    global   []byte             // last assembled; reused when no hosted gateway or shared input changed
}
```

- **Invalidation.** `Put` and `Delete` replace one gateway's entry; `Rebuild`
  replaces the whole map. Scoped tenant bytes are rebuilt for dirty gateways and
  for gateways whose shared stamps changed (caps of their tenant, their
  revocations, playground keys, usage). Otherwise the previous slice and its
  version are reused, as in #1273.
- **Memory bound.** The cache holds one copy of every element's encoded bytes,
  about the size of all tenant parts (the global hosted snapshot plus hybrid
  gateways), plus about 50 B of headers per element. Served blobs are separate
  copies. The expected total is a small multiple of one global snapshot, against one
  catalog copy per scope per compile before #1273. No eviction is needed: size tracks configuration size.

**Outbox cursor** (app, dispatcher-owned):

- State: `lowWater int64`, `seen map[int64]struct{}` (seqs above `lowWater`),
  and `gaps map[int64]time.Time` (missing seqs and when they were first
  noticed).
- `Observe`: add the new markers to the dirty set. Any seq between `lowWater`
  and the maximum seen that is neither seen nor already a gap becomes a gap.
  A gap older than `CONFIG_SYNC_OUTBOX_GAP_EXPIRY` (default 30 s; rolled-back
  inserts leave permanent gaps) moves from `gaps` to `late`, a bounded set of
  expired seqs kept until the retention prune would remove them. Every cycle
  also reads `seq = ANY(late)`: a marker that commits after its gap expired is
  processed on the next cycle like any other marker, so a slow transaction is
  never left to the backstop. If `late` exceeds its bound, the cycle runs a full
  compile and clears it. Then
  `lowWater = min(open gaps) - 1`, or the maximum seen when there are none, and
  `seen` is pruned to entries above `lowWater`.
- Prune guard: if `minSeq > lowWater + 1` and the seqs in between are not
  known gaps, rows were pruned before this replica read them, so the cycle runs
  a full compile immediately (not at the next backstop tick).
- `Commit` makes the observed state current only after a successful publish.
  Failed cycles re-read.

**Phase 2 proto** (`configsync.proto`, additive):

```proto
message Hello { … bool accepts_layered = 5; }
message VersionNotice { string version = 1; bool layered = 2; }
rpc GetManifest(GetManifestRequest) returns (Manifest);
rpc GetFragments(GetFragmentsRequest) returns (stream FragmentChunk);
message GetManifestRequest { string applied_version = 1; }
message Manifest { string version = 1; bool not_modified = 2; repeated FragmentRef fragments = 3; }
message FragmentRef { bytes digest = 1; int64 size = 2; }
message GetFragmentsRequest { repeated bytes digests = 1; }
message FragmentChunk { bytes digest = 1; bytes data = 2; bool last = 3; }
```

- **Fragments.**
  - Gateway fragment = `Snapshot`-message bytes holding only that gateway's
    elements: fields 2–6, 12, 13, 15 (its revocations) and 16, 18. It is
    shared between the global manifest and the gateway's own scoped manifest.
  - Shared fragment per scope = 10, 14 (that scope's tenants) and 17.
  - Catalog fragment = #1273's catalog bytes.
- **Manifest order:** gateway fragments by gateway id, then shared, then
  catalog. Proto merge of the concatenation appends repeated fields, and
  `readmodel.Build` is order-insensitive (consumers, registries and policies
  are re-sorted at `readmodel/snapshot.go:266,312`; the other indexes are
  keyed), so the decoded read model equals the v1 decode. A test guards this.
- **Admin retention.** The holder keeps the fragments referenced by the
  current manifests plus the previous publish's fragments, a one-generation
  grace for in-flight pulls. An unknown digest returns `NotFound`, and the
  worker restarts from `GetManifest`.
- **Limits.** `GetFragments` reuses the 1 MiB chunking, `maxSnapshotBytes`,
  per-chunk revocation checks and gzip negotiation from `GetSnapshot`.
- **Worker.**
  - Keeps `frags map[digest][]byte` for the last applied manifest.
  - Converge: on a `layered` notice or the poll backstop it calls
    `GetManifest`. On `Unimplemented` it marks the server non-layered and uses
    `GetSnapshot`.
  - It fetches the missing digests, verifies each sha256, recomputes the
    manifest version, concatenates, decodes, swaps, persists LKG and acks.
  - Cache size equals snapshot size.
  - The LKG file format is unchanged. After a restart, the restored version is
    the v1 sha of the raw bytes, so the first layered converge fetches every
    fragment once. That is accepted: it equals today's restart cost.

## File Changes

| File | Layer | Action | Description |
|---|---|---|---|
| `pkg/infra/database/migrations/2026110612xxxx_outbox_dirty_scope.go` | infra | Create | `ADD COLUMN gateway_id UUID NULL, ADD COLUMN kind TEXT NULL`; down drops both |
| `pkg/infra/repository/outbox/repository.go` | infra | Modify | `AppendGatewayTx`, `AppendCatalogTx`; `AppendTx` writes `kind='all'`; `ReadSince` returns markers plus `min(seq)`; drop `Pending`/`DeleteSeqs` use |
| `pkg/infra/repository/{consumer,auth,gateway,policy,registry,catalog,keygroup,storeaccess/*}/repository.go`, `registry/secrets.go`, `sessionrevocation/repository.go` | infra | Modify | `withMarkedTx` → `withGatewayMarkedTx(ctx, gw, fn)` / `withMarkedTxFor(ctx, fn → gatewayID)` (`RETURNING gateway_id` for child-id methods); catalog → catalog kind; multi-gateway writes (`RestampEntitlementsByTenantID`, secret rotation) emit one marker per affected gateway via `RETURNING`, or `all` |
| `pkg/app/configsyncport/outbox.go` | app port | Modify | `Marker`, `MarkerKind`, new `OutboxRepository` |
| `pkg/app/configsnapshot/cursor.go` | app | Create | outbox cursor with gaps, expiry and prune guard |
| `pkg/app/configsnapshot/incremental.go` | app | Create | dirty-set dispatch: per-gateway collect, encoder calls, shared inputs, full fallback, drift compare |
| `pkg/app/configsnapshot/dispatcher.go` | app | Modify | `Run` compiles immediately in incremental mode; cursor replaces `Pending`/`DeleteSeqs`; mode switch; backstop runs full + compare |
| `pkg/app/configsnapshot/compiler.go` | app | Modify | export per-gateway collect (`CollectGateway`, `CollectAll`, `ListShared`) for the incremental path; stage timings |
| `pkg/app/configsnapshot/gateway_reader.go` | app port | Modify | add `FindByID` (already on the repository) |
| `pkg/app/configsnapshot/fragment_port.go` | app port | Create | `FragmentEncoder`, `SharedInputs`, `Assembled` |
| `pkg/infra/configsnapshot/fragments.go` | infra | Create | element encoding (reusing `toProto` element builders and admission), cache, k-way merge, assembly |
| `pkg/infra/configsnapshot/codec.go` | infra | Modify | factor per-element builders out of `toProto` so both paths share them |
| `pkg/app/configsnapshot/snapshot_metrics.go` | app | Modify | `compile_stage_duration{stage,mode}`, `compiles{mode,reason}`, `drift{scope_kind}` |
| `pkg/config/config.go` | config | Modify | `IncrementalCompile`, `OutboxGapExpiry`, `LayeredPull` (data plane) |
| `pkg/container/modules/control_config_sync.go` | composition | Modify | wire encoder, cursor, mode |
| `pkg/infra/configsnapshot/proto/configsync.proto` + generated | infra | Modify (P2) | Hello flag, notice flag, `GetManifest`, `GetFragments` |
| `pkg/infra/configsync/grpc/{service,hub,client}.go` | infra | Modify (P2) | per-conn capability, dual-version notices, new RPCs, client calls |
| `pkg/app/configsnapshot/holder.go` | app | Modify (P2) | manifests per scope, fragment store with one-generation grace |
| `pkg/runtimeconfig/sync/{worker,configsync}.go` | runtimeconfig | Modify (P2) | layered fetcher, fragment cache, manifest verification, fallback |
| `k8s/overlays/*/config.env` | deploy | Modify | switch off by default; enabled per env during rollout |

## Testing Strategy

| Layer | What to test | Approach |
|---|---|---|
| Unit (infra) | Byte identity | Property test over seeded random data (gateways hosted and own-plane, all entity kinds, smart-routing consumers passing and failing admission, empty `key_hash`, usage on and off, caps, revocations): `Assemble` == legacy `CompileAll` + `Encode` for global and every scope, bytes and versions |
| Unit (app) | Incremental vs full | Random mutation sequences (add, update and delete of every entity, a gateway switching hosted ↔ dedicated, gateway delete, catalog change, caps and revocation changes); after each step, incremental dispatch output equals a fresh full compile |
| Unit (app) | Cursor | Out-of-order visibility (seq 5 visible before 4), rollback gap expiry, prune past cursor → full, NULL kind → full, failed cycle does not commit |
| Unit (app) | Loop | Signal while compiling → exactly one follow-up compile with no timer wait; backstop → full + compare; drift counted only when the max seq is unchanged during the compare |
| Race | Concurrency | `go test -race`: concurrent Signal, writes, `GetSnapshot` serving and dispatch |
| Benchmark | Cost | 600 gateways: one dirty gateway (target < 10 ms excluding DB), catalog dirty, full rebuild; `ReportAllocs` |
| Repository (`-tags functional`) | Outbox | Migration up/down; markers carry `gateway_id`/`kind` for each repository write path (table-driven over the writer methods) |
| Functional | End to end | Existing `TestDBLessDataPlane_*` and `TestAdminLKG_*` with the switch on and off; new test: write → data plane converge, asserting incremental mode in the logs |
| Unit/functional (P2) | Layered pull | Decode(layered) read model equals Decode(v1); new client ↔ old server (`Unimplemented` → `GetSnapshot`); old client ↔ new server; digest mismatch rejected; `NotFound` retry; only missing fragments fetched |

## Migration / Rollout

1. **Image A** (switch off): migration, writers stamping markers, cursor,
   telemetry, new loop and encoder present but legacy compile active. No replica
   deletes markers once rolled. Old replicas inserting markers write NULL kind,
   which is `all`. Measure stage timings in production.
2. **DEV:** `CONFIG_SYNC_INCREMENTAL_COMPILE=true`. Check drift = 0 over days,
   `compile` in milliseconds, and the functional suite on DEV.
3. **Prod EU, then US:** enable the switch after image A is fully rolled. Watch
   drift, compile and write → applied latency.
4. **Phase 2:** first an admin image serving both paths, then data plane
   releases with `CONFIG_SYNC_LAYERED_PULL=true` (DEV first). Hybrid customer
   planes stay on v1 until they upgrade.
5. **Rollback:** switch off (phase 1). For phase 2, the data plane flag off, or
   an older admin, which answers `Unimplemented`. The migration stays; the
   columns are nullable and harmless.

## Rejected Alternatives

- Approach A and approach C: see D1.
- Single compiling replica or leader election: adds a hop and failover latency.
  With millisecond compiles every replica can compile.
- Debounce, adaptive debounce or a fixed interval: adds latency under exactly
  the sustained traffic we need to serve.
- `pg_snapshot_xmin` watermark: needs an xid column and xid-wraparound
  handling. The gap cursor plus backstop is simpler and bounded.
- LISTEN/NOTIFY instead of the outbox: notifications are lost while a replica
  is disconnected; the outbox is durable.
- Incremental apply on the data plane: out of scope; the apply costs about
  150 ms today.

## Open Questions

- [ ] None blocking. Stage telemetry (image A) will show whether re-reading
  tenant caps and session revocations every cycle (D8) is negligible. If not,
  revocations can move to a per-gateway marker (the domain carries
  `GatewayID`) and caps can get a `gateway`-kind marker from
  `SaveWithTenantCap` / `UpdateWithTenantCap` / `RestampEntitlementsByTenantID`.
