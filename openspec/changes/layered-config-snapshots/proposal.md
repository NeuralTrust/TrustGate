# Proposal: Layered config snapshots (fragment compile and fragment pull)

## Intent

Every admin write recompiles the **whole** config snapshot, covering every
gateway scope, on every admin replica. Every data plane then downloads the
full blob again. Measured in production during a sustained write burst on
one gateway:

- compile took several seconds per cycle;
- publish → applied on a data plane took a fraction of a second;
- so **compile is about 95% of propagation latency**;
- a write that lands mid-compile waits for two compiles, about 8–9 s from
  write to data plane.

Changes must reach the data plane as fast as possible, including under
sustained high traffic. That rules out debounce and a single leader replica,
because both add latency. The fix is to make the cost of a compile
proportional to what changed, the same way `docker push`/`docker pull` move
only new layers. Evidence: `exploration.md`.

Linear: ENG-3112 (TrustGate). Parent: ENG-3111. Builds on TrustGate#1273
(shared catalog, reuse of unchanged scopes, gzip).

## Scope

### In Scope

**Phase 1: fragment compile. No change to the protocol or the version.**
- **Compile timing per stage.** Measure DB reads per entity kind, validation,
  encode, and hash. Add the timings to the existing `published config
  snapshot` log line and to a histogram. This lands first, so we know where
  the compile time goes before and after the change.
- **Dirty tracking in the outbox.**
  - An additive migration adds nullable `gateway_id` and `kind` to
    `config_snapshot_outbox`.
  - Writers stamp the gateway they dirty. Writers that only hold a child id
    resolve the gateway (`RETURNING gateway_id`).
  - A marker without a gateway forces a full compile. This is the safe
    default for any writer not yet migrated.
- **Outbox cursor per replica.**
  - Each replica reads markers through its own cursor, with a time lookback
    window, deduplicated by seq.
  - This replaces the per-cycle `DeleteSeqs`. Markers age out through the
    existing retention prune.
  - Redis `SnapshotDirtyEvent` may carry the dirty gateway ids as a fast
    path. The outbox remains the source of truth.
- **Element cache and incremental compile (approach B).**
  - Cache the encoded proto element of each entity, grouped by gateway.
  - On a write, re-read and re-encode only the dirty gateways, reusing
    `collectGateway`. Re-validate the consumers of a dirty gateway against
    registries, as `admitConsumers` / `validateConsumerSmartRouting` require.
  - Build the global and scoped blobs by merging the cached runs in
    `sortData` order. The served bytes and versions are **byte-identical** to
    a full compile.
- **Compile-while-dirty loop.**
  - When idle, compile immediately.
  - Writes that arrive during a compile fold into the next compile, which
    starts as soon as the current one ends.
  - No timer delay. Every replica keeps compiling (no leader).
- **Full compiles as a safety net.** Boot, LKG restore and the periodic
  backstop (5 min) run a full compile. The backstop also compares the full
  result with the incremental state, logs and counts any drift, then
  publishes the full result.

**Phase 2: manifest and fragment pull (approach D).**
- **Capability flag.** `Hello` gains `accepts_layered`.
- **New RPCs, both gzipped.**
  - `GetManifest(scope)` returns the ordered list of fragment digests.
  - `GetFragments(digests)` streams the fragments.
- **Data plane.**
  - Caches fragments by digest and verifies the digest of each fragment.
  - Assembles the snapshot locally.
  - For layered planes, the version is the hash of the manifest.
- **Old data planes**, including hybrid customer planes on older builds, keep
  the single-blob `GetSnapshot` path and the v1 version, unchanged.
- **Sync notices** carry the version that matches each plane's capability.

### Out of Scope
- Incremental apply on the data plane: it still decodes the assembled
  snapshot, which costs about 150 ms today.
- TrustGuard v2 (ENG-3113) and TrustGuard-v3 (ENG-3114): they port this
  design once it is validated here.
- A single compiling replica or leader election, and any debounce or rate
  limit that adds latency.
- Changing the content of the snapshot (entities, fields, validation rules).

## Capabilities

### New Capabilities
- `snapshot-compile-telemetry`: per-stage compile timings in the publish log
  and a histogram.
- `snapshot-dirty-tracking`: outbox markers that name the gateway (or kind)
  they dirty; a per-replica cursor; the full-compile fallback for unnamed
  markers.
- `snapshot-fragment-compile`: element cache, incremental compile of dirty
  gateways, byte-identical merge, the compile-while-dirty loop, and backstop
  drift detection.
- `snapshot-layered-pull`: the `accepts_layered` negotiation, the
  `GetManifest` / `GetFragments` RPCs, the fragment cache on the data plane,
  manifest versioning, and the legacy single-blob path for old planes.

### Modified Capabilities
None. `openspec/specs/` has no config-snapshot spec today.

## Approach

**Phase 1** keeps the wire contract. Replicas of different versions,
incremental or not, serve the same bytes and the same version, so the admin
rollout carries no risk for data planes. The element cache keeps the
`sortData` ordering by merging per-gateway runs of already-encoded elements:
only dirty gateways hit Postgres and the encoder. Data shared by every
gateway (catalog, tenant caps, session revocations, playground keys, usage
enforcement) is re-read per compile, or tracked as its own marker kind.

Correctness rests on three things:
1. an unnamed marker always means a full compile;
2. full compiles run at boot, after LKG restore, and on the backstop;
3. the backstop compares its result with the incremental state.

**Phase 2** adds an opt-in protocol on top of the same fragments. Planes
advertise `accepts_layered`. The admin serves manifests and fragments to
them, and the v1 blob to everyone else.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `pkg/infra/database/migrations` | New | additive columns on `config_snapshot_outbox` |
| `pkg/infra/repository/**` (`withMarkedTx`, `AppendTx` callers) | Modified | writers stamp `gateway_id` / `kind` |
| `pkg/app/configsnapshot/dispatcher.go` | Modified | cursor, compile-while-dirty loop, full and incremental paths, drift check |
| `pkg/app/configsnapshot/compiler.go` | Modified | per-gateway incremental collect, element cache, ordered merge, stage timings |
| `pkg/app/configsnapshot/snapshot_metrics.go` | Modified | stage histogram, drift counter |
| `pkg/infra/configsnapshot/distributed_signaler.go`, cache events | Modified | optional dirty ids on `SnapshotDirtyEvent` |
| `pkg/infra/configsnapshot/proto`, `pkg/infra/configsync/grpc` | Modified (phase 2) | `accepts_layered`, `GetManifest`, `GetFragments`, per-capability notices |
| `pkg/runtimeconfig/sync` | Modified (phase 2) | fragment cache, manifest assembly and verification |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| An incremental blob differs from a full one, so versions split across replicas | Med | byte-equivalence tests over randomized writes; backstop drift counter; a full compile wins |
| A writer forgets to stamp its gateway, so the change is missed | Med | an unnamed marker forces a full compile; an audit test lists every `AppendTx` caller |
| A lower seq becomes visible after a higher one, so the cursor skips it | Low | time lookback window, dedupe by seq, backstop full compile |
| A cross-gateway validation dependency (consumer ↔ registry) is missed | Med | re-validate the dirty gateway's consumers; registry/secret writes mark every affected gateway or force a full compile |
| The element cache costs memory | Low | it holds the same encoded bytes that are served today; measure with the stage timings and `kubectl top` |
| Phase 2 breaks old hybrid planes | Low | v1 path unchanged and the capability is opt-in; test an old client against a new server |

## Rollback Plan

The migration is additive. A config switch (default off on the first
deploy) chooses between incremental and full compile; turning it off
restores today's behaviour without a rollback. Because Phase 1 output is
byte-identical, rolling back the admin image has no effect on data planes.
Phase 2 is gated by `accepts_layered`: an admin that does not serve it, or a
data plane that does not advertise it, falls back to `GetSnapshot`.

## Dependencies

- TrustGate#1273, merged first. This change is stacked on it.

## Success Criteria

- [ ] Compile after a single dirty gateway runs in milliseconds (benchmark with about 600 gateways, and the prod `compile` stage timings).
- [ ] Write → applied on the data plane stays under 1 s at p90 during a sustained write burst in prod.
- [ ] The backstop reports zero drift between incremental and full compiles in DEV and prod.
- [ ] Old and new data planes converge on the same configuration (local functional suite and DEV).
- [ ] A layered plane downloads only the fragments that changed (bytes per apply visible in logs).
