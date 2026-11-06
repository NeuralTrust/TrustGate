# Tasks: Layered config snapshots (fragment compile and fragment pull)

Linear: ENG-3112 (parent ENG-3111). Base `origin/develop` (TrustGate#1273 is merged).
Chain strategy: stacked PRs to `develop`, one branch per slice
(`feat/eng-3112-sN-<slug>`), each cut from the previous slice.

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~2,900 total: Phase 1 ~2,000 (S1–S5), Phase 2 ~900 (S6–S7), tests included |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | S1 → S2 → S3 → S4 → S5 (Phase 1, deployable with the switch off) → S6 → S7 (Phase 2) |
| Delivery strategy | ask-on-risk |
| Chain strategy | stacked PRs to `develop` (approved) |

Decision needed before apply: No (approved: S1–S7)
Chained PRs recommended: Yes
Chain strategy: stacked-to-develop
400-line budget risk: High

Why stacked PRs to `develop`: every Phase 1 slice is inert in production until
`CONFIG_SYNC_INCREMENTAL_COMPILE=true`. Before S5 the new code is unused or only
adds telemetry and markers, so each slice can merge and deploy alone. That also
lets image A collect the stage timings in prod before the switch is flipped.

### Suggested Work Units

| Unit | Goal | PR | Lines | Notes |
|------|------|----|-------|-------|
| S1 | Per-stage compile telemetry | PR 1 | ~200 | Base: `develop`. No behavior change. |
| S2 | Outbox dirty scope: migration, port, repository, writers | PR 2 | ~550 | Over budget: the writer sweep is mechanical, table-driven tests. Split S2a/S2b if a reviewer asks. |
| S3 | Outbox cursor + compile-while-dirty loop (legacy compile still active) | PR 3 | ~400 | Removes `DeleteSeqs` in every mode (D11). |
| S4 | Fragment encoder: element builders, cache, merge, assemble + byte-identity property test | PR 4 | ~600 | Test-heavy (~300 of the lines). Unused until S5. |
| S5 | Incremental dispatch behind `CONFIG_SYNC_INCREMENTAL_COMPILE` (default off), drift compare, wiring | PR 5 | ~550 | Phase 1 complete. Deploy with the switch off, then enable on DEV. |
| S6 | Phase 2 admin: proto, Hello flag, `GetManifest`/`GetFragments`, holder fragments, hub per-conn capability | PR 6 | ~500 | Only after Phase 1 runs in prod. Old data planes unaffected. |
| S7 | Phase 2 data plane: layered fetcher, fragment cache, fallback, `CONFIG_SYNC_LAYERED_PULL` | PR 7 | ~400 | DEV first; hybrid customer planes stay on v1 until they upgrade. |

Common verification for every slice (run from the worktree root):

```bash
go build ./... && go vet ./... && go vet -tags functional ./...
go test -race ./pkg/app/configsnapshot/... ./pkg/infra/configsnapshot/... ./pkg/infra/configsync/... ./pkg/runtimeconfig/...
golangci-lint run ./pkg/...
```

Each slice ends by running `clean-comments` on its touched Go files and
committing as one work unit.

## Phase 1 — Fragment compile, protocol unchanged

### S1: Compile stage telemetry

- [x] 1.1 Add a stage timer to the compile path: `pkg/app/configsnapshot/compiler.go`
  (`CompileAll` reads per entity kind, catalog, caps, revocations, validation/admission)
  and `dispatcher.go` (encode, hash, holder set, persist). Collect it into a
  `compileStages` value on `compiledSnapshot`.
  Verify: `go test ./pkg/app/configsnapshot/ -run Stage`.
- [x] 1.2 Extend the `published config snapshot` log with `mode`, `reason`,
  `dirty` and per-stage durations. Keep `compile` as the total.
  Verify: log assertion test in `snapshot_metrics_test.go`.
- [x] 1.3 Add `trustgate.configsnapshot.compile_stage_duration{stage,mode}` and
  `trustgate.configsnapshot.compiles{mode,reason}` in `snapshot_metrics.go`,
  recorded on failed compiles too. Spec `snapshot-compile-telemetry` scenarios.
  Verify: `go test ./pkg/app/configsnapshot/ -run Metrics`.
- [x] 1.4 Test that telemetry never changes snapshot bytes or versions: the
  existing equivalence tests stay green, plus one assertion with telemetry on.

S1 notes (applied):
- Legacy compiles report stages `read`, `build`, `encode`, `merge`, `hash`.
  `build` (sortData + readmodel.Build) is an extra stage not in the spec list;
  it is reported separately so read time is not inflated by in-memory work.
- `validate` is not separable in the legacy path: consumer admission runs
  inside `Codec.Encode`, so it is counted in `encode`. The fragment path (S4)
  reports `validate` on its own.
- Legacy compiles always log `mode=full`, `dirty=0`; reason is `boot` for the
  first successful compile in the process, `backstop` for the ticker and
  `signal` for a compile triggered by an admin write. `switch_off` is reserved
  for a write-triggered full compile once the incremental switch exists (S5).

### S2: Outbox dirty scope (markers know their gateway)

- [x] 2.1 Migration `pkg/infra/database/migrations/2026110612xxxx_outbox_dirty_scope.go`:
  `ADD COLUMN gateway_id UUID NULL, ADD COLUMN kind TEXT NULL`, with a down that
  drops both. Register it in the migrations list.
  Verify: `PG_TEST_URL=… go test -tags functional ./pkg/infra/database/migrations/...`.
- [x] 2.2 Port `pkg/app/configsyncport/outbox.go`: `MarkerKind` (`gateway`,
  `catalog`, `all`), `Marker`, `ReadSince(ctx, afterSeq) ([]Marker, minSeq, error)`.
  Keep `PendingCount` and `PruneOlderThan`. NULL kind, or `gateway` with a NULL
  id, decodes as `all`.
- [x] 2.3 `pkg/infra/repository/outbox/repository.go`: `AppendGatewayTx`,
  `AppendCatalogTx`, `AppendTx` writing `kind='all'`, `ReadSince`.
  Verify: functional repository tests for each kind, for NULL-kind rows written
  as an old build would, and for out-of-order seq visibility.
- [x] 2.4 Writer sweep: replace `withMarkedTx` with `withGatewayMarkedTx` /
  `withMarkedTxFor` in `pkg/infra/repository/{consumer,auth,gateway,policy,registry,catalog,keygroup,storeaccess/*}`,
  `registry/secrets.go:411` and `sessionrevocation/repository.go:66`. Child-id
  methods (`DetachAuth`, `DetachPolicy`, …) resolve the gateway via `RETURNING gateway_id`.
  Multi-gateway writes (`RestampEntitlementsByTenantID`, secret rotation) emit one
  marker per affected gateway, or `all`. Catalog writes emit `catalog`.
  Verify: one table-driven functional test over the writer methods, asserting
  `gateway_id`/`kind` for each (`go test -tags functional -p 1 ./tests/functional/repositories/...`).
- [x] 2.5 Leave the dispatcher behavior unchanged in this slice: it still uses
  `Pending`/`DeleteSeqs` through a thin adapter, so S2 deploys alone.

S2 notes (as implemented):
- Migration `20261106120000_outbox_dirty_scope`; it registers through `init`
  like every other migration, so there is no list to edit.
- `OutboxRepository` is unchanged for the dispatcher (`Pending`/`DeleteSeqs`
  stay on the repository, no adapter needed). `ReadSince` is a separate port,
  `configsyncport.OutboxMarkerReader`, which S3 folds into `OutboxRepository`.
  It reads the minimum seq and the markers in one statement.
- Writers record what they dirtied on an `outbox.Marks`
  (`outbox.WithMarkedTx` / `WithGatewayMarkedTx`). Recording nothing, or a nil
  gateway, appends one `all` marker, so an unmigrated writer fails safe.
- Child-id consumer writes (`AttachRegistry`, `AttachAuth`, `DetachAuth`,
  `AttachPolicy`, `DetachPolicy`) resolve the gateway with a `SELECT gateway_id`
  on the consumer in the same transaction rather than `RETURNING`: the link
  tables carry no gateway column. A consumer that no longer exists falls back
  to `all`.
- Session revocations, key group budgets and store grants/policies/Everyone
  stamp their gateway; tenant caps and revocations are re-read on every cycle
  (D8), so a gateway marker is enough to start one. Only the D3 kinds exist
  (`gateway`, `catalog`, `all`); the spec's extra shared kinds were folded into
  them, and any unknown kind decodes as `all`.
- A nil appender writes no marker (keygroup and storeaccess already allowed it).

### S3: Outbox cursor + compile-while-dirty loop

- [x] 3.1 `pkg/app/configsnapshot/cursor.go`: `lowWater`, `seen`, `gaps` with
  first-seen time, `Observe(markers, minSeq) dirtySet`, prune guard (forces a
  full compile when rows were pruned before this replica read them), and
  `Commit` only after a successful publish. Add config `CONFIG_SYNC_OUTBOX_GAP_EXPIRY`
  (default 30s) in `pkg/config/config.go`.
  Verify: `cursor_test.go` covers seq 5 visible before 4, gap expiry after
  rollback, a marker that commits after its gap expired is processed on the
  next cycle (late set, no backstop wait), late set over its bound → full,
  prune past cursor → immediate full, NULL kind → full, failed cycle re-reads.
- [x] 3.2 `dispatcher.go`: replace `Pending` + `DeleteSeqs` with the cursor. No
  code path deletes markers any more (D11); rows age out via `PruneOlderThan`.
  Remove the S2 adapter. This changes behavior even with the switch off: the
  outbox is no longer drained and grows to the retention/row bound, and the
  boot `PendingCount` check is always above zero, so boot always signals a
  compile (it already does a full one). Update `TestDispatch_Drains…` to the
  new contract on purpose instead of deleting it.
  Rollout rule: the incremental switch is turned on in an environment only in a
  separate deploy, after every admin replica runs the S3 build, so no old
  replica can delete markers the new ones still need.
- [x] 3.3 `Dispatcher.Run`: in incremental mode, compile immediately on a
  signal; signals during a compile fold into exactly one follow-up compile with
  no timer. Legacy mode keeps today's leading-edge plus 250 ms debounce. The
  backstop tick is unchanged. The legacy compile is still the one that runs.
  Verify: `dispatcher_test.go` checks that a signal during a compile gives one
  follow-up with no wait, that a burst of N signals gives at most 2 compiles,
  and runs with `-race`.
- [x] 3.4 Functional: `TestDBLessDataPlane_*` and `TestAdminLKG_*` stay green,
  and markers are no longer deleted per cycle.
  Verify: `go test -tags functional -count=1 -run 'TestDBLessDataPlane_|TestAdminLKG_' ./tests/functional/`
  with an isolated `.env.functional` (ports 8190+).

S3 implementation notes:

- The port `OutboxRepository` is now `ReadSince`, `ReadSeqs` and
  `PruneOlderThan`; `Pending`, `PendingCount` and `DeleteSeqs` are gone from the
  port and the repository, and the separate `OutboxMarkerReader` from S2 is
  folded in. `ReadSeqs` re-reads the expired gaps (`late`) with `seq = ANY($1)`.
- The cursor (`cursor.go`) is pure: `observe` returns the next state and the
  dirty set, and the dispatcher adopts it with `commit` only after a cycle
  that compiled. A failed compile or a failed outbox read leaves it unchanged,
  so the next cycle reads the same markers.
- The late set is bounded at 1024 seqs (`defaultLateBound`, not configurable)
  and its entries age out after the outbox retention. Overflow and a prune
  past the cursor both force a full compile with reason `cursor_reset`; a
  marker without a kind forces reason `unnamed_marker`.
- First read: the cursor starts at the oldest row then in the outbox. A seq
  below it that was still in flight at start-up is not awaited; that cycle is
  a full compile and the backstop covers the in-flight write. In practice the
  outbox keeps 24 h of markers now, so in-flight seqs sit above the oldest row.
- `Run` signals itself at start (the boot `PendingCount` check is gone), and
  `WithCompileWhileDirty()` selects the no-timer loop. It is not wired yet; S5
  turns it on with the incremental switch. The legacy debounce stays the
  active behavior.
- The S3 compile is still the full one. The dirty set only feeds the log
  (`reason`, `dirty` = dirty gateway count) until S5 consumes it.
- 3.4: the functional suite passes. That markers are no longer deleted is
  covered by the dispatcher unit tests (`TestDispatch_NeverDeletesMarkers…`);
  no code path calls a delete other than the retention prune.


### S4: Fragment encoder (byte-identical assembly)

- [ ] 4.1 `pkg/infra/configsnapshot/codec.go`: factor the per-element builders
  out of `toProto` (consumers, registries, policies, auths, … and JSON-wrapped
  entities), so the legacy encode and the fragment path share them.
  Before refactoring, freeze today's encoder as a test-only oracle
  (`legacy_encode_test.go`: a verbatim copy of the current `toProto` +
  `Codec.Encode`) plus golden versions for fixed fixtures generated from the
  base branch. Every identity test asserts against the oracle, not against
  the shared builders, so "byte-identical to today" is proven, not just
  "incremental equals full".
  Verify: existing `codec_*_test.go` stay green and the golden versions match.
- [ ] 4.2 Port `pkg/app/configsnapshot/fragment_port.go`: `FragmentEncoder`,
  `SharedInputs`, `Assembled` (design § Interfaces).
- [ ] 4.3 `pkg/infra/configsnapshot/fragments.go`:
  - `element{key, bytes}` and per-gateway `runs[field]`;
  - `Put`, which encodes, runs admission (`admitConsumers` / `validateConsumerSmartRouting` per gateway, D9) and replaces the gateway's runs;
  - `Delete`, `PutCatalog` and `Rebuild`;
  - `Assemble`: a k-way merge in `sortData` comparator order per field, in field-number order, stamping the shared inputs (caps per tenant, revocations, playground keys, usage) and reusing unchanged scoped tenant slices (#1273).
- [ ] 4.4 Byte-identity property test `fragments_identity_test.go`: seeded
  random data covering hosted and own-plane gateways, every entity kind,
  smart-routing consumers that pass and fail admission, empty `key_hash`, usage
  on and off, caps and revocations. Assert `Assemble` equals the frozen
  oracle from 4.1 (and the live `CompileAll` + `Encode`) for the global
  snapshot and every scope (bytes and versions). Spec `snapshot-fragment-compile` "byte-identical" scenarios.
  Verify: `go test -race ./pkg/infra/configsnapshot/ -run Identity -count=20`.
- [ ] 4.5 Benchmark in `fragments_bench_test.go`: 600 gateways, one dirty
  gateway (`Put` + `Assemble`), catalog dirty, full `Rebuild`, with `ReportAllocs`.
  Target: one dirty gateway under 10 ms, excluding the DB.

### S5: Incremental dispatch behind the switch

Review note from S2: a dirty gateway can change which flavor carries it (a
`DataPlane` entitlement change moves it between the global snapshot and its own
scope only), and a gateway delete cascades to all of its entities. Both must be
covered by the mutation-sequence test in 5.x, and the incremental path must
re-derive global membership from the freshly read gateway, never from the cache.

- [ ] 5.1 `pkg/app/configsnapshot/compiler.go`: export `CollectGateway`,
  `CollectAll` and `ListShared` for the incremental path. Add `FindByID` to the
  `GatewayReader` port (`gateway_reader.go`); the repository already has it.
- [ ] 5.2 `pkg/app/configsnapshot/incremental.go`: from the dirty set, call
  `CollectGateway` → `Put` for each dirty gateway, `Delete` for removed ones,
  `PutCatalog` on a catalog marker, then re-read the shared inputs each cycle
  (D8) and `Assemble`. Fall back to a full compile on `all`, at boot, after LKG
  restore, on the prune guard and on cache-integrity errors.
- [ ] 5.3 Backstop (5 min) in incremental mode: run a full `Rebuild`, compare it
  against the incremental state, count `trustgate.configsnapshot.drift{scope_kind}`
  only when the max seq did not move during the compare, then publish the full
  result.
- [ ] 5.4 Config `CONFIG_SYNC_INCREMENTAL_COMPILE` (default `false`) in
  `pkg/config/config.go`; wiring in `pkg/container/modules/control_config_sync.go`.
  Add explicit `false` to `k8s/overlays/{dev,prod,prod-us}/config.env`.
- [ ] 5.5 Mutation-sequence test `incremental_test.go`: random add, update and
  delete of every entity; a gateway flipping between hosted and dedicated;
  gateway delete; catalog change; caps and revocation changes. After each step,
  the incremental output must equal a fresh full compile.
  Verify: `go test -race ./pkg/app/configsnapshot/ -run Incremental -count=10`.
- [ ] 5.6 Functional: `TestDBLessDataPlane_*` and `TestAdminLKG_*` with the
  switch off and on, plus a new test that a write reaches the data plane with
  `mode=incremental` in the publish log.
  Verify: the functional suite twice, once with `CONFIG_SYNC_INCREMENTAL_COMPILE=true`
  in the isolated `.env.functional`.
- [ ] 5.7 Rollout notes in the PR: image A with the switch off and stage timings
  measured in production, then DEV on (drift = 0 for days), then each production region in turn.
  Rollback means switching it off.

## Phase 2 — Manifest and fragment pull

Phase 2 starts only after Phase 1 runs in prod with the switch on.

### S6: Admin side

- [ ] 6.1 `pkg/infra/configsnapshot/proto/configsync.proto`: `Hello.accepts_layered`,
  `VersionNotice.layered`, `GetManifest` and `GetFragments` with their messages
  (design § Phase 2 proto). Regenerate with `make proto`.
- [ ] 6.2 Fragments and manifests:
  - gateway fragment = that gateway's elements;
  - shared fragment per scope = caps, revocations and keys of its tenants;
  - catalog fragment = the #1273 catalog bytes;
  - manifest order: gateways by id, then shared, then catalog;
  - version `m1:` + sha256 over the digests (D12).
  - Code: `pkg/infra/configsnapshot/fragments.go`, `pkg/app/configsnapshot/holder.go`
    (manifests per scope; fragment store keeping one extra generation of grace).
- [ ] 6.3 `pkg/infra/configsync/grpc/{service,hub}.go`:
  - store `layered` per connection from `Hello`;
  - Sync notices carry the version that matches each plane's capability (D13);
  - `GetManifest` with `not_modified`;
  - `GetFragments` with 1 MiB chunks, `maxSnapshotBytes`, per-chunk revocation, gzip and `NotFound` for unknown digests.
- [ ] 6.4 Tests:
  - decoding the concatenated layered fragments gives a read model equal to the v1 decode;
  - an old client against the new server keeps v1 versions and `GetSnapshot`;
  - notices per capability;
  - `NotFound` once a digest has left the store.
  - Verify: `go test -race ./pkg/infra/configsync/... ./pkg/app/configsnapshot/...`.

### S7: Data plane side

- [ ] 7.1 `pkg/runtimeconfig/sync/{worker,configsync}.go` and
  `pkg/infra/configsync/grpc/client.go`:
  - layered fetcher: `GetManifest`, then fetch the missing digests, verify each
    sha256, recompute the manifest version, concatenate, decode, swap, persist
    LKG and ack;
  - fragment cache `map[digest][]byte` for the last applied manifest;
  - `Unimplemented` falls back to `GetSnapshot`;
  - a partial fetch is never applied.
- [ ] 7.2 Config `CONFIG_SYNC_LAYERED_PULL` (data plane, default `false`); send
  `accepts_layered` in `Hello` only when it is on.
- [ ] 7.3 Tests:
  - a new client against an old server falls back;
  - a digest mismatch is rejected;
  - `NotFound` restarts from the manifest;
  - only the missing fragments are fetched (count the RPC bytes);
  - an LKG restart converges.
  - Verify: unit tests with `-race`, plus a functional run with the flag on.
- [ ] 7.4 Rollout notes: admin image serving both paths first, then data planes
  with `CONFIG_SYNC_LAYERED_PULL=true` on DEV, then prod. Rollback means the flag off.

## Phase 3 — Close-out

- [ ] 8.1 Feature-wide review over `git diff origin/develop...HEAD`, then
  `clean-comments` on the full diff.
- [ ] 8.2 Docs: config reference for the three new env vars, and the operations
  note: verify with the `compile` / `mode` log fields and the `drift` counter,
  not `encoded_bytes{scoped,total}`.
- [ ] 8.3 Linear: post a close-out comment on ENG-3112 with the deviations and
  the measured before/after for compile and for write → applied latency.
