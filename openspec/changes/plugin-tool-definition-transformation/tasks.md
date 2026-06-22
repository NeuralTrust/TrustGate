# Tasks: Tool definition transformation plugin — RUN-707

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~1500–1750 across 5 phases (≈600 prod + ≈1000 test/wiring) |
| 400-line budget risk | Medium — manageable with the phase split below |
| Chained PRs recommended | Yes (5) |
| Suggested split | PR1 → PR2 → PR3 → PR4 → PR5 (one per phase) |
| Delivery strategy | ask-on-risk |
| Chain strategy | feature-branch-chain off `feat/tool-definition-transformation` |

Decision needed before apply: No (the split already targets ≤400/PR)
Chained PRs recommended: Yes
Chain strategy: feature-branch-chain
400-line budget risk: Medium

### Per-phase line estimate

| Phase | Files | Prod | Test/wiring | Total | Fits 400 |
|-------|-------|------|-------------|-------|----------|
| 1 | `config.go`, `mergepatch.go`, `plugin_test.go` (slice) | ~125 | ~225 | ~350 | Yes |
| 2 | `transform.go`, `inject.go`, `plugin_test.go` (slice) | ~115 | ~270 | ~385 | Yes |
| 3 | `plugin.go`, `data.go`, `plugin_test.go` (2 smoke) | ~330 | ~45 | ~375 | Yes |
| 4 | `plugin_test.go` (provider matrix + no-op + extras) | 0 | ~380 | ~380 | Yes |
| 5 | `plugins.go`, `catalog_metadata.go`, `catalog_test.go`, functional | ~130 | ~200 | ~330 | Yes |

Recommendation: **feature-branch-chain** off a tracker branch
`feat/tool-definition-transformation`. PR #1 base = `develop`; each later PR base
= the previous slice's branch, so each child diff stays ≤~400 lines and the chain
lands in order. Phases 3 and 4 are a **tested pair** — Phase 3 merges the
orchestration with only two smoke tests (pipeline + no-op) to keep it under
budget; Phase 4 immediately follows with the full provider/edge-case matrix, so
the orchestration is never long-lived without its full test suite. Do not merge
Phase 3 to `develop` independently of Phase 4.

(Alternative: 5 independent PRs off `develop` — cleaner history but more rebase
churn because the phases are strictly dependent. Prefer the chain.)

### Seam adjustments vs design.md (intentional)

- **`matchToolPattern` lives in `transform.go`**, not `plugin.go`. Its only caller
  is `applyTransforms`, so co-locating keeps Phase 2 self-contained and testable
  without `plugin.go`. (`validate()` in Phase 1 uses stdlib `path.Match`
  directly, not this helper.)
- **`data.go` (trace payload + builders + `setExtras`) lands in Phase 3** with the
  orchestration that calls it, rather than with the pure transform/inject helpers,
  to keep Phase 2 ≤400.

## Phase 1: Config & merge-patch foundation (pure, no registry)

- [x] 1.1 Create `pkg/infra/plugins/tooltransform/config.go` with structs `fnDef`,
      `injectDef`, `transformDef`, `config` and `mapstructure` tags exactly as
      design.md (`scope`, `transform_tools`, `inject_tools`, `on_conflict`).
- [x] 1.2 Add consts `conflictGatewayWins|conflictClientWins|conflictReject`, the
      `validScopes` and `validConflicts` sets, and `parseConfig(settings) (*config, error)`
      delegating to `pluginutil.Parse[config]` then `cfg.validate()` (mirror
      `pertoolratelimit.parseConfig`).
- [x] 1.3 Implement `(*config).validate()` (all errors prefixed
      `tool_definition_transformation:`): `Scope` ∈ `{consumer,global}` when set;
      `OnConflict` ∈ `{gateway_wins,client_wins,reject}` when set; each
      `transform_tools[i].Tool` non-empty and a valid glob (`path.Match(Tool,"")`
      must not error); each `inject_tools[i].Function.Name` non-empty; at least one
      of `TransformTools`/`InjectTools` non-empty.
- [x] 1.4 Implement `(*config).onConflict()` returning `conflictGatewayWins` for the
      empty string (default lives only here; `validate()` accepts empty).
- [x] 1.5 Create `pkg/infra/plugins/tooltransform/mergepatch.go`: `mergePatch(target,
      patch map[string]interface{}) map[string]interface{}` per RFC 7386 (nil value
      deletes; object∧object recurses; otherwise replace; nil target allocated).

### Phase 1 tests (`plugin_test.go`)

- [x] 1.6 `mergePatch` table (RFC 7386 matrix): set scalar, replace scalar, null
      deletes, nested recurse, nested null delete, array replaces wholesale, object
      replaces scalar (no recurse), nil target allocates, and the spec
      `properties{include_archived,internal_only}` example (remove + set + preserve
      siblings + add `required`).
- [x] 1.7 `ValidateConfig`/`validate` table: valid transform-only ok; valid
      inject-only ok; `scope:"team"` err; `on_conflict:"merge"` err; inject with empty
      `function.name` err; `transform_tools[].tool:""` err; invalid glob
      `transform_tools[].tool:"["` err; both arrays empty err; empty `on_conflict`
      with injects ok (defaults `gateway_wins` via `onConflict()`).

**Verify**: `go build ./... ; go vet ./pkg/infra/plugins/tooltransform/... ; go test -race ./pkg/infra/plugins/tooltransform/...`.
**Rollback**: delete `config.go`, `mergepatch.go`, and their test rows; no other package touched.

## Phase 2: Transform & inject core (pure functions)

- [x] 2.1 Create `pkg/infra/plugins/tooltransform/transform.go`: `applyTransforms(tools
      []adapter.CanonicalTool, entries []transformDef) (changed bool)` — tools-outer /
      entries-inner so ALL matching entries apply in declaration order; `schema_patch`
      via `mergePatch` (cumulative), `description_override` last-writer-wins; unmatched
      tools untouched.
- [x] 2.2 Add `matchToolPattern(pattern, name string) bool` to `transform.go` (stdlib
      `path.Match` with `/`→`\x00` sentinel, copied verbatim from
      `pertoolratelimit/plugin.go`).
- [x] 2.3 Create `pkg/infra/plugins/tooltransform/inject.go`: `injectOutcome` struct,
      outcome consts (`appended|replaced|dropped|rejected`), `indexOfTool`, and
      `applyInjections(tools []adapter.CanonicalTool, entries []injectDef, conflict
      string) ([]adapter.CanonicalTool, []injectOutcome, error)` mapping
      `function{name,description,parameters}`→`CanonicalTool{Name,Description,Schema}`,
      appending on no-collision and resolving collisions (vs surviving + already-injected
      names) by `gateway_wins` (replace in place), `client_wins` (drop), `reject`
      (short-circuit).
- [x] 2.4 Implement `rejectError(name string) error` returning
      `*appplugins.PluginError{StatusCode:400, Type:"tool_name_reserved",
      Message:..., Body: json.Marshal(map{"error":{"type":...,"name":name}})}`.

### Phase 2 tests (`plugin_test.go`)

- [x] 2.5 `matchToolPattern` matrix: `search_*` vs `search_docs` (match) / `send_email`
      (no match); `?` single-char; `[abc]` class; `/`-containing name via sentinel.
- [x] 2.6 `applyTransforms`: single match patches schema + sets description
      (`changed==true`); no match untouched (`changed==false`); **cumulative** — `search_*`
      and `search_logs` both match `search_logs`, both patches accrue, last
      `description_override` wins; description-only (nil `SchemaPatch`) and schema-only
      (nil `DescriptionOverride`) entries.
- [x] 2.7 `applyInjections` on_conflict matrix: no-collision append; client-name
      collision under `gateway_wins` (replace in place, order preserved), `client_wins`
      (drop), `reject` (error); injected-vs-injected (same name twice) under each mode
      (`gateway_wins` keeps later, `client_wins` keeps earlier, `reject` 400 with the
      duplicated name); empty `on_conflict` behaves as `gateway_wins`.
- [x] 2.8 Reject-body byte-exactness: assert `StatusCode==400`, `Type=="tool_name_reserved"`,
      and `Body` semantically equals `{"error":{"type":"tool_name_reserved","name":"safety_check"}}`
      — derive expected bytes by marshaling the same `map[string]any` (no hand-written
      key-ordered string) and assert deep-equal after `json.Unmarshal`.

**Verify**: `go build ./... ; go vet ./pkg/infra/plugins/tooltransform/... ; go test -race ./pkg/infra/plugins/tooltransform/...`.
**Rollback**: delete `transform.go`, `inject.go`, and their test rows; Phase 1 unaffected.

## Phase 3: Plugin orchestration + graft + observability

- [x] 3.1 Create `pkg/infra/plugins/tooltransform/data.go`: exported `ToolTransformData`,
      `TransformedTool`, `InjectedOutcome` (json tags per design); pure builder that
      diffs `before` vs final tools into `Transformed` flags and maps `outcomes` into
      `Injected`; `rejectData(...)` (minimal payload, outcome `rejected`); `setExtras`
      (nil-checks `in.Event`, calls `event.SetExtras`).
- [x] 3.2 Create `pkg/infra/plugins/tooltransform/plugin.go`: `PluginName` const,
      `var _ appplugins.Plugin = (*Plugin)(nil)`, `Plugin{registry *adapter.Registry}`,
      `New(registry *adapter.Registry) *Plugin`, and contract methods `Name`,
      `MandatoryStages`/`SupportedStages` (`pre_request`), `SupportedModes`
      (`enforce`), `ValidateConfig` (delegates to `parseConfig`).
- [x] 3.3 Implement `Execute`: nil-registry → `okResult()`; `parseConfig` (wrap err
      `tool_definition_transformation: %w`); `in.Scope.Subject()` → no-op on err;
      dispatch `StagePreRequest`→`preRequest`, default→`okResult()`.
- [x] 3.4 Implement `preRequest`: early no-op on nil/empty body, empty `wireFormat`,
      decode error/nil canonical, or `len(Tools)==0 && len(InjectTools)==0`;
      `before := cloneTools(canonical.Tools)`; `applyTransforms`; `applyInjections`
      (on err → `setExtras(rejectData)` + return wrapped err); set `canonical.Tools`;
      if `!transformed && len(outcomes)==0` → `okResult()`; else `setExtras(data)` +
      `encodeAndGraft`.
- [x] 3.5 Implement `encodeAndGraft` (baseline-with-`before` vs `encoded`-with-mutated
      `EncodeRequest`, then `graftChangedFields(originalBody, baseline, encoded)` with
      fallback to `encoded` on graft error) and copy helpers `wireFormat`,
      `graftChangedFields`, `cloneTools`, `okResult` (verbatim from `pertoolratelimit`,
      comments stripped).

### Phase 3 tests (`plugin_test.go`) — smoke only (full matrix in Phase 4)

- [x] 3.6 Pipeline smoke: OpenAI completions body with one tool + a `search_*`
      transform + a `safety_check` injection → `Result.RequestBody` decodes back to the
      transformed client tool plus the injected tool; assert event extras populated
      (`Transformed` flag + `Injected` outcome).
- [x] 3.7 No-op smoke: nil/empty body → `okResult()` with no `RequestBody`.

**Verify**: `go build ./... ; go vet ./pkg/infra/plugins/tooltransform/... ; go test -race ./pkg/infra/plugins/tooltransform/...`.
**Rollback**: delete `plugin.go`, `data.go`, and their test rows; pure helpers from Phases 1–2 remain compilable as a library.

## Phase 4: Full provider matrix + edge-case suite (test-only)

- [x] 4.1 Per-provider round-trip (graft) — for OpenAI completions, OpenAI responses,
      Anthropic (mandatory), plus Gemini, Bedrock, Mistral (parity with
      `pertoolratelimit`): build a raw body with one tool + a provider-specific
      top-level field, run `preRequest` with a transform + injection, decode the
      returned `RequestBody` and assert (a) transformed tool carries the patched
      schema/description, (b) injected tool present, (c) untouched top-level field
      survives verbatim. Resolve design open-questions 1 (OpenAI Responses tool
      envelope) and 2 (Anthropic `type+custom` re-encode) here; if a format drops
      tools, drop it from the v1 coverage claim and note it.
- [x] 4.2 Cross-provider equivalence: equivalent OpenAI and Anthropic requests with the
      same logical tools + same config yield equivalent canonical tool sets.
- [x] 4.3 Inject-after-transform ordering: transform on `search_*` + injection whose
      name collides only with a post-transform tool exercises the post-transform
      conflict set.
- [x] 4.4 No-op/passthrough matrix via `Execute`: unknown/empty wire format; undecodable
      body; tools present but no transform matches and no `inject_tools`;
      `len(Tools)==0 && len(InjectTools)==0` → all `okResult()` with no rewrite.
- [x] 4.5 Reject path via `Execute`: `on_conflict:reject` collision returns the
      `*appplugins.PluginError` (400, `tool_name_reserved`, exact body) and records
      reject extras.
- [x] 4.6 Nested-patch decode guard (design open-question 3): assert mapstructure
      decodes nested JSON objects in `schema_patch`/`parameters` into
      `map[string]interface{}` (not `map[interface{}]interface{}`) so `mergePatch`
      type assertions hold.

**Verify**: `go test -race ./pkg/infra/plugins/tooltransform/...`.
**Rollback**: revert the added test rows; production code unchanged.

## Phase 5: DI registration + catalog + functional

- [ ] 5.1 `pkg/container/modules/plugins.go`: add the `tooltransform` import and
      `tooltransform.New(p.Adapters)` to the `catalog` slice in `newPluginRegistry`
      (no `pluginParams` change — `Adapters` already injected).
- [ ] 5.2 `pkg/app/plugins/catalog_metadata.go`: add
      `pluginCatalogMeta["tool_definition_transformation"]`, group `groupOther`,
      name "Tool Definition Transformation"; hand-authored `SettingsSchema.Fields`:
      `transform_tools` (`FieldTypeArray` of object `{tool string req, schema_patch
      FieldTypeObject free-form, description_override string}`), `inject_tools`
      (`FieldTypeArray` of object `{type enum [function], function FieldTypeObject
      {name string req, description string, parameters FieldTypeObject free-form}}`),
      `on_conflict` (`FieldTypeEnum [gateway_wins,client_wins,reject]`,
      `Default:"gateway_wins"`), `scope` (`FieldTypeEnum [consumer,global]`,
      informational). Stages/modes read from the plugin, not duplicated.
- [ ] 5.3 `pkg/app/plugins/catalog_test.go`: assert the new slug appears, group
      "Other", stages `[pre_request]` (mandatory+supported), modes `[enforce]`, and the
      top-level field keys/types/enums/default; tolerate the v1 opaque
      `FieldTypeObject` with empty `Fields` (design open-question 4).
- [ ] 5.4 `tests/functional/` (`functional` build tag), mirroring
      `plugin_per_tool_rate_limiter_test.go`: policy-routed request with `tools[]` →
      assert the upstream-received body was patched/injected (recording upstream); and
      a `reject` collision → `400` with the exact envelope. Keep path == consumer name
      (AGENT.md §14.7).

**Verify**: `go test -race ./pkg/app/plugins/... -run Catalog ; go test -tags functional -race ./tests/functional/... -run ToolDefinitionTransformation ; go vet ./...`.
**Rollback**: remove the `newPluginRegistry` line, the catalog entry + test, and the functional test; the plugin package becomes dormant (unregistered) with zero traffic impact.

## Final verification (run before the last PR merges)

- [ ] V.1 `go build ./...`
- [ ] V.2 `go vet ./...`
- [ ] V.3 `golangci-lint run ./pkg/infra/plugins/tooltransform/... ./pkg/app/plugins/... ./pkg/container/modules/...`
- [ ] V.4 `go test -race ./pkg/infra/plugins/tooltransform/... ./pkg/app/plugins/...`
- [ ] V.5 `go test -tags functional -race ./tests/functional/... -run ToolDefinitionTransformation`
- [ ] V.6 Confirm pre-commit comment-strip hook leaves no comments (AGENT.md §11.1);
      only the Apache license header / `//go:generate` survive.
- [ ] V.7 Cross-check success criteria in `proposal.md` are all covered by Phase 1–5 tests.
