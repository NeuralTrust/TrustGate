# Tasks: Tool allowlist plugin (pre-request tool-array access control) — RUN-706

Standards (sdd-apply MUST honor): `.agents/AGENT.md` (hexagonal layout,
one-use-case-per-file, NO code/doc comments except the Apache header per DR-8,
DTO placement, conventional commits, 400-line PR budget) and
`~/.agents/skills/golang-pro/SKILL.md` (idiomatic Go, `%w` error wrapping,
`context` propagation; `go vet` + `golangci-lint` + `go test -race ./...` green).
Mirror `modelallowlist` + `pertoolratelimit`. New pkg `pkg/infra/plugins/toolallowlist/`.

## Phase 1: Config + validation + telemetry structs

- [x] 1.1 Create `config.go`: `config` struct (`Scope`,`AllowTools`,`DenyTools`,`OnEmptyAfterFilter` mapstructure tags), `onEmpty{Reject,PassThrough,StripField}` consts, `parseConfig` (`pluginutil.Parse[config]`), `(*config).applyDefaults` (`""`→`reject`), `(*config).validate`.
- [x] 1.2 `validate` rules: ≥1 of allow/deny non-empty; each pattern non-blank + valid via `path.Match(p,"")`; `OnEmptyAfterFilter ∈ {reject,pass_through_empty,strip_tools_field}`; `Scope` if set `∈ {consumer,global}`.
- [x] 1.3 Create `data.go`: `ToolAllowlistData` (exported trace), `errorBody`/`errorDetail`, `newErrorBody`, decision/action/`onEmpty` consts. Apache header only; no comments.
- [x] 1.4 Create `config_test.go`: table-driven `-race` — missing both lists, blank pattern, bad glob `[a-`, bad `on_empty` `drop`, bad scope, default `""`→reject, inert-scope parity.

**Verify**: `go build ./... && go vet ./pkg/infra/plugins/toolallowlist/... && golangci-lint run pkg/infra/plugins/toolallowlist/... && go test -race ./pkg/infra/plugins/toolallowlist/...`; grep new files for stray `//` (header only).

## Phase 2: Plugin Execute + filter/glob/body-rewrite

- [x] 2.1 Create `plugin.go`: `PluginName="tool_allowlist"`, `Plugin struct{ registry *adapter.Registry }`, `New(*adapter.Registry) *Plugin` (concrete return per OQ-3 orchestrator decision; both compile into the `[]appplugins.Plugin` catalog), `var _ appplugins.Plugin = (*Plugin)(nil)`, `Name/MandatoryStages/SupportedStages=[StagePreRequest]`, `SupportedModes=[ModeEnforce,ModeObserve]`, `ValidateConfig`.
- [x] 2.2 Local helpers: `wireFormat` (SourceFormat else Provider), `matchToolPattern` (`path.Match` + `/`→sentinel), `matchAny`, `graftChangedFields` (local copy), `okResult`, `setExtras` (nil-safe).
- [x] 2.3 `filter`: allow-first (drop non-matches when allow non-empty) then deny-after (deny overrides allow, DR-7); return kept/removed canonical names.
- [x] 2.4 `Execute` flow per design: no-op guards (nil req/empty body/unresolved format/decode err/no tools); `removed==0`→setExtras+ok; observe→setExtras+`SetDecision`+ok (never mutate); enforce partial→`stripTools`; all-removed→`on_empty` switch.
- [x] 2.5 `stripTools` (graft re-encode, preserves `parallel_tool_calls`), `rewriteEmpty(deleteTools bool)` (raw-map delete `tool_choice`/`parallel_tool_calls`, +`tools` or `[]`), `newRejectResult` (`Result{StopUpstream,403,JSON,Content-Type}`).
- [x] 2.6 Create `plugin_test.go` table-driven `-race`, OpenAI+Anthropic fixtures: allow-only, deny-only, allow+deny precedence, globs (`search_*`,`admin_?`,`db_[rw]*`), each `on_empty` (403 body, strip 3 keys, pass `[]`+drop 2), partial graft preserves `parallel_tool_calls`, byte-stable no-change pass, all no-op cases, observe never mutates.

**Verify**: same `go build`/`vet`/`golangci-lint`/`go test -race ./pkg/infra/plugins/toolallowlist/...` + comment-strip check.

## Phase 3: Wiring — DI + catalog metadata + catalog_test

- [x] 3.1 `pkg/container/modules/plugins.go`: import `toolallowlist`, add `toolallowlist.New(p.Adapters)` to `newPluginRegistry` catalog slice (no `pluginParams` change).
- [x] 3.2 `pkg/app/plugins/catalog_metadata.go`: add `pluginCatalogMeta["tool_allowlist"]` (`groupRouting`, name "Tool Allowlist", description, `SettingsSchema` fields `allow_tools`/`deny_tools` array-of-string, `on_empty_after_filter` enum default `reject`, `scope` enum informational).
- [x] 3.3 `pkg/app/plugins/catalog_test.go` (OQ-1/OQ-2 RESOLVED): add `"tool_allowlist"` to `builtinSlugs`; add `{"tool_allowlist",[]policy.Stage{policy.StagePreRequest},[]policy.Stage{policy.StagePreRequest}}` to `registerBuiltins` `specs`; extend `TestCatalogService_GroupsAndOrder` Routing `ElementsMatch` to `{semantic_cache,model_allowlist,tool_allowlist}`. Optional `TestToolAllowlistSchema`.

**Verify**: `go build ./... && go vet ./... && golangci-lint run pkg/container/modules/... pkg/app/plugins/... && go test -race ./pkg/app/plugins/... -run Catalog`.

## Phase 4: Functional test

- [ ] 4.1 Create `tests/functional/plugin_tool_allowlist_test.go` (`//go:build functional`): mirror `plugin_per_tool_rate_limiter_test.go` helpers (`setupPolicyRoute`,`policyPlugin`,`proxyRequest`,`mustJSON`,`chatRequestWithTools`,`forwardedToolNames`,`Track`,`fakeUpstream`). Cover allow/deny/empty across OpenAI + Anthropic; assert forwarded `tools[]` and 403 `no_tools_allowed`.

**Verify**: `go build -tags functional ./... && go vet -tags functional ./tests/functional/... && go test -race -tags functional ./tests/functional/... -run ToolAllowlist` + comment-strip check.

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~890 (P1 ~240, P2 ~440, P3 ~60, P4 ~150) |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR1 → PR2 → PR3 → PR4 (one per phase) |
| Delivery strategy | ask-on-risk |
| Chain strategy | pending (recommend feature-branch-chain) |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: pending
400-line budget risk: High

Recommendation: **feature-branch-chain** off tracker `feat/plugin-tool-allowlist`.
PR #1 base = `develop`; each later PR base = previous slice's branch so each child
diff stays focused. Phase 2 (~440) slightly exceeds budget — acceptable as a
cohesive unit (plugin + its tests), or split plugin.go (P2a) from plugin_test.go
(P2b) if a reviewer requires ≤400.

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | config + validation + data.go + tests | PR 1 | base `develop`; no wiring, no behavior |
| 2 | plugin Execute + filter/glob/rewrite + tests | PR 2 | base PR 1; ~440 lines (watch budget) |
| 3 | DI + catalog metadata + catalog_test | PR 3 | base PR 2; activates the plugin |
| 4 | functional test (OpenAI + Anthropic) | PR 4 | base PR 3; `functional` tag |
