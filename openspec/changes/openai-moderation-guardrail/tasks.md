# Tasks: OpenAI moderation guardrail plugin — RUN-717

Package root: `pkg/infra/plugins/openaimoderation/`. No code comments (AGENT.md §11,
Apache header only). Hexagonal layout, one-responsibility-per-file, conventional
commits. Every phase ends green under `go build ./...`, `go vet ./...`,
`golangci-lint` (incl. `unused`), and `go test -race ./...`. The exported
`Plugin`/`New` keep an unwired package lint-clean; each phase ships its own tests
so new unexported symbols are exercised and never flagged dead.

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines (total) | ~1,200 (prod ~580 + tests ~530 + wiring ~90) |
| Per-phase estimate | P1 ~280 prod + ~230 test (~510) · P2 ~280 prod + ~300 test (~580) · P3 ~90 + ~40 test (~130) |
| 400-line budget risk | High (P1, P2) · Low (P3) |
| Chained PRs recommended | Yes |
| Number of chained PRs | 3 |
| Suggested split | PR1 → PR2 → PR3 (each phase = one PR) |
| Delivery strategy | ask-on-risk |
| Chain strategy | feature-branch-chain |

Recommended strategy: **feature-branch-chain**. The worktree feature branch
(`openai-moderation-guardrail`, off `origin/develop`) is the integration target.
PR1 bases on the feature branch; PR2←PR1; PR3←PR2 so each child diff stays
focused. Only the feature branch merges to `develop`. Order is dependency-forced:
leaf code (P1) → plugin behavior (P2) → activation (P3). P1/P2 exceed 400 lines
mainly via table-driven `-race` tests; production code per phase is ~280. If a
child PR shows a predecessor's changes, retarget/rebase before review.

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: feature-branch-chain
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Leaf code: config/client/data/extract, package compiles + tested, inert | PR 1 | base = feature branch; not registered (no behavior change on main) |
| 2 | Plugin behavior: evaluate + reject + Execute | PR 2 | base = PR 1 branch; still not registered |
| 3 | Activation: env config + catalog + registration | PR 3 | base = PR 2 branch; go-live diff, trivially reviewable |

## Phase 1: Leaf code — config, client, data, extract (PR1)

- [x] 1.1 Create `config.go`: `PluginName` const (`"openai_moderation"`, declared here so `client.go` can key the pool before `plugin.go` lands), `defaultModel`/`stagePreRequest`/`stagePreResponse` consts, `Settings` + `ActionSettings` (`mapstructure`, `api_key` carries `// #nosec G101`), `parseConfig`→`applyDefaults`→`validate`, `selectsStage(policy.Stage) bool`.
- [x] 1.2 Create `data.go`: `moderationRequest`/`moderationInput`/`moderationResponse`/`moderationResult` JSON shapes, exported `ModerationData`, `violation` (`threshold,omitempty`), nil-checked `setExtras(*metrics.EventContext, ModerationData)`.
- [x] 1.3 Create `client.go`: `client` (http + timeout), `newClient(timeout)` via `providers.NewHTTPClientPool().Get(PluginName, timeout)`, `Moderate(ctx, baseURL, apiKey, moderationRequest)` POST `/v1/moderations` with `context.WithTimeout`, Bearer + Content-Type headers, `io.LimitReader`(`maxResponseBytes`), `providers.DrainBody`, non-2xx → typed `errModeration` carrying only status (no body leak), `%w` wrapping.
- [x] 1.4 Create `extract.go`: `joinRequestText(*adapter.CanonicalRequest)` (System + each `Messages[].Content`, blanks skipped), `responseText(*adapter.CanonicalResponse)`.
- [x] 1.5 Tests: `config_test.go` (defaults; api_key required; invalid stage; threshold <0/>1; valid; `selectsStage` matrix), `data_test.go` (`setExtras` nil-safe + omitempty), `client_test.go` (`httptest`: 200 decode; non-2xx typed error body-not-leaked; malformed JSON; headers set; ctx deadline cancels slow server, no leak), `extract_test.go` (system+messages joined, blanks skipped; response content; empty → "" for OpenAI + Anthropic via `ResolveAgentFormat`+`DecodeRequestFor`).
- [x] 1.6 Verify: `go build ./... && go vet ./... && go test -race ./pkg/infra/plugins/openaimoderation/...` green; strip any code comments.

## Phase 2: Plugin behavior — evaluate, reject, Execute (PR2)

- [x] 2.1 Create `evaluate.go`: `aggregated{scores,flagged}`, `aggregate([]moderationResult)` (max-per-category + flagged OR across all `results[]`), `evaluate(cfg, agg) []violation` (allow-list when non-empty else union of response categories; threshold-crossed or `block_on_flagged`+flagged; one per category; sorted/deterministic).
- [x] 2.2 Create `reject.go`: type/message consts (`content_flagged`, `moderation_unavailable`, default block message), `blockBody([]violation)`, `blockError(message, violations)` → 403 `*appplugins.PluginError`, `unavailableError()` → 502 fixed generic body (no OpenAI detail).
- [x] 2.3 Create `plugin.go`: `Plugin{registry,client,baseURL,logger}`, `New(registry, baseURL, timeout, logger)`, interface methods (`Name`=PluginName; `MandatoryStages`={}; `SupportedStages`={pre_request,pre_response}; `SupportedModes`={enforce,observe}; `Mutates*`=false; `ValidateConfig`→parseConfig), `passThrough()`, nil-safe `warn`, `Execute` per design (stage/baseURL/nil/empty/streaming guards → decode → extract → `Moderate` → fail-CLOSED 502 in enforce / pass-through+record in observe → `aggregate`/`evaluate` → 403 `blockError` when `len>0 && Blocks(mode)` else `setExtras`+`SetDecision`+passThrough).
- [x] 2.4 Tests: `evaluate_test.go` (max-across-results; flagged OR; threshold crossed/below; allow-list restricts; empty allow-list evaluates all; `block_on_flagged` true/false; deterministic order — spec "Block decision", "Multi-input aggregation"), `plugin_test.go` (contract; enforce→403 `content_flagged` body verbatim; observe violation→pass-through+`decision=reported`; enforce 5xx→502 `moderation_unavailable` no leaked body; observe failure→pass-through; streaming/unselected-stage/empty-text/nil-request→skip — spec "Mode", "Fail-closed", "Streaming", "Empty input").
- [x] 2.5 Verify: `go build ./... && go vet ./... && go test -race ./pkg/infra/plugins/openaimoderation/...` green; strip any code comments.

## Phase 3: Activation — env config, catalog, registration (PR3)

- [ ] 3.1 `pkg/config/config.go`: `defaultOpenAIModerationTimeout = 15s` const, `OpenAIModerationConfig{BaseURL,Timeout}`, `getOpenAIModerationConfig()` (`OPENAI_MODERATION_BASE_URL` default `https://api.openai.com`, `OPENAI_MODERATION_TIMEOUT` default 15s), `OpenAIModeration` field on `Config` after `TrustGuard`, wired in `LoadConfig`.
- [ ] 3.2 `.env.example`: add `OPENAI_MODERATION_BASE_URL` + `OPENAI_MODERATION_TIMEOUT` (+ comment) after the TrustGuard block.
- [ ] 3.3 `pkg/app/plugins/catalog_metadata.go`: add `pluginCatalogMeta["openai_moderation"]` (group `groupGuardrails`) with `SettingsSchema` fields `{api_key, model, stages, categories, thresholds, block_on_flagged, action.message}` per design.
- [ ] 3.4 `pkg/container/modules/plugins.go`: import package + append `openaimoderation.New(p.Adapters, p.Cfg.OpenAIModeration.BaseURL, p.Cfg.OpenAIModeration.Timeout, p.Logger)` to the `catalog` slice in `newPluginRegistry`.
- [ ] 3.5 `pkg/container/modules/plugins_test.go`: assert registration (`Get`/`Names` include `openai_moderation`) + catalog-metadata entry (group, non-empty Name/Description/SettingsSchema.Fields, field-key set).
- [ ] 3.6 Verify: `go build ./... && go vet ./... && go test -race ./pkg/config/... ./pkg/app/plugins/... ./pkg/container/modules/...` green; strip any code comments.
