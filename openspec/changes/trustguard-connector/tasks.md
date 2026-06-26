# Tasks: TrustGuard connector plugin — RUN-669

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~1235 (P1 ~75, P2 ~245, P3 ~205, P4 ~545, P5 ~165) |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR1 (P1) → PR2 (P2) → PR3 (P3) → PR4 (P4) → PR5 (P5) |
| Delivery strategy | ask-on-risk |
| Chain strategy | feature-branch-chain |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: feature-branch-chain
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Env config plumbing | PR 1 | base = feature/trustguard-connector; compiles+tests alone |
| 2 | TrustGuard HTTP client | PR 2 | base = PR 1 branch; standalone package, no plugin deps |
| 3 | Plugin Settings/config | PR 3 | base = PR 2 branch; uses policy types only |
| 4 | Plugin core + DTOs | PR 4 | base = PR 3 branch; depends on P2+P3; largest slice |
| 5 | DI wiring + catalog + docs | PR 5 | base = PR 4 branch; only the tracker merges to main |

Apache header on every new file. No other comments. `go test -race` per phase.

## Phase 1: Config & env plumbing

- [x] 1.1 In `pkg/config/config.go` add `defaultTrustGuardTimeout = 15 * time.Second`, `TrustGuardConfig{BaseURL, Timeout}`, `Config.TrustGuard` field, `getTrustGuardConfig()` (`TRUSTGUARD_BASE_URL` default "", `TRUSTGUARD_TIMEOUT` via `getEnvDuration`), wire into `LoadConfig`. No `Validate()` rule.
- [x] 1.2 Add `pkg/config/config_test.go` cases: defaults (empty base URL, 15s), env overrides, malformed `TRUSTGUARD_TIMEOUT` falls back to default.

## Phase 2: TrustGuard HTTP client

- [x] 2.1 Create `pkg/infra/plugins/trustguard/client.go`: `guardPath`, `maxResponseBytes`, `client{http}`, `newClient(timeout)`, `Guard(ctx, baseURL, apiKey, GuardRequest)` (Bearer + JSON headers, `io.LimitReader`, non-2xx → error).
- [x] 2.2 Create `pkg/infra/plugins/trustguard/data.go`: `GuardRequest`/`GuardInput`/`GuardAttributes`/`GuardModel`, `GuardResponse`/`GuardFinding` DTOs (P4 adds `guardData`/`setExtras`).
- [x] 2.3 Add `client_test.go` (`httptest.NewServer`): 2xx decode, non-2xx error, transport error, context timeout, malformed JSON, asserts headers + `/v1/guard` path + `LimitReader` cap.

## Phase 3: Plugin config

- [x] 3.1 Create `pkg/infra/plugins/trustguard/config.go`: `inspect*` consts, `Settings` (mapstructure tags, `#nosec G101`), `parseConfig` (Parse→applyDefaults `request_response`→validate: `api_key` required, enum, `base_url` URL), `selectsStage`.
- [x] 3.2 Add `config_test.go`: required-field rejection, inspect enum+default, `base_url` validation, `selectsStage` matrix.

## Phase 4: Plugin core

- [x] 4.1 Append `guardData` struct + `setExtras` to `data.go`.
- [x] 4.2 Create `pkg/infra/plugins/trustguard/plugin.go`: `PluginName`, `Plugin`, `New(registry, baseURL, timeout, logger)`, `Name`/stages(both mandatory+supported)/modes(enforce,observe)/capabilities(all false), `ValidateConfig`, `Execute` (stage×inspect gate, direction, base-URL resolve, adapter decode input/output, streaming passthrough, `client.Guard`, fail-open, block→403 `*PluginError` with `blockBody`, observe/allow→passThrough+`setExtras`), `passThrough`.
- [x] 4.3 Add `plugin_test.go` (`httptest` fake + real `adapter.NewRegistry()`): block→403 (pre_request short-circuit, pre_response replace), observe→reported passThrough, allow statuses, streaming passThrough, empty base_url passThrough+warn, transport fail-open, stage-not-selected, request-body→GuardRequest assertion.

## Phase 5: Wiring & catalog

- [x] 5.1 `pkg/container/modules/plugins.go`: import `trustguard`, add `Cfg *config.Config` to `pluginParams`, append `trustguard.New(p.Adapters, p.Cfg.TrustGuard.BaseURL, p.Cfg.TrustGuard.Timeout, p.Logger)` to `newPluginRegistry`.
- [x] 5.2 `pkg/app/plugins/catalog_metadata.go`: add `"trustguard"` entry (`groupOther`, hand-authored `SettingsSchema`: `api_key`, `inspect` enum, optional `base_url`).
- [x] 5.3 `pkg/app/plugins/catalog_test.go`: add `TestTrustGuardSchema` mirroring the token-schema test.
- [x] 5.4 Add `TRUSTGUARD_BASE_URL` + `TRUSTGUARD_TIMEOUT` to `.env.example`. Plugin docs skipped: repo has no per-plugin docs convention (no markdown exists for `tool_call_validation`/`prompt_template`/`tool_definition_transformation`); slug/config/stage-direction matrix/fail-open/streaming limitation are documented under `openspec/changes/trustguard-connector/`.
