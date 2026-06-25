# Tasks: Bedrock Guardrail plugin (RUN-719)

Gate **G** (run at the end of every phase): `go vet ./... && golangci-lint run && go test -race ./pkg/infra/plugins/bedrockguardrail/...`. Binding: `.agents/AGENT.md` (no comments incl. Go doc comments; one thing per file; mockery for app-layer mocks) + `golang-pro`.

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~2000 (impl ~790, tests ~950, wiring ~33, functional ~270) |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR1→PR2→PR3→PR4→PR5→PR6 (Phase 4 split into 4a/4b) |
| Delivery strategy | ask-on-risk |
| Chain strategy | pending (user decision) |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: pending
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | PR | Est. lines | Notes |
|------|------|----|-----------|-------|
| 1 | config + data + tests | PR1 | ~320 | base = feat/bedrock-guardrail |
| 2 | client cache + auth + seam | PR2 | ~250 | base = PR1 |
| 3 | assess + reject envelope | PR3 | ~430 | base = PR2; test-heavy, near budget |
| 4a | Execute orchestration + plugin tests | PR4 | ~420 | base = PR3; test-heavy |
| 4b | anonymize re-encode + tests | PR5 | ~280 | base = PR4 |
| 5+6 | registration + catalog + functional | PR6 | ~300 | base = PR5; activates plugin |

Phase 4 alone (~710) exceeds 400 → split into 4a (orchestration) and 4b (anonymize).

## Phase 1: Config + Settings/validation + Data event struct
<!-- RUN-719 -->

- [x] 1.1 Create `pkg/infra/plugins/bedrockguardrail/config.go`: `Settings`+`Credentials` (mapstructure tags), constants (`piiActionBlock/Anonymize`, `defaultVersion=DRAFT`, `defaultRegion=us-east-1`, `defaultSessionName`), `parseConfig` via `pluginutil.Parse[Settings]`, `applyDefaults`, `validate`.
- [x] 1.2 Create `pkg/infra/plugins/bedrockguardrail/data.go`: `Data` struct (json tags, no content fields) + `setExtras(event,*Data)` nil-safe.
- [x] 1.3 Create `config_test.go`: defaults (DRAFT/block/us-east-1/session); validate failures — missing `guardrail_id`, bad `pii_action`, `use_role` w/o `role_arn`, static auth w/o keys. Gate G.

## Phase 2: Client wrapper + per-credential cache + auth + seam

- [ ] 2.1 Create `client.go`: `awsCredentials`+`credentialsFromConfig`+`fingerprint()` (sha256), `guardrailClient` interface over `ApplyGuardrail`, `cacheEntry`/`clientCache.get` (sync.Once single-flight, delete-on-error), `cachedGuardrailClient`, `newCachedGuardrailClient`, `buildRuntimeClient` (static-key + STS assume-role, region fallback).
- [ ] 2.2 Create `client_test.go`: `fingerprint` stability/difference; `clientCache.get` single-flight under `-race` (build called once for N goroutines) + error-not-cached, injected fake `build`. Gate G.

## Phase 3: Assessment inspection + 403 reject envelope

- [ ] 3.1 Create `assess.go`: `buildApplyInput(cfg,text,source)`, `finding`/`assessmentResult` types, `inspect` walking all 5 families (topic/content/word/sensitive-info/contextual-grounding) using verified `Blocked`/`Anonymized` constants, `aws.ToString` nil-safe.
- [ ] 3.2 Create `reject.go`: `typeGuardrailBlocked` const, `blockBody(finding)` exact `{"error":{"type":...,"policy":...,"name":...}}`, `blockError(finding) *PluginError` (403, JSON header).
- [ ] 3.3 Create `assess_test.go` (table per family+action; PII classify; empty→allow) and `reject_test.go` (exact 403 JSON). Gate G.

## Phase 4a: Execute orchestration (PreRequest + PreResponse)

- [ ] 4a.1 Create `plugin.go`: `PluginName`, decision consts, `Plugin`+`New`, 9 interface methods (`SupportedStages={PreRequest,PreResponse}`, `MandatoryStages=nil`, modes enforce/observe, Mutates*=true), `ValidateConfig`, `Execute` dispatch, `executePreRequest`/`executePreResponse` (guards, decode, `lastUserText`/`responseText`, ApplyGuardrail, block/report gating via `Blocks`, fail-closed on error, `setExtras`+`SetDecision`), `passThrough`.
- [ ] 4a.2 Create `plugin_test.go` (fake `guardrailClient`): INPUT/OUTPUT source, guard pass-throughs, non-PII block enforce→403/observe→reported, client-error fail-closed, stages/modes/Mutates asserts. Gate G.

## Phase 4b: Anonymize re-encode path

- [ ] 4b.1 Create `anonymize.go`: `maskedText`, `supportsReencode`, `rewriteRequest`(span=msgIndex)/`rewriteResponse` via `registry.GetAdapter().Encode*`; wire PII branch in `plugin.go` (block vs anonymize, BLOCKED→fallback block, enforce mutate via `RequestBody`/`Body`+`StopUpstream`, degraded fail-closed enforce / report observe).
- [ ] 4b.2 Create `anonymize_test.go` (round-trip + unsupported/encode-fail) and extend `plugin_test.go` (anonymize enforce mutate, BLOCKED fallback, observe no-mutate, degraded). Gate G.

## Phase 5: Registration + catalog metadata

- [ ] 5.1 `pkg/container/modules/plugins.go`: import `bedrockguardrail`, append `bedrockguardrail.New(p.Adapters, p.Logger)` to `catalog`.
- [ ] 5.2 `pkg/app/plugins/catalog_metadata.go`: add `bedrock_guardrail` entry under `groupGuardrails` (name/group/description + `SettingsSchema` per design §7). Gate G.

## Phase 6: Functional test

- [ ] 6.1 Add `//go:build functional` test shim in package (`newWithClient` + exported setter) so the harness injects a scripted fake `guardrailClient`.
- [ ] 6.2 Create `tests/functional/plugin_bedrock_guardrail_test.go` mirroring azure: benign→allow upstream hit; topic block→exact 403 no upstream; observe→hit+reported; PII anonymize→forwarded body rewritten. Gate G.
