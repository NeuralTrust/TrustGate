---
linear: RUN-993
type: feat
phase: tasks
depends_on: openspec/changes/run-993-regex-replace-plugin/design.md
---

# Tasks: Regex Replace plugin (RUN-993)

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines (add+del) | ~1162 total / ~432 production-only |
| 400-line budget risk | High |
| Chained PRs recommended | No |
| Suggested split | Single PR + `size:exception` (fallback: 2-PR feature-branch-chain) |
| Delivery strategy | ask-on-risk (default; none passed) |
| Chain strategy | size-exception |

Decision needed before apply: Yes
Chained PRs recommended: No
Chain strategy: size-exception
400-line budget risk: High

### Per-phase estimate (add+del)

| Phase | Files | Total | Production-only |
|-------|-------|-------|-----------------|
| 1 core | config.go, replace.go + 2 unit tests | ~420 | ~170 |
| 2 plugin | plugin.go, data.go + plugin_test.go | ~410 | ~200 |
| 3 wiring | plugins.go, catalog_metadata.go, catalog_test.go | ~102 | ~62 |
| 4 integration | functional test, policies.json, Postman | ~230 | ~40 |
| **Total** | | **~1162** | **~432** |

### Recommendation: ONE PR with `size:exception`

The smallest *functional* slice (config+replace+plugin+data+registration) is ~432
production lines — already over 400 before any test. No split yields a working,
under-budget slice. A core-only PR 1 (config.go+replace.go) would merge
package-level production code that nothing calls yet (compiles + unit-tests green
in isolation, but ships transient dead code to `develop`). The change is fully
additive and cohesive (one new plugin, zero behavior change to existing code), so
a single reviewable PR with `size:exception` is cleanest.

Fallback if the team refuses the exception — **feature-branch-chain**:
- PR 1 (base = `feat/run-993-regex-replace-plugin`): Phases 1+2+3 — complete wired
  plugin + unit tests + catalog. Builds and tests green; plugin fully functional.
- PR 2 (base = PR 1 branch): Phase 4 — functional test + docs + Postman.

Neither slice stays under 400; the chain only bounds reviewer diff-per-PR.

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Complete wired plugin + unit + catalog (Phases 1-3) | PR 1 | base = tracker branch; green standalone |
| 2 | Functional test + docs + Postman (Phase 4) | PR 2 | base = PR 1 branch (only if chained) |

## Phase 1: Core (pure, no wiring)

- [x] 1.1 Create `pkg/infra/plugins/regexreplace/config.go`: `PluginName`, target consts, sentinels (`ErrNoRules`/`ErrInvalidTarget`/`ErrEmptyPattern`/`ErrBadPattern`), `Rule`, `Settings` (+ unexported `compiled`), `compiledRule`, `parseConfig`, `validate`, `compile`, `buildPattern`, `isRequestLeg`/`isResponseLeg`. RE2 compiled once, `%w` wrapping. [spec: Config validation; Ordered chained rules]
- [x] 1.2 Create `pkg/infra/plugins/regexreplace/replace.go`: pure `applyRules([]compiledRule,string)(string,bool)` — ordered chaining, net-change flag. [spec: Ordered chained rules; Edge-case behavior]
- [x] 1.3 Create `config_test.go` (table-driven, `-race`): valid/one+many rules, missing/invalid target→`ErrInvalidTarget`, empty rules→`ErrNoRules`, empty pattern→`ErrEmptyPattern`, invalid RE2 (`(`, `\1`, `(?=x)`)→`ErrBadPattern` via `errors.Is`, `buildPattern` `(?i)`/`(?m)`. [spec: Config validation]
- [x] 1.4 Create `replace_test.go` (table-driven, `-race`): single match, `$1`, `${name}`, chaining, no-match→`changed=false`, empty replacement deletes, net no-op. [spec: Ordered chained rules; Edge-case behavior]

## Phase 2: Plugin behavior

- [x] 2.1 Create `plugin.go`: `Plugin{registry,logger}`, `New(*adapter.Registry,*slog.Logger)`, descriptor methods — `SupportedStages=[pre_request,pre_response]`, `MandatoryStages=[]`, `SupportedModes=[Enforce,Observe]`, `SupportedProtocols=[ProtocolLLM]`, `MutatesRequestBody/ResponseBody=true`, `MutatesMetadata=false`, `ValidateConfig`. [spec: Descriptor & stage registration; Modes]
- [x] 2.2 In `plugin.go` add `Execute` dispatch by stage+`target` (`passThrough` no-op on mismatch) + `executeRequest` (rewrite `System`+all `Messages[].Content`, `Result{RequestBody}`) + `rewriteRequest`. [spec: Request-leg rewrite; Provider-agnostic behavior]
- [x] 2.3 In `plugin.go` add `executeResponse` (streaming pass-through guard, rewrite `CanonicalResponse.Content`, `Result{Body,StopUpstream:true}`) + `rewriteResponse`. [spec: Response-leg rewrite]
- [x] 2.4 Create `data.go`: `Data` struct + `setExtras` via `in.Event.SetExtras`; wire `decision` (`rewritten`/`observed`/`no_match`) and `SetDecisionFromOutcome`. [spec: Modes]
- [x] 2.5 Create `plugin_test.go` (`-race`, real `adapter.NewRegistry()`): descriptor values, stage/target no-op both ways, request leg rewrite, response leg `Body`+`StopUpstream`, observe no-mutate, streaming pass-through, no-match extras, cross-provider (OpenAI+Anthropic), nil guards. [spec: all Requirement scenarios]

## Phase 3: Wiring + catalog

- [x] 3.1 `pkg/container/modules/plugins.go`: add `regexreplace` import + `regexreplace.New(p.Adapters, p.Logger)` in the catalog slice. [spec: Descriptor & stage registration]
- [x] 3.2 `pkg/app/plugins/catalog_metadata.go`: add `pluginCatalogMeta["regex_replace"]`, group `groupGuardrails`, `target` enum (required, `enumOptions("request","response")`) + `rules` array of objects {pattern (required), replacement, case_insensitive, multiline}. [spec: Descriptor & stage registration]
- [x] 3.3 `pkg/app/plugins/catalog_test.go`: add dedicated `TestRegexReplaceSchema` reading `pluginCatalogMeta["regex_replace"]` (mirror `TestAzureContentSafetySchema`). Do NOT add to `builtinSlugs`/`registerBuiltins`. [spec: Descriptor & stage registration]

## Phase 4: Functional test + docs

- [x] 4.1 Create `tests/functional/plugin_regex_replace_test.go`: request-side asserts `up.LastBody()` shows rewrite; response-side asserts client raw body rewritten; use `setupPolicyRoute`/`policyPlugin`/`proxyRequest`/`newJSONUpstream`. [spec: Non-functional; Request/Response-leg rewrite]
- [x] 4.2 `docs/policies.json`: add a `regex_replace` policy entry mirroring existing plugin docs (target + rules). [spec: Descriptor & stage registration]
- [x] 4.3 `postman/TrustGate.postman_collection.json`: add a `regex_replace` policy example mirroring existing plugin requests. [spec: Descriptor & stage registration]
- [x] 4.4 Run `go test -race ./...` + confirm no code comments in production files; `go vet`/`golangci-lint` clean. [spec: Non-functional coverage gate]
