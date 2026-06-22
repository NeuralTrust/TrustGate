# Tasks: Prompt template plugin — RUN-702

Package root: `pkg/infra/plugins/prompttemplate/`. No code comments (AGENT.md §11,
Apache header only). Every phase ends green under `go vet`, `golangci-lint`,
`go test -race ./...`. Phases are PR-sized: design.md's 5 logical phases are
split into 9 chained PRs to fit the 400-line budget (P1→1+2, P2→3+4, P3→5+6,
P4→7+8, P5→9).

## Phase 1: Skeleton + config tree + registration + catalog (PR1)

- [x] 1.1 Create `plugin.go`: `PluginName` const, exported `Plugin`, `New()`, `Name/MandatoryStages/SupportedStages(pre_request)/SupportedModes(enforce,observe)`, no-op `Execute` returning `okResult()`, `ValidateConfig` delegating to `parseConfig`, error-`Type` consts.
- [x] 1.2 Create `config.go`: full struct tree + enums (`engine`, `onMissingContext`, `onMissingClient`, `onExistingSystem`, `varSource`), `parseConfig` via `pluginutil.Parse[config]`, `applyDefaults`.
- [x] 1.3 Add `pluginCatalogMeta["prompt_template"]` entry + nested `SettingsSchema` in `pkg/app/plugins/catalog_metadata.go` (group `groupOther`).
- [x] 1.4 Register in `pkg/container/modules/plugins.go`: import + `prompttemplate.New()` in `newPluginRegistry` catalog slice.
- [x] 1.5 Extend `catalog_test.go`: assert entry exists, supports `enforce`, schema round-trips.

## Phase 2: Config validation (PR2)

- [x] 2.1 Implement `(*config).validate` in `config.go`: engine enum gate (jinja2_subset → "not yet supported" 4xx); reject `consumer_attribute` source as deferred; `context_variables[*]` source/name; ≥1 inject or named template.
- [x] 2.2 Validate `inject_templates[]` (id/content non-blank, position=`system`, role non-blank, on_existing_system enum) and `named_templates` (unique name/version/label, `required_variables.type` enum, `max_length>=0`, `default_label` resolves) and placeholder syntax `[\w.-]+`.
- [x] 2.3 Write `config_test.go`: defaults; mustache accepted; jinja2/consumer_attribute rejected; duplicate name/version/label; empty inject content; bad on_existing_system; unresolved default_label; bad type (spec "Configuration validation" scenarios).

## Phase 3: Render engine (PR3)

- [x] 3.1 Create `render.go`: `placeholderRe` (`\{\{\s*([\w.-]+)\s*\}\}`), `renderTemplate(tmpl, vars) (string, []string)` reporting missing keys, `escapeControlChars` stripping raw C0 bytes (keep `\n`/`\t`).
- [x] 3.2 Write `render_test.go`: substitution; whitespace tolerance `{{ var }}`; unknown placeholder reported in `missing`; control-char strip on/off; no-placeholder passthrough.

## Phase 4: Context variables + unverified JWT (PR4)

- [x] 4.1 Create `jwt.go`: `bearerToken(req)` + `unverifiedClaim(token, name)` via `jwt.NewParser().ParseUnverified`.
- [x] 4.2 Create `variables.go`: `resolveContextVars(cfg, req)` / `resolveOne` for `header` + `jwt_claim`; missing/unparsable → reported missing.
- [x] 4.3 Write `jwt_test.go` + `variables_test.go`: bearer extraction; non-bearer/empty → ""; valid + tampered token still read; header case-insensitive; absent header/claim → missing (spec "Header and jwt_claim resolve").

## Phase 5: Body Mode A helpers + trace data (PR5)

- [x] 5.1 Create `body.go`: `requestBody` struct, `decodeBody`, shape detection (top-level `system` string vs `messages[]`), `injectSystem(mode, role, content)` (merge/replace/insert per design), `marshal`.
- [x] 5.2 Create `data.go`: exported `PromptTemplateData` + decision consts.
- [x] 5.3 Write `body_test.go` (Mode A scope): system-string merge/replace/absent; messages[] system merge/replace/insert; marshal stable (spec "Mode A injection and system collision" scenarios).

## Phase 6: Mode A orchestration + Execute wiring (PR6)

- [x] 6.1 Create `modea.go`: `applyModeA(cfg, rb, ctxVars)` over `inject_templates[]` applying `on_missing_context_variable` (error/empty_string/skip_injection).
- [x] 6.2 Wire Mode A into `Execute`: guard nil request, resolve ctx vars, inject, `template_variable_unresolved` 500 reject when `blocks`; observe path records decision via `SetExtras`+`SetDecision`, no mutation; return `Result.RequestBody`.
- [x] 6.3 Write `modea_test.go`: inject+merge; inject+replace; on_missing error→500 / empty_string / skip_injection; observe no mutation (spec "Mode A context variable resolution" + observe scenarios).

## Phase 7: Body Mode B helpers + resolution/render/splice (PR7)

- [x] 7.1 Extend `body.go`: `takeProperties()` (decode + strip top-level `properties`), `findReferences` over `messages[].content` + top-level `system` (`templateRefRe`), `replaceMessages(fragment)` (JSON-array or bare-string→user msg).
- [x] 7.2 Create `modeb.go`: `resolveVersion(nt, label, defaultLabel)` (label → `default_label` fallback; unknown → `template_not_found` 400); render with `client > context` precedence; replace `messages`.
- [x] 7.3 Write `body_test.go` (Mode B scope) + `modeb_test.go` (resolution): reference scan in content + system; takeProperties strips; replace with array/bare-string; label + default_label resolve; unknown → `template_not_found` (spec "Mode B reference detection").

## Phase 8: Client-variable validation + error codes + Mode B wiring (PR8)

- [x] 8.1 Create `validate.go`: `validateClientVars(version, properties)` — presence (`template_variable_missing`), type/enum/max_length (`template_variable_invalid`); non-required absent → `on_missing_client_variable` handled in `renderTemplateContent` (context-aware).
- [x] 8.2 Wire Mode B into `Execute` before Mode A: strip `properties` always; `allow_untemplated_requests:false` + no ref → `template_required` 400; observe no mutation/no reject.
- [x] 8.3 Write `validate_test.go` + extend `modeb_test.go` + `plugin_test.go`: each error code→status/Type; properties precedence + stripped; contract (Name/Stages/Modes); Execute nil/Mode A only/Mode B only/both (spec "Mode B client variable validation", "rendering and body substitution", "Runtime error mapping").

## Phase 9: Functional tests + catalog finalization (PR9)

- [x] 9.1 Create `tests/functional/plugin_prompt_template_test.go`: end-to-end Mode A (header+jwt), Mode B render via proxy, all five error codes, observe vs enforce. Reuse `setupPolicyRoute`/`createScopedPolicy`/`proxyRequest`; POST path must equal consumer name (§14.7).
- [x] 9.2 Finalize `catalog_test.go` assertions for full nested schema round-trip.

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines (total) | ~2,400 (incl. table-driven tests) |
| Per-phase estimate | P1 ~310 · P2 ~260 · P3 ~180 · P4 ~280 · P5 ~330 · P6 ~350 · P7 ~380 · P8 ~340 · P9 ~290 |
| 400-line budget risk | High (whole feature) — each PR slice Low |
| Chained PRs recommended | Yes |
| Number of chained PRs | 9 |
| Suggested split | PR1→PR2→…→PR9 (each phase = one PR) |
| Delivery strategy | ask-on-risk |
| Chain strategy | feature-branch-chain |

Recommended strategy: **feature-branch-chain**. Keep the worktree feature branch
(`plugin-prompt-template`, off `origin/develop`) as the integration target. PR1
bases on the feature branch; each later PR bases on its immediate predecessor
(PR2←PR1, …, PR9←PR8) so every child diff stays focused. Only the feature branch
merges to `develop`. Order is dependency-forced: config (1–2) → engine/vars
(3–4) → Mode A (5–6) → Mode B (7–8) → functional (9). If any child PR shows a
predecessor's changes in its diff, retarget/rebase before review.

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: feature-branch-chain
400-line budget risk: High
