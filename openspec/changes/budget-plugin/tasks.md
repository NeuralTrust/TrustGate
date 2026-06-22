# Tasks: Budget plugin (token / dollar budget + cost cap) — RUN-696

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~1800–2400 across 6 phases |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR1 → PR2 → PR3 → PR4 → PR5 → PR6 (one per phase) |
| Delivery strategy | ask-on-risk |
| Chain strategy | pending (recommend feature-branch-chain) |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: pending
400-line budget risk: High

Recommendation: **feature-branch-chain** off a tracker branch `feat/budget-plugin`.
PR #1 base = `develop`; each later PR base = the previous slice's branch, so each
child diff stays near/under 400 lines and only the final integration lands once.
(Alternative: 6 independent PRs off `develop` — cleaner history but more rebase
churn because phases are strictly dependent. Prefer the chain.)

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Config struct + normalize + validate + window parse + glob | PR 1 | base `develop`; no behavior change; unit tests |
| 2 | Per-model + aggregate token budget (keys, gate, accrual) | PR 2 | base PR 1; legacy single-window preserved |
| 3 | Pricing plumbing (`SlugCandidates`) + dollar budget | PR 3 | base PR 2; metrics tests stay green |
| 4 | Stateless cost cap | PR 4 | base PR 3 |
| 5 | Downgrade + responses/headers + mode reconciliation | PR 5 | base PR 4 |
| 6 | Catalog metadata + docs | PR 6 | base PR 5 |

## Phase 1: Config & validation foundation (back-compat)

- [x] 1.1 Add `config`, `windowConfig`, `budgetRule`, `aggregateConfig`, `costCapConfig`, `costCeiling`, `customPrice` structs to `pkg/infra/plugins/tokenratelimit/config.go` with `mapstructure` tags per design.
- [x] 1.2 Implement `parseConfig` + `(*config).normalize` (zero-value defaults: unit→tokens, counting→total, pricing_table→builtin, behavior_on_exceeded→reject; synthesize `Aggregate` from legacy `Window.Max`).
- [x] 1.3 Implement `parseWindow(string) (int, error)` (`"30m"`,`"1h"`,`"1d"`; 60s floor) + keep legacy `windowSeconds()` via `validUnits[Window.Unit]`.
- [x] 1.4 Implement table-driven `(*config).validate` covering all spec validation scenarios (bad unit, per_model w/o rules+window, dollars w/o pricing, downgrade w/o target, max<=0, malformed window).
- [x] 1.5 Create `pkg/infra/plugins/tokenratelimit/glob.go`: `globMatch(pattern, s) bool` (two-pointer) + `bestMatch[T]` (exact > longest literal glob).
- [x] 1.6 Unit tests: `config_test.go` (normalize/validate/back-compat) + `glob_test.go`.

**Verify**: `go test -race ./pkg/infra/plugins/tokenratelimit/...` ; `go vet ./...` ; `golangci-lint run`.
**Rollback**: revert `config.go`/`glob.go` additions; legacy struct unchanged.

## Phase 2: Per-model + aggregate token budget

- [ ] 2.1 Create `keys.go`: `counterKeyPrefix` const, `aggregateKey`, `modelKey` (`:model:{slug}` segment) from `RuntimeScope.Subject()`.
- [ ] 2.2 Move existing Lua into `scripts.go` (`recordScript`, reused unchanged).
- [ ] 2.3 Implement `budget.go`: `selectRule`, `windowsFor`, `budgetGate` (pre-request GET per window), `accrue` (post-response INCRBY); honor `counting` input/output/total.
- [ ] 2.4 Wire `preRequest`/`postResponse` dispatch in `plugin.go`; preserve legacy single-window path + `X-Ratelimit-*-Tokens` headers + 429.
- [ ] 2.5 Unit tests for keys + budget selection; functional test: per-model isolation, aggregate, crossing-request-passes, legacy back-compat.

**Verify**: `go test -race ./pkg/infra/plugins/tokenratelimit/...` ; `go test -race ./tests/functional/... -run TokenRateLimiter`.
**Rollback**: revert `budget.go`/`keys.go`/dispatch; legacy gate restored.

## Phase 3: Pricing plumbing + dollar budget

- [ ] 3.1 Extract `appcatalog.SlugCandidates(...string)` in `pkg/app/catalog` (from `deploymentCatalogSlug`/`appendModelSlugs`/`uniqueNonEmptySlugs`).
- [ ] 3.2 Refactor `pkg/app/metrics/builder.go::pricingSlugs` to call `SlugCandidates` (behavior-preserving); keep metrics tests green.
- [ ] 3.3 Inject `appcatalog.PricingResolver` into `pluginParams` (`pkg/container/modules/plugins.go`); change `tokenratelimit.New(redis, registry, pricing)`.
- [ ] 3.4 Implement `pricing.go`: `priceFor` (custom overlay→resolver), `per1k`, `microUSD`; `count_cache_reads` toggle.
- [ ] 3.5 Dollar accrual in `accrue`: scaled-integer micro-USD via `recordScript`; unknown model accrues 0 + warn.
- [ ] 3.6 Unit tests (pricing overlay, per-1k, micro-USD, resolver mock via `go generate` mockery) + functional dollar-budget test.

**Verify**: `go generate ./...` ; `go test -race ./pkg/app/metrics/... ./pkg/infra/plugins/tokenratelimit/... ./tests/functional/...`.
**Rollback**: revert injection + `pricing.go`; keep token-only accrual.

## Phase 4: Stateless cost cap

- [ ] 4.1 Implement `costcap.go`: `decision` struct, `evaluateCeiling`, `costCapDecision` (global + `per_model_overrides` via `bestMatch`).
- [ ] 4.2 Run cost cap BEFORE budget gate in `preRequest`; 403 `model_too_expensive` with four price fields.
- [ ] 4.3 `unknown_model` policy: reject | pass_through | assume_max.
- [ ] 4.4 Unit tests (reject/override/unknown ×3, runs-before-budget) + functional cost-cap reject test.

**Verify**: `go test -race ./pkg/infra/plugins/tokenratelimit/... ./tests/functional/...`.
**Rollback**: revert `costcap.go` + preRequest hook; budget path intact.

## Phase 5: Downgrade + responses/headers + mode reconciliation

- [ ] 5.1 Implement downgrade: same-provider guard (`routingdomain.ParseModelRef`) + target ∈ `req.AllowedModels` (when non-empty) else fall back to reject; `req.Body = adapter.OverrideModel(req.Body, target)`.
- [ ] 5.2 Emit `X-NeuralTrust-Model-Downgraded: <orig>→<new>` via `Result.Headers`.
- [ ] 5.3 `X-Budget-*` headers + 429 bodies (`token_budget_exceeded`/`dollar_budget_exceeded`).
- [ ] 5.4 Mode reconciliation: `observe` forces non-blocking (overrides behavior), `throttle` delays budget only, `enforce` applies `behavior_on_*`.
- [ ] 5.5 Functional tests: successful same-provider downgrade, cross-provider falls back to reject, observe never blocks, enforce rejects. Document single-plugin-batch caveat (§14.2).

**Verify**: `go test -race ./pkg/infra/plugins/tokenratelimit/... ./tests/functional/...`.
**Rollback**: revert downgrade/header/mode code; reject-only behavior remains.

## Phase 6: Catalog metadata + docs

- [ ] 6.1 Expand `catalog_metadata.go` `SettingsSchema.Fields` (keep `window`+`group_by_header`; add unit, per_model, counting, rules[], aggregate, cost_cap, pricing_table, custom_pricing) using `FieldTypeObject/Array/Map/Enum`.
- [ ] 6.2 Update `token_rate_limiter` name → "Token & Dollar Budget + Cost Cap" + description.
- [ ] 6.3 Update `catalog_test.go` for the new schema tree.
- [ ] 6.4 Update any example/docs for the new config.

**Verify**: `go test -race ./pkg/app/plugins/... -run Catalog` ; `go vet ./...`.
**Rollback**: revert metadata/name/description; legacy schema entry restored.
