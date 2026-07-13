# Tasks: RUN-703 Prompt Decorator

## Review Workload Forecast

| Field | Value |
|---|---|
| Estimated additions + deletions | 1,850–2,650 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | Nine stacked slices: PR 1 targets `develop`; PRs 2–9 target their immediate predecessor |
| Delivery strategy | ask-on-risk |
| Chain strategy | Recommend predecessor-based stack to `develop`; approval pending |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: pending
400-line budget risk: High

### Suggested Work Units

| Unit | Scope | Estimate |
|---|---|---:|
| 1 | Original-body foundation | 150–250 |
| 2 | Configuration | 180–260 |
| 3 | OpenAI document | 280–400 |
| 4 | Anthropic document | 280–400 |
| 5 | Pure plugin execution | 220–340 |
| 6 | Composition invariant | 160–260 |
| 7 | Provider translation | 160–240 |
| 8 | Catalog/DI activation | 160–260 |
| 9 | Functional acceptance | 260–400 |

One commit/PR per phase. PR 1 targets `develop`; each later PR targets the preceding phase branch and lands in order. Phases 1–7 merge dormant or compatibility-only.

## Phase 1: Immutable Original Request

- [x] 1.1 Add `OriginalBody` in `pkg/infra/context/request_context.go`; independently allocate it and `Body` in `pkg/api/handler/http/proxy/proxy_handler.go`.
- [x] 1.2 Extend `proxy_handler_test.go` to mutate either slice and prove bidirectional non-aliasing. Verify: `go test -race ./pkg/api/handler/http/proxy`.

## Phase 2: Strict Configuration

- [x] 2.1 Create `pkg/infra/plugins/promptdecorator/config.go` with strict fields, enums, pairings, content, scope metadata, useful-action validation, and no caps.
- [x] 2.2 Cover the valid/invalid matrix in `config_test.go`. Verify: `go test ./pkg/infra/plugins/promptdecorator -run Config`.

## Phase 3: Private OpenAI Document

- [x] 3.1 Create `document.go` to copy current `Body` into private RawMessages, preserve unknown/rich fields, and marshal separately allocated output without input edits.
- [x] 3.2 Add OpenAI anchors, strategies, ordering, fidelity, fuzz, and bidirectional alias tests in `document_test.go`. Verify: `go test -race ./pkg/infra/plugins/promptdecorator`.

## Phase 4: Private Anthropic Document

- [x] 4.1 Land the independently verified core slice: `anthropic_document.go`, `anthropic_message_sequence.go`, `anthropic_system.go`, and `anthropic_document_core_test.go`. This production-heavy slice uses the documented size exception and lands with 4.2 unchecked.
- [x] 4.2 Stack `anthropic_document_placement_test.go`, `anthropic_document_system_strategy_test.go`, `anthropic_document_system_edge_test.go`, and `anthropic_document_fidelity_test.go` in that order; the final slice checks 4.2 after exact-key, 2,048-merge stress, fidelity, alias, OpenAI regression, race, and fuzz verification.

## Phase 5: Pure Plugin Execution

- [x] 5.1 Create `plugin.go`: read folded `Body`, validate only `OriginalBody`, return new `Result.RequestBody`, expose `MutatesRequestBody=true`, and never write context/backing data.
- [x] 5.2 In `plugin_test.go`, prove enforce/observe, exact 400, malformed JSON, unchanged input, and independent result storage. Verify: `go test -race ./pkg/infra/plugins/promptdecorator`.

## Phase 6: Existing Composition Contract

- [ ] 6.1 Create `composition_test.go` with preceding/following body mutators, including `parallel=true`; prove StagePlan serialization and executor-folded deterministic inputs.
- [ ] 6.2 Prove read-only parallel safety and original-vs-folded semantics. Do not change planner/executor production code; stop for redesign on a proven gap. Verify: `go test -race ./pkg/infra/plugins/promptdecorator`.

## Phase 7: Provider Translation

- [ ] 7.1 Update `pkg/infra/providers/adapter/anthropic_adapter.go` to translate copied system string/text arrays without unrelated changes.
- [ ] 7.2 Extend `anthropic_adapter_test.go` and `bedrock_adapter_test.go` for Claude/OpenAI-compatible targets. Verify: `go test ./pkg/infra/providers/adapter`.

## Phase 8: Catalog and DI Activation

- [ ] 8.1 Register `prompt_decorator` in `pkg/container/modules/plugins.go`; add schema/catalog expectations in `pkg/app/plugins/catalog_metadata.go` and `catalog_test.go`.
- [ ] 8.2 Prove registration resolves and `prompt_template` is unchanged. Verify: `go test ./pkg/app/plugins ./pkg/container/modules ./pkg/infra/plugins/promptdecorator`.

## Phase 9: Functional Acceptance

- [ ] 9.1 Create `tests/functional/plugin_prompt_decorator_test.go` for scope, modes, protocols, ordering, exact rejection/no upstream, and Bedrock targets.
- [ ] 9.2 Verify: `go test -tags functional -run 'TestPluginE2E_PromptDecorator' ./tests/functional/...`; then `make fmt`, `go vet ./...`, `make lint`, and `make test-race`.
