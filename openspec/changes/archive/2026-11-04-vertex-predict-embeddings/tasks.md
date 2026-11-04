# Tasks: Native Vertex `:predict` embeddings on consumers (ENG-3023)

## Linked artifacts
- Linear: ENG-3023
- Proposal: [`proposal.md`](./proposal.md)
- Design: [`design.md`](./design.md) (its "Resolved questions" section overrides earlier text)
- Spec: [`specs/vertex-predict-embeddings/spec.md`](./specs/vertex-predict-embeddings/spec.md)

## Conventions for every phase
- Base branch `develop`. Phases are stacked: PR N targets PR N-1's branch, PR 1 targets `develop`. Re-fetch `develop` before the first commit (a stale base trips the gosec pre-commit hook on untouched files).
- No ticket ids (`ENG-3023`, `RUN-*`) in code comments. Ticket keys stay in branch, commit and PR titles only.
- Each phase compiles and passes `make test` on its own. Each phase is one reviewable commit series.
- Run `go vet -tags functional ./tests/...` in any phase that touches `tests/` (`make test` does not compile the functional tag).
- Errors use the Google/Gemini envelope on the new route. Do not change OpenAI-envelope behaviour for existing formats.

## Decisions to settle before apply

- **D-1 RESOLVED (a): JSON-equal, reuse `StripModel`; spec amended.** Original note: The spec says the outgoing body equals the original "byte for byte" minus the `model` key. The existing `adapter.StripModel` (`pkg/infra/providers/adapter/model.go`, ~:177) unmarshals into `map[string]json.RawMessage` and re-marshals, which sorts keys and compacts whitespace. So it is not byte-exact. Options:
  - (a) Recommended: relax the contract to "same JSON document minus top-level `model`; key order and whitespace may change". Vertex parses JSON, so `task_type`, `title`, `autoTruncate` and all `parameters` survive. Reuse `StripModel`.
  - (b) Keep byte-exact: add `adapter.StripTopLevelModelBytes` that splices the `model` member out of the raw bytes with a `json.Decoder` offset scan. About +40 lines and more tests.
  - Recommendation (a) unless Edu wants the byte-exact guarantee. If (a), amend the spec scenario "Passthrough preserves Vertex-only fields" in the same PR as phase 3.
- **D-2 RESOLVED: spec amended.** Original note: Dropped per design Resolved question 1. `VertexEmbedAdapter` is not touched. Spec still lists it, so amend the spec bullet in phase 1 or mark it out of scope.
- **D-3 RESOLVED: one PR, one commit per phase** (Edu's choice; the code is ~300 lines and the rest is tests).

## As delivered

- Phases 1 to 4 landed as one commit each, plus a review-fix commit.
- Skipped 2.7: the OpenAI embeddings response is already returned in input order; reordering by `index` is not part of this bug.
- 4.7 to 4.9 (handler-level tests) are covered by the functional tests instead, which drive the full route: 200 on an embedding model, 403 from a model allowlist read from the path, 404 for a chat model on `:predict`, 400 on an empty body against a non-Vertex registry.
- 4.10 (telemetry parity) is not asserted by a dedicated test; the route reuses the embeddings capability and the canonical embedding shape.
- Error envelopes: `EncodeErrorBody` / `NeedsAdaptedError` use a narrower `gatewayErrorDialect`, so `/v1/rerank` and the other embedding sources keep their current envelope.

---

## Phases

### Phase 1: Plumbing and Dimensions (PR 1)
**Goal:** The adapter layer knows the new format name and error dialect, and OpenAI encodes `dimensions` when set. Existing formats produce byte-identical output. Nothing routes to the new format yet.
**Files:** `pkg/infra/providers/adapter/format.go`, `pkg/infra/providers/adapter/format_chat_request_test.go`, `pkg/infra/providers/adapter/error_envelope.go`, `pkg/infra/providers/adapter/error_envelope_test.go`, `pkg/infra/providers/adapter/cohere_embed_adapter.go`, `pkg/infra/providers/adapter/cohere_embed_adapter_test.go`
**Forecast:** ~115 lines (code ~55, tests ~60)

- [ ] 1.1 Add `FormatVertexPredictEmbed Format = "vertex_predict_embed"` next to `FormatVertexEmbed` in the format enum (`format.go`, ~:49). Proof: `go build ./pkg/infra/providers/adapter/...` plus the constant appears in the table in 1.2.
- [ ] 1.2 Add the new format to the non-chat branch of `IsChatRequest` (`format.go`, ~:188) and to `SupportedSourceFormat` (`format.go`, ~:201). Test: `format_chat_request_test.go` non-chat table gets a row (~:41) asserting `IsChatRequest` is false, and a `SupportedSourceFormat` assertion is true.
- [ ] 1.3 `errorDialect` (`error_envelope.go`, :162) maps `FormatVertexPredictEmbed` to `FormatGemini`. Test: `error_envelope_test.go` table row, `errorDialect(FormatVertexPredictEmbed) == FormatGemini`; existing rows unchanged.
- [ ] 1.4 `EncodeErrorBody` (`error_envelope.go`, :185) and `NeedsAdaptedError` (:401) switch on `errorDialect(source)` instead of the raw `normalizeFormat(source)`. Test: `error_envelope_test.go` asserts `EncodeErrorBody(FormatVertexPredictEmbed, 403, msg)` produces the Google error shape, and `EncodeErrorBody(FormatVertexEmbed, ...)` and `EncodeErrorBody(FormatOpenAI, ...)` still produce their current output. Also `NeedsAdaptedError(predict)` matches `NeedsAdaptedError(FormatGemini)`.
- [ ] 1.5 Add `Dimensions int \`json:"dimensions,omitempty"\`` to `CanonicalEmbeddingRequest` (`cohere_embed_adapter.go`, :19). Proof: package compiles; the field is exercised by 1.6.
- [ ] 1.6 `openAIEmbeddingRequest` (`cohere_embed_adapter.go`, :34) gets `Dimensions int \`json:"dimensions,omitempty"\``, set by the OpenAI `EncodeRequest` from canonical `Dimensions`. Test: `cohere_embed_adapter_test.go` case with `Dimensions: 256` asserts body contains `"dimensions":256`; case with `Dimensions: 0` asserts body is byte-identical to the existing golden output (existing test kept green).
- [x] 1.7 Update spec bullet "Dimensions encoding" to drop the Vertex `embedContent` item (D-2). Doc-only edit in the same PR. Proof: `grep -n outputDimensionality openspec/changes/vertex-predict-embeddings/specs/vertex-predict-embeddings/spec.md` shows only the predict scenario.

---

### Phase 2: `vertex_predict_embed` adapter and target resolution (PR 2)
**Goal:** A dedicated adapter decodes and encodes `:predict` bodies. Cross-format translation to OpenAI works at unit level. The format is registered and resolved for Vertex registries. Nothing is routed to it yet.
**Files:** `pkg/infra/providers/adapter/vertex_predict_embed_adapter.go` (new), `pkg/infra/providers/adapter/vertex_predict_embed_adapter_test.go` (new), `pkg/infra/providers/adapter/registry.go`, `pkg/infra/providers/adapter/format.go`, `pkg/infra/providers/adapter/cohere_embed_adapter.go` (OpenAI response decode order), `pkg/infra/providers/adapter/cohere_embed_adapter_test.go`
**Forecast:** ~350 lines (code ~150, tests ~200). Largest phase. If it grows past 400, split into 2a (tasks 2.1–2.3) and 2b (2.4–2.8).

- [ ] 2.1 New `VertexPredictEmbedAdapter` in `vertex_predict_embed_adapter.go`, `DecodeRequest`: reads `instances[].content` into canonical `Metadata["embedding"]` `{Model, Inputs, Dimensions}`, `Dimensions` from `parameters.outputDimensionality`. Test: `vertex_predict_embed_adapter_test.go` "decodes instances and outputDimensionality" with two instances and `outputDimensionality: 256`.
- [ ] 2.2 `DecodeRequest` returns `RequestDecodeError` for: missing `instances`, `instances: []`, an item with no `content`, an item with blank `content` (whitespace only). Test: table test in `vertex_predict_embed_adapter_test.go` asserts the error type for each case. (Gateway-side 400 applies only on the cross-format path. See Phase 4.)
- [ ] 2.3 `EncodeRequest`: canonical to `{"instances":[{"content":...}], "parameters":{"outputDimensionality":n}}`, `parameters` present only when `Dimensions > 0`. Test: encode with and without dimensions, then decode back, inputs and dimensions round-trip. Note in the test file that this encoder is reached only by unit tests because same-format passthrough never encodes.
- [ ] 2.4 `DecodeResponse`: `predictions[].embeddings.values` to canonical embeddings in order; `statistics.token_count` summed into usage. Test: two predictions with `token_count` 3 and 5 give usage total 8.
- [ ] 2.5 `DecodeResponse` with no `statistics`: no error, usage left empty. Test: response without `statistics` decodes cleanly and usage is empty (matches `/v1/embeddings` to Vertex today).
- [ ] 2.6 `EncodeResponse`: canonical to `{"predictions":[{"embeddings":{"values":[...],"statistics":{"token_count":n}}}]}`. No `truncated` key (design Resolved question 6). Test: encode, then decode, values and token counts round-trip; the JSON has no `truncated` key.
- [ ] 2.7 OpenAI response order: confirm `OpenAIEmbeddingsAdapter.DecodeResponse` (`cohere_embed_adapter.go`, `Index` field at :42) places embeddings by `index`, not arrival order. If not, sort or place by index. Test: `cohere_embed_adapter_test.go` response with indexes 1 then 0 yields canonical embeddings in input order 0, 1.
- [ ] 2.8 Register in `registry.go` (:116): `r.Register(FormatVertexPredictEmbed, &VertexPredictEmbedAdapter{})` next to `FormatVertexEmbed`. Test: registry lookup returns the adapter for both source and target use; `vertex_embed_adapter.go` and its tests are untouched (`git diff --stat` shows no change there).
- [ ] 2.9 `ResolveTargetFormatForCapability` (`format.go`, :425): for `capability == "embeddings"`, `providerName == provider.Vertex`, `sourceFormat == FormatVertexPredictEmbed`, return `FormatVertexPredictEmbed`. Otherwise current behaviour (`FormatVertexEmbed` for other Vertex sources). Test: existing format-resolution test file gets rows: (vertex, embeddings, predict) returns predict; (vertex, embeddings, openai) returns `vertex_embed`; (openai, embeddings, predict) returns `openai_embeddings`.
- [ ] 2.10 Cross-format chain at unit level: decode a predict body with two instances and `outputDimensionality: 256`, encode with the OpenAI embeddings encoder. Test: upstream body equals `{"model":...,"input":["a","b"],"dimensions":256}`; without `outputDimensionality` the body has no `dimensions` key.

---

### Phase 3: Resolver, routing and Vertex client (PR 3)
**Goal:** `:predict` on an embedding model resolves to embeddings with the path model stamped into the body. The Vertex client calls `:predict` and strips the stamped `model`. Depends on D-1.
**Files:** `pkg/api/resolver/proxy_path_resolver.go`, `pkg/api/resolver/proxy_path_resolver_test.go`, `pkg/app/proxy/routing.go`, `pkg/app/proxy/routing_*_test.go` (add to the file that already covers `modelRefFromRequest` and `applyIntentToBody`), `pkg/infra/providers/vertex/client.go`, `pkg/infra/providers/vertex/client_test.go`
**Forecast:** ~225 lines (code ~95, tests ~130)

- [ ] 3.1 `proxy_path_resolver.go`: replace `isVertexGenerateContentPath` (:232, only caller :208) with `vertexAction(rest string) (model, action string, ok bool)`. `matchesVertexLayout` (:242) returns the action instead of a bool. Keep both vertex layouts (`vertexPathLayouts`, :220). Test: existing `proxy_path_resolver_test.go` chat rows stay green with no expectation change.
- [ ] 3.2 Add `isEmbeddingModel(model string) bool` with prefixes `gemini-embedding-`, `text-embedding-`, `text-multilingual-embedding-`. Test: table in `proxy_path_resolver_test.go`: each prefix true; `gemini-2.5-flash` false; `text-embedding` (no dash) false; `text-multilingual-embedding-002` true (not caught by the shorter prefix only).
- [ ] 3.3 `formatForRoute` (`proxy_path_resolver.go`, :175) branches on action: chat actions keep `FormatGemini`/`CapabilityChat`; `predict` with `isEmbeddingModel` gives `FormatVertexPredictEmbed`/`CapabilityEmbeddings`; any other `predict` returns `ErrUnknownProxyPath` (404). Tests in `proxy_path_resolver_test.go`: full layout and express layout, `v1` and `v1beta1`, embedding model gives the expected format and capability; `gemini-2.5-flash:predict` gives `ErrUnknownProxyPath`; `:generateContent` and `:streamGenerateContent` on both layouts unchanged; `/v1beta/models/gemini-embedding-001:predict` result identical to pre-change.
- [ ] 3.4 `modelRefFromRequest` (`pkg/app/proxy/routing.go`, :358): treat `FormatVertexPredictEmbed` like `FormatGemini` (model from `adapter.GeminiModelFromPath(req.Path)`). Check that `SplitGeminiModelAction` in `format.go` handles the `:predict` action; fix there if not. Test: routing test asserts a predict-source request returns the path model (`gemini-embedding-001`), not empty.
- [ ] 3.5 `applyIntentToBody` (`routing.go`, :407): the Gemini short-model stamp condition also accepts `FormatVertexPredictEmbed`. Test: after `applyIntentToBody` with a short intent, body has `"model":"gemini-embedding-001"`; a qualified intent still overrides via `OverrideModel`; a Bedrock-native request is untouched (existing guard).
- [ ] 3.6 `vertex/client.go` `embeddingsAction` (:188): returns `predict` when the body has top-level `instances`. Check `instances` before the existing `requests` batch probe. Test: `client_test.go` table: `instances` gives `:predict`; `requests` gives `batchEmbedContents`; `content` only gives `embedContent`.
- [ ] 3.7 `vertex/client.go` `Embeddings` (:133): on the predict branch only, apply the strip from D-1 to `reqBody` before `newHTTPRequest`. Note `buildEmbeddingsURL` reads the model from the body via `resolveModel` (:252), which runs before the strip, so URL resolution is unaffected. Test: `client_test.go` with an `httptest` upstream asserts the outgoing body has no top-level `model`, keeps `task_type`, `title`, `autoTruncate`, `parameters`; for option (a) assert JSON equality, for option (b) assert byte equality. `embedContent` and `batchEmbedContents` bodies are unchanged (existing assertions green).
- [ ] 3.8 Vertex target URL: test asserts that with registry base URL `B` and model `gemini-embedding-001` the request goes to `B/gemini-embedding-001:predict` (both the `BaseURL` branch and `buildVertexURL` branch in `buildEmbeddingsURL`). Test: `client_test.go` two sub-cases.

---

### Phase 4: Proxy, handler and functional tests (PR 4)
**Goal:** End-to-end behaviour is proven through the proxy with fake Vertex and fake OpenAI upstreams. Test-only phase, no production code changes expected. If a gap is found, fix it in this PR and note it in the commit body.
**Files:** `pkg/app/proxy/provider_embeddings_test.go`, `pkg/api/handler/http/proxy/proxy_handler_test.go`, `tests/functional/embeddings_provider_test.go`
**Forecast:** ~260 lines (tests only: provider ~90, handler ~60, functional ~110)

- [ ] 4.1 Passthrough predict to a fake Vertex in `provider_embeddings_test.go`: fake receives `:predict` URL, body has no `model` key, the other fields survive (per D-1); response returned unchanged including `predictions[].embeddings.values`. Test name: `TestEmbeddings_VertexPredictPassthrough`.
- [ ] 4.2 Usage on passthrough: usage recorded from `statistics.token_count` (two predictions, 3 and 5, total 8). Test: same file, subtest of 4.1 asserting recorded usage 8.
- [ ] 4.3 Missing `statistics` on passthrough: no error, usage accounted as `/v1/embeddings` does for the same upstream. Test: subtest with a fake response that has no `statistics`.
- [ ] 4.4 Cross-format predict to a fake OpenAI in `provider_embeddings_test.go`: upstream receives `input` as the ordered instance contents; `dimensions` present only when `outputDimensionality > 0`; response re-encoded as `predictions`, in input order. Test: two subtests (with and without dimensions).
- [ ] 4.5 Empty instances, cross-format: gateway returns 400 in the Google envelope and makes no upstream call (fake OpenAI call count is 0). Test: subtest in `provider_embeddings_test.go`.
- [ ] 4.6 Empty instances, Vertex registry (design Resolved question 5): body forwarded, the fake Vertex 400 is relayed unchanged. Test: subtest asserts fake Vertex received the request and the client got Vertex's 400 body.
- [ ] 4.7 Handler, `proxy_handler_test.go` (~:595): predict on an embedding model returns 200; the path model reaches the policy input (capture the model the policy sees). Test: `TestProxyHandler_VertexPredictEmbeddings`.
- [ ] 4.8 Handler: disallowed model on `:predict` returns the same status and policy error as the same disallowed model on `/v1/embeddings`, in the Google error envelope. Test: subtest comparing the two responses' status and error type; assert envelope shape.
- [ ] 4.9 Handler: non-embedding model on `:predict` returns 404 in the Gemini error envelope. Test: subtest in `proxy_handler_test.go`.
- [ ] 4.10 Telemetry and guardrail parity: for one request on `:predict` and one on `/v1/embeddings`, recorded telemetry capability is `embeddings` and trace attributes match. Locate the existing telemetry assertion helper first (grep `CapabilityEmbeddings` in `_test` files). If none exists, assert on the capability field of the emitted event only and note the gap in the commit body.
- [ ] 4.11 Functional, `tests/functional/embeddings_provider_test.go`: fake Vertex serves `:predict` on the full regional path; full chain through the proxy, mirroring `TestVertexProvider_Embeddings` (:216). Test: `TestVertexProvider_VertexPredictEmbeddings`, asserts 200 and `predictions[].embeddings.values`.
- [ ] 4.12 Functional: cross-format leg with a fake OpenAI behind a consumer bound to an OpenAI embeddings registry. Test: subtest in the same file; fake OpenAI receives `dimensions` only when set.
- [ ] 4.13 Gate: `go vet -tags functional ./tests/...` passes with the new tests. Run before commit.

---

### Phase 5: Final verification (no commit; runs on top of PR 4)
**Goal:** Prove the stack is green and works against a live local gateway with a fake Vertex upstream. Produces evidence, not code.

- [ ] 5.1 `make test` green on the top of the stack.
- [ ] 5.2 Race: `go test -race ./pkg/app/proxy/... ./pkg/api/...` green (proxy path is concurrent; also `make test-race` if present).
- [ ] 5.3 `make lint` green.
- [ ] 5.4 `go vet -tags functional ./tests/...` green.
- [ ] 5.5 Local run against a fake Vertex upstream: start the gateway with a Vertex registry pointed at a local fake (`BaseURL`). POST `gemini-embedding-001:predict` on both layouts (`v1` and `v1beta1`). Expect 200 with `predictions[].embeddings.values`. POST `gemini-2.5-flash:predict` and expect 404. Check the fake receives no `model` key. Before starting, override the local `.env` OTLP endpoint so telemetry does not reach the real collector (see the local activity E2E recipe in memory).
- [ ] 5.6 Repo verifier and reviewer pass on each PR before its commit (verifier gate, then reviewer, then pr-shipper).
- [ ] 5.7 Post-merge, out of this PR chain: live check on DEV with a real Vertex registry and key (success criterion 4). Requires Edu's OK for any promote to `main`. No promote is implied.

---

## Notes and gaps found while checking against the code
- The design's Risks table points to an "Open questions" section that does not exist. Empty-instances handling is settled by Resolved question 5, so nothing is open there.
- `StripModel` is not byte-exact (see D-1). The spec's "byte for byte" wording is the only blocking mismatch.
- The `Dimensions on Vertex predict` scenario is reachable only through the unit-level encoder (2.3). Same-format passthrough never encodes, so there is no proxy-level assertion for it.
- Telemetry and guardrail parity scenarios have no named test seam in the spec. Task 4.10 locates one.
- `isVertexGenerateContentPath` has one caller (`proxy_path_resolver.go:208`), so the rename is contained.

---

## Review Workload Forecast

| Phase | PR | Code lines | Test lines | Total (est.) | Files | Risk |
|---|---|---|---|---|---|---|
| 1. Plumbing and Dimensions | PR 1 | ~55 | ~60 | ~115 | 6 modified, 0 new (+1 spec doc) | Low |
| 2. `vertex_predict_embed` adapter and target resolution | PR 2 | ~150 | ~200 | ~350 | 4 modified, 2 new | Medium (new adapter; order and decode edge cases) |
| 3. Resolver, routing, Vertex client | PR 3 | ~95 | ~130 | ~225 | 3 modified (+ routing test file) | Medium (D-1 strip decision; `:predict` action parsing) |
| 4. Proxy, handler and functional tests | PR 4 | ~0 | ~260 | ~260 | 3 modified | Medium (functional fakes; telemetry seam) |
| 5. Verification | none | 0 | 0 | 0 | n/a | Low (gates only) |
| **Total** | 4 PRs | **~300** | **~650** | **~950** | ~16 files | |

Range: ~800 to ~1,100 changed lines (`additions + deletions`). Sizing used per-file judgement from the design file table, not the default create/modify heuristic, because several files are known to be small (format enum, registry line) and the adapter and its test are known to be medium.

**400-line budget risk:** High. Total is about 2.4x the budget. Phase 2 (~350) is under the limit but close, and Phase 4 is test-only so it can be reviewed fast.

**Chained PRs recommended:** Yes. The change is about 950 lines and phases 1 to 4 each ship as a slice with their own tests, and only phase 5 has no commit. Phases are stacked because phase 2 depends on the constant from phase 1, phase 3 on the adapter from phase 2, and phase 4 on the route from phase 3. Chain order cannot be reversed.

**Decision needed before apply:** Yes. D-1 (byte-exact strip vs. relaxed contract) and D-3 (confirm stacked strategy) must be settled first.
