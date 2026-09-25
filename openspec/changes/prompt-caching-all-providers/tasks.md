# Tasks: Prompt caching and cache usage accounting across all providers (ENG-1618)

Contract: Linear ENG-1618. Inputs: `proposal.md`, `specs/*`, `design.md` (slice map, D1–D11). Paths below are relative to `pkg/infra/` unless they start with `pkg/`, `docs/` or `src/`.

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~2,830 TrustGate (S1a 250, S1b 260, S1c 340, S2a 390, S2b 370, S3 270, S4a 300, S4b 260, S5 390) + ~300 multi-agent-tests (E) |
| 400-line budget risk | High (total); per slice Low–Medium, S2a and S5 closest to the cap |
| Chained PRs recommended | Yes |
| Suggested split | S1a → S1b → S1c → S2a → S2b → S3 → S4a → S4b → S5; E (multi-agent-tests) in parallel with S1a |
| Delivery strategy | ask-on-risk (none received; default) |
| Chain strategy | single integration PR (user decision 2026-09-23, later the same day): all phases land as commits on `fix/eng-1618-prompt-caching-all-providers` and go to `main` in ONE PR labelled `size:exception`, reviewed commit by commit; slice PRs #846–#852 closed. Earlier plan, superseded: feature-branch integration branch `fix/eng-1618-prompt-caching-all-providers`; each slice is a PR into it; one final PR integration → `main` (base is `origin/main`, nothing from develop). ENG-1608 stays a separate branch with its own path. |

Decision needed before apply: No (approved 2026-09-23)
Chained PRs recommended: Yes
Chain strategy: feature-branch
400-line budget risk: High

Measure each slice with `git diff --shortstat <parent> -- pkg tests docs` (parent = the integration branch for S1a, the previous slice branch otherwise); openspec/ is excluded. Over 400 → split along task lines before the PR.

### Dependencies

- **ENG-1608** (unpushed, `TrustGate-eng1608`, 5 commits) touches `canonical.go`, `anthropic_adapter.go`, `openai_completions_adapter.go`, `bedrock_adapter.go`, `converse.go`, `app/proxy/provider.go`. S1a–S1c are independent. S2a, S2b, S4a are written base-agnostic and rebase onto 1608 with the conflict map in design.md ("ENG-1608 composition"): keep both sides, gofmt, `go test ./pkg/infra/providers/... ./pkg/app/proxy/...`, then `git rebase --update-refs` for the rest of the stack.
- **PR #826** overlaps the Anthropic SSE usage struct (S1c) and trustguard (S5). Merge order decided before S1c and S5 open.

### Suggested Work Units

| Unit | Goal | PR | Base |
|------|------|----|------|
| E | e2e `prompt_caching` suite | multi-agent-tests PR | `main` of multi-agent-tests |
| S1a | Bedrock usage correct | PR 1 | integration (from main) |
| S1b | OpenAI-family/Cohere usage decode | PR 2 | S1a |
| S1c | Client encoders + 1h pricing | PR 3 | S1b |
| S1e-1 | Gemini tool results paired by name, grouped per turn (~40 prod / ~110 test) | PR 3e-1 | S1c-3b |
| S1e-2 | Upstream stream error marker + shared Anthropic stop reasons (~170 prod / ~150 test) | PR 3e-2 | S1e-1 |
| S1e-3 | Stateful Anthropic stream encoder (~470 prod / ~260 test) | PR 3e-3 | S1e-2 |
| S1e-4 | Proxy streams Anthropic clients through the encoder (~260 prod / ~1,230 test) | PR 3e-4 | S1e-3 |
| S1d | Cohere v2 stream contract | PR 3d | S1e-4 |
| S1f | Gemini thought-signature decode + sentinel | integration PR | S1d |
| S1b-2 | Groq regression tests from captures (+ optional `x_groq.usage` fallback) | integration PR | S1f |
| S2a | Canonical intent + Anthropic | PR 4 | S1c (+1608) |
| S2b | OpenAI Chat/Responses intent | PR 5 | S2a |
| S3 | Request passthrough, Mistral/OpenRouter/Azure | PR 6 | S2b |
| S4a | Bedrock `cachePoint` wire + SDK | PR 7 | S3 |
| S4b | Bedrock capability + retry | PR 8 | S4a |
| S5 | Plugins + docs | PR 9 | S4b |

### Verification block (V) — ends every phase

- **V1** `go vet`, `golangci-lint run`, `go test -race` on the phase packages; `make test` before the PR.
- **V2** clean-comments pass on touched Go (orchestrator, haiku).
- **V3** adversarial review of the phase diff (orchestrator: judgment-day dual review / reviewer).
- **V4** per listed provider X, against LOCAL TrustGate from the worktree (`make run-all` + `run-proxy-sandbox`; never prod; `E2E_ADMIN_URL`/`AG_ADMIN_URL` = localhost): `make matrix-ag UPSTREAM=X AGENT=X`, same with `STREAM=1`, `make matrix-ag PROVIDER=X`, same with `STREAM=1`, `uv run pytest -m prompt_caching -k X`. Missing/expired key → STOP and report. Bedrock: `aws sts get-caller-identity` first. Moonshot out of scope (provider not on main); openai_compatible unit-only; Vertex covered by Gemini.
- **V5** commit as one work unit (Conventional Commit, attribution lines).

## Phase E: multi-agent-tests prompt_caching suite (`/Users/edu/Neuraltrust/multi-agent-tests-eng1618`)

- [x] E.1 `pyproject.toml`: add marker `prompt_caching: cached-prefix accounting across providers`.
- [x] E.2 `src/e2e/tests/test_prompt_caching.py`: session fixture checks `upstreams.unavailable(X)` for selected upstreams; any missing → `pytest.exit(reason, returncode=2)` naming the vars (never skip). Bedrock also runs `sts get-caller-identity`.
- [x] E.3 Same file: ~5k-token static prefix builder; HS256 `X-AG-Playground-Token` (purpose `playground`, consumer slug, local `SERVER_SECRET_KEY`).
- [x] E.4 Parametrize (upstream, client format ∈ {native, openai, anthropic}, stream); Bedrock variants implicit / explicit 5m / explicit 1h; plugin cases Anthropic+OpenAI with regexreplace and toolallowlist.
- [x] E.5 Assertions: second call R>0 in provider body; `GET {E2E_ADMIN_URL}/v1/playground/traces/{X-AG-Trace-Id}` with admin Bearer `E2E_ADMIN_TOKEN`; trace I/R/W/W1h == provider usage; cost per D10. Groq cache assertion only for gpt-oss.
- [x] E.6 `README.md` + `.env.example`: local-gateway notes (localhost admin/proxy, sandbox domain, never prod, `-k` per slice since later slices' cases fail until landed).
- [x] E.7 `src/agentgateway/catalog.py` only if needed: cache-capable default models (Claude Haiku 4.5 on Bedrock, GPT-5.6 for Responses breakpoints, Groq gpt-oss).
- [ ] E.8 V: `make lint`, `uv run pytest -m prompt_caching --collect-only`; V2–V3; V4 = `-k bedrock` against S1a local build; V5.

## Phase 1 (S1a): Bedrock usage fold

- [x] 1.1 `providers/adapter/canonical.go`: `(*CanonicalUsage).setCache(read, write, write1h)`.
- [x] 1.2 `providers/adapter/bedrock_adapter.go`: `ConverseUsage.CacheDetails []ConverseCacheDetail`; `converseUsageToCanonical` folds I=in+R+W, W1h from `ttl=="1h"`, Total=max(total, I+O).
- [x] 1.3 Same file: encoder writes `inputTokens=PlainInputTokens()` and rebuilds `cacheDetails`.
- [x] 1.4 `providers/bedrock/converse.go`: `wireUsage` copies `TokenUsage.CacheDetails`.
- [x] 1.5 Tests: rewrite `bedrock_adapter_test.go:382-403`, `converse_test.go:178-193`; add 12+4+2→18/25 and 1h split, buffered + stream.
- [x] 1.6 `providers/bedrock/live_test.go`: same prefix twice, R>0, raw `inputTokens` excludes R+W, Total≥I+O.
- [ ] 1.7 V1 (adapter, bedrock; `go test -tags bedrock_live`); V2; V3; V4 **Bedrock**; V5.

## Phase 2 (S1b): OpenAI-family and Cohere usage decode

- [x] 2.1 `openai_completions_adapter.go`: `openaiUsage.{PromptCacheHitTokens,PromptCacheMissTokens}`, details `CacheWriteTokens`; R=max(details, DeepSeek hit), W from details, I=max(prompt, hit+miss); routed through `setCache` only when R+W > 0; `setCache` does NOT raise I (provider folds stay in adapters: Bedrock in+R+W, DeepSeek max(prompt, hit+miss)). Top-level `CachedTokens` (Moonshot) skipped: provider not on main.
- [x] 2.2 `openai_responses_adapter.go`: `input_tokens_details.cache_write_tokens` → W.
- [x] 2.3 `cohere_adapter.go`: `usage.cached_tokens` → R.
- [x] 2.4 `openrouter_adapter.go`: `cost`/`cache_discount` → `slog.Debug` only (buffered and usage-bearing stream chunks; parsed only when debug is enabled).
- [x] 2.5 Tests: DeepSeek 80/80→R=80; GPT-5.6 write in `include_usage` chunk; Responses write; Cohere; OpenRouter shared parser + cost log; buffered + stream. Moonshot skipped (not on main).
- [ ] 2.6 V1 (adapter); V2; V3; V4 **OpenAI, openai_responses, Azure, DeepSeek, OpenRouter, Cohere**; matrix-only regression (shared Chat parser) xAI, Cerebras, Groq, Mistral; Moonshot unit-only; V5.

## Phase 3 (S1c): client encoders emit cache usage, 1h pricing

- [x] 3.1 `openai_completions_adapter.go`: `openaiUsageFromCanonical`, used at both encode sites (buffered, SSE).
- [x] 3.2 `openai_responses_adapter.go`, `cohere_adapter.go`: emit R/W in response and `response.completed`.
- [x] 3.3 `anthropic_adapter.go`: `cache_creation{ephemeral_5m, ephemeral_1h}` in `anthropicUsage`, `anthropicSSEUsage` (rebase vs #826).
- [x] 3.4 `adapter_test.go`: `decode(encode(u))==u` table for Chat, Responses, Cohere, Anthropic, Bedrock.
- [x] 3.5 `plugins/llmcost/pricing.go`: `ratesFor(..., cacheWrite1h, premium1h)`, `billsOneHourCacheWrite(provider)`; tests $0.006, non-Claude, discount $4.80/M, override wins.
- [x] 3.6 `plugins/tokenratelimit/budget_test.go`: Anthropic upstream R=1000 → OpenAI client, `CountCacheReads=false`, real registry.
- [x] 3.6b Same test with a **Bedrock** upstream (buffered + stream) → OpenAI/Responses/Cohere clients, `CountCacheReads=false` (S1a review: until S1c the client body lacks R, so budgets would charge cache reads; S1a must not reach main without S1c).
- [x] 3.6d `anthropic_adapter.go` decode: clamp `CacheWrite1hInputTokens` to `CacheWriteInputTokens` (route through `setCache`); unify the R+W>I unfold rule (`PlainInputTokens` → `max(0, I-R-W)`, Bedrock reuses it) (S1a round-2 review).
- [x] 3.6e Bedrock encoder: only emit `cacheDetails` when the canonical usage carries a TTL breakdown source; otherwise omit (S1a round-2 review, TTL unknown ≠ 5m).
- [x] 3.6c `pkg/app/proxy/provider_stream.go` `emitWithoutUsage`: buffer usage and emit a single merged Converse `metadata` event after `messageStop` (S1a review: Anthropic upstream → Bedrock client currently emits one metadata per usage chunk and the last one loses cache fields).
- [ ] 3.7 V1 (adapter, llmcost, tokenratelimit); V2; V3; V4 **Anthropic, OpenAI, openai_responses, Cohere, Bedrock** (1h pricing); V5.

## Phase 3b (S1d): Cohere v2 stream contract (added 2026-09-23, user request)

Evidence: scratchpad capture `gw_openai.sse` (openai upstream → Cohere client) vs real `direct.sse`. multi-agent-tests PR #16 fixes the separate langchain-cohere client bug.

- [x] 3b.1 `cohere_adapter.go` `EncodeStreamChunk`: `message-start` on Role; `tool-call-start` with `delta.message.tool_calls{id,type,function{name,arguments:""}}` on ID/Name; `tool-call-delta` with `delta.message.tool_calls.function.arguments`; `Index` without `omitempty`.
- [x] 3b.2 `cohereUsage`: add `billed_units`; emit it (billed = tokens) and cached_tokens (S1c).
- [x] 3b.3 `pkg/app/proxy/provider_stream.go`: stateful Cohere-client branch (like Gemini): emit `tool-call-end{index}` on index change / finish; merge finish reason with the trailing usage chunk into ONE `message-end` (keep TOOL_CALL); emit after upstream end.
- [ ] 3b.3b (moved to 3c.1) Same stateful path for **Responses** clients: a usage-only upstream chunk after the finish chunk (Bedrock `messageStop` then `metadata`; OpenAI `include_usage`) must still reach the client in `response.completed` (S1c finding: today `response.completed` is only emitted on the finish chunk, so the client gets no usage).
- [x] 3b.4 `DecodeStreamChunk`: read `delta.message.tool_calls` and handle `tool-call-start` (Cohere upstream → non-Cohere client keeps id/name/args).
- [x] 3b.5 Tests: encoder unit tests per event shape; `provider_stream_test.go` golden (openai tool-call stream → Cohere client sequence, incl. 2 parallel calls); decoder test fed real `direct.sse` events.
- [ ] 3b.6 V1; V2; V3; V4 **Cohere** (native + `matrix-ag -p cohere` with STREAM on/off, incl. `openai → cohere`, `openai_responses → cohere`, `cohere → openai_completions`) using the multi-agent server with PR #16; V5.

## Phase 3c (S1c-3): stream usage for Anthropic and Responses clients (S1c review, both judges)

- [x] 3c.1 `pkg/app/proxy/provider_stream.go`: generalize the Bedrock-client `deferUsage` path to Anthropic and Responses clients: on the finish chunk hold back the closing events, merge usage until upstream ends, then emit the finish with the merged usage (Anthropic: one `message_delta` + `message_stop`; Responses: `response.completed`).
- [x] 3c.2 Tests: Bedrock upstream → Anthropic client (R/W/W1h reach `message_delta`); OpenAI `include_usage` → Anthropic and → Responses clients; upstream error mid-stream (no trailing usage event); client disconnect (yield false) emits nothing more; OpenAI `include_usage` → Bedrock client emits exactly one `metadata` after `messageStop`.
- [ ] 3c.3 V1; V2; V3; V4 **Anthropic, openai_responses, Bedrock** (streams); V5.

## Phase 3d (S1e): Anthropic client stream encoder (added 2026-09-23, user request)

Found in the S1c-3 review; affects Claude Code behind any non-Anthropic upstream. Builds on the S1c-3 stateful stream path.

- [x] 3d.1 Block indices: text block and each tool_use block get distinct Anthropic indices (offset tool indices past an open text block; no collision between the role-opened text block 0 and upstream tool index 0).
- [x] 3d.2 Close every open block: one `content_block_stop` per open block, in order, before `message_delta` (parallel tool calls).
- [x] 3d.3 Thinking: canonical `ReasoningDelta` is deliberately NOT emitted to Anthropic clients (decision 2026-09-23). A `thinking` block needs a `signature`, and canonical cannot carry one yet, so an unsigned block would be rejected when the client replays it. Tracked under `thinking_signature` in state.yaml.
- [x] 3d.4 stop_reason: a finish that comes with tool calls maps to `tool_use` even when the upstream reason is a generic stop (Gemini `STOP` + functionCall).
- [x] 3d.5 Tests: text + tool, 2 parallel tools, thinking then text, Gemini STOP + functionCall, Bedrock/OpenAI/Responses upstreams; golden event sequences validated against the Anthropic streaming contract.
- [x] 3d.5a Mid-stream upstream errors (Anthropic clients): decoders mark an error object sent as a stream payload on `CanonicalStreamChunk.UpstreamError` (`adapter.UpstreamStreamError`); the proxy sends the content that came with it, then aborts the client stream with an `event: error` (or ends it normally when the finish was already held, with the merged usage) and yields `ClientNotifiedStreamError`, on which `writeStream` stops without appending its generic error frame.
- [x] 3d.5b Gemini tool results: pair each `functionResponse` with its call by function name (request id→name map; a generated `toolu_` id falls back to the only declared tool) and group a turn's results into one content.
- Out of scope: payload errors for non-Anthropic clients keep their previous behaviour (tracked in ENG-1626).
- [ ] 3d.6 V1; V2; V3; V4 **Anthropic client** (`matrix-ag` column anthropic, STREAM=1, against openai, openai_responses, google, bedrock, deepseek, openrouter, groq, xai, mistral, cerebras, cohere upstreams); V5.

## Phase 3e (S1b-2): Groq stream usage (found in S1c-3 round 3)

Reduced scope (investigation 2026-09-23, captures in the scratchpad `groq/`): stream usage is NOT lost. It arrives top-level on the finish chunk and in `x_groq.usage`; `include_usage` adds a trailing usage chunk; `cached_tokens` is parsed and `MergeUsage` takes the max.

- [x] 3e.1 Live-check a Groq stream through TrustGate (with the injected stream_options.include_usage): usage arrives as a standard usage chunk and in `x_groq.usage`. Captured. (Done in the 2026-09-23 investigation, before apply.)
- [x] 3e.2 Regression tests from the real captures (buffered + stream): usage and `cached_tokens` on the finish chunk, the trailing `include_usage` chunk, max-not-sum merge.
- [x] 3e.3 Optional: fall back to `x_groq.usage` when the standard usage fields are absent (max-not-sum with any standard usage chunk).
- [ ] 3e.4 V1–V5 with V4 **Groq** (native + matrix, STREAM on/off, prompt_caching -k groq on gpt-oss). V1 done (vet, golangci-lint adapter+proxy, `go test -race` proxy+providers green); V2–V5 pending.
- Follow-ups noted, not in this phase: `delta.reasoning` (analysis channel) dropped by `openaiStreamDelta`; trailing usage chunk re-encoded as `choices:[{index:0,delta:{}}]` instead of `[]`; Anthropic→Groq trims the system prompt's trailing whitespace (fixed in S2a).

## Phase 3f (S1f): Gemini thought signatures (found in the S1e review, confirmed 2026-09-23)

Gemini 2.5 (default thinking) and 3.x attach `thoughtSignature` to `functionCall` and text parts. Today the stream decoder drops signed `functionCall` parts (tool calls lost cross-format), buffered Gemini 3 duplicates the signed answer text as reasoning and content, and Gemini 3 returns 400 on the second tool turn when the signature is missing.

- [x] 3f.1 Gemini decode (stream, buffered and request): only parts with `thought: true` are reasoning; a `thoughtSignature` alone does not make a part reasoning, so signed `functionCall` and text parts keep their normal meaning.
- [x] 3f.2 Gemini encode: when a model turn has no signature to replay, put the sentinel `skip_thought_signature_validator` on the first `functionCall` part of that turn.
- [x] 3f.3 Buffered Gemini 3: stop duplicating signed answer text as reasoning plus content.
- [x] 3f.4 Tests: stream and buffered decode of signed `functionCall`/text parts (real captures), request decode, sentinel placement (one per model turn, first `functionCall` only, not when a signature exists), cross-format tool-call stream from Gemini 3 to OpenAI and Anthropic clients.
- [ ] 3f.5 V1; V2; V3; V4 **Gemini** (2.5-flash and 3.x, native + matrix with STREAM on/off, 2-turn tool loop); V5.
- [x] 3f.6 (found in V4) Gemini 3 streams parallel calls one per chunk, each at part index 0: `adaptStream` gives a Gemini upstream's tool calls stream-wide indexes so OpenAI Chat and Responses clients stop merging them into one call.
- Out of scope: carrying the real signature through canonical for a proper round-trip (ENG-1627).

## Phase 3g (S1g): Responses client stream contract (found in the S1f review, 2026-09-23)

Cross-format Responses clients got a partial event stream: no `response.created`, no content parts, no `*.done` events, an unscoped `function_call_arguments.done`, `output_index` 0 dropped by `omitempty`, and an empty `output` in `response.completed`. Clients that rebuild the response from the stream (openai-python `ResponseStreamState`, Codex) lost items. Same-format passthrough is unchanged.

- [x] 3g.1 `ResponsesStreamEncoder`: `response.created` and `response.in_progress` first (id, object, created_at, status, model); `sequence_number` on every event, counting up from 0; `output_index`/`content_index` always present.
- [x] 3g.2 Message item: added on the first non-empty text only (not on a role-only chunk), with `content_part.added`, then `output_text.delta` carrying `item_id`/`output_index`/`content_index`; at finish `output_text.done`, `content_part.done` and `output_item.done` with the full text.
- [x] 3g.3 Function call items: `output_item.added` (`id`, `call_id`, `name`, empty `arguments`, `in_progress`) once a delta carries a name or id, replaying the arguments held until then; scoped `function_call_arguments.delta`; at finish `function_call_arguments.done` and `output_item.done` with the full arguments. A different call id at the same canonical index starts a new item; a repeated call id gets a generated one. The old unscoped `function_call_arguments.done` is gone from this path.
- [x] 3g.4 Terminal event: `response.completed` with `output` built from the done items in `output_index` order and the merged usage (S1c-3 deferral kept); a `length` finish ends with `response.incomplete` (`incomplete_details.reason: max_output_tokens`), as the Responses API does. Error paths unchanged (ENG-1626).
- [x] 3g.5 Tests: contract checker (every item added then done, indexes and item ids consistent across events, sequence numbers, terminal output equals the done items) over golden sequences for text only, text and two tools, tools only (no empty message item), length stop, and Anthropic, Bedrock, Gemini (parallel, with and without ids) and Cohere upstreams; encoder unit tests for held arguments, same-index new calls, finish order. The produced streams were replayed through the openai-python 3.19 `ResponseStreamState` accumulator with strict pydantic validation of every item event and output item.
- [ ] 3g.6 V1; V2; V3; V4 **openai_responses client** (`matrix-ag` column openai_responses, STREAM=1, against openai, anthropic, google, bedrock, cohere upstreams); V5.
- Out of scope: custom tool calls stream as `function_call` items (no `custom_tool_call` events yet); reasoning deltas are not emitted.

## Phase 4 (S2a): canonical intent, normalize hook, Anthropic

- [x] 4.1 `adapter/cache_intent.go` (new): `CacheTTL`, `CanonicalCacheBreakpoint`, `CanonicalCacheOptions`, `cacheProfile`, `cacheProfileFor`, `normalizeCacheIntent` (4 steps). Rows: anthropic, bedrock; every other target drops all intent until its slice adds a row. `cacheProfileFor(target)` takes no model yet; S2b adds it with the GPT-5.6 predicate.
- [x] 4.2 `canonical.go`: `SystemCache`, `CacheOptions`, `CanonicalMessage.Cache`, `CanonicalTool.Cache` (separate hunks per conflict map).
- [x] 4.3 `registry.go`: call `normalizeCacheIntent` after `dropRequestExtensionsForCrossFormat`.
- [x] 4.4 `anthropic_adapter.go` decode: `anthropicCacheControl`, `tool_result`→tool message. Markers are read in the existing block loop (ENG-1608 is in the base), so there is no `attachAnthropicCache` second pass and no `bytes.Contains` fast path is needed. System text is no longer trimmed (byte-stable across client formats; fixes the Anthropic→Groq 1677/1678 prefix drift).
- [x] 4.5 Same file encode: system blocks, marker on the last emitted block (built in `anthropicMessageContent`, no raw-JSON `anthropicCached`), tool/tool_use/tool_result markers, top-level `Auto`.
- [x] 4.6 `cache_intent_test.go` + Anthropic suite: no markers; round-trip (stream on/off); image-then-text; six→4; TTL downgrade; Gemini/Groq/Cohere drop.
- [x] 4.7 N/A: ENG-1608 image content is already in the base.
- [ ] 4.8 V1 (adapter); V2; V3; V4 **Anthropic, Gemini** (drop path); V5.

## Phase 5 (S2b): OpenAI Chat and Responses intent

- [x] 5.1 `openai_completions_adapter.go` decode: parts/tool `cache_control`, `prompt_cache_{key,retention,options}`, top-level `cache_control`. Parts join through the shared `cacheTextJoin` (moved from the Anthropic adapter), so the newline-index boundary is kept; system/developer messages join byte-exact as before.
- [x] 5.2 Same file encode: faithful; marked content becomes text parts split at the boundary (`cachedTextParts`), system/tool-result parts, tool `cache_control`, top-level keys from `CacheOptions`.
- [x] 5.3 `openai_responses_adapter.go`: `prompt_cache_breakpoint` decode/encode on user, developer and `function_call_output` parts; system breakpoint → leading `developer` item (instructions cleared); string `input` shortcut skipped when a marker must be emitted; top-level keys.
- [x] 5.4 `cache_intent.go`: `isGPT56OrLater` (one-digit major, vendor prefix, suffixes); `cacheProfileFor(target, model)`. Responses GPT-5.6+: system+messages, max 4 (3 unless `mode=explicit`). openai/azure/Responses: key always, `prompt_cache_options` only on GPT-5.6+, `prompt_cache_retention` only before GPT-5.6 (OpenAI/Azure docs: 400 on options before 5.6, retention deprecated on 5.6). **xAI Chat: nothing** (xAI Chat caches by the `x-grok-conv-id` header, not a body key) — deviation from D3.
- [x] 5.5 Tests: Responses options and breakpoints round-trip; Anthropic→Responses gpt-5.6 vs gpt-4o (buffered + stream); OpenAI Chat→Anthropic markers, no key (buffered + stream); Responses→openai/azure/xai drops breakpoints; same-wire passthrough byte-identical; GPT-5.6 predicate table.
- [ ] 5.6 V1 (adapter); V2; V3; V4 **OpenAI, openai_responses, Azure, xAI**; V5.

## Phase 6 (S3): request passthrough and pass-through fixes

- [ ] 6.1 `format.go`/`registry.go`: `ShouldPassthroughRequest`; `AdaptRequest` uses it; responses keep `ShouldPassthroughSameWireFormat`.
- [ ] 6.2 `pkg/app/proxy/provider.go:326`: request predicate.
- [ ] 6.3 `cache_intent.go`: OpenRouter and Mistral rows.
- [ ] 6.4 `providers/azure/client.go`: on 400 naming `prompt_cache_retention`, retry once key-only (D5).
- [ ] 6.5 Tests: openai→groq/openrouter byte-equal request; routing keys; `groq_adapter_test.go:179-215`, `openrouter_adapter_test.go:192-245` green; Mistral key; Responses→Azure Chat key+retention and 400 fallback.
- [ ] 6.6 V1 (adapter, `pkg/app/proxy`, azure); V2; V3; V4 **Groq, OpenRouter (Claude + OpenAI upstreams), Mistral, Azure**; V5.

## Phase 7 (S4a): Bedrock cachePoint wire and SDK

- [ ] 7.1 `bedrock_adapter.go`: `ConverseCachePoint`; `CachePoint` on content/system/tool; system `Text` omitempty.
- [ ] 7.2 Same file: encode after tool, after system, last block of marked message; decode back to `Cache`.
- [ ] 7.3 `bedrock/converse.go`: SDK members (system, content first case, tool); `Ttl` only for 1h.
- [ ] 7.4 `converse.go` `foldSystemIntoFirstTurn`: prepend `[text, cachePoint]`, no merge.
- [ ] 7.5 Tests: positions, merge order, fold; rebase vs 1608 conflict map.
- [ ] 7.6 V1 (adapter, bedrock); V2; V3; V4 **Bedrock** (implicit, 5m, 1h); V5.

## Phase 8 (S4b): Bedrock capability table and retry

- [ ] 8.1 `bedrock/cache_capability.go` (new): `bedrockCacheFamilies`, `cacheCapabilityFor` (strip region prefixes, longest prefix; ARNs/unknown → none).
- [ ] 8.2 `converse.go`: `applyCacheCapability`, `stripCachePoints`, `converseWithCachePointFallback`; rename `systemFoldMemo`→`modelMemo`.
- [ ] 8.3 `bedrock/client.go:86,:251`: nested fallback with `cacheStrip` memo.
- [ ] 8.4 Tests: profile prefix, Mistral 7B, 1h on 3.7 cleared; retry on ValidationException only, not Throttling; memo only after success.
- [ ] 8.5 V1 (bedrock; `bedrock_live`); V2; V3; V4 **Bedrock** (all three variants); V5.

## Phase 9 (S5): plugins keep cache intent

- [ ] 9.1 `adapter/graft.go` (new) `GraftChangedFields`; `adapter/tools.go` (new) `FilterTools`; tests.
- [ ] 9.2 `plugins/{toolinjection,toolallowlist,pertoolratelimit}/plugin.go`: use shared helpers; toolinjection copies `Cache` on in-place replace.
- [ ] 9.3 `plugins/regexreplace/replace.go`, `bedrockguardrail/anonymize.go`, `googlemodelarmor/anonymize.go`, `trustguard/rewrite.go`: baseline+graft on change path (rebase vs #826).
- [ ] 9.4 Plugin tests: each plugin-cache-preservation scenario; no-op byte-identical.
- [ ] 9.5 `docs/prompt-caching.md` (new): prefix stability, lossy matrix.
- [ ] 9.6 V1 (adapter, `pkg/infra/plugins/...`); V2; V3; V4 **Anthropic, OpenAI, openai_responses** (plugin cases) plus Bedrock for bedrockguardrail; V5.
