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
| Chain strategy | feature-branch (user decision 2026-09-23): integration branch `fix/eng-1618-prompt-caching-all-providers`; each slice is a PR into it; one final PR integration → `develop`. ENG-1608 stays a separate branch with its own path. |

Decision needed before apply: No (approved 2026-09-23)
Chained PRs recommended: Yes
Chain strategy: feature-branch
400-line budget risk: High

Measure each slice with `git diff --shortstat <parent> -- pkg tests docs` (parent = `origin/develop` for S1a, the previous slice branch otherwise); openspec/ is excluded. Over 400 → split along task lines before the PR.

### Dependencies

- **ENG-1608** (unpushed, `TrustGate-eng1608`, 5 commits) touches `canonical.go`, `anthropic_adapter.go`, `openai_completions_adapter.go`, `bedrock_adapter.go`, `converse.go`, `app/proxy/provider.go`. S1a–S1c are independent. S2a, S2b, S4a are written base-agnostic and rebase onto 1608 with the conflict map in design.md ("ENG-1608 composition"): keep both sides, gofmt, `go test ./pkg/infra/providers/... ./pkg/app/proxy/...`, then `git rebase --update-refs` for the rest of the stack.
- **PR #826** overlaps the Anthropic SSE usage struct (S1c) and trustguard (S5). Merge order decided before S1c and S5 open.

### Suggested Work Units

| Unit | Goal | PR | Base |
|------|------|----|------|
| E | e2e `prompt_caching` suite | multi-agent-tests PR | `main` of multi-agent-tests |
| S1a | Bedrock usage correct | PR 1 | develop |
| S1b | OpenAI-family/Cohere usage decode | PR 2 | S1a |
| S1c | Client encoders + 1h pricing | PR 3 | S1b |
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
- **V4** per listed provider X, against LOCAL TrustGate from the worktree (`make run-all` + `run-proxy-sandbox`; never prod; `E2E_ADMIN_URL`/`AG_ADMIN_URL` = localhost): `make matrix-ag UPSTREAM=X AGENT=X`, same with `STREAM=1`, `make matrix-ag PROVIDER=X`, same with `STREAM=1`, `uv run pytest -m prompt_caching -k X`. Missing/expired key → STOP and report. Bedrock: `aws sts get-caller-identity` first. Moonshot and openai_compatible unit-only; Vertex covered by Gemini.
- **V5** commit as one work unit (Conventional Commit, attribution lines).

## Phase E: multi-agent-tests prompt_caching suite (`/Users/edu/Neuraltrust/multi-agent-tests-eng1618`)

- [ ] E.1 `pyproject.toml`: add marker `prompt_caching: cached-prefix accounting across providers`.
- [ ] E.2 `src/e2e/tests/test_prompt_caching.py`: session fixture checks `upstreams.unavailable(X)` for selected upstreams; any missing → `pytest.exit(reason, returncode=2)` naming the vars (never skip). Bedrock also runs `sts get-caller-identity`.
- [ ] E.3 Same file: ~5k-token static prefix builder; HS256 `X-AG-Playground-Token` (purpose `playground`, consumer slug, local `SERVER_SECRET_KEY`).
- [ ] E.4 Parametrize (upstream, client format ∈ {native, openai, anthropic}, stream); Bedrock variants implicit / explicit 5m / explicit 1h; plugin cases Anthropic+OpenAI with regexreplace and toolallowlist.
- [ ] E.5 Assertions: second call R>0 in provider body; `GET {E2E_ADMIN_URL}/v1/playground/traces/{X-AG-Trace-Id}` with admin Bearer `E2E_ADMIN_TOKEN`; trace I/R/W/W1h == provider usage; cost per D10. Groq cache assertion only for gpt-oss.
- [ ] E.6 `README.md` + `.env.example`: local-gateway notes (localhost admin/proxy, sandbox domain, never prod, `-k` per slice since later slices' cases fail until landed).
- [ ] E.7 `src/agentgateway/catalog.py` only if needed: cache-capable default models (Claude Haiku 4.5 on Bedrock, GPT-5.6 for Responses breakpoints, Groq gpt-oss).
- [ ] E.8 V: `make lint`, `uv run pytest -m prompt_caching --collect-only`; V2–V3; V4 = `-k bedrock` against S1a local build; V5.

## Phase 1 (S1a): Bedrock usage fold

- [ ] 1.1 `providers/adapter/canonical.go`: `(*CanonicalUsage).setCache(read, write, write1h)`.
- [ ] 1.2 `providers/adapter/bedrock_adapter.go`: `ConverseUsage.CacheDetails []ConverseCacheDetail`; `converseUsageToCanonical` folds I=in+R+W, W1h from `ttl=="1h"`, Total=max(total, I+O).
- [ ] 1.3 Same file: encoder writes `inputTokens=PlainInputTokens()` and rebuilds `cacheDetails`.
- [ ] 1.4 `providers/bedrock/converse.go`: `wireUsage` copies `TokenUsage.CacheDetails`.
- [ ] 1.5 Tests: rewrite `bedrock_adapter_test.go:382-403`, `converse_test.go:178-193`; add 12+4+2→18/25 and 1h split, buffered + stream.
- [ ] 1.6 `providers/bedrock/live_test.go`: same prefix twice, R>0, raw `inputTokens` excludes R+W, Total≥I+O.
- [ ] 1.7 V1 (adapter, bedrock; `go test -tags bedrock_live`); V2; V3; V4 **Bedrock**; V5.

## Phase 2 (S1b): OpenAI-family and Cohere usage decode

- [ ] 2.1 `openai_completions_adapter.go`: `openaiUsage.{CachedTokens,PromptCacheHitTokens,PromptCacheMissTokens}`, details `CacheWriteTokens`; R=max(3 sources), W from details.
- [ ] 2.2 `openai_responses_adapter.go`: `input_tokens_details.cache_write_tokens` → W.
- [ ] 2.3 `cohere_adapter.go`: `usage.cached_tokens` → R.
- [ ] 2.4 `openrouter_adapter.go`: `cost`/`cache_discount` → `slog.Debug` only.
- [ ] 2.5 Tests: DeepSeek 80/80→R=80; Moonshot both shapes; GPT-5.6 write in `include_usage` chunk; Cohere; buffered + stream.
- [ ] 2.6 V1 (adapter); V2; V3; V4 **OpenAI, openai_responses, Azure, DeepSeek, OpenRouter, Cohere**; matrix-only regression (shared Chat parser) xAI, Cerebras, Groq, Mistral; Moonshot unit-only; V5.

## Phase 3 (S1c): client encoders emit cache usage, 1h pricing

- [ ] 3.1 `openai_completions_adapter.go`: `openaiUsageFromCanonical`, used at both encode sites (buffered, SSE).
- [ ] 3.2 `openai_responses_adapter.go`, `cohere_adapter.go`: emit R/W in response and `response.completed`.
- [ ] 3.3 `anthropic_adapter.go`: `cache_creation{ephemeral_5m, ephemeral_1h}` in `anthropicUsage`, `anthropicSSEUsage` (rebase vs #826).
- [ ] 3.4 `adapter_test.go`: `decode(encode(u))==u` table for Chat, Responses, Cohere, Anthropic, Bedrock.
- [ ] 3.5 `plugins/llmcost/pricing.go`: `ratesFor(..., cw1h, claude)`, `isClaudeModel`; tests $0.006, non-Claude, discount $4.80/M, override wins.
- [ ] 3.6 `plugins/tokenratelimit/budget_test.go`: Anthropic upstream R=1000 → OpenAI client, `CountCacheReads=false`, real registry.
- [ ] 3.7 V1 (adapter, llmcost, tokenratelimit); V2; V3; V4 **Anthropic, OpenAI, openai_responses, Cohere, Bedrock** (1h pricing); V5.

## Phase 4 (S2a): canonical intent, normalize hook, Anthropic

- [ ] 4.1 `adapter/cache_intent.go` (new): `CacheTTL`, `CanonicalCacheBreakpoint`, `CanonicalCacheOptions`, `cacheProfile`, `cacheProfileFor`, `normalizeCacheIntent` (4 steps).
- [ ] 4.2 `canonical.go`: `SystemCache`, `CacheOptions`, `CanonicalMessage.Cache`, `CanonicalTool.Cache` (separate hunks per conflict map).
- [ ] 4.3 `registry.go`: call `normalizeCacheIntent` after `dropRequestExtensionsForCrossFormat`.
- [ ] 4.4 `anthropic_adapter.go` decode: `anthropicCacheControl`, `attachAnthropicCache`, `tool_result`→tool message, `bytes.Contains` fast path.
- [ ] 4.5 Same file encode: system blocks, `anthropicCached`, tool/tool_use/tool_result markers, top-level `Auto`.
- [ ] 4.6 `cache_intent_test.go` + Anthropic suite: no markers; round-trip (stream on/off); image-then-text; six→4; TTL downgrade; Gemini/Groq/Cohere drop.
- [ ] 4.7 Rebase onto ENG-1608 if merged; else keep base-agnostic.
- [ ] 4.8 V1 (adapter); V2; V3; V4 **Anthropic, Gemini** (drop path); V5.

## Phase 5 (S2b): OpenAI Chat and Responses intent

- [ ] 5.1 `openai_completions_adapter.go` decode: parts/tool `cache_control`, `prompt_cache_{key,retention,options}`, top-level `cache_control`.
- [ ] 5.2 Same file encode: `openAICachedContent`, system/tool-result parts, top-level keys from `CacheOptions`.
- [ ] 5.3 `openai_responses_adapter.go`: `prompt_cache_breakpoint` decode/encode; system → leading `developer` item; skip string `input` shortcut.
- [ ] 5.4 `cache_intent.go`: GPT-5.6+ predicate; Responses and openai/azure/xai rows (D3, D4).
- [ ] 5.5 Tests: Responses options round-trip; Anthropic→Responses gpt-5.6 vs gpt-4o; OpenAI→Anthropic marker, no key; Chat target drops breakpoints.
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
