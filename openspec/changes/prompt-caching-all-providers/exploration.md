# Exploration: prompt-caching-all-providers (ENG-1618)

Audited on `fix/eng-1618-prompt-caching-all-providers` @ `0b99b40d` (= `origin/develop`, re-fetched 2026-09-23).
Contract: Linear ENG-1618 (findings table, 6 scope blocks, out-of-scope, 5 open questions, QA checklist).
Starting point: `prior-explore-eng1580.md`. Every claim below was re-checked with file:line in this worktree.
Corrections to the ticket or prior exploration are marked **[correction]**.

## Current State

### 1. Usage data flow (buffered and streaming)

```
upstream body/SSE ──► target-format adapter Decode*  ──► *CanonicalUsage
                                                          │
  buffered: provider.go:200 decodeResponseMeta(raw, targetFormat)
            → ProviderResponse.Usage → forwarder.go:403 span.ObserveUsage
  streamed: provider_stream.go:183-205 observeChunk(payload, target) in BOTH
            passthrough and cross-format paths → provider.go:899-926 streamObserver:
              req.Metadata["usage"] = MergeUsage(prev, chunk.Usage)   (provider.go:916-917)
              requestTrace.ObserveLLMUsage → span.go:216 MergeUsage
                                                          │
  ┌──────────────────────────────┬────────────────────────┴───────────────────────┐
  metrics events (DataCore)       llmcost                     tokenratelimit
  builder.go:440-483              pricing.go:81-104 CostUSD   budget.go:115-158 counting
  → events.Usage (event.go:148)   (called from builder.go:476 budget.go:438-462 extractUsage
  → Kafka/OTLP/Postgres exporters  and budget.go:397)          streaming: req.Metadata["usage"]
    (telemetry/kafka, otlp/mapping.go:81-83)                  buffered: DecodeResponseFor(resp.Body,
                                                               req.SourceFormat)  ← CLIENT format
```

Key facts:
- Usage is always decoded from the **upstream** wire (target format), in both passthrough and cross-format paths (`provider.go:200`, `provider_stream.go:183-185, 204`). Good: vendor-field parsing belongs in the target adapter's Decode.
- `MergeUsage` (`canonical.go:166-189`) keeps the max of every field and re-synthesises `Total >= In+Out`. It is only correct if **each chunk is already folded** (cache ⊂ input). Anthropic does this (`anthropic_adapter.go:114-130`); Bedrock does not.
- **tokenratelimit buffered path decodes the *client-format* body** (`budget.go:438-462`, `responseFormat` = `req.SourceFormat`, `budget.go:465-474`). So for cross-format calls it depends on our **Encode*Response** usage output, not the upstream's. Most encoders drop cache fields (see §2), so cache discounts (`CountCacheReads=false`) and Bedrock folding are lost there. Response-rewriting plugins (regexreplace, anonymize, trustguard) also re-encode `resp.Body` and have the same effect on same-format flows. **[new finding]**
- Cost is computed **in the gateway** and shipped as `evt.Cost` next to the raw counts (`builder.go:445-482`). DataCore receives `prompt_tokens`, `cached_input_tokens`, `cache_write_input_tokens`, `cache_write_1h_input_tokens` (`event.go:148-156`). That makes an after-the-fact recompute possible for Bedrock (Q5).
- `fillSavings` (`builder.go:494-510`) prices the baseline as `InputTokens*Input` with no cache rates, so savings are overstated when caching is active. Minor; commit `060d3833` on a stale branch documents it as a "cold-cache baseline assumption".

### 2. Usage parsing per adapter (decode = in, encode = out to client)

| Adapter | Decode (upstream → canonical) | Encode (canonical → client) |
|---|---|---|
| OpenAI Chat `openai_completions_adapter.go` | `openaiUsageToCanonical` 158-170: only `prompt_tokens_details.cached_tokens` + reasoning. **No** `cache_write_tokens`, DeepSeek `prompt_cache_hit/miss_tokens`, top-level `cached_tokens` (Moonshot-style), OpenRouter `cost`/`cache_discount` | `encodeCompletionsResponse` 442-448 and stream 569-575 emit prompt/completion/total **only**. Cached, write and reasoning details are dropped |
| OpenAI Responses `openai_responses_adapter.go` | 86-114: `input_tokens_details.cached_tokens` only; no `cache_write_tokens` | 535-539 and stream 626-630: no details |
| Anthropic `anthropic_adapter.go` | 114-130: folds read+write into Input; 1h from `cache_creation.ephemeral_1h_input_tokens` ✅ | Response 583-589: no `cache_creation` breakdown. SSE `anthropicSSEUsage` 194-199: no `cache_creation`, no `service_tier` (TODO ENG-416 at 704) |
| Bedrock `bedrock_adapter.go` | `converseUsageToCanonical` 739-750: **no fold**, Input = Converse `inputTokens` | `converseUsageFromCanonical` 752-763 sends folded Input back (would need the inverse fold) |
| Bedrock SDK `bedrock/converse.go` | `wireUsage` 397-408: ignores `TokenUsage.CacheDetails` (SDK `types.go:3011`, sorted 1h before 5m) | n/a |
| Gemini `gemini_adapter.go` | 103-116: `cachedContentTokenCount` ⊂ `promptTokenCount` ✅ | 118-127 ✅ |
| Cohere `cohere_adapter.go` | 121-126: `usage.tokens` only; top-level `usage.cached_tokens` not parsed | 366-372, 473-477: no cache |
| Mistral / Groq / DeepSeek / OpenRouter | all delegate to the OpenAI parser (`mistral_adapter.go:61-71`, `registry.go:97-100`, `openrouter_adapter.go:47-51`) | same as OpenAI |

**Bedrock semantics, now confirmed by AWS docs (prompt-caching page, fetched 2026-09-23):** "`inputTokens` field represents only the non-cached input tokens … `total input tokens = inputTokens + cacheReadInputTokens + cacheWriteInputTokens`". **[correction]** The finding is confirmed by docs, not only suspected. The live test is still needed to pin `totalTokens` (the SDK doc just says "total of input tokens and tokens generated").

Effect of Bedrock today in `CostUSD` (`pricing.go:85-103`): with I = inputTokens, R = read, W = write:
- `I < R+W` (the normal cache-hit shape): `PlainInputTokens` returns I (`canonical.go:153-156`), the guard at `pricing.go:87-94` fires, and R and W are billed **$0**. This is under-billing, and it can hit current traffic because Claude on Bedrock caches implicitly.
- `I >= R+W`: plain = I−R−W. Under-billed by (R+W)×(Input−cache rate).
- tokenratelimit: `billableInputTokens`/`countedTokens` (`budget.go:115-158`) subtract R from an I that never contained it, so input budgets are undercounted or can go negative.
- Existing Bedrock tests pin the wrong assumption: `bedrock_adapter_test.go:382-403` (inputTokens 12 with cache 4+2, total 19 = 12+7) and `converse_test.go:178-193`.

### 3. Canonical model and every Decode/Encode (cache intent)

`canonical.go:25-48`: `System string`, `CanonicalMessage.Content string`, `CanonicalTool{Kind,Name,Description,Schema,Format}`. The only escape hatch is `RequestExtensions` (`canonical.go:39`), which only OpenRouter uses (`openrouter_adapter.go:36,45`), and `registry.go:320-326` wipes it whenever `source != target`.

Where content gets flattened or markers get dropped:

| Adapter | Request decode | Request encode |
|---|---|---|
| OpenAI Chat | `contentToString` (`openai_adapter.go:140-162`) joins text parts. System and developer messages are concatenated into one string (`openai_completions_adapter.go:257-277`). Unknown top-level keys (`prompt_cache_key`, `prompt_cache_retention`, `seed`, `n`, …) are not in `openaiRequest` (22-35) and are lost | `stringToContent` is always a plain string (325-341). Breakpoints cannot be emitted without a parts array |
| OpenAI Responses | `openaiResponsesRequest` (23-33) has no `prompt_cache_key`, `prompt_cache_retention`, `prompt_cache_options`, or `prompt_cache_breakpoint` | same |
| Anthropic | `anthropicRequest` (31-44) has no top-level `cache_control`. `anthropicContentBlock` (83-94) has no `cache_control`. `anthropicTool` (52-58) has none. System is joined to a string (`anthropicSystemText` 835-856). Non-text or non-tool blocks are dropped (`decodeAnthropicMessageContent` 261-311) | system is a plain string (858-867). Messages are strings except tool blocks (398-445) |
| Bedrock Converse | `ConverseSystemBlock{Text}` (56-58) and `ConverseContentBlock` (48-53) have no `CachePoint`. `ConverseTool{ToolSpec}` (109-111) has none. System is joined (291-303) | 381-398 |
| Bedrock SDK | `decodeConverseBody` (`converse.go:47-68`) maps text system only. `sdkContentBlock` 195-216 **silently drops** unknown blocks (default → nil). `sdkToolConfig` 285-309. `foldSystemIntoFirstTurn` 73-108 keeps only text, so a system cachePoint would be lost on the Mistral-7B fallback path | |
| Gemini | `geminiRequest` (25-31) has no `cachedContent`. Passthrough keeps it; cross-format drops it | |
| Mistral / OpenRouter / Cohere | wrap or mimic OpenAI; same losses | |

SDK readiness: `bedrockruntime v1.62.0` (`go.mod:108`) has `CachePointBlock{Type,Ttl}` (`types.go:220-231`), `CacheTTLFiveMinutes/OneHour` (`enums.go:92-93`), `ContentBlockMemberCachePoint` (460), `SystemContentBlockMemberCachePoint` (2931), `ToolMemberCachePoint` (3037) and `TokenUsage.CacheDetails` (3011). No SDK bump is needed ✅.

What a provider-neutral cache intent has to touch: `canonical.go`. Decode and Encode in `anthropic_adapter.go`, `openai_completions_adapter.go`, `openai_responses_adapter.go`, `bedrock_adapter.go`, `bedrock/converse.go`, `openrouter_adapter.go` and `mistral_adapter.go`. Explicit drops, with no-op documentation, in `gemini_adapter.go` and `cohere_adapter.go`. `registry.go` passthrough rules. Then every plugin that re-encodes (§5).

### 4. Registry passthrough rules (`registry.go:284-300`, `format.go:308-323`)

- `normalizeFormat` folds azure, groq, deepseek, xai and openrouter into openai, and vertex into gemini. **Mistral is not folded, so openai→mistral is always cross-format.** Moonshot, Cerebras and openai_compatible resolve to `FormatOpenAI` (`format.go:146-167`), so they pass through.
- `formatUsesExtensionAdapter` forces re-encoding for any pair involving Groq or OpenRouter. The rationale comes from the original design (`git show 591a86f1:openspec/changes/openrouter-llm-provider/design.md` l.16): "wire-similar ≠ byte-identical". It is about **responses** (`x_groq`, OpenRouter `provider` metadata, SSE `: OPENROUTER PROCESSING` comments). The request side needs nothing: the Groq request fixes already work on raw JSON (`NormalizeGroqRequest`, `normalize.go:162-199`, applied in `provider.go:339` for every body).
- **[new finding]** There is no inbound OpenRouter route (`proxy_path_resolver.go:89-120`: only openai, anthropic, responses, cohere and gemini). So `OpenRouterAdapter.DecodeRequest` (`openrouter_adapter.go:31-38`) never runs on the proxy path. The OpenAI adapter decodes and captures no extensions, and `registry.go:170` wipes them anyway. OpenRouter routing keys are **always** lost for every real client today. The unit test `openrouter_adapter_test.go:103` only covers openrouter→openrouter, which is unreachable.
- What breaks if requests pass through (openai→groq/openrouter): nothing functional on the request side. On the response side, passing responses through would leak `x_groq` and `provider` keys and SSE comments to OpenAI clients. These are harmless to OpenAI SDKs (unknown keys are ignored; SSE lines starting with `:` are comments by spec) but change the asserted behaviour. Tests that pin the current rules: `groq_adapter_test.go:104-106, 179-215` and `openrouter_adapter_test.go:94-96, 192-245`. Usage accounting is unaffected either way (observer decodes the upstream).
- Azure Responses: `resolveChatTargetFormat` (`format.go:265-283`) mirrors a Responses source only for OpenAI, not for Azure (279). Without `api=responses`, a Responses request to Azure is downgraded to Chat, and `prompt_cache_key`/`prompt_cache_retention` die in the decode.

### 5. Plugins that re-encode or change the prefix

| Plugin | Mechanism | Cache impact |
|---|---|---|
| regexreplace `replace.go:27-56` | full `EncodeRequest` of canonical | strips every marker and unmodelled field on the passthrough |
| bedrockguardrail `anonymize.go:34-47`, googlemodelarmor `anonymize.go:38-43` | full re-encode | same |
| trustguard `rewrite.go:73-89` (also changed by open PR #826) | full re-encode | same |
| toolinjection `plugin.go:95-139`, toolallowlist `plugin.go:257-280`, pertoolratelimit `plugin.go:309-329` | re-encode then `graftChangedFields` (top-level diff, triplicated at `toolinjection:170`, `toolallowlist:401`, `pertoolratelimit:336`) | only `tools` is replaced, but the whole array goes, so per-tool `cache_control` is lost and the tools→system→messages prefix changes |
| promptcompression `safety.go:24-110` | `roundTripSafe` veto: skips bodies with unmodelled keys (incl. `cache_control`) | safe, but compression silently disabled for cached traffic |
| prompttemplate `body.go:60-110,168-190` | raw JSON surgery | injects per-user variables into `system`, which breaks prefix stability. **Suspected bug:** an Anthropic `system` given as an array fails the string unmarshal (70-74), so a system template is **prepended as a `role:"system"` message** (106), which Anthropic rejects. Out of scope; flag |
| response-side rewrites (regexreplace/anonymize/trustguard `rewriteResponse`) | `EncodeResponse` | drop cache usage from the body that tokenratelimit reads |

### 6. Catalog cache pricing

- Source: models.dev (`pkg/infra/catalog/modelsdev/client.go:88-99,160-165`), per-million prices converted to per-token (`formatPerTokenPrice` 193-198). Empty means "bills at input" (`app/catalog/pricing.go:103-139` `coalescePrice`; `llmcost/pricing.go:56-61, 151-172`). Columns come from migrations `20260826120000` and `20260827120000`. Provider mapping is in `app/catalog/sync.go:111-126`. Bedrock keeps only global profiles (`skipModel` 142+). There are no seed prices except the Cohere seed models (80-106), which have no prices.
- Live models.dev coverage (queried 2026-09-23, models with cache_read / cache_write): amazon-bedrock 115/109 of 177 (e.g. `global.anthropic.claude-sonnet-4-6` in 3, read 0.3, write 3.75; Nova has read, write = input); deepseek 4/0 of 4 (read ≈ 2% of input); moonshotai 4/0; openrouter 226/67 of 382; openai 34/7; azure 54/20; anthropic 15/15; google 18/0; google-vertex 45/15; xai 8/0; groq 3/0; mistral 2/0; cerebras 0; cohere 0.
- **No 1h write rate exists anywhere.** `Resolve` sets `CacheWrite1h = CacheWrite` (`pricing.go:162`), so Anthropic and Bedrock 1h writes (2x input) are billed at the 5m rate (1.25x) unless a registry override sets `cache_write_1h` (`pricing.go:35-38`, `domain/registry/pricing.go`).
- Consequence: once the Bedrock fold lands, Bedrock and DeepSeek rows already have the rates needed to price correctly.

### 7. Tests and fixtures

- No `testdata/` directories. All fixtures are inline JSON strings, and none are recorded real responses.
- Adapter unit suites (lines): anthropic 614, bedrock 689, openai_completions 370, openai_responses 806 (+ sse), gemini 573, mistral 442, openrouter 309, groq 280, cohere 105, adapter_test 908. `bedrock/converse_test.go` 492.
- Cache assertions exist in: anthropic (38 hits), llmcost/pricing_test (17), trace_test (6), gemini (6), bedrock (4, wrong semantics), openai_completions (3), responses (3), otlp mapping (3), metrics builder (2), tokenratelimit (2).
- Live tests: only `pkg/infra/providers/bedrock/live_test.go` (`//go:build bedrock_live`, env `BEDROCK_LIVE_MODELS`). It has no cache case; add one (same long prefix twice, assert R>0 and the `inputTokens` semantics).
- E2E: `multi-agent-tests` has no caching tests (grep: only prompt compression). Per memory it targets prod, so develop fixes need a local or develop gateway.

### 8. In-flight overlap

| Branch / PR | Touches | Risk |
|---|---|---|
| **ENG-1608** worktree `TrustGate-eng1608` (5 commits ahead, unpushed PR) | `canonical.go` (+`CanonicalImage`, `CanonicalMessage.Images` **sidecar**), `anthropic_adapter.go` (+114: `anthropicContentBlock.Source`, `decodeAnthropicMessageContent`, new `anthropicUserContent`), `openai_adapter.go`/`openai_completions_adapter.go` (`decodeOpenAIContent`, `openaiContentPart`, `encodeOpenAIContent`), `bedrock_adapter.go` (+`ConverseContentBlock.Image`), `converse.go` `sdkContentBlock`, `provider.go:329-333` (`ErrUnsupportedContent`) | **High textual overlap** with blocks 2 and 4: the same structs and functions. Semantically compatible if cache intent is also a sidecar. Land ENG-1608 first and rebase. Its encoders emit images first, then text, so a breakpoint must attach to the **last emitted block** |
| PR #826 `feat/streaming-guardrail-enforcement` | `canonical.go` (`CanonicalStreamChunk.ContentBlockIndex/Closed/OpenItem`), anthropic/responses/gemini/cohere **stream encoders**, trustguard | Medium: same Anthropic SSE encoder (`EncodeStreamChunk`) where the `cache_creation` usage breakdown goes; trustguard rewrite (block 5). No usage changes |
| PR #611 `sergividal/tier3-all-providers` | `format.go` (+14 OpenAI-wire providers) | Low conflict. Scope creep: Fireworks, Together, DashScope/Qwen (`cache_control`), ZAI, MiniMax and others get the shared OpenAI parser, so whatever block 1 adds must be shape-tolerant |
| `origin/fix/normalise-cache-token-accounting` | canonical/usage | **Already squash-merged** as `f1a46e1f` (#560). Stale; ignore |
| `origin/fix/stream-cut-terminators`, `refactor/run-1184…`, `mintcloud/…` | canonical.go | subsumed by #826 or merge commits; no cache relevance |

## Affected Areas

- `pkg/infra/providers/adapter/canonical.go:25-72,128-158,166-215`: cache-intent types; usage contract doc; `MergeUsage`.
- `pkg/infra/providers/adapter/bedrock_adapter.go:48-58,109-111,154-160,739-763`: CachePoint wire; fold; inverse fold.
- `pkg/infra/providers/bedrock/converse.go:47-68,73-108,195-216,285-309,397-408`: SDK CachePoint; CacheDetails → 1h; system-fold keeps cachePoint.
- `pkg/infra/providers/adapter/openai_completions_adapter.go:22-35,142-170,302-370,422-448,569-575`: vendor usage fields; usage encode; `prompt_cache_key`/retention; breakpoint parts.
- `pkg/infra/providers/adapter/openai_responses_adapter.go:23-33,86-114,535-539,626-630`: same for Responses.
- `pkg/infra/providers/adapter/anthropic_adapter.go:31-58,83-130,194-199,317-478,583-589,835-867`: `cache_control` decode/encode; usage breakdown out.
- `pkg/infra/providers/adapter/cohere_adapter.go:88-126`: `cached_tokens`.
- `pkg/infra/providers/adapter/openrouter_adapter.go`, `mistral_adapter.go`, `registry.go:149-178,284-326`, `format.go:265-283,308-323`: passthrough fixes.
- `pkg/infra/plugins/llmcost/pricing.go:63-76,151-172`: 1h rate derivation (optional).
- `pkg/infra/plugins/tokenratelimit/budget.go:115-158,438-471`: behaviour change after fold; source-format decode caveat.
- `pkg/app/metrics/builder.go:440-510`: consumers only (no change needed beyond tests; optional savings fix).
- Plugins: `regexreplace/replace.go`, `bedrockguardrail/anonymize.go`, `googlemodelarmor/anonymize.go`, `trustguard/rewrite.go`, `toolinjection|toolallowlist|pertoolratelimit/plugin.go` (graft), `promptcompression/safety.go`.
- Tests: all adapter suites listed in §7, `bedrock/live_test.go`, `llmcost/pricing_test.go`, `tokenratelimit/*_test.go`, `metrics/builder_test.go`, `trace/trace_test.go`.

## Approaches: canonical cache intent (scope block 2)

1. **A: Sidecar markers (recommended).** Add `Cache *CanonicalCacheBreakpoint{TTL}` to `CanonicalMessage` and `CanonicalTool`, `SystemCache *CanonicalCacheBreakpoint` to `CanonicalRequest`, and `CacheOptions *CanonicalCacheOptions{Key, Retention, Mode, Auto *CanonicalCacheBreakpoint}` for request-level intent (Anthropic top-level `cache_control`, OpenAI `prompt_cache_key`/`prompt_cache_retention`/`prompt_cache_options`, Mistral key, OpenRouter top-level). The semantics are "cache boundary at the end of this segment". Anthropic and OpenRouter emit it on the last block, Converse appends a `cachePoint` block, and GPT-5.6 Responses puts `prompt_cache_breakpoint` on the last input part.
   - Pros: same pattern ENG-1608 chose (`Images` sidecar), so the rebase is easy. `Content string` stays, so none of the ~12 content-reading plugins change. Faithful for the common shapes (Claude Code or SDK breakpoints on the last system block, last tool, last user block).
   - Cons: block granularity is lost cross-format. A breakpoint on a non-last block moves to the segment end, and several system breakpoints collapse into one at the end of `System`. Both are legal degradations (they still cache a valid prefix and stay ≤ 4). Same-format passthrough is untouched; only same-format *re-encoding* plugins would shift them.
   - Effort: Medium.
2. **B: Content-block canonical model.** Replace `Content string`/`System string` with ordered `[]CanonicalPart{Type, Text, Image, Cache}` (keeping `Content` as a derived view).
   - Pros: lossless; also fixes image ordering, tool_result arrays and multi-block systems.
   - Cons: touches every adapter, every plugin that reads or writes `.Content`/`.System` (regexreplace, anonymize ×2, trustguard, openai moderation, azure content safety, semantic cache, promptcompression, metrics builder), and collides head-on with ENG-1608 and #826. Well over 400 lines on its own.
   - Effort: High.
3. **C: Raw-JSON preservation instead of canonical intent.** Keep canonical as is. For same-wire-family hops, pass the body through or graft unmodelled keys back from the original. For re-encoding plugins, patch text in place in the raw JSON.
   - Pros: fixes passthrough and plugin loss for *every* unmodelled field, not only cache.
   - Cons: does nothing for true cross-format (anthropic→bedrock, openai→anthropic), which is exactly ISDIN's case and scope block 4.
   - Effort: Medium.

Complementary (not alternatives): block 3 is best solved C-style (request passthrough), block 2/4 A-style.

## Recommendation

Deliver as chained PRs, usage correctness first (the ticket's ordering constraint):

1. **S1a Bedrock usage:** fold R+W into `InputTokens`, set `Total = max(total, in+out)`, map `CacheDetails` (TTL "1h") → `CacheWrite1hInputTokens`, inverse fold in `converseUsageFromCanonical`, and fix the existing Bedrock fixtures. Add a `bedrock_live` cache test.
2. **S1b OpenAI-family usage:** parse `prompt_tokens_details.cache_write_tokens`, `input_tokens_details.cache_write_tokens` (Responses), DeepSeek `prompt_cache_hit_tokens` (cached = max(details.cached, hit), never a sum), top-level `usage.cached_tokens` (Moonshot and Cohere shapes), and keep OpenRouter `cost`/`cache_discount` as `ProviderExtensions` or log-only (do not trust them for billing). Emit cached/write details in **all** Chat, Responses and Cohere encoders, and emit `cache_creation` in the Anthropic response and SSE encoders. This also repairs tokenratelimit's source-format decode.
3. **S2 canonical cache intent (Approach A)** plus Anthropic and OpenAI (Chat/Responses) decode and encode, and a cross-format drop matrix with tests.
4. **S3 passthrough:** split `ShouldPassthroughSameWireFormat` into a request predicate (pass through openai→groq/openrouter/azure bodies; keep response adaptation), map `CacheOptions.Key` for Mistral (keep `MistralAdapter` for tool-ID rewriting, or move it to raw JSON like `NormalizeGroqRequest`), and let Azure Responses carry the key via `CacheOptions`.
5. **S4 Bedrock cachePoint** from canonical breakpoints: ≤4 in tools→system→messages order, 1h-before-5m ordering, a model-family allowlist, and a retry-without-cachePoint memo that mirrors `converseWithSystemFallback` (`converse.go:141-156`). Keep the cachePoint in `foldSystemIntoFirstTurn`.
6. **S5 plugins:** carry the `Cache` sidecar through the canonical round-trip automatically (A makes this free for full re-encoders once decode and encode are faithful). For graft plugins, graft per-tool rather than the whole array, or re-attach the tool `Cache`. Document prefix-breaking plugins (prompttemplate, tool injection).
7. **S6 gateway-inserted breakpoints:** follow-up ticket (see Q4).

## Recommended resolutions for the open questions

1. **Representation and precedence:** Approach A (sidecar segment-end breakpoints plus `CacheOptions`). Client markers always win. A gateway option (S6) only inserts when the request carries **no** client breakpoint, and never pushes the total past the target's max (4). When a client sends more than 4 cross-format, keep the **last** breakpoint of each section in tools→system→messages order and drop the earliest message breakpoints first (the last one covers the longest prefix, and Bedrock's simplified mode looks back ~20 blocks). Enforce 1h-before-5m by downgrading any later 1h to 5m.
2. **Per-model capability:** in code (`pkg/infra/providers/bedrock`), as a family-prefix table (`anthropic.claude-*` with a 1h list per the AWS table; `amazon.nova-*` explicit only where the model card says so). Not the catalog: models.dev publishes no support, minimum or TTL fields, and a catalog column means a migration plus a config-snapshot proto change. Do **not** enforce minimum tokens: AWS says a checkpoint below the minimum "still succeeds, but your prefix isn't cached". Pair the table with the ValidationException retry memo so unknown or ARN model IDs degrade safely.
3. **Converse-native inbound route:** no, not in this issue. Nothing asks for it (ISDIN uses OpenAI/Anthropic SDKs), and it would add a sixth source format to every matrix. Open a follow-up only if a customer needs byte-exact Converse.
4. **Gateway-inserted breakpoints:** follow-up ticket; default **off**; opt-in per registry via `provider_options` (e.g. `prompt_cache: {auto: true, ttl: "5m"}`); **1h is opt-in** because it costs 2x input on write. Justification: Claude on Bedrock already caches implicitly, and the correctness work (S1–S5) is already several PRs.
5. **Historical cost:** no backfill in TrustGate (it owns no history). Annotate: release note plus a DataCore follow-up. Bedrock rows are **recomputable** from stored raw counts, because the events carry `prompt_tokens`(=I), `cached_input_tokens`, `cache_write_input_tokens`, and cost = (I)·in + R·read + W·write for rows where R+W>0 and `prompt_tokens < R+W`. DeepSeek hits were never recorded, so they are unrecoverable: annotate only.

## Risks

- **Behaviour change after S1a:** Bedrock `prompt_tokens`, cost and tokenratelimit input counts rise for cached traffic. Dashboards and budgets will jump, so ship a release note and give ISDIN a heads-up.
- `totalTokens` semantics for Converse are unconfirmed (the docs formula covers input only). Synthesise `max(total, in+out)` and pin it with `bedrock_live`.
- Moonshot `cached_tokens` shape (top-level vs `prompt_tokens_details`) is unconfirmed. Parse both, take the max, and never sum. The same no-double-count rule applies to DeepSeek (it may send both hit_tokens and details.cached_tokens).
- tokenratelimit buffered usage comes from the **client-format** body, so any encoder or response plugin that drops cache fields reintroduces mis-counting. Cover it with a cross-format test (anthropic backend → openai client).
- 1h writes are underpriced (catalog has one write rate). Decide whether llmcost derives `CacheWrite1h = 2×Input` for Anthropic-family models when no override exists.
- Unknown Bedrock models may reject `cachePoint`. Mitigate with the allowlist plus the retry memo.
- Merge conflicts with ENG-1608 (same structs and functions) and #826 (Anthropic SSE encoder, trustguard). Sequence ENG-1608 → S2/S4.
- Relaxing the Groq/OpenRouter passthrough rewrites 10+ pinned tests and leaks `x_groq`/`provider`/SSE comments if the change goes beyond requests. Keep it request-only.
- PR #611 adds 14 OpenAI-wire providers that inherit whatever the shared parser does.
- Suspected prompttemplate bug with Anthropic array `system`: out of scope, flag separately.
- E2E needs a develop or local gateway (`multi-agent-tests` points at prod) and real keys for about 12 providers.

## Ready for Proposal

Yes. Resolve Q1–Q5 as recommended (or override). Confirm the S6 split into a follow-up and the slicing (S1a → S1b → S2 → S3 → S4 → S5) under the 400-line budget, with ENG-1608 landing before S2 and S4.
