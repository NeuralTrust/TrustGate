# Design: Prompt caching and cache usage accounting across all providers (ENG-1618)

Inputs: `proposal.md`, `exploration.md`, `specs/*/spec.md`, Linear ENG-1618, ENG-1608 branch (`TrustGate-eng1608`, 5 commits, unpushed).
Base audited: `origin/develop` @ `0b99b40d`. **Rebased to `origin/main` @ `925edeb7` (2026-09-23, user decision): files touched by S1a/S1c/S4/S5 are identical on main; re-verify registry.go, format.go, canonical.go and openai_responses_adapter.go against main before S2a/S2b/S3. Moonshot does not exist on main (out of scope).** Conventions: `.agents/AGENTS.md`, `golang.mdc`, `go-comments.mdc` (doc comments on exported identifiers only, no narrative comments).

> The page is longer than the usual 800-word design budget because the orchestrator asked for the full contract (types, per-adapter mapping, slice map). Tables stand in for prose wherever possible.

## Technical Approach

The work splits into three independent mechanisms. All of them live in `pkg/infra/providers/adapter` and `pkg/infra/providers/bedrock`, with thin hooks elsewhere.

1. **Usage.** Each target adapter's decode produces a folded `CanonicalUsage`. Each client-format encoder writes it back out losslessly, so `decode(encode(u)) == u`. `llmcost` derives the 1h write rate.
2. **Intent.** Side fields on the canonical model (Approach A, the same pattern as ENG-1608 `Images`). Encoders are *faithful*: they emit whatever intent the canonical request carries. *Policy* (which target accepts what, the max of 4, TTL order) is one shared function, `normalizeCacheIntent`. Only `Registry.AdaptRequest` calls it, on the cross-format path. Same-format plugin re-encodes therefore round-trip unchanged.
3. **Fidelity.**
   - Same-wire requests (OpenAI Chat to Groq or OpenRouter) pass through. Only responses stay re-encoded.
   - Plugins graft only the top-level keys they changed onto the original body.
   - Bedrock gates on the model inside the SDK client, where the final model id is known.

## Architecture Decisions

| # | Decision | Alternatives | Rationale |
|---|---|---|---|
| D1 | Side-field intent (`Cache` on message/tool, `SystemCache`, `CacheOptions`) | B: content-block canonical model; C: raw-JSON preservation only | B rewrites every adapter and plugin and collides with ENG-1608 and #826. C cannot do true cross-format (anthropic→bedrock is the ISDIN case). A leaves the `Content string` readers untouched. |
| D2 | Encoders are faithful; target policy lives in one `normalizeCacheIntent(req, target)` | Per-adapter dialect flags (`OpenAIAdapter{cache: …}`) | Plugins re-encode in the **client** format (`req.SourceFormat`). Dialect flags would strip OpenRouter-style parts `cache_control` from an OpenAI client body headed to OpenRouter. One function gives one place for precedence, the max of 4 and TTL order. |
| D3 | OpenAI Chat targets get request-level keys only, gated on the provider that serves the target: provider `openai` gets `prompt_cache_key`, plus `prompt_cache_options` on GPT-5.6+ or `prompt_cache_retention` before it; provider `azure` gets `prompt_cache_key`, plus `prompt_cache_retention` unless the model name reads GPT-5.6+; xAI Chat, Cerebras, openai_compatible and any other provider get nothing. Per-block breakpoints are dropped | Emit parts `cache_control`; gate on the wire format | OpenAI rejects unknown part keys, and parts-level `cache_control` goes to OpenRouter only. Cerebras and openai_compatible share `FormatOpenAI`, so the format alone would send them OpenAI's keys; `AdaptRequestForProvider` passes the target provider into `cacheProfileFor`. xAI Chat caches by the `x-grok-conv-id` header, not a body key. An Azure model is usually a deployment name, so the GPT-5.6 gate cannot pick between options and retention; Azure sends retention and its client retries once key-only on a 400 naming `prompt_cache_retention` when the gateway mapped it (cross-format), and remembers the deployment for an hour so it stops sending it; a client that sent retention itself on a passthrough gets Azure's 400 (S3, D5). |
| D4 | Responses breakpoint = `prompt_cache_breakpoint:{"mode":"explicit"}` on the last input part, only when the model is GPT-5.6+ (`gpt-5.6`, `gpt-5.N` N≥6, `gpt-6+`). A system breakpoint moves system from `instructions` to a leading `developer` message | Always emit; never emit | This is the only documented placement (OpenAI and AWS docs), and older models may reject it. `instructions` is a string and cannot carry a marker. |
| D5 | Azure keeps today's API selection. Responses→Azure Chat maps `CacheOptions` into Chat `prompt_cache_key`/`prompt_cache_retention` | Force Responses for Azure | Coordinator decision. The Azure client only builds `chat/completions` (`azure/client.go:379`). **The passthrough spec's "Azure Responses stays Responses" must be amended.** |
| D6 | *(amended in S3 after review)* Groq and OpenRouter requests are re-encoded through canonical, as before S3. For an OpenAI Chat client, OpenRouter additionally gets an allowlist grafted from the client body: `provider` (an object, with any `model`/`models` key inside it dropped), `session_id` and `user` (strings). Cache intent reaches OpenRouter through the profile rows (parts `cache_control` for the families below, top-level auto for `anthropic/*`), capped at 4 and TTL-ordered by `normalizeCacheIntent`. Groq caches automatically and gets no cache fields. Responses stay re-encoded | Pass the request through (`ShouldPassthroughRequest`, the first S3 cut); graft every unmodelled key | Passthrough broke requests: live Groq answers 400 to `n:2`, `service_tier:"default"`, `modalities`, `metadata` on gpt-oss, and very likely `logprobs`/`top_logprobs`/`logit_bias`/`messages[].name`/`reasoning_effort` on non-reasoning models; `developer` role and array system/assistant content stopped being normalised; `stream_options` extras went upstream. On OpenRouter a client `models` fallback list bypasses `EnforceModel`/`AllowedModels`, `route` changes routing, and `plugins` (web search) bills the tenant key. OpenRouter's `provider` object only filters and orders providers for the chosen model (docs 2026-09), so it is safe. Seed, `parallel_tool_calls` and `response_format.json_schema` are now modelled in canonical so the re-encode no longer loses them. Grafting is rejected for Mistral because Mistral answers 422 `extra_forbidden` on unknown fields. Mistral gets only the mapped key. |
| D7 | Bedrock capability table and ValidationException retry live in `pkg/infra/providers/bedrock` (SDK layer) | Gate in the adapter encoder | `EnforceModel` can replace the model **after** adaptation (`provider.go:340`). Only `client.requireModel` knows the id that is actually sent. |
| D8 | Capability table in code, keyed by family prefix after stripping `us.\|eu.\|apac.\|jp.\|au.\|ca.\|global.` | Catalog column | models.dev publishes no support or TTL fields, and a catalog column needs a migration plus a proto change. Unknown ids and ARNs get no `cachePoint`. |
| D9 | Double-reported counts use `max`, never the sum (DeepSeek hit vs `details.cached`; Moonshot top-level vs details) | Sum | Vendors mirror the same number. Summing double-bills the discount. |
| D10 | 1h rate: override `cache_write_1h` → else `2×Input` for Claude (provider `anthropic`/`bedrock`, slug contains `claude`) → else `CacheWrite`. The registry discount applies only to catalog-derived rates, as today | Always `CacheWrite` | Anthropic and AWS docs give 2× for 1h. Keeps today's override semantics. |
| D11 | Gateway-inserted breakpoints: follow-up ticket, off by default, 1h opt-in | In this issue | Out of scope per the proposal. Client markers always win. |

## Interfaces / Contracts

### Usage (`canonical.go`, S1)

The contract doc on `CanonicalUsage` is unchanged: I ⊇ R+W, W1h ⊆ W. Add one factory helper that every adapter uses to set the cache buckets:

```go
func (u *CanonicalUsage) setCache(read, write, write1h int) {
	u.CachedInputTokens, u.CacheWriteInputTokens = read, write
	u.CacheWrite1hInputTokens = min(write1h, write)
	u.TotalTokens = max(u.TotalTokens, u.InputTokens+u.OutputTokens)
}
```

`setCache` does NOT raise I to R+W: an upstream that reports R+W > I stays inconsistent so the `llmcost` `CostUSD` guard can see it. Provider-specific I folds stay in the adapters (Bedrock I = in+R+W; DeepSeek I = max(prompt, hit+miss)). Chat, Responses and Cohere call `setCache` only when R+W > 0, so responses without cache fields keep their upstream Total.

| Adapter | Decode (buffered + stream share one func) | Encode to client (buffered + SSE) |
|---|---|---|
| Bedrock `converseUsageToCanonical` | `newCanonicalUsage(in+R+W, out, total)`. W1h = Σ `CacheDetails[ttl=="1h"].InputTokens`. Total = max(total, I+O) | `inputTokens = PlainInputTokens()`, `cacheDetails` rebuilt from W1h and W−W1h |
| Bedrock SDK `wireUsage` | copies `TokenUsage.CacheDetails` → `[]ConverseCacheDetail` | n/a |
| OpenAI Chat `openaiUsageToCanonical` | R = max(`details.cached_tokens`, top-level `cached_tokens`, `prompt_cache_hit_tokens`). W = `details.cache_write_tokens` | new `openaiUsageFromCanonical` used at both sites (442, 569): details `{cached_tokens, cache_write_tokens}` and reasoning, omitted when zero |
| Responses | R, W from `input_tokens_details` | same fields in the response and in `response.completed` |
| Cohere | R = `usage.cached_tokens` | `usage.cached_tokens` |
| Anthropic | unchanged | adds `cache_creation{ephemeral_5m=W−W1h, ephemeral_1h=W1h}` to `anthropicUsage` and `anthropicSSEUsage` (`message_start`/`message_delta`) |
| OpenRouter | shared OpenAI parser. `cost` and `cache_discount` → `slog.Debug` in `OpenRouterAdapter.DecodeResponse` (never used for billing) | shared |

New wire fields:
- `openaiUsage`: `CachedTokens`, `PromptCacheHitTokens`, `PromptCacheMissTokens`.
- `openaiPromptTokensDetails` and `openaiResponsesInputTokensDetails`: `CacheWriteTokens`.
- `cohereUsage`: `CachedTokens`.
- `ConverseUsage`: `CacheDetails []ConverseCacheDetail{InputTokens int; TTL string}`.

`llmcost.ratesFor(input, output, cr, cw, cw1h *float64, claude bool)`. `Resolve` computes `claude := isClaudeModel(provider, slug)` and sets `CacheWrite1h = 2*Input` before the discount. `tokenratelimit` needs no code change: it becomes correct once the encoders emit cache usage (`budget.go:438-474`).

### Intent (`cache_intent.go`, new, S2a)

```go
// CacheTTL is a requested prompt-cache lifetime; empty means the provider default.
type CacheTTL string

const (
	CacheTTL5m CacheTTL = "5m"
	CacheTTL1h CacheTTL = "1h"
)

// CanonicalCacheBreakpoint marks the end of a segment as a prompt-cache boundary.
type CanonicalCacheBreakpoint struct {
	TTL CacheTTL `json:"ttl,omitempty"`
}

// CanonicalCacheOptions is request-level cache intent.
type CanonicalCacheOptions struct {
	Key       string                    `json:"key,omitempty"`       // prompt_cache_key
	Retention string                    `json:"retention,omitempty"` // prompt_cache_retention
	Mode      string                    `json:"mode,omitempty"`      // prompt_cache_options.mode
	Options   json.RawMessage           `json:"options,omitempty"`   // prompt_cache_options verbatim
	Auto      *CanonicalCacheBreakpoint `json:"auto,omitempty"`      // top-level cache_control
}
```

(The inline field comments above are for the design reader only. The code gets a doc comment on each type and no narrative comments.)

New fields:
- `CanonicalRequest.SystemCache *CanonicalCacheBreakpoint`, inserted after `System`.
- `CanonicalRequest.CacheOptions *CanonicalCacheOptions`, inserted after `Metadata`.
- `CanonicalMessage.Cache *CanonicalCacheBreakpoint`.
- `CanonicalTool.Cache *CanonicalCacheBreakpoint`.

Nil means no intent.

```go
type cacheProfile struct {
	tools, system, messages, ttl1h           bool
	max                                      int
	key, retention, options, auto            bool
}

func cacheProfileFor(target Format, providerName, model string) cacheProfile
func normalizeCacheIntent(req *CanonicalRequest, target Format, providerName string) // called in AdaptRequestForProvider after dropRequestExtensionsForCrossFormat
```

`normalizeCacheIntent` runs these steps in order:
1. Clear the kinds the profile disallows.
2. While the count is above `max` (Auto counts as one): drop the earliest message breakpoint that is not the last message breakpoint, then the earliest tool breakpoint that is not the last tool breakpoint. Message breakpoints go first because the design keeps the latest boundary of every section; one per section always fits in 4.
3. If `!ttl1h`, 1h becomes 5m.
4. Walk tools → system → messages → auto, and downgrade any 1h found after a 5m or default marker to `5m`. This runs after the cap so a dropped breakpoint cannot downgrade the ones kept.
5. If no breakpoint is left, remove `mode: "explicit"` from `prompt_cache_options` (and omit it when nothing else is in it): explicit mode turns off the provider's implicit breakpoint, so sent without one it disables caching.

Step 1 also clears, for Responses, markers on assistant messages (with or without tool calls), since Responses marks input parts only, and, for targets whose encoder cannot mark an image (Responses sends no images), markers that sat on an image, which fall back to an earlier text marker of the same segment when there is one. Bedrock counts as such a target until S4a places `cachePoint` after the marked image. Both happen before the cap so they never take a slot.

`Registry.AdaptRequest(body, source, target)` stays for callers that only know the format and assumes the provider the format is named after (`openai` for Responses). The proxy calls `AdaptRequestForProvider` with `bk.Provider()`.

| Target (`Format`) | tools | system | msgs | max | 1h | key | ret | opts | auto |
|---|---|---|---|---|---|---|---|---|---|
| anthropic | ✓ | ✓ | ✓ | 4 | ✓ | – | – | – | ✓ |
| bedrock | ✓ | ✓ | ✓ | 4 | ✓ (SDK strips per model) | – | – | – | – |
| openai_responses, provider openai, model GPT-5.6+ | – | ✓ | user and tool only | 4 if Mode=explicit, else 3 | n/a | ✓ | – | ✓ | – |
| openai_responses, provider openai, other models | – | – | – | – | – | ✓ | ✓ | – | – |
| openai, provider openai, GPT-5.6+ | – | – | – | – | – | ✓ | – | ✓ | – |
| openai, provider openai, other models | – | – | – | – | – | ✓ | ✓ | – | – |
| azure, or openai_responses with provider azure (ret unless the name reads GPT-5.6+; the client retries key-only on a 400 naming it) | – | – | – | – | – | ✓ | ✓ | – | – |
| openai with any other provider (cerebras, openai_compatible), xai | – | – | – | – | – | – | – | – | – |
| openrouter, model `anthropic/*` | – | ✓ | ✓ | 4 | ✓ | – | – | – | ✓ |
| openrouter, model `google/gemini*`, `qwen/*`, `openai/` GPT-5.6+ (OpenRouter documents breakpoints for these) | – | ✓ | ✓ | 4 | – | – | – | – | – |
| openrouter, other models | – | – | – | – | – | – | – | – | – |
| mistral | – | – | – | – | – | ✓ | – | – | – |
| groq, deepseek, google, vertex, cohere | – | – | – | – | – | – | – | – | – |

Lossy cases, deliberate and tested as no-ops:
- Decoders merge text blocks with `"\n"`, so a breakpoint records its boundary as a newline index (unexported fields): the joiner's ordinal among the newlines of the merged text, and the segment's total newline count. The Anthropic encoder splits the text at that newline (dropping the joiner), so a marker on a stable block never covers the volatile text that followed it. A byte offset would go stale when a rewriting plugin (TrustGuard mask, regexreplace, promptcompression, Bedrock Guardrails or Model Armor anonymize) changes the text length, and could land on a user newline inside the volatile text. The newline index survives length changes that keep the lines (masking). If the newline count changed, or a split would leave a blank block, the marker falls back to the end of its segment. A plugin that removes one newline and adds another keeps the count and splits at the wrong line; that stays a known limitation. Other targets ignore the boundary until their slice.
- Several markers in one segment collapse into one: the last position, with the longest TTL (valid, since every marker before a 1h one is already 1h). Unmarked block boundaries are still merged. Raising the later marker to 1h has a cost: the text between the two markers is now written at the 1h rate (2× input instead of 1.25×) even though the client asked for 5m there. The alternative, keeping the later 5m, would lose the 1h the client asked for on the prefix; we keep the longer TTL.
- A marker on a blank system block moves to the text block before it (blank blocks are skipped because Anthropic rejects them). A marker on a leading blank block is dropped: it caches no text.
- A marker on an image stays on that image: the decoder records its position among the segment's images, and the Anthropic and Chat encoders, which emit images before the text, put `cache_control` on it. It keeps its own TTL instead of merging with an earlier text marker, since the reorder puts the image ahead of that text. Responses sends no images, so the marker is dropped there, or replaced by the segment's earlier text marker, which the decoder keeps behind the image marker; it is also dropped when a plugin changed the image count, and on segments whose images the canonical model drops (system, assistant and tool content). It never moves onto the text after the image, which is usually the volatile part. A marker on a non-last `tool_use` moves to the last one.
- With top-level automatic caching, an explicit marker that ends up on the last block of the last message with a different TTL is dropped when the gateway put it there: a fallback from its block boundary, a TTL raised by merging markers, a reorder (images go first), or a marker a plugin added. Anthropic answers 400 to that pair. A client that sent the pair itself (the marker was on its last block with that TTL) gets it unchanged, the same 400 it gets on passthrough.
- Markers on block types the canonical model drops (`thinking`, `redacted_thinking`, `document`, server tool blocks, markers nested inside `tool_result` content) are dropped with the block.
- An assistant turn with only tool calls and no text keeps its marker on the last `tool_use` (Anthropic) or drops it (Chat, which has no part to mark).
- Gemini `cachedContent`, and anything bound for Groq, DeepSeek or Cohere, is dropped.
- `FormatOpenAI` is shared by Cerebras and openai_compatible. The profile is gated on the target provider, so a Responses or Anthropic client routed there sends no cache key.

### Per-adapter decode/encode (S2a/S2b)

| Adapter | Decode | Encode |
|---|---|---|
| Anthropic | `anthropicCacheControl{Type, TTL}` on `anthropicContentBlock`, `anthropicTool` and `anthropicRequest` (top level → `Auto`). System blocks → `SystemCache` (last marker position as a newline index, longest TTL). Messages: new hook `attachAnthropicCache(out []CanonicalMessage, raw json.RawMessage)` called from `DecodeRequest` right after `decodeAnthropicMessageContent`. A marked `tool_result` goes to the `tool` message with that `ToolCallID`; any other marked block goes to the user/assistant message. Fast path: `bytes.Contains(raw, "cache_control")` | System as `[{type:text, text, cache_control}]` when `SystemCache` is set. `anthropicCached(content json.RawMessage, bp) json.RawMessage` turns a string into a single text block, or sets the marker on the last block of an array (so after ENG-1608 images). `tool_result` and `tool_use` blocks set the field directly. Tools set `CacheControl` |
| OpenAI Chat | parts `cache_control` on system/developer messages → `SystemCache`, on other messages → `Cache`. `tools[].cache_control` → `Tool.Cache`. Top-level `prompt_cache_key`, `prompt_cache_retention`, `prompt_cache_options` (Mode parsed, raw kept) and `cache_control` → `CacheOptions` | `openAICachedContent(raw, bp)`, a raw-JSON helper that works on develop and on 1608. System as parts when marked. Tool results as parts. Top-level keys from `CacheOptions` |
| Responses | `prompt_cache_breakpoint` on any `input_*` part of a system/developer item → `SystemCache`, of a user item → `Cache`, and on `function_call_output` → `Cache`. The same three top-level keys | Marked messages become `[{type:input_text, text, prompt_cache_breakpoint:{mode:"explicit"}}]` (the single-string `input` shortcut is skipped when any marker exists). `SystemCache` → a leading `developer` item |
| Bedrock (S4a) | `cachePoint` after a block, tool or system entry → the preceding segment's `Cache` | see Bedrock below |
| Gemini, Cohere | no change (drop) | no change |

### Pass-through (S3)

```go
// ShouldPassthroughRequest reports whether a request body can be forwarded unchanged.
func ShouldPassthroughRequest(source, target Format) bool { return IsSameWireFormat(source, target) }
```

- `Registry.AdaptRequest` and `provider.go:326` (`crossFormat`) switch to it.
- `AdaptResponse`, `AdaptStreamChunk` and `provider_stream.go:158` keep `ShouldPassthroughSameWireFormat`, so `x_groq`, OpenRouter `provider` and SSE comments are still normalised.
- `OpenRouterAdapter.EncodeRequest` then only runs from Responses/Anthropic/Gemini sources. It still merges `RequestExtensions`, which are empty there.
- Mistral: `MistralAdapter.EncodeRequest` needs no change. The profile row plus the Chat encoder emit `prompt_cache_key`.

### Bedrock (S4a wire + SDK, S4b capability + retry)

Adapter wire:
- `ConverseCachePoint{Type string "type"; TTL string "ttl,omitempty"}`.
- `ConverseContentBlock.CachePoint`, `ConverseSystemBlock.CachePoint` (and `Text` gains `omitempty`), `ConverseTool.CachePoint`.

`EncodeRequest` appends `{cachePoint:{type:"default", ttl}}` in three places:
- after each marked tool;
- after the system text;
- as the last block of a marked message, only when that message has another block.

`appendConverseMessage` merges keep the position.

SDK layer (`converse.go`):
- `decodeConverseBody` maps system cache points → `SystemContentBlockMemberCachePoint`.
- `sdkContentBlock` gets a first `case b.CachePoint != nil` → `ContentBlockMemberCachePoint`.
- `sdkToolConfig` maps tool cache points → `ToolMemberCachePoint`.
- All three build `CachePointBlock{Type: CachePointTypeDefault, Ttl: CacheTTLOneHour}` only for 1h.

```go
type cacheCapability struct{ explicit, ttl1h bool }

func cacheCapabilityFor(model string) cacheCapability // longest-prefix match on bedrockCacheFamilies
func (p *converseParams) applyCacheCapability(c cacheCapability) // strip all or clear Ttl
func (p *converseParams) stripCachePoints() bool
func converseWithCachePointFallback[T any](memo *modelMemo, model string, p *converseParams, call func(*converseParams) (T, error)) (T, error)
```

`bedrockCacheFamilies` (per the AWS table, 2026-09-23):
- Explicit with 1h: `anthropic.claude-{opus-5, fable-5, mythos-5, opus-4-8, opus-4-7, opus-4-6, opus-4-5, sonnet-5, sonnet-4-6, sonnet-4-5, haiku-4-5}`.
- Explicit, 5m only: `anthropic.claude-3-7-sonnet`, `anthropic.claude-3-5-sonnet-20241022-v2`, `amazon.nova-{micro, lite, pro, premier}`.
- Minimum token counts are not enforced.

Retry, fold and wiring:
- The retry fires on a `ValidationException` only when `stripCachePoints()` removed something. The model is remembered **only if the retry succeeds**, so an unrelated validation error does not disable caching.
- `systemFoldMemo` is renamed `modelMemo` and reused.
- Wiring in `client.go:86` and `:251` nests the calls: `converseWithSystemFallback(&c.systemFold, …, func(p) { return converseWithCachePointFallback(&c.cacheStrip, model, p, call) })`.
- `foldSystemIntoFirstTurn`: when the system has a cache point, it prepends `[text(system), cachePoint]` and does **not** merge into the first user text. That also covers Mistral 7B, even though the table already strips cache points for it.

### Plugins (S5)

- `adapter.GraftChangedFields(original, baseline, mutated []byte) ([]byte, error)` moves out of its three copies (`toolinjection:170`, `toolallowlist:401`, `pertoolratelimit:336`).
- regexreplace, bedrockguardrail and googlemodelarmor anonymize, and trustguard `rewriteRequest` take the original body. Only on their change path they encode a baseline before mutating, encode after, and graft. Unchanged `system`/`tools` and unmodelled keys stay byte-identical; `messages` is re-encoded with its markers.
- `adapter.FilterTools(tools []CanonicalTool, keep func(CanonicalTool) bool) []CanonicalTool` keeps order. If the last marked tool is removed, its marker moves to the last retained tool. toolallowlist and pertoolratelimit use it.
- toolinjection copies `Cache` when it replaces a tool in place. Appended tools carry no marker.
- Response rewrites keep R, W and W1h through the S1c encoders.
- `docs/prompt-caching.md` covers prefix stability (prompttemplate, the tool plugins, promptcompression skip) and the lossy table.

## Data Flow

```
client body ─► [same wire?]──yes──► passthrough (Groq/OpenRouter now included) ─► Normalize*Request ─► upstream
                  │no
                  ▼
      source.DecodeRequest ─► canonical{+SystemCache,+Cache,+CacheOptions}
                  ▼
      normalizeCacheIntent(target, model)   ◄── only cross-format
                  ▼
      target.EncodeRequest (faithful) ─► EnforceModel ─► [bedrock] SDK map ─► capability(model) ─► Converse
                                                                   └─ ValidationException ─► strip cachePoint, retry once

upstream usage ─► target.Decode* (folded, max-not-sum) ─► metrics/llmcost/trace
             └─► source.Encode* (cache fields kept) ─► client body ─► tokenratelimit re-decode (same numbers)

plugin (same format): decode ─► mutate ─► encode baseline+mutated ─► GraftChangedFields(original) ─► body
```

## File Changes

| Path | Change | Slice | Est. lines (prod+test) |
|---|---|---|---|
| `adapter/canonical.go` | `setCache`; fields `SystemCache`, `CacheOptions`, `Cache` ×2 | S1a, S2a | 25 |
| `adapter/bedrock_adapter.go` | usage fold/unfold, `CacheDetails`; cachePoint wire, encode, decode | S1a, S4a | 45 + 70 |
| `bedrock/converse.go` | `wireUsage` details; SDK CachePoint members; fold; capability; fallback | S1a, S4a, S4b | 20 + 60 + 70 |
| `bedrock/cache_capability.go` (new) | family table and lookup | S4b | 45 |
| `bedrock/client.go` | nested fallback, `cacheStrip` memo | S4b | 10 |
| `adapter/openai_completions_adapter.go` | vendor usage fields, `openaiUsageFromCanonical`; intent decode/encode | S1b, S1c, S2b | 45 + 30 + 80 |
| `adapter/openai_responses_adapter.go` | usage write; usage encode; intent | S1b, S1c, S2b | 10 + 20 + 90 |
| `adapter/anthropic_adapter.go` | `cache_creation` out; intent | S1c, S2a | 25 + 125 |
| `adapter/cohere_adapter.go` | `cached_tokens` in and out | S1b, S1c | 10 + 12 |
| `adapter/openrouter_adapter.go` | cost/discount debug log | S1b | 20 |
| `adapter/cache_intent.go` (new) | types, profile, `normalizeCacheIntent`, GPT-5.6 predicate | S2a, S2b, S3 | 150 + 15 + 10 |
| `adapter/registry.go` | normalize hook; `ShouldPassthroughRequest` | S2a, S3 | 3 + 20 |
| `app/proxy/provider.go` | request predicate at :326 | S3 | 2 |
| `plugins/llmcost/pricing.go` | 1h rule | S1c | 25 |
| `adapter/graft.go` (new), `adapter/tools.go` (new) | `GraftChangedFields`, `FilterTools` | S5 | 45 + 25 |
| `plugins/{toolinjection,toolallowlist,pertoolratelimit}/plugin.go` | use shared graft/filter (−90 duplicate lines) | S5 | 110 |
| `plugins/{regexreplace/replace.go, bedrockguardrail/anonymize.go, googlemodelarmor/anonymize.go, trustguard/rewrite.go}` | baseline + graft | S5 | 60 |
| `docs/prompt-caching.md` (new) | prefix stability, lossy matrix | S5 | 40 |
| `*_test.go` next to each file above, `bedrock/live_test.go` | see Testing | all | in slice totals |

## Testing Strategy

| Layer | What | Approach |
|---|---|---|
| Unit: usage | Per adapter, buffered and stream: the spec fixtures (Bedrock 12+4+2→18/25; SDK 1h split; DeepSeek 80/80→R=80; Moonshot both shapes; GPT-5.6 write in the `include_usage` chunk; Cohere) | Table tests in `*_adapter_test.go` and `converse_test.go`. Rewrite the wrong fixtures at `bedrock_adapter_test.go:382-403` and `converse_test.go:178-193` |
| Unit: round trip | `decode(encode(u)) == u` for Chat, Responses, Cohere, Anthropic and Bedrock | One table in `adapter_test.go` |
| Unit: pricing | Claude 1h $0.006; non-Claude; discount → $4.80/M; override wins | `llmcost/pricing_test.go` |
| Unit: intent | No markers → no fields; round trip per format (stream flag on and off); image-then-text; six markers → 4; TTL downgrade; each target row of the profile table, including deliberate drops (Gemini, Groq, Cohere); Responses on GPT-5.6 vs gpt-4o | `cache_intent_test.go`, adapter suites |
| Unit: re-encode | openai→groq/openrouter request JSON-equal to the pre-S3 re-encode for the S3 review fixtures plus the intended additions (seed, `parallel_tool_calls`, OpenRouter allowlist); `models`/`plugins`/`route`/`transforms` stripped; response still re-encoded (existing `groq_adapter_test.go:179-215` and `openrouter_adapter_test.go:192-245` stay green); Mistral key; Responses→Azure Chat key and retention | `registry` and adapter tests |
| Unit: Bedrock | cachePoint positions; capability (profile prefix, Mistral 7B, 1h on 3.7); retry on ValidationException, none on Throttling, memo only after success; fold `[text, cachePoint, …]` | `bedrock_adapter_test.go`, `converse_test.go`, fake SDK call |
| Integration | Cross-format tokenratelimit (Anthropic upstream R=1000 → OpenAI client, `CountCacheReads=false`) | `tokenratelimit` test with the real registry |
| Plugins | Each spec scenario (regexreplace on Anthropic, anonymize on Responses, trustguard response usage, allowlist move, injection, no-op byte-identical) | Plugin `_test.go` |
| Live | `bedrock_live`: same prefix twice, R>0, raw `inputTokens` excludes R+W, Total ≥ I+O | `bedrock/live_test.go` |
| E2E | Local gateway from the worktree, **never prod** | See below |

E2E plan (`/Users/edu/Neuraltrust/multi-agent-tests-eng1618`, branch `feat/eng-1618-prompt-caching-e2e`):

- **Providers.** Every modified provider runs: Bedrock (implicit, explicit 5m, explicit 1h), Anthropic, OpenAI, Azure, Mistral, OpenRouter (Claude and OpenAI upstreams), DeepSeek, Groq (gpt-oss), Cohere (usage only) and Gemini (which also covers Vertex). xAI and Cerebras run as regression. Moonshot, Vertex and openai_compatible get no e2e.
- **Matrix runs, per provider X.** Each command runs with `STREAM=1` and without it: native `make matrix-ag UPSTREAM=X AGENT=X`, and cross-format `make matrix-ag PROVIDER=X`.
- **New test.** `src/e2e/tests/test_prompt_caching.py` under a new `prompt_caching` marker in `pyproject.toml`. It is parametrised as (upstream, client format ∈ {native, openai, anthropic}, stream), plus one Anthropic and one OpenAI run with regexreplace and toolallowlist enabled. For each case:
  1. Provision a registry and consumer with the existing `upstreams.registry_payload`.
  2. Send a static prefix of about 5k tokens (above Haiku 4.5's 4,096) twice, with an `X-AG-Playground-Token` (HS256, purpose `playground`, bound to the consumer slug, signed with the local `SERVER_SECRET_KEY`).
  3. Read `X-AG-Trace-Id` and fetch `GET {E2E_ADMIN_URL}/v1/playground/traces/{id}`. **Correction to the brief:** that route sits behind `AdminAuth` (`admin_router.go:263`), so it takes the admin Bearer `E2E_ADMIN_TOKEN`. The playground token rides on the proxy call, and admin auth rejects it.
  4. Assert R>0 on the second call, both in the provider body and in the trace. The trace's I/R/W/W1h must equal the provider usage, and its cost must match D10.
- **Stop on a missing key.** A session fixture checks `upstreams.unavailable(X)` for every provider in the run. If any credential is missing it calls `pytest.exit(reason, returncode=2)` and names the variables. It never skips.

## Migration / Rollout

- No schema or config migration.
- After S1a, Bedrock `prompt_tokens`, cost and budgets rise for cached traffic: release note, and a heads-up to ISDIN through ENG-1580.
- Each slice can be reverted on its own, in reverse order.

## Slice Map (chained PRs, each ≤ 400 changed lines)

S2 and S4 do not fit in 400 lines each, so the chain has **9** PRs instead of the proposal's 7.

| PR | Scope | Est. | Base | Touches ENG-1608 files? |
|---|---|---|---|---|
| S1a | Bedrock usage fold, `CacheDetails`, inverse fold, fixtures, `bedrock_live` cache case | ~250 | develop | no (usage hunks only) |
| S1b | OpenAI/Responses/DeepSeek/Moonshot/OpenRouter/Cohere decode | ~260 | S1a | no |
| S1c | Client encoders emit cache usage (Anthropic `cache_creation`), 1h pricing, tokenratelimit test | ~340 | S1b | no (#826 overlaps the Anthropic SSE usage struct) |
| S2a | `cache_intent.go`, canonical fields, registry hook, Anthropic decode/encode | ~390 | S1c (+1608) | yes |
| S2b | OpenAI Chat and Responses intent, GPT-5.6 gate | ~370 | S2a | yes |
| S3 | OpenRouter allowlist graft (D6 amended), OpenRouter/Mistral/Azure profile rows, Azure retention retry + memo, tests | ~220 | S2b | provider.go only |
| S4a | Converse `cachePoint` wire, encode, decode, SDK members, fold | ~300 | S3 | yes |
| S4b | Capability table, cachePoint fallback, `modelMemo`, client wiring | ~260 | S4a | no |
| S5 | Shared graft and FilterTools, 7 plugins, docs | ~380 | S4b | no (#826 overlaps trustguard) |

### ENG-1608 composition

S1a–S1c apply cleanly to either base. S2a, S2b and S4a are written base-agnostic: raw-JSON helpers wrap whatever content the existing code builds. The conflicts below are expected when rebasing onto ENG-1608, all mechanical: keep both sides.

| File | ENG-1608 hunk | ENG-1618 hunk | Resolution |
|---|---|---|---|
| `canonical.go` | `CanonicalImage` after `CanonicalRequest`; `Images` in `CanonicalMessage` | `Cache` after `ToolCallID` | Keep both fields. `SystemCache`/`CacheOptions` sit in separate hunks (after `System` and after `Metadata`) |
| `anthropic_adapter.go` | `anthropicContentBlock` re-aligned (+`Source`); user branch rewritten; `anthropicMessageContent` | `+CacheControl` field; `anthropicCached(...)` wrap on the final `append` | Take 1608's struct, add the field, run gofmt. Wrap 1608's `content` variable. `attachAnthropicCache` lives in `DecodeRequest`, which does not conflict |
| `openai_completions_adapter.go` | `decodeOpenAIContent` in the decode loop; `encodeOpenAIContent` in the encode loop | `cm.Cache = openAIContentCache(m.Content)`; `content = openAICachedContent(content, m.Cache)` | Place the hook after 1608's lines |
| `bedrock_adapter.go` | `Image` field; `converseMessageFromCanonical` now returns `error` | `CachePoint` field; cachePoint append in the `EncodeRequest` loop | Add the field and append after 1608's `msg, err :=` |
| `converse.go` | `case b.Image` in `sdkContentBlock` | `case b.CachePoint` as the **first** case | Separate hunk, applies cleanly |
| `app/proxy/provider.go` | :332-333 error wrap | :326 predicate | Adjacent, keep both |

ENG-1608 follows its own path (separate branch, user decision). If it reaches main first, rebase the integration branch onto `origin/main`. Resolve the hunks above, run `go test ./pkg/infra/providers/... ./pkg/app/proxy/...`, then re-stack S2b…S5 with `git rebase --update-refs`.

## Known limitations

- Pre-existing: `thinking` and `redacted_thinking` blocks are not part of the canonical model, so a same-format plugin re-encode of an Anthropic request drops them (and any marker on them). Passthrough without a re-encoding plugin keeps them.
- A whitespace-only string `system` decodes to `""`, so no target receives a blank system; non-blank system text is byte-exact.
- W5, S5 scope: a same-format plugin re-encode is not byte-faithful. Responses `instructions` and `developer` items are folded into one system text, which comes back as `instructions` or as a leading `developer` item wherever the client had put it, several Chat system messages are merged into one, JSON schema keys come back in Go's order, and Codex fields the canonical model does not carry (`reasoning`, `include`, `store`, `parallel_tool_calls`, `tool_choice`, tool `strict`) are dropped. Cache markers survive, but the prefix bytes can change. S5 (`GraftChangedFields`, see Plugins) fixes this by grafting only the changed fields onto the original body.

## Open Questions

- [ ] Live confirmation, owned by the e2e run rather than design: Converse `totalTokens` semantics, the Moonshot `cached_tokens` location, the Mistral cached-usage field, and whether Azure Chat accepts `prompt_cache_retention` (D5 falls back to key-only if Azure returns 400).
- [ ] Spec and proposal amendments the orchestrator should apply: passthrough spec "Azure Responses stays Responses" → D5; intent spec Chat row → D3; slice count 7 → 9.
