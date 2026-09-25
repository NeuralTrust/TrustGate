# Prompt caching

Providers bill a cached prompt prefix at a discount, but only when the bytes
before the cache boundary are identical from one request to the next.
TrustGate sits in the middle of that prefix, so it has three jobs:

1. **Account** for cache reads and writes the same way for every provider.
2. **Carry cache intent** (breakpoints, TTLs, cache keys) from the client's
   format to the upstream's format, and send each upstream only what it accepts.
3. **Keep the prefix stable**: never change bytes the client did not ask to
   change, and say plainly where the gateway does.

## Usage accounting

Every adapter decodes usage into one shape. `input_tokens` is the whole
prompt, whatever rate each token bills at. Cache reads (R), cache writes (W)
and 1h writes (W1h) are subsets of it, never added on top.

| Provider | R | W / W1h | Input |
|---|---|---|---|
| Anthropic | `cache_read_input_tokens` | `cache_creation_input_tokens`; W1h from `cache_creation.ephemeral_1h_input_tokens` | `input_tokens` + R + W |
| Bedrock (Converse, HTTP and SDK) | `cacheReadInputTokens` | `cacheWriteInputTokens`; W1h from `cacheDetails` entries with TTL `1h` | `inputTokens` + R + W |
| OpenAI, Azure (Chat) | `prompt_tokens_details.cached_tokens` | `prompt_tokens_details.cache_write_tokens` | `prompt_tokens` |
| OpenAI, Azure (Responses) | `input_tokens_details.cached_tokens` | `input_tokens_details.cache_write_tokens` | `input_tokens` |
| DeepSeek | the larger of `prompt_cache_hit_tokens` and `details.cached_tokens` | none | `prompt_tokens` |
| OpenRouter | `details.cached_tokens` | `details.cache_write_tokens` | `prompt_tokens` |
| Groq | `details.cached_tokens` (also read from `x_groq.usage`) | none | `prompt_tokens` |
| Cohere | `usage.cached_tokens` | none | `tokens.input_tokens` |
| Gemini, Vertex | `cachedContentTokenCount` | none | `promptTokenCount` |

When a provider reports the same number in two places, TrustGate keeps the
larger one and never sums them, so a discount is not counted twice.

Usage survives the trip back to the client: each client encoder writes R, W
and W1h in its own dialect. An OpenAI client of an Anthropic upstream sees
`prompt_tokens_details.cached_tokens`, and an Anthropic client gets
`cache_creation` with the 5m and 1h split. `tokenratelimit` and `llmcost`
read the same numbers whichever format the client speaks.

**Pricing.** A 1h write is priced at the registry override `cache_write_1h`
when one is set. Otherwise Claude models (provider `anthropic` or `bedrock`)
use 2x the input rate, and every other model uses the plain cache-write rate.
See [pricing.md](pricing.md) for how rates are resolved.

## Cache intent

Clients mark cache boundaries in their own dialect: Anthropic
`cache_control`, OpenAI Chat parts `cache_control` (the OpenRouter style), the
Responses `prompt_cache_breakpoint`, Bedrock `cachePoint`, and the request-level
`prompt_cache_key`, `prompt_cache_retention` and `prompt_cache_options`.
TrustGate decodes all of them into one model: a breakpoint with a TTL on
tools, system and messages, plus request-level options.

**Same format** (the client and the upstream speak the same API). The body is
forwarded as the client sent it, apart from the model the gateway enforces and
the provider fixes in `NormalizeRequestForProvider` (for example an
empty `parameters` schema on tools that some SDKs send without one). Markers are never added, moved or
dropped.

**Cross format.** The intent is translated, then trimmed to what the target
accepts:

| Target | Tools | System | Messages | Max | 1h TTL | Key | Retention | Options | Automatic |
|---|---|---|---|---|---|---|---|---|---|
| Anthropic | yes | yes | yes | 4 | yes | – | – | – | yes |
| Bedrock Converse | yes | yes | yes | 4 | yes, per model (see below) | – | – | – | yes, as a cachePoint ending the last message |
| OpenAI Responses, GPT-5.6 and later | – | yes | user and tool items | 4 with `mode: explicit`, else 3 | – | yes | – | yes | – |
| OpenAI Responses, earlier models | – | – | – | – | – | yes | yes | – | – |
| OpenAI Chat, GPT-5.6 and later | – | – | – | – | – | yes | – | yes | – |
| OpenAI Chat, earlier models | – | – | – | – | – | yes | yes | – | – |
| Azure OpenAI | – | – | – | – | – | yes | yes, unless the deployment name reads GPT-5.6+ | – | – |
| OpenRouter, `anthropic/*` | – | yes | yes | 4 | yes | – | – | – | yes |
| OpenRouter, `google/gemini*`, `qwen/*`, `openai/` GPT-5.6+ | – | yes | yes | 4 | – | – | – | – | – |
| Mistral | – | – | – | – | – | yes | – | – | – |
| Groq, DeepSeek, Gemini, Vertex, Cohere, xAI, Cerebras, OpenAI-compatible | – | – | – | – | – | – | – | – | – |

Trimming follows these rules, in this order:

1. Kinds the target does not accept are dropped.
2. Above the maximum, the earliest message breakpoint goes first, then the
   earliest tool breakpoint. The last breakpoint of each section is always
   kept.
3. A 1h TTL becomes 5m where the target has no 1h cache.
4. A 1h breakpoint after a 5m one becomes 5m, since providers require longer
   TTLs first.
5. `prompt_cache_options.mode: "explicit"` is removed when no breakpoint is
   left, since explicit mode with no breakpoint turns caching off.

The last group of targets caches automatically or not at all. They get no
cache fields.

Azure rejects `prompt_cache_retention` on some deployments. When the gateway
added it (cross format), the Azure client retries once without it and
remembers that deployment for an hour.

### Bedrock models

TrustGate sends `cachePoint` only to models that take it. The model is read
after routing (`EnforceModel`), with one inference-profile prefix (`us.`,
`eu.`, `apac.`, `jp.`, `au.`, `ca.`, `us-gov.`, `global.`) stripped.

| Model family | cachePoint | 1h TTL | In tools |
|---|---|---|---|
| Claude Opus 5.5, Opus 5, Fable 5.1, Fable 5, Mythos 5.1, Mythos 5, Sonnet 5, Opus 4.8, 4.7, 4.6, 4.5, Sonnet 4.6, 4.5, Haiku 4.5 | yes | yes | yes |
| Claude 3.7 Sonnet, Claude 3.5 Sonnet v2 | yes | – | yes |
| Nova Micro, Lite, Pro, Premier, Nova 2 Lite | yes | – | – |
| Any other model, ARNs | – | – | – |

When Bedrock still answers a `ValidationException` that names the cache,
TrustGate retries once without any `cachePoint` and remembers that model.
The table follows the AWS prompt-caching guide as read on 2026-09-25.

## Prefix stability

### What TrustGate forwards as is

- Same-format requests with no request-rewriting plugin keep the client's
  bytes, with the exceptions listed under Cache intent.
- Cross-format requests are re-encoded, since the target speaks another API.
  Their prefix is stable across requests, because the same input always
  encodes to the same bytes. It is not the client's bytes.
- OpenAI Chat to Groq or OpenRouter is re-encoded too: Groq rejects several
  Chat fields, and some OpenRouter keys change routing or billing. For an
  OpenRouter upstream, TrustGate copies only `provider` (minus any
  `model`/`models` inside it), `session_id` and `user` from the client body.

### Lossy cases

Some shapes cannot survive translation. None of them fails the request:

- Text blocks of one message are merged with `"\n"`. The boundary a marker
  sat on is kept as a newline index, so an encoder can split at it again.
- Several markers in one segment collapse into one: the last position, with
  the longest TTL.
- A marker on a blank system block moves to the text before it. One on a
  leading blank block is dropped.
- A marker on an image stays on that image where the target takes images.
  Responses sends no images, so there it falls back to an earlier text
  marker of the same segment, or is dropped.
- Markers on blocks the canonical model does not carry (`thinking`,
  `redacted_thinking`, `document`, server tool blocks, markers inside
  `tool_result` content) are dropped with the block.
- An assistant turn with only tool calls keeps its marker on the last
  `tool_use` (Anthropic) or drops it (Chat has no part to mark).
- Gemini `cachedContent` is not translated.

## Plugins

A plugin that rewrites the request decodes the body, edits it, and hands the
result to `adapter.GraftChangedFieldsWith`. The body that goes upstream is
the client's own body, with only the edited parts replaced:

- **Text.** The edited text is diffed against the text it replaces, and each
  changed run is written into the block that holds it, by character offset.
  A run that crosses a block boundary or touches the joiner between blocks
  re-encodes only that message's content. Every other message, the system
  prompt, the tools and all cache markers keep their bytes.
- **Tools.** Kept tools keep their bytes, removed ones go, and injected ones
  are appended. See the fail-closed rules for tools the gateway does not
  model.
- **Everything else** stays as sent: key order, fields the canonical model
  does not carry (Codex `reasoning`, `include`, `store`, `parallel_tool_calls`,
  tool `strict`, Anthropic `thinking`), and whitespace.
- **No change**, no edit: when nothing matches, the body goes upstream
  byte-identical.

### Redaction guarantee

`trustguard` (mask), `bedrock_guardrail` (anonymize) and `regex_replace`
graft with `Redaction`. Every piece of text the edit removed is searched for,
line by line and decoded (JSON escapes cannot hide it), in each string of the
grafted body, object keys included. If a piece appears in a string that the
full re-encode would not also send, the graft is dropped and the plugin sends
the full re-encode. So a masked value never reaches the upstream through a
field the canonical model does not carry (a `thinking` or
`redacted_thinking` block, a `document`, `search_result` or web search
result, `citations`, Responses `reasoning.summary`, `prompt.variables` or
tool call outputs, Chat `prediction`, `refusal`, `name`, `user`, `metadata`
or file parts, Gemini `thought` parts, `labels`, `inlineData` or code
execution parts, Bedrock `guardContent`, `reasoningContent`, `document` or
`promptVariables`, Cohere `documents`).

Other plugins search only for pieces of four bytes or more. Blank pieces are
never searched for.

What the guarantee does not cover:

- Text the canonical model carries outside prompt text (tool call
  arguments, tool descriptions and schemas, Anthropic `metadata.user_id`,
  Responses `text.format`) is not masked by these plugins, grafted or not.
  The full re-encode sends it too.
- A value that only appears in a field the canonical model does not carry is
  never seen by the plugin, so nothing is masked and the body is forwarded
  as sent. Before grafting, a plugin that masked something else in the same
  request dropped such fields with the re-encode; now they stay.

### Fail-closed rules

The graft falls back to the full re-encode, never to a partial body, when:

- the body is not valid JSON, is over 8 MiB, or has more than 250,000 JSON
  values;
- an object repeats a key, exactly or in a case variant that encoding/json
  folds into the same field (`content` and `Content`, `messages` and
  `Messages`). A body with such keys is re-encoded even when the plugin
  changed nothing, so the upstream sees the copy the plugin inspected;
- the plugin added or removed messages, or changed a field other than the
  prompt text and the tools;
- the edit differs from the original text in more than 512 words;
- the edited system text crosses a block boundary;
- the grafted body does not decode to the edited request;
- removed text survives, as described above.

`tool_allowlist` and `per_tool_rate_limiter` drop every tools entry the
gateway does not model (Responses `mcp`, `web_search`, `file_search`,
`computer_use_preview`, `code_interpreter`, `local_shell`; Anthropic
`mcp_toolset`; Bedrock `systemTool`) whenever they strip a tool, as the full
re-encode did before grafting. `tool_allowlist` keeps one only when
`allow_tools` names its `type` exactly (for Gemini and Bedrock, its only key,
such as `googleSearch` or `systemTool`) and no deny pattern matches it;
patterns such as `*` never keep one. Gemini tool groups are always replaced
whole, so `googleSearch` and `codeExecution` go with any tool change.
`tool_injection` keeps them.

Tools declared outside the tools array (Chat `functions` and
`function_call`, Anthropic `mcp_servers`) and a `tool_choice` or Gemini
`allowedFunctionNames` that names a removed tool are not filtered. ENG-1637
tracks them.

| Plugin | Changes | Effect on the cached prefix |
|---|---|---|
| `regex_replace` | matched text in system and messages; response text | Only the matched strings change. A match inside the cached prefix changes it on every request the same way, so the prefix stays stable. |
| `bedrock_guardrail`, anonymize | the last user message | Earlier messages and the system prompt keep their bytes. |
| `trustguard`, mask | masked spans in system and messages | Only the masked spans change. |
| `prompt_compression` | whitespace and JSON in messages | Skips any body with cache markers, multimodal parts or unmodelled message fields. |
| `tool_injection` | appends gateway tools, or replaces a client tool with `gateway_wins` | The appended tools come after the client's, so the client's tool prefix is unchanged. A replaced tool keeps the client's marker. Injected tools carry no marker. |
| `tool_allowlist` | removes tools | The tool block changes whenever the kept set changes. A marker on a removed tool moves to the nearest kept tool before it. |
| `per_tool_rate_limiter` | removes a tool while it is over its limit | The tool block changes while a tool is withdrawn, so the tools prefix misses the cache until it comes back. |
| `prompt_template` | injects the system prompt | Per-user variables in the system prompt give each user a different prefix. Keep them after the cached part, or leave them out of it. |

Response rewrites (`regex_replace`, `trustguard` and `bedrock_guardrail` on
buffered responses) keep R, W and W1h in the rewritten body. Streamed
responses are not rewritten.

### Known limits

- Adding text to a message that had none (an assistant turn with only tool
  calls) cannot be placed. The request falls back to a full re-encode.
- A graft decodes the body twice (once to map its text, once to check the
  result), so it costs about three to four decodes of the body. For an
  8000-message, 1 MB Chat body that is 150 to 230 ms against about 50 ms for
  the decode and re-encode it replaces.
