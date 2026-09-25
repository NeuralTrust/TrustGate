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

Plugins that rewrite the request take one of two paths.

**Redaction re-encodes.** `trustguard` (mask), `bedrock_guardrail`
(anonymize) and `regex_replace` send the edited request encoded in full
(`EncodeRequest`) whenever they change text. The encoders keep the cache
markers the canonical request carries (system, message, tool and automatic
markers, with their TTLs), so the prefix stays cached up to the first masked
span. Fields the canonical model does not carry are dropped, on purpose: a
copy of the masked value can sit in any of them (a `thinking` or
`redacted_thinking` block, a `document`, `search_result` or web search
result, `citations`, Responses `reasoning.summary`, `prompt.variables` or
tool call outputs, Chat `prediction`, `refusal`, `name`, `user`, `metadata`
or file parts, Gemini `thought` parts, `labels`, `inlineData` or code
execution parts, Bedrock `guardContent`, `reasoningContent`, `document` or
`promptVariables`, Cohere `documents`), and no text search can prove that
none holds one in another spelling, split or encoding. When nothing is
masked, the body goes upstream byte-identical.

A few top-level keys that hold no prompt text survive every re-encode, since
dropping them changes what the upstream keeps: Responses `store`,
`previous_response_id`, `include` and `reasoning`, and Chat `store`. Without
`store: false` the upstream would store a response the client asked it not to
keep. They are carried only within one wire format. `metadata` is dropped in
both formats, since it may hold personal data.

What redaction does not cover:

- Text the canonical model carries outside prompt text (tool call
  arguments, tool descriptions and schemas, Anthropic `metadata.user_id`,
  Responses `text.format`) is not masked by these plugins. The re-encode
  sends it as is.
- A value that only appears in a field the canonical model does not carry is
  never seen by the plugin. If the plugin masks nothing, the body is
  forwarded as sent, that field included.

**Tool plugins and compression graft.** `tool_injection`, `tool_allowlist`,
`per_tool_rate_limiter` and `prompt_compression` hand the edit to
`adapter.GraftChangedFieldsWith`. The body that goes upstream is the
client's own body, with only the edited parts replaced:

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
- **No change**, no edit: the body goes upstream byte-identical.

None of these edits hides anything from the upstream: the tool plugins do
not change text, and compression only drops filler whitespace and
reformats JSON the upstream sees anyway. So the graft does not look for
copies of removed text elsewhere in the body.

### Fail-closed rules

The graft falls back to the full re-encode, never to a partial body, when:

- the body is not valid JSON, is over 8 MiB, has more than 250,000 JSON
  values, nests more than 64 containers deep, or has so much of its bytes
  deep in the tree that indexing it would rescan more than 16 times its
  size. These checks run in one pass before any other work;
- an object repeats a key, exactly or in a case variant that encoding/json
  folds into the same field (`content` and `Content`, `messages` and
  `Messages`). A body with such keys is re-encoded even when the plugin
  changed nothing, so the upstream sees the copy the plugin inspected. This
  check reads the whole body in one pass at any size or depth, so it also
  runs on bodies over the caps;
- the plugin added or removed messages, or changed a field other than the
  prompt text and the tools;
- the edit differs from the original text in more than 512 words, the text
  left after the common prefix and suffix holds more than 4M words and
  separators, or the diff exhausts its comparison budget (about twice the
  words compared, which only repetitive text such as `x x x` reaches);
- the edited system text crosses a block boundary;
- the grafted body does not decode to the edited request.

A tools entry the gateway does not model is one the adapter skips when it
decodes (Responses `mcp`, `web_search`, `file_search`,
`computer_use_preview`, `code_interpreter`, `local_shell`,
`image_generation`; Gemini `googleSearch`, `codeExecution`, `urlContext`;
Bedrock `systemTool`), or one that shares its name with more entries than the
decoded request has tools of that name. A Gemini tools object that mixes
function declarations with other keys counts once per other key, and each is
kept or dropped on its own; both `functionDeclarations` and
`function_declarations` are decoded. Chat's legacy `functions` and
Anthropic's `mcp_servers` are a second tools list the adapters do not decode,
and their entries count as unmodelled too. `per_tool_rate_limiter` drops the
tools entries whenever it withdraws a modelled tool, as the full re-encode did
before grafting. It limits a legacy function by its name like any tool,
withdrawing it at the request whatever the behavior (the response rewrite
does not model a legacy `function_call`), and counts a legacy call once a
`function` message answers it. `tool_injection` keeps them all, except a
legacy function or a second client copy named like an injected tool, which
`on_conflict` settles as it does a clashing tool.

`tool_allowlist` evaluates each such entry on every request, whether or not
it removes a modelled tool, and counts a refused one as removed:

- A legacy Chat function is judged by its name, like any function tool. A
  `function_call` naming a removed one goes with it.
- A built-in tool of the wire format stays when no deny pattern matches its
  kind or name and, if `allow_tools` is set, `allow_tools` names its kind
  exactly. The kind is its `type` (matched ignoring case, as the decoder
  reads it), or for Gemini its key and for Bedrock `systemTool:<name>`, as in
  `systemTool:nova_grounding`. With only `deny_tools` set, built-ins no deny
  pattern names stay. The built-ins are the Responses and Gemini tools above
  (`googleSearch`, `googleSearchRetrieval`, `codeExecution`, `urlContext`, in
  either spelling), Bedrock system tools, Anthropic `mcp_servers`, and
  Anthropic dated server tools (`web_search_*`, `web_fetch_*`,
  `code_execution_*`, `bash_*`, `text_editor_*`, `computer_*`, such as
  `web_search_20250305`).
- Any other kind, such as `mcp_toolset` or a nameless entry, is always
  refused, and patterns such as `*` never keep a built-in.
- A request left with only built-ins that `allow_tools` does not name is
  refused (or handled by `on_empty_after_filter`). This is intended: an allow
  list that names no built-in does not let one through.

Anthropic server tools carry a `name`, so the adapter models them by it;
`allow_tools` and `deny_tools` match either that name or the dated `type`,
and a removed one leaves the body. When a Gemini or Bedrock tool change
cannot be placed entry by entry, the tools value is replaced by the
re-encoded one and the kept built-ins are appended to it. When
`on_empty_after_filter` strips the tools field, it also drops `tool_choice`,
`parallel_tool_calls`, the second tools lists and, for Bedrock and Gemini,
`toolConfig`; Bedrock takes no empty tools list, so `pass_through_empty` drops
its `toolConfig` too.

A `tool_choice` that names a tool `tool_allowlist` or `per_tool_rate_limiter`
removed becomes `auto`, as does a Responses `tool_choice` naming a dropped
built-in. A Gemini `allowedFunctionNames` list loses the removed names, and
once none is left, or no function declaration stays under an `ANY` or
`VALIDATED` mode, the mode relaxes to `AUTO`.

The gateway refuses a chat request whose body repeats a key, at any depth,
or holds two keys that differ only in case where the decoder folds them into
one struct field (`tools` and `TOOLS`, `content` and `Content`,
`function.name` and `function.Name`), with 400 `invalid_request_body`, before
any plugin runs: the plugins would judge the copy the decoder reads, and the
upstream may read the other. Keys that differ in case stay allowed inside
the objects the formats carry as free-form maps (JSON schemas, tool call
arguments, `metadata`, `labels`, MCP `headers`), where both copies reach the
decoder and the upstream alike. Embeddings, files, images and audio requests
are not checked. The tool plugins still never forward such a body when they
run outside the proxy: they send their own encoding of it instead.

| Plugin | Changes | Effect on the cached prefix |
|---|---|---|
| `regex_replace` | matched text in system and messages; response text | The body is re-encoded once a rule matches: cache markers survive and unmodelled fields go. A match inside the cached prefix changes it on every request the same way, so the prefix stays stable. |
| `bedrock_guardrail`, anonymize | the last user message | The body is re-encoded: cache markers survive, unmodelled fields go, and the prefix is stable up to the masked message. |
| `trustguard`, mask | masked spans in system and messages | The body is re-encoded: cache markers survive, unmodelled fields go, and the prefix is stable up to the first masked span. |
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
