# Sessions (conversation id)

Every proxied LLM request is assigned one **session id**, which TrustGate treats
as the id of the conversation the request belongs to. The same id is used by
every feature that needs one:

- telemetry (`trustgate.session_id`, the "Sessions" view in analytics),
- smart routing's complexity scorer (as the conversation id),
- the TrustGuard plugin (`session_id`),
- the session store, which threads OpenAI Responses turns
  (`previous_response_id`) for clients that do not send it themselves,
- traffic labels' conversation window.

The id is echoed on every response in the `X-Session-Id` header. Sessions are
on by default; `session_config.enabled: false` on the gateway turns the whole
mechanism off.

## Resolution order

The session middleware tries these sources in order and keeps the first valid
value. An id the client sent explicitly (headers, the configured body field)
always wins over anything inferred from the body.

1. **Configured header**: `session_config.header_name` (default `X-Session-Id`).
2. **Well-known client headers**, in this order:

   | Header | Sent by |
   |---|---|
   | `X-Session-Id` (when it is not the configured header) | opencode |
   | `X-TG-Session-Id` | TrustGate's own namespace, for any client |
   | `X-OpenWebUI-Chat-Id` | Open WebUI |
   | `X-Claude-Code-Session-Id` | Claude Code (2.1.86 and later) |
   | `session_id`, `session-id` | Codex CLI |
   | `x-session-affinity` | opencode |
   | `Helicone-Session-Id` | Helicone-instrumented clients |
   | `x-litellm-session-id`, `x-litellm-trace-id` | LiteLLM |

   `session_id` contains an underscore. ingress-nginx drops such headers
   unless `enable-underscores-in-headers: "true"` is set in its ConfigMap;
   without it Codex CLI requests fall through to the next source.
3. **Vendor pattern**: any header named `x-<vendor>-session-id`
   (case-insensitive, vendor `[a-z0-9-]+`). When several are present they are
   tried in header-name order, so the choice is deterministic.
4. **Configured body field**: `session_config.body_param_name`, a top-level
   JSON string.
5. **OpenAI Responses `conversation`** (`/v1/responses` requests only): the
   Conversations API id, either `"conversation": "conv_..."` or
   `"conversation": {"id": "conv_..."}`.
6. **OpenAI Responses `previous_response_id`** (`/v1/responses` requests only):
   the session the previous turn was recorded under, looked up in the turn
   index (see below).
7. **Generated**: a UUIDv7.

The body is only read when step 4, 5 or 6 can apply (a body field is
configured, or the request is an OpenAI Responses request), and only within
the server's 8 MiB body limit, also after decompression.

### Validation

A value that fails validation is skipped and the next source is tried.

| Source | Accepted |
|---|---|
| Configured header, configured body field | 1–128 characters, no control characters |
| Well-known headers, vendor pattern, `conversation`, `previous_response_id` | 8–128 characters of `[A-Za-z0-9._:-]` |

The stricter rule applies where the gateway guessed the source: a header that
merely shares a name, or a short placeholder, must not merge unrelated traffic
into one session.

## OpenAI Responses

The Responses API has no stable conversation id unless the client uses the
Conversations API, so TrustGate derives one:

- **Conversations API**: the `conversation` id is the session id.
- **`previous_response_id` chains**: after every successful (2xx) turn,
  streamed or not, TrustGate records `session_turn:{gateway}:{response_id}` →
  session id in Redis, next to the session itself
  (`session:{gateway}:{session}`). A later request that continues from that
  response inherits its session. Both keys use the session store TTL
  (`SESSION_STORE_TTL`, default 1h) and every turn refreshes it. With
  `SESSION_STORE_ENABLED=false` nothing is recorded and this step never matches.
- **First turn of a chain**: no source applies, so the gateway generates an id
  and keeps it: it is the conversation id of the chain, even a chain of one
  turn. The turn is indexed under it, so the next turn inherits it.
- **Expiry**: once a turn's index has expired, a continuation from it starts a
  new session.
- **Branches**: every turn is indexed, so two requests that continue from the
  same earlier response (a branch or a retry) share the session id.
- **Stateless full history** in `input` with no `previous_response_id` and no
  `conversation`: each request is its own session unless the client sends a
  header.

The turn index is written for every resolved session id, including ids that
came from a header, so a later turn that drops the header still inherits the
session through `previous_response_id`. The index is not written after a
failed (non-2xx) turn.

## Generated ids on other APIs

On every format other than OpenAI Responses (Chat Completions, Anthropic
Messages, Gemini, ...) a generated id stands for a single stateless request,
not a conversation. It is still echoed in `X-Session-Id` so a client can adopt
it and send it back, but it is hidden from every consumer: telemetry carries
no `trustgate.session_id`, the complexity scorer and TrustGuard receive no
session id, and nothing is written to the session store.

In code, consumers never read the raw id: they use
`infracontext.EffectiveSessionID(ctx)` (or `middleware.EffectiveSessionID(c)`),
which returns empty for a hidden generated id.
