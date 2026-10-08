# OTLP metadata export contract

**Schema:** `events.Event` (`trustgate.schema_version`)

TrustGate emits one OTLP **log record** per completed gateway request. This contract describes
the **metadata** data class: input is `evt.MetadataView()`, so request/response **bodies are not
exported**. Raw bodies are written to PostgreSQL `trustgate_data` via the `postgres` exporter,
and — when an `otlp` exporter is declared under `exporters.raw[]` — also emitted on OTLP as
`trustgate.request.body` / `trustgate.response.body`. See the raw stream section below.

## Invariants

| Rule | Detail |
|------|--------|
| Event name | `trustgate.<version>.<verb>` (`resource.version.verb`): resource `trustgate`, version = event schema version, verb = data class. One trace emits `trustgate.<version>.metadata` and `trustgate.<version>.raw`. Downstream routing keys on it. |
| Log body | Always empty |
| Bodies (metadata class) | Not emitted (no `trustgate.request.body` / `trustgate.response.body`) |
| Bodies (raw class) | Emitted as `trustgate.request.body` / `trustgate.response.body` when an `otlp` exporter is declared under `exporters.raw[]` |
| Policy chain | `policy_chain[]` on the Event is JSON-encoded in `trustgate.policy_chain` (evidence never included) |
| Policy scope | `mcp.policy_scope` on the Event (MCP `tools/call` resolved against an upstream only) records how the consumer's scoped policies applied: `evaluated` counts them, `matched[]` lists the ids that entered the plan and `skipped[]` the ones left out with a `reason` (`destination`, `principal`, `except`). Unscoped policies never appear; `policy_chain[]` keeps listing only the plugins that ran. Absent on discovery, prompts, resources, meta-tools and on consumers without scoped plans. Not flattened to an OTLP attribute yet |
| `is_flagged` | Emitted as `trustgate.is_flagged` (bool) |
| Retention | `trustgate.retention.expires_at` on **both** classes, or on neither. Absent means the gateway has no stamped plan retention — the sink applies its own fallback |

## HTTP semconv

| Attribute | Event field |
|-----------|-------------|
| `http.request.method` | `request.method` |
| `http.response.status_code` | `response.status_code` (for MCP, aligned with `trustgate.mcp.upstream_status` / gateway denial outcome) |
| `url.path` | `request.path` |

## GenAI semconv

| Attribute | Event field |
|-----------|-------------|
| `gen_ai.provider.name` | `request.provider` |
| `gen_ai.request.model` | `request.model` |
| `gen_ai.response.finish_reasons` | `response.finish_reason` (when set) |
| `gen_ai.request.stream` | `request.stream` OR `response.streaming` |
| `gen_ai.usage.input_tokens` | `usage.prompt_tokens` (when usage present) |
| `gen_ai.usage.output_tokens` | `usage.completion_tokens` (when usage present) |

## `trustgate.*` attributes

| Attribute | Source |
|-----------|--------|
| `trustgate.schema_version` | `schema_version` |
| `trustgate.kind` | `kind` |
| `trustgate.trace_id` | `trace_id` |
| `trustgate.gateway_id` | `gateway_id` |
| `trustgate.tenant_id` | `tenant_id` |
| `trustgate.consumer.id` | `consumer.id` |
| `trustgate.consumer.name` | `consumer.name` |
| `trustgate.auth.id` | `auth_id`: the id of the auth that authenticated an LLM proxy request (`/<slug>/v1/*` and `/store/v1/*`, where it is the personal key). Omitted when no auth id was resolved; MCP records do not carry it yet |
| `trustgate.principal.subject` | `principal_subject` (inbound identity: OIDC `sub`, the API key name for an application key, or the key owner for a personal key) |
| `trustgate.principal.method` | `principal_method` (`api_key`, `jwt`, `introspection`, `mtls`) |
| `trustgate.principal.email` | `principal_email` (display identity: inbound JWT `email` / `upn` / email-shaped `preferred_username`, or the unique vault `account_ref` when that is an email) |
| `trustgate.session_id` | `session_id`: the conversation id resolved by the session middleware (see [sessions](../sessions.md)). Omitted when the request belongs to no conversation, i.e. a non-Responses request whose id the gateway generated; count sessions on distinct non-empty values |
| `trustgate.turn_id` | `turn_id` |
| `trustgate.ip` | `ip` |
| `trustgate.requested_model` | `request.requested_model` |
| `trustgate.model_label` | `request.model_label` |
| `trustgate.status.outcome` | `status.outcome` |
| `trustgate.status.reason` | `status.reason` (when set) |
| `trustgate.status.is_timeout` | `status.is_timeout` (omitted when false) |
| `trustgate.usage.total_tokens` | `usage.total_tokens` |
| `trustgate.usage.cached_input_tokens` | `usage.cached_input_tokens` (when > 0) |
| `trustgate.usage.reasoning_output_tokens` | `usage.reasoning_output_tokens` (when > 0) |
| `trustgate.cost.total_usd` | `cost.total_usd` (when cost present; registry pricing + catalog) |
| `trustgate.cost.prompt_usd` | `cost.prompt_usd` (when cost present) |
| `trustgate.cost.completion_usd` | `cost.completion_usd` (when cost present) |
| `trustgate.cost.currency` | `cost.currency` (when cost present) |
| `trustgate.cost.savings_usd` | `cost.savings_usd` (when smart routing's tier table chose the route) |
| `trustgate.latency.total_ms` | `latency.total_ms` |
| `trustgate.latency.provider_ms` | `latency.provider_ms` |
| `trustgate.latency.policies_ms` | `latency.policies_ms` |
| `trustgate.latency.gateway_ms` | `latency.gateway_ms` |
| `trustgate.is_flagged` | `is_flagged` (bool) |
| `trustgate.security` | `security[]` string array (when non-empty) |
| `trustgate.policy_chain` | `policy_chain[]` as JSON string (when non-empty) |
| `trustgate.attempts` | `attempts[]` as JSON string (when non-empty) |
| `trustgate.attempts.count` | `len(attempts)` (when non-empty) |
| `trustgate.mcp.method` | `mcp.method` (JSON-RPC method, e.g. `tools/call`) |
| `trustgate.mcp.operation` | `mcp.operation` (`tool`, `discovery`, `prompt`, `resource`, `initialize`) |
| `trustgate.mcp.server_name` | `mcp.server_name` (federated MCP registry name the call was routed to) |
| `trustgate.mcp.registry_id` | `mcp.registry_id` |
| `trustgate.mcp.host` | `mcp.host` |
| `trustgate.mcp.catalog_code` | `mcp.catalog_code` |
| `trustgate.mcp.transport` | `mcp.transport` |
| `trustgate.mcp.tool` | `mcp.tool` (exposed tool name as the client called it) |
| `trustgate.mcp.upstream_tool` | `mcp.upstream_tool` (upstream tool name when it differs) |
| `trustgate.mcp.prompt` | `mcp.prompt` |
| `trustgate.mcp.resource_uri` | `mcp.resource_uri` |
| `trustgate.mcp.targets` | `mcp.targets` |
| `trustgate.mcp.upstream_status` | `mcp.upstream_status` |
| `trustgate.mcp.upstream_latency_ms` | `mcp.upstream_latency_ms` |
| `trustgate.mcp.rpc_error_code` | `mcp.rpc_error_code` |
| `trustgate.mcp.account_ref` | `mcp.account_ref` (connected upstream account for this call, typically the OAuth email stored in the vault) |
| `trustgate.mcp.decision` | `mcp.decision` (call-level outcome; only `failed_open` today, when a plugin stage failed on a non-block error and the call proceeded uninspected. Omitted when nothing at that level failed — a per-plugin decision still lives in `policy_chain[]`) |
| `trustgate.mcp.tool_risk` | `mcp.tool_risk` (tools/call only: the called tool's risk from the MCP annotations its server declares — `read_only` when `readOnlyHint` is true, else `destructive` unless `destructiveHint` is false (the protocol default), else `additive`. Omitted when the tool declares none of the four hints: unannotated tools are never guessed. Advisory, the server's own claim) |
| `trustgate.mcp.tool_open_world` | `mcp.tool_open_world` (bool; the tool's `openWorldHint`, `true` by default once any hint is declared. Omitted with `tool_risk`) |
| `trustgate.retention.expires_at` | `retention.expires_at` (epoch millis, int64; only when the gateway carries a stamped plan retention) |
| `trustgate.retention.plan` | `retention.plan` (the plan label the window came from; omitted when empty) |

### Latency semantics

The four latency attributes split the request wall clock into stages that can be acted on
separately:

| Attribute | Meaning |
|-----------|---------|
| `total_ms` | Wall clock from the moment the gateway accepted the request until the response was written. |
| `provider_ms` | Time spent in the upstream provider, summed across attempts (retries and fallbacks included), **net of any time a streaming policy held bytes back during drain** — see below. |
| `policies_ms` | Time spent in the policy chain across **every** stage: `pre_request`, `pre_response` and `post_response`. |
| `gateway_ms` | The gateway's own overhead: routing, adapter translation, serialization. |

`post_response` policies run after the client already received its response, so the client
never waited for them. `gateway_ms` therefore discounts that asynchronous share:

```
gateway_ms  = max(0, total_ms - provider_ms - blocking_policies_ms)
total_ms    = provider_ms + blocking_policies_ms + gateway_ms
```

where `blocking_policies_ms` is the `pre_request` + `pre_response` share of `policies_ms`.
Discounting the async part is what makes the attribute usable: it is routinely larger than
the gateway's own overhead, so counting it drives the remainder negative and flattens
`gateway_ms` to zero on most requests.

#### The streamed response leg is blocking

A policy that inspects a streamed response block by block runs **during stream drain**,
after the `pre_response` stage has already returned. It holds bytes the client is waiting
for, so it is client-visible latency, and the split above has no third bucket for it: it
is neither a stage that ran before the response nor an asynchronous pass that ran after.

It is resolved into `blocking_policies_ms`, not into a bucket of its own. The policy-chain
entry for a streamed leg carries `stage: pre_response`, which the fold already counts as
blocking, and the entry's `latency_ms` is set explicitly to the time **that policy** spent
deciding while bytes were held — **not** to the span's wall clock. The distinction
matters: a stream span opens on the first block and ends when the stream does, so its
default wall clock would be the whole drain, provider generation included, and
`policies_ms` on a streamed request would come out at roughly the whole request.

**The overlap is resolved out of `provider_ms`, so the reconciliation holds on a streamed
leg too.** The block loop runs *during* drain, so the hold elapses inside the provider
span and the raw attempt sum contains it. Left there it would be counted twice — once as
provider time and once in `blocking_policies_ms` — the remainder would go negative and
`gateway_ms` would clamp to zero on every streamed request with per-block inspection
enabled. `provider_ms` is therefore reported net of the streamed share:

```
provider_ms = max(0, sum(attempt latencies) - streamed_policies_ms)
```

where `streamed_policies_ms` is the part of `policies_ms` contributed by policies that
inspected the response block by block.

Be clear about what this is: **a convention, not a measurement.** The provider keeps
generating while the guard decides, so the two really do overlap, and no split of that
overlap is the "true" one. Attributing it to the policy is the useful choice, because the
policy is what made the bytes late and it is the only one of the two an operator can
switch off. The consequence is that on a streamed request `provider_ms` is **lower** than
the upstream call's wall clock by exactly the guard's hold. To chart raw upstream time on
a streamed leg, add back the `pre_response` entries of `trustgate.policy_chain`.

Four consequences for anyone charting this:

- `provider_ms` is not the upstream span's wall clock on a streamed request. Comparing it
  against a provider-side latency metric will show the guard's hold as a gap.
- `policies_ms` on a streamed request grows when per-block inspection is enabled. That is
  a real change in what the client waited for, not an accounting artefact.
- The per-entry `latency_ms` of a streamed leg is **not** `ended_at - started_at`. Do not
  reconstruct it from span timestamps: a stream span opens on the first block and ends
  when the stream does, so its wall clock is the whole drain. Each streaming policy sets
  its own figure explicitly when the stream closes.
- Each streaming policy is charged its own share, so the sum over a chain of N streaming
  policies is one hold, not N. The figure a policy reports is what that policy cost, never
  what the chain around it cost — and so the deduction from `provider_ms` is one hold too.

The deduction applies to the LLM proxy path only. An MCP `tools/call` has no stream drain
for a policy to run inside, so its `provider_ms` is the upstream sum unchanged.

The per-stage split is deliberately **not** duplicated into its own attribute — it is
derivable from `trustgate.policy_chain`, where each entry already carries `stage` and
`latency_ms`. To chart the full policy cost use `policies_ms`; to chart what the client
actually waited for, subtract the `post_response` entries of the policy chain:

```sql
SELECT
  JSONExtractInt(latency, 'policies_ms') AS policies_ms,
  arraySum(arrayMap(
    p -> if(JSONExtractString(p, 'stage') = 'post_response', JSONExtractInt(p, 'latency_ms'), 0),
    JSONExtractArrayRaw(policy_chain)
  )) AS policies_async_ms
FROM trustgate_events
```

### Streamed response inspection

A policy that inspects a streamed response per block emits **one** policy-chain entry for
the whole stream, not one per block. Its `extras` carry a `streaming` object, written once
when the stream ends because span extras are replaced rather than merged — a per-block
write would leave only the last block's account of a response that took several.

Several streaming policies can inspect the same response, and each gets its own entry. The
**Scope** column says whether a key answers for that policy or for the response as a
whole. A per-stream key repeats, byte for byte, on every entry of the same stream: sum a
per-policy key across entries, never a per-stream one.

| Key | Scope | Meaning |
|-----|-------|---------|
| `streaming.enabled` | stream | The leg ran with per-block inspection. Always `true` when the object is present |
| `streaming.stream_id` | stream | Correlates the evaluate calls of this response leg. Derived from the trace id; distinct from `session_id`, which spans the conversation |
| `streaming.evals_total` | stream | Blocks handed to the chain |
| `streaming.guard_calls` | stream | Blocks that came back with a verdict. `evals_total - guard_calls` is the number that failed |
| `streaming.guard_latency_ms_total` | policy | Time this policy spent deciding, summed over the stream's blocks. This is the value the entry's own `latency_ms` carries |
| `streaming.guard_latency_ms_max` | stream | The slowest single block, measured across the chain |
| `streaming.added_latency_ms` | stream | How long held text waited before reaching the client, summed over blocks. **Not** a policy's own cost and **not** gateway overhead — see below |
| `streaming.final_pass` | stream | A block covering the end of the response was inspected. `false` means the tail went uninspected on this leg |
| `streaming.cut_at_eval` | policy | The block at which the stream stopped, on the policy the stop is attributable to. `0` on every policy that did not cut, which is every observe-mode policy |
| `streaming.cut_offset_chars` | policy | Characters the client had **already received** when the cut landed. Not what the provider had produced — this is the exposure the cut did not prevent, and the number `min_chars_between_evals` sets |
| `streaming.degraded_reason` | stream | Why one block was released without the verdict the policy asked for |
| `streaming.fallback_reason` | stream | Why per-block inspection stopped for the rest of the stream |

Every key is emitted even when zero. Once the object is present a zero is an answer — "no
cut", "no degradation" — and dropping it would make an absent key ambiguous with a leg
that never reported.

Since RUN-1745:

- **Only policies that take part in per-block inspection get an entry.** A policy of a
  streaming-capable plugin takes part unless its `streaming.enabled` is `false`, or absent
  for a plugin whose default is off (`bedrock_guardrail`). A policy that opted out is no
  longer walked per block, so it writes no streamed entry with no decision. Its settings no longer failing to parse
  cannot fail the blocks of a stream another policy opted into.
- **A cut on a failure is the failing policy's.** When a block's call fails and
  `streaming.on_error` is `fail_closed`, `cut_at_eval` lands on the policy whose call
  failed, not on a policy that masked the same block. A mask that `fail_open` could not
  apply is still the masking policy's cut.
- **A masked stream says so.** An enforcing policy whose mask reached the client reports
  the same decision as its buffered leg: `transformed` (`trustguard`) or `anonymized`
  (`bedrock_guardrail`, `google_model_armor`); it used to read `allowed`.
  `regex_replace` in observe mode reports `observed`, not `rewritten`.
- **Per-response metrics are recorded once per plugin.** The policy that reports the
  stream is chosen per plugin (the one that cut, else the first in the chain), so
  `trustguard_stream_*` is written whenever a TrustGuard policy inspected the stream, even
  when another plugin cut it or came first.

#### `added_latency_ms` and `guard_latency_ms_total` are different quantities

They are not two views of one number and neither bounds the other. Only
`guard_latency_ms_total` is what the policy chain cost, and it is the one the entry's
`latency_ms` carries; `added_latency_ms` answers a different question and belongs on no
latency ledger.

`added_latency_ms` is charged from the moment the oldest unreleased event arrived to the
moment a flush released it, summed over the blocks that released something. Between those
two moments the gateway is still pulling from the provider, so each term is **block fill
plus the verdict's round trip** — and block fill is the provider generating the rest of
the block. It is therefore a sum of per-block worst cases, not a delay added to the
request: within a block only the first event waits the whole term and the last waits
almost nothing.

Two consequences:

- **Do not add it to `gateway_ms`, and do not treat it as gateway overhead.** Most of it
  is provider time already counted in `provider_ms`; adding it back is the
  double-subtraction the per-entry `latency_ms` exists to prevent.
- **`added_latency_ms` can be `0` against a real hold.** It is charged only where a flush
  released something, so a head-of-stream block that released nothing, a mid-stream cut
  whose last verdict released nothing, and a client that disconnected all report `0` with
  a non-zero round trip behind them. A zero here means "nothing was ever handed over after
  waiting", not "nothing waited".

New tokens. `degraded` is per block and recoverable; `fallback` retires inspection for the
rest of the stream; `skip_reason` says the leg never inspected anything at all:

| Token | Field | Meaning |
|-------|-------|---------|
| `accumulation_cap` | `degraded_reason` | The payload crossed its size cap and the block was inspected against a tail window rather than the whole prefix |
| `guard_timeout` | `degraded_reason` | A block's verdict did not arrive within `guard_timeout` and the held text was released uninspected |
| `guard_error` | `degraded_reason` | A block's call failed for another reason (the provider rejected it, a transport error) and the held text was released uninspected. Before RUN-1745 these read `guard_timeout` |
| `tool_input_uninspected` | `degraded_reason` | A native Amazon Bedrock stream released a tool call without its input having been read by the policies as a text of its own: the call outgrew the hold (the configured hold, `BEDROCK_NATIVE_TOOL_HOLD`, 30 seconds by default, or the bytes the guard keeps), the stream ended before it closed, another frame sat inside it, its start had already been released, or its model family's tool calls are not understood. The call is not cut. It stays the reason of the stream when a later `accumulation_cap`, `guard_timeout` or `guard_error` would have replaced it |
| `segmentation_unavailable` | `fallback_reason` | Consecutive failures retired per-block inspection. The buffered `post_response` pass still audits the whole response |
| `client_disconnected` | `fallback_reason` | The client stopped reading. Inspection stops; no further calls are issued |
| `provider_not_streaming` | `skip_reason` | The leg ran with per-block inspection and no block ever closed. Emitted with `skipped: true`, so it is distinguishable from a stream inspected and found clean. The token names the common cause but not the only one: a response that did stream and was wholly opaque — no assistant text, reasoning or tool call to close a block on — reports it too |
| `inspected_as_stream` | `skip_reason` | The `pre_response` leg of a streamed LLM response whose policy opted into per-block inspection. The leg runs with headers only and hands the response to the stream guard, which writes its own entry. Emitted with `skipped: true`, but it is not a coverage gap: the response is inspected block by block and audited again by `post_response` |
| `streaming_stage_mismatch` | `skip_reason` | The leg does not handle this response mode: a streamed `pre_response` with per-block inspection off or not selected (and every MCP streamed leg), or a buffered `post_response`. Another leg handles the response |
| `empty_response_body` | `skip_reason` | A buffered response leg that arrived with no body, so there was nothing to send to the guard |
| `stream_cut` | `skip_reason` | The `post_response` leg of a stream the stream guard cut mid-way. What was delivered ends on the cut terminator and nothing after the cut reached the client; the guard's own entry already reports `blocked`, so the truncated body is not inspected again. Emitted with `skipped: true`, but it is not a coverage gap. A stream that completes, degrades or whose client disconnects without a cut keeps its `post_response` audit |

**A cut is not always a verdict.** Under `on_error: fail_closed` a guard call that fails
outright stops the stream too, and that stop is reported the way a verdict's is:
`cut_at_eval` names the block and the decision is `blocked`, on every policy that could
have blocked. Nothing in `degraded_reason` marks it — fail_closed does not degrade, it
stops — so the tell is `guard_calls` short of `evals_total` on a leg with a cut. Read
`cut_at_eval` as "the block at which the stream stopped", not "the block whose verdict
stopped it".

**`status.reason` does not yet name a mid-stream cut.** It is set on the error path only
(`writeProxyError`), so a head-of-stream block — which happens before a single byte is
written and is a real HTTP 403 — carries a reason, while a cut after the first release is
an HTTP 200 whose `status.reason` is empty. On the wire the response ends with the
dialect's content-filter terminator, and on the event the cut is visible only through
`streaming.cut_at_eval`. Charting cuts means reading that field, not `status.reason`.

### External guardrail failures

`azure_content_safety`, `bedrock_guardrail`, `google_model_armor` and `openai_moderation`
record a failure to reach a verdict the same way. On the buffered (non-streamed) leg they
**fail open** by default, in every mode and for every `failure_reason`: a guardrail the gateway
could not consult does not refuse the request (RUN-1792). A policy can opt out with
`settings.on_error: fail_closed`. The stream leg is covered by RUN-1786. The entry's `decision` says what happened to the request:

| Mode | `on_error` | `decision` | Request |
|------|------------|------------|---------|
| enforce, throttle or observe | `fail_open` (default) | `failed_open` | Forwarded; the chain carries on |
| observe | `fail_closed` | `failed_open` | Forwarded; observe never refuses |
| enforce or throttle | `fail_closed` | `failed_closed` | Refused with HTTP 502 `guardrail_unavailable` |

Under `fail_closed`, `decode_failed` refuses too: a body the guardrail could not read is a body it
did not inspect. A `config_invalid` failure on settings that could not be parsed at all fails open,
since `on_error` is one of those settings.

Their `extras` carry two keys:

| Key | Meaning |
|-----|---------|
| `failure_reason` | `transport` (the call failed or returned non-2xx), `verdict_incomplete` (the provider answered without covering what the policy asked for), `config_invalid` (the stored settings or credentials could not be used), `decode_failed` (the gateway could not read the body) |
| `failure_detail` | Optional. The category, or the Model Armor sub-reason, that produced no verdict |

A streamed response leg follows `streaming.on_error` for enforce entries; an observe entry
that fails records `failed_open` and never cuts the stream.

**Changed in RUN-1786.** `google_model_armor` and `openai_moderation` inspect a streamed
response by default: a policy with no `streaming` block is on, and `streaming.enabled: false`
is the opt-out (the trace then marks it `skipped` with `skip_reason: streaming_disabled`).
`bedrock_guardrail` stays **opt-in** (`streaming.enabled: true`): every block resends the
accumulated prefix to ApplyGuardrail, whose on-demand quota is per account and region (25 text
units per second in most non-US regions), so inspecting every stream by default would throttle
the customer's buffered requests too. Until the console exposes the control (RUN-1661) a
Bedrock policy with no `streaming` block records `skipped` / `streaming_disabled` on a streamed
response. For all three, the stream leg fails **open** by default once it takes part, as the
buffered leg does since RUN-1792: a provider error or timeout on a block
releases the held text and does not cut the stream. A policy that wants the old behaviour sets
`streaming.on_error: fail_closed`.

When the stream leg has several participants the stream still runs on one head gate and one
cadence (the first participant that owns them), but two options are merged across the chain:
`on_error` is `fail_closed` when any enforcing policy asked for it, and
`max_accumulated_bytes` is the smallest any participant asks for. `on_error` is also resolved per policy:
a failing policy that resolved `fail_open` is recorded `failed_open` and the chain carries on
with the next policy on the same block, so another policy's `fail_closed` neither cuts the
stream on its behalf nor stops the policies behind it from inspecting. A `fail_closed` cut is
labelled `failed_closed` on the failing policy (RUN-1710; it used to read `blocked`), at the
head (HTTP 403) and after it. Only the policy whose own call failed carries it: the other
policies on the stream do not, and a cut that is a block verdict, or a mask that could not be
applied, stays `blocked`.

When a policy's own provider call failed on at least one block and the stream was not cut,
its `decision` is `failed_open`, in enforce and in observe alike. The count is per policy:
two policies of one plugin on the same stream, one with a bad key, label only the bad one.
Cancellation (a client that left) is not a failure. The `decision` of a stream leg is, in
order of precedence: a cut that resolved this policy's own failed call as fail_closed
(`failed_closed`), any other cut (`blocked`), a mask (`anonymized`), a finding (`reported`), a
failed block (`failed_open`), otherwise `allowed`; a positive finding is never hidden behind
a missing inspection. `streaming.degraded_reason` is a different, chain-wide signal and is
not what the decision is read from: it is one value for the whole stream, overwritten by a
later size degrade, and the failure of an observe policy, or of an enforcing policy that
resolved `fail_open`, never reaches it (the chain absorbs it per policy).

**Streamed failures carry their reason (RUN-1710).** `bedrock_guardrail`, `google_model_armor`
and `openai_moderation` write `failure_reason` and `failure_detail` (the same vocabulary and keys
as the buffered leg, above) on the stream entry's `extras`, once, when the stream closes. They
are present whenever the policy's own call failed on at least one block, whatever the final
`decision`: a stream whose first block failed and which was later cut by a finding still says
`decision: blocked` with the failure's `failure_reason`. With several failed blocks the **first
failure that carries a reason** is kept; later failures, which are usually the same outage
repeating, do not overwrite it. A failure of a plugin that does not use the shared vocabulary
carries no reason and is not tracked, so a later one that does carry a reason is the first kept. If the closing call itself fails, the entry still gets a decision (`failed_open`, or
`failed_closed` when the guard's fail_closed cut was on that policy's failed call) and, when a
reason is known, a minimal `extras` of `decision`, `failure_reason` and `failure_detail`. The
keys are additive: nothing that shipped is renamed or retyped.

A policy absorbed this way whose provider fails on three blocks in a row is not called again
for the rest of that stream: its span keeps `failed_open` and carries
`streaming.fallback_reason: entry_retired`, and the other policies keep inspecting every
block. A retired policy is not retried for the rest of that stream, and from then on it
lowers `streaming.guard_calls` on every later block (each is a block without its verdict).
`streaming.guard_calls` counts only the blocks that got every verdict, so an absorbed
failure leaves it short of `evals_total`.

**Changed in RUN-1792.** An enforce-mode failure used to record `failed_closed` and refuse the
request with HTTP 502 (`guardrail_unavailable`); it now records `failed_open` and forwards it,
exactly as observe always did. This replaces the RUN-1672 fail-closed rule. When a usable
mask is available (Model Armor `sdp_action: anonymize` with a missing `block_on` filter),
it is still applied: the decision is `anonymized` and the event also carries
`failure_reason: verdict_incomplete`.

One deliberate exception stays fail-closed: in enforce, when Model Armor or Bedrock flags
sensitive data in an anonymize configuration but returns no masked output
(`degraded_reason: anonymize_no_output`, `reasonAnonymizeNoOutput`), the request is blocked,
because the provider confirmed the data and gave the gateway no way to mask it. The same
applies to the other degraded reasons (unsupported format, encode failure).

**Changed in RUN-1672.** `azure_content_safety` no longer emits the `failed_open` boolean,
and its observe-mode failures used to say `failed_closed`. `google_model_armor`'s
`failure_reason` used to carry `filter_not_in_template` / `filter_not_executed`; those
values now travel in `failure_detail`, next to `failure_reason: verdict_incomplete`.
`openai_moderation`'s enforce failures used to say `unavailable`.

### Native Amazon Bedrock Runtime calls (`native_bedrock_passthrough`)

A call to a native Bedrock Runtime route (`/{slug}/model/{modelId}/converse`, `converse-stream`,
`invoke`, `invoke-with-response-stream`) is relayed as the client sent it, so policies cannot
rewrite it the way they rewrite a translated one. Three outcomes are recorded in
`policy_chain[]`, all under the entry name **`native_bedrock_passthrough`** (one constant,
`appplugins.BedrockNativePassthrough`):

| Entry | When | `decision` | Extras |
|-------|------|------------|--------|
| A plugin that did not run | `prompt_template`, `tool_injection`, `prompt_compression` and `semantic_cache`, which transform the request and have nowhere to write on a relayed call | none (`skipped: true`) | `stage`, `skipped: true`, `skip_reason: native_bedrock_passthrough` |
| A mask that could not be applied | A masking policy (`regex_replace`, `trustguard`, `bedrock_guardrail`, `google_model_armor`) changed the text a call carries and the change could not be carried onto the client's bytes safely, and the policy's `on_mask_failure` is `pass` (the default). The call goes through unmasked | `failed_open` | `decision: failed_open`, `stage` (`pre_request` or `pre_response`), `mode`, `failure_reason: mask_not_applicable:<cause>`, `streamed: true` on a stream |
| A refusal | A policy that does not mask rewrote the call (a tool filter, a per-tool limit that strips a tool, a model downgrade), or a masking policy whose `on_mask_failure` is `block` could not apply its mask. The call is blocked with HTTP 403 (`AccessDeniedException`) and the error type `native_bedrock_passthrough`. On a stream the stream ends like a block verdict | the policy's own (`block`) | the error of the block |

`failure_reason` is `mask_not_applicable:` followed by one of these causes, which are additive
tokens:

| Cause | Meaning |
|-------|---------|
| `decode_failed` | The original body or the policy's could not be read |
| `not_a_text_replacement` | The policy added text, or changed something that is not text |
| `short_value_place_unknown` | A value under three characters whose place in the call could not be established |
| `signed_block` | The mask would edit a signed thinking or reasoning block |
| `patch_failed` | The substitutions could not be written into the original bytes |
| `outside_read_strings` | Something outside the text the policies read would have changed |
| `shape_mismatch` | The masked call does not read as the policy's own result |
| `leak_remaining` | Text the policy removed would remain somewhere in the result (a key, a number, a signed block) |
| `error_response` | The response is an AWS error, which is never masked |
| `reasoning_not_maskable` | A stream window holds model reasoning |
| `tool_call_not_held` | A stream window holds a tool call the guard could not hold whole, or of a family whose tool calls are not understood |
| `already_released_text` | The mask reaches text the client has already read |
| `already_released_input` | The removed text is in tool input or reasoning that was already released |
| `no_inspected_window` | The verdict does not name a window of the held text |
| `tool_input_not_maskable` | The mask is not a replacement inside a string of the tool input, or the input is not valid JSON or does not read back exactly |
| `tool_frames_not_rewritable` | The held frames of a tool call cannot be rewritten |

A failed-open entry is written once per kind of cause on a request, or on a stream.
`on_mask_failure` (`pass` or `block`) is a setting of the policies that mask; it changes the
outcome of a mask that cannot be applied from `failed_open` to a block, and nothing else.

### Counter-store (rate-limit / budget) failures

`rate_limiter`, `per_tool_rate_limiter` and `token_rate_limiter` all read and write a
counter in Redis on every call. An outage here is
**TrustGate's own infrastructure**, not a third party the operator asked to gate traffic:
the product rule is that our own infrastructure fails open, in every mode, enforce
included. The external guardrails above follow the same rule, so no mode-dependent branch
exists for either, apart from the `partition: key` exception below:

| Mode | `decision` | Request |
|------|------------|---------|
| enforce, throttle or observe | `failed_open` | Forwarded; the chain carries on |

This applies to both legs of the counter: a failed read (the limit/budget could not be
checked) and a failed record/accrue (the check passed but the write-back failed) both
fail open the same way — a successful read that only fails to persist must not turn into
a refusal.

**Exception: `token_rate_limiter` with `partition: key`.** A failed read in enforce records
`failed_closed` and refuses the request with HTTP 503, error type `budget_unavailable`.
Observe keeps `failed_open`, a failed accrual after the response still fails open, and every
other partition and plugin keeps the table above.

**Exception: a canceled or timed-out request is not an outage.** When the request itself
was already canceled or past its deadline (a client disconnect, an upstream timeout
unwinding the chain), the counter-store call failing is a symptom of that, not evidence our
infrastructure is down. That case emits no `failed_open` decision, no `counter_unavailable`
extras and no warning: the plugin's error simply propagates as it would have without this
behavior.

Their `extras` carry the same two keys the external guardrails use, plus whatever the call
already knew before the counter store failed:

| Key | Meaning |
|-----|---------|
| `failure_reason` | Always `counter_unavailable` |
| `failure_detail` | Which counter operation failed: `read` / `record` (`rate_limiter`, `per_tool_rate_limiter`), or `read_counter` / `record_tokens` / `record_cost` (`token_rate_limiter`) |

For example, `rate_limiter`'s extras keep `rate_limit_exceeded`, `current_count` and
`limit` from the read that already succeeded, and `token_rate_limiter`'s keep `provider`,
`model` and any cost-cap fields — a record failure never wipes out what the read (or the
request itself) already established.

### Ran but had nothing to evaluate (`per_tool_rate_limiter`)

A `policy_chain[]` entry normally exists only when the plugin recorded something: the builder
drops a span with no decision, extras, score or error. `per_tool_rate_limiter` on a
`pre_request` leg whose request declares no tools, or none matching a rule, used to record
nothing, so the entry vanished and looked the same as a policy that was never attached. It now
records the same `skipped` / `skip_reason` keys `trustguard` uses (additive, only on these entries):

| Key | Meaning |
|-----|---------|
| `stage` | `pre_request` |
| `skipped` | Always `true` |
| `skip_reason` | `no_tools` (no tool declared, no tool result to count, or an MCP call with no tool name) or `no_matching_rule` (tools present, none matches a rule) |

The entry carries **no `decision`**, so it is neither allowed nor blocked and is never `flagged`.
This is opt-in per plugin: every other plugin that runs and records nothing is still dropped
from the chain. It does not distinguish "not evaluated" from "not attached to this consumer";
that needs the consumer's policy set and is not carried by the event.

**Decision precedence when a window was already found exceeded.** `rate_limiter` runs in
throttle or observe when its read already finds the window over budget (enforce would have
refused the request outright, before any record is attempted). If the record that follows
then fails, the `throttle` / `observe` decision from that exceeded read wins over
`failed_open`: the exceeded signal is what those modes exist to report, and
`failure_reason: counter_unavailable` still travels in the same extras to say the
write-back failed on top of it. A read that was not already exceeded keeps `failed_open`.

As a second layer, any policy running in a non-blocking mode (observe) that fails with an
error of its own — from any plugin, not just this family, whenever that plugin did not
already fail itself open — is also forwarded rather than surfaced as a gateway error, the
same way a streamed response already handles an observe-mode inspection failure.

**New in RUN-1675.**

### TrustGuard failures

`trustguard` treats a failure of TrustGuard itself differently from the providers above:
it **fails open by default**, so a TrustGuard problem never cuts the client's request.
A policy opts into refusing with `on_error: fail_closed`, and `on_timeout: fail_closed`
for timeouts. An unset `on_timeout` inherits `on_error`. A TrustGuard block (a finding)
and a 429 rate limit are the guard's answers, not failures, and always block.

| `on_error` / `on_timeout` | `decision` | Request |
|---------------------------|------------|---------|
| `fail_open` (default) | `failed_open` | Forwarded uninspected; the chain carries on |
| `fail_closed` | `failed_closed` | Refused (502, 503 or 504 depending on the reason) |

`extras.failed_open` / `extras.failed_closed` is set to match, and `extras.failure_reason`
names the cause. The same token labels `trustguard_evaluate_failures_total{reason}`:

| `failure_reason` | Cause |
|------------------|-------|
| `transport` | The call failed, or returned a non-2xx status other than the ones below |
| `timeout` | The call did not answer within the policy's `timeout` (governed by `on_timeout`) |
| `unauthorized` | `/v1/evaluate` answered 401 (after one token refresh) or 403, or `/v1/token` answered 400, 401 or 403 |
| `entitlements_unavailable` | `/v1/evaluate` answered 503 |
| `credentials_missing` | The gateway has no `TRUSTGUARD_CLIENT_ID` / `TRUSTGUARD_CLIENT_SECRET` |
| `base_url_missing` | The gateway has no `TRUSTGUARD_BASE_URL` |
| `transform_failed` | TrustGuard asked for a mask the gateway could not write back; `degraded_reason` says which step failed. Under `fail_open` the content is forwarded **unmasked**. Under `fail_closed` the request is blocked and the decision is `blocked`, because TrustGuard did find something |
| `config_invalid` | The stored settings could not be parsed. Always `failed_open`: there is no `on_error` to read |
| `gateway_id_missing` | The request carried no gateway id. Always `failed_open` |
| `payload_unreadable` | The gateway could not read the body. Always `failed_open` |

On a streamed response leg the plugin resolves `streaming.on_error` itself. Under
`fail_open` it allows the block, so later policies in the chain still inspect it, and the
closing event carries `decision: failed_open` with the last `failure_reason`. After three
failed blocks in a row the policy stops calling TrustGuard for the rest of that stream, and
the closing event also carries `streaming.fallback_reason: segmentation_unavailable`. A block
the guard does answer resets the count. A stream that was cut reports `blocked` even if earlier
blocks failed open; those still count in `trustguard_evaluate_failures_total`. Under
`fail_closed` the block is returned as a failure and the stream is cut. The
`trustguard_stream_evals_total` / `trustguard_stream_responses_total` metrics label such a
stream `outcome="failed_open"`, ranked just below `blocked`; the label reflects the policy
that reports the stream, so on a route with two TrustGuard policies read the other one's span.
Without a stream identity (telemetry disabled, so no trace) nothing is recorded per stream:
each failed block fails open on its own and inspection never retires.

**Changed in RUN-1725.** Rejected or missing credentials, a missing base URL and a 503 used
to always fail closed, and an unappliable mask always blocked; all now follow `on_error`.
`on_timeout` used to default to `fail_closed`; it now inherits `on_error`, whose default is
`fail_open`. Policies saved through the console since `on_timeout` was added hold an
explicit `on_timeout: fail_closed` and keep it. On a stream these failures used to be
reported as `degraded_reason: guard_timeout`; they now appear as `failed_open` on the
closing event.

### Savings semantics

`trustgate.cost.savings_usd` is what smart routing avoided spending on this
request: the request's own token counts repriced at the **highest configured
tier**, minus what the request actually cost. It rides inside the cost group
rather than a group of its own, so a single column carries it.

```
savings_usd = (prompt_tokens * top_tier_input_rate + completion_tokens * top_tier_output_rate) - cost.total_usd

# prompt_tokens is the whole prompt, cache reads and writes included. The two
# legs are asymmetric by design: the served leg prices its cached share at the
# cache rates, the baseline leg does not. See below.
```

The baseline total is not emitted separately — it is `cost.total_usd + cost.savings_usd`.

"Highest tier" is the tier with the greatest `min_score` — the one a maximal
complexity score selects. It orders by threshold, not by price: a misconfigured
ladder that puts an expensive model at a low threshold yields a **negative**
`savings_usd`, which is left unclamped so the misconfiguration stays visible.

The attribute is emitted only when the tier table itself chose the route. Smart
routing silently falls back to round-robin whenever the scorer is unconfigured,
the score is unavailable, or the mapped tier has no available candidate — those
requests emit nothing rather
than crediting a decision smart routing never made. A baseline whose model has no
resolvable price likewise emits nothing, because a zero would be
indistinguishable from "the top tier was already served". A request that *was*
served by the top tier emits `savings_usd` exactly `0`. Absent and zero are
therefore different answers, which is why the field is nullable.

Both legs are priced through the same resolution ladder — registry overrides,
then catalog rates × `1 - discount` — with the baseline using its own registry's
overlay, which is not necessarily the served registry's. Plugin-level custom
pricing is deliberately not consulted for either leg, so the event's cost and
savings always describe registry and catalog rates.

The figure is a **modelled counterfactual, not a measurement**. It reprices the
served model's tokens, but a premium model tokenizes differently and stops at a
different completion length.

The two legs price cached tokens differently, and this is the assumption that
moves the number most. The served leg bills its cached share at the cache read
and write rates; the baseline leg prices the entire prompt at the plain input
rate. A route that was never taken has no warm cache to read from, so charging
the counterfactual a cache discount would credit it a saving it could not have
earned. The figure is therefore biased **upward** by an assumption that is
defensible but not neutral. The size of that bias is exactly the cached share
repriced from the plain input rate down to the baseline's cache read rate, so it
depends on the token mix: on a prompt-dominated request that is mostly a cache
hit it is worth roughly an order of magnitude, and on an output-dominated request
it is marginal. Reasoning-output tokens remain priced at the plain output rate
on both legs. Treat the whole figure as an estimate, and label it as one wherever
it is shown. Cost-cap model downgrades are
a separate mechanism and are not covered by this attribute.

The sink-1 example carries no `trustgate.cost.savings_usd`: its record is a
request that named `gpt-4o` explicitly, and naming a model bypasses the load
balancer entirely, so smart routing never runs for it.

## Raw stream

The raw data class carries the request/response bodies plus join keys. It is routed to any
exporter declared under `exporters.raw[]`:

| Sink | Content |
|------|---------|
| PostgreSQL `trustgate_data` | `request_body` + `response_body` only |
| OTLP (`otlp` under `raw`) | `trustgate.request.body` / `trustgate.response.body` + join keys |
| Join keys | `trace_id`, `gateway_id`, `tenant_id`, `occurred_on` |

The raw OTLP record emits `trustgate.schema_version`, `trustgate.trace_id`,
`trustgate.gateway_id`, `trustgate.tenant_id`, `trustgate.request.body`,
`trustgate.response.body`, and the retention pair — no other metadata attributes, no
policy chain. Raw bodies land in their own table, which needs its own expiry to key a
TTL on, so retention is deliberately not treated as metadata-only.

### Retention

`retention.expires_at` is `occurred_on + retention_days` of the plan stamped on the
gateway (`entitlements.retention_days`, set by the control plane). It is derived from
`occurred_on` rather than from wall-clock time at export, so a record's expiry can never
disagree with its own timestamp.

Two properties downstream storage can rely on:

- **Absent, never zero.** A gateway with no stamp emits no retention attribute at all. A
  `0` would read as "expired at the epoch", so the attribute is dropped instead and the
  sink's fallback decides.
- **`0` means unlimited**, the same sentinel `quota_per_month` and `max_instances` use.
  It is resolved to a concrete window (`UnlimitedRetentionWindow`, 10 years) before the
  expiry is computed, because a TTL needs a real date to compare against. That resolution
  happens in the gateway, not in the sink, so every exporter agrees on it — and it is
  bounded rather than far-future because ClickHouse `DateTime` is uint32 seconds and tops
  out in 2106. `TrustGuard` pins the same value.

## Severity

| `status.code` | OTLP severity |
|---------------|---------------|
| &lt; 400 | Info |
| 4xx | Warn |
| 5xx | Error |

## Examples

Per-sink example records: [`examples/`](./examples/). These are schema-accurate
representative records, not a live capture:

- [`sink-1-metadata-otlp.json`](./examples/sink-1-metadata-otlp.json) — OpenAI chat completion flagged by a DLP policy
- [`sink-2-raw-otlp.json`](./examples/sink-2-raw-otlp.json) — raw body class
- [`sink-3-mcp-metadata-otlp.json`](./examples/sink-3-mcp-metadata-otlp.json) — MCP `tools/call` with request identity, server, and tool

## Out of scope

- OTLP → ClickHouse ingestion (collector / data-plane)

## Traffic labels event

Gateways with `traffic_labeling.enabled` emit one extra record per labeled chat
request of a consumer that holds label sets, after the request itself, through
the gateway's `otlp` exporters (default and per gateway, metadata class only).
It is correlated with the request's `trustgate.<version>.metadata` and
`trustgate.<version>.raw` records by trace id. The record has one result per
label set the request was evaluated against; a set none of whose labels
applies still has its result, with `label` `""`, so unlabeled traffic can be
counted per set.

| Rule | Detail |
|---|---|
| Event name | `trustgate.<version>.traffic_labels`. Downstream routing keys on it |
| Prompt | **Never emitted**, nor anything derived from it: not the text, its hash or its length, nor the system prompt or the classifier's answer |
| Namespace | Every attribute is under `trustgate.label.*`, except the retention pair |
| Tenant | Sent as `trustgate.label.tenant_id`, **not** `trustgate.tenant_id`: the view that fills `trustgate_events` takes any record carrying that key and would count the labeling as one more request |
| Exporters | Only `otlp`. Postgres exporters never receive it: they key rows on the trace id |
| Timestamp | When the request was labeled. `trustgate.label.requested_on` is when it arrived |

| Attribute | Content |
|---|---|
| `trustgate.label.schema_version` | Version of this payload (int). `2` since label sets: the version that carries `results`. It is not the `<version>` of the event name |
| `trustgate.label.trace_id` | Trace id of the request, to join with its metadata and raw records |
| `trustgate.label.gateway_id` | Gateway id |
| `trustgate.label.consumer_id` | Consumer whose label sets were evaluated |
| `trustgate.label.tenant_id` | Tenant id |
| `trustgate.label.requested_on` | Unix ms when the request arrived (int) |
| `trustgate.label.results` | JSON `[{"label_set_id","label_set_name","label"}]`, one entry per evaluated label set in the consumer's order. `label` is the label name as spelled in the catalog, `""` when none applies |
| `trustgate.label.results.count` | Number of evaluated label sets (int) |
| `trustgate.label.registry_id` | Registry that ran the classification |
| `trustgate.label.model` | Model that ran the classification |
| `trustgate.label.catalog_hash` | Order-independent hash of the evaluated label sets: ids, names, instructions, label names and descriptions |
| `trustgate.label.usage.input_tokens` / `trustgate.label.usage.output_tokens` | Classifier token usage (int). `0` when the provider reports none or the result came from the cache |
| `trustgate.label.latency_ms` | Classifier call latency in ms (int). `0` for a cached result |
| `trustgate.retention.expires_at` / `trustgate.retention.plan` | Same expiry as the request event, counted from when the request arrived |

Version 1 of this payload, which never reached a release, carried
`trustgate.label.matched`, `trustgate.label.matched.count` and
`trustgate.label.evaluated` (single labels, several per request). Version 2
replaces them with `trustgate.label.results` and
`trustgate.label.results.count`; they are no longer emitted. Version 1 records
were stamped with the event name's version (`3`) in
`trustgate.label.schema_version`, so a reader tells them apart by the presence
of `trustgate.label.results`, not by the version alone.
