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
| `trustgate.principal.subject` | `principal_subject` (inbound identity: OIDC `sub`, or the API key name) |
| `trustgate.principal.method` | `principal_method` (`api_key`, `jwt`, `introspection`, `mtls`) |
| `trustgate.principal.email` | `principal_email` (display identity: inbound JWT `email` / `upn` / email-shaped `preferred_username`, or the unique vault `account_ref` when that is an email) |
| `trustgate.session_id` | `session_id` |
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
| `trustgate.retention.expires_at` | `retention.expires_at` (epoch millis, int64; only when the gateway carries a stamped plan retention) |
| `trustgate.retention.plan` | `retention.plan` (the plan label the window came from; omitted when empty) |

### Latency semantics

The four latency attributes split the request wall clock into stages that can be acted on
separately:

| Attribute | Meaning |
|-----------|---------|
| `total_ms` | Wall clock from the moment the gateway accepted the request until the response was written. |
| `provider_ms` | Time spent in the upstream provider, summed across attempts (retries and fallbacks included). |
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

**The reconciliation does not survive a streamed leg, and that is a known limitation.**
The block loop runs *during* drain, so the hold is inside the provider span: `provider_ms`
already contains the guard time that `blocking_policies_ms` now also carries. Subtracting
both leaves a negative remainder and `gateway_ms` clamps to zero on a streamed request
with per-block inspection enabled — not because the policy chain was charged the drain,
but because the two buckets overlap by construction. Do not read that zero as "the gateway
spent nothing", and do not reconcile `total_ms` against the three buckets on a streamed
leg. The chain's own cost is the entry's `latency_ms`, which stays honest either way.

Three consequences for anyone charting this:

- `policies_ms` on a streamed request grows when per-block inspection is enabled. That is
  a real change in what the client waited for, not an accounting artefact.
- The per-entry `latency_ms` of a streamed leg is **not** `ended_at - started_at`. Do not
  reconstruct it from span timestamps.
- Each streaming policy is charged its own share, so the sum over a chain of N streaming
  policies is one hold, not N. The figure a policy reports is what that policy cost, never
  what the chain around it cost.

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
| `guard_timeout` | `degraded_reason` | A block's verdict did not arrive and the held text was released uninspected |
| `segmentation_unavailable` | `fallback_reason` | Consecutive failures retired per-block inspection. The buffered `post_response` pass still audits the whole response |
| `client_disconnected` | `fallback_reason` | The client stopped reading. Inspection stops; no further calls are issued |
| `provider_not_streaming` | `skip_reason` | The leg opted into per-block inspection and no block ever closed. Emitted with `skipped: true`, so it is distinguishable from a stream inspected and found clean. The token names the common cause but not the only one: a response that did stream and was wholly opaque — no assistant text, reasoning or tool call to close a block on — reports it too |

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
- Kafka `trustgate.requests` path (legacy, being retired)
