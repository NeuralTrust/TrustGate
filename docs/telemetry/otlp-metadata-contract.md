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
the score is unavailable, or no tier matches — those requests emit nothing rather
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
