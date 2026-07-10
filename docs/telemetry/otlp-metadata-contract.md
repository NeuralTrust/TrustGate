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

## HTTP semconv

| Attribute | Event field |
|-----------|-------------|
| `http.request.method` | `request.method` |
| `http.response.status_code` | `response.status_code` |
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
| `trustgate.cost.total_usd` | `cost.total_usd` (when cost present) |
| `trustgate.cost.prompt_usd` | `cost.prompt_usd` (when cost present) |
| `trustgate.cost.completion_usd` | `cost.completion_usd` (when cost present) |
| `trustgate.cost.currency` | `cost.currency` (when cost present) |
| `trustgate.latency.total_ms` | `latency.total_ms` |
| `trustgate.latency.provider_ms` | `latency.provider_ms` |
| `trustgate.latency.policies_ms` | `latency.policies_ms` |
| `trustgate.latency.routing_ms` | `latency.routing_ms` |
| `trustgate.latency.gateway_ms` | `latency.gateway_ms` |
| `trustgate.is_flagged` | `is_flagged` (bool) |
| `trustgate.security` | `security[]` string array (when non-empty) |
| `trustgate.policy_chain` | `policy_chain[]` as JSON string (when non-empty) |
| `trustgate.attempts` | `attempts[]` as JSON string (when non-empty) |
| `trustgate.attempts.count` | `len(attempts)` (when non-empty) |
| `trustgate.mcp.*` | `mcp.*` fields (when the request is an MCP call) |

## Raw stream

The raw data class carries the request/response bodies plus join keys. It is routed to any
exporter declared under `exporters.raw[]`:

| Sink | Content |
|------|---------|
| PostgreSQL `trustgate_data` | `request_body` + `response_body` only |
| OTLP (`otlp` under `raw`) | `trustgate.request.body` / `trustgate.response.body` + join keys |
| Join keys | `trace_id`, `gateway_id`, `tenant_id`, `occurred_on` |

The raw OTLP record emits `trustgate.schema_version`, `trustgate.trace_id`,
`trustgate.gateway_id`, `trustgate.tenant_id`, `trustgate.request.body`, and
`trustgate.response.body` — no metadata attributes, no policy chain.

## Severity

| `status.code` | OTLP severity |
|---------------|---------------|
| &lt; 400 | Info |
| 4xx | Warn |
| 5xx | Error |

## Examples

Per-sink example records: [`examples/`](./examples/). These are schema-accurate
representative records (an OpenAI chat completion flagged by a DLP policy), not a live capture.

## Out of scope

- OTLP → ClickHouse ingestion (collector / data-plane)
- Kafka `trustgate.requests` path (legacy, being retired)
