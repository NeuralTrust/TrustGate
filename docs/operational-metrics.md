# Operational metrics

Set `OPS_METRICS_ENABLED=true` to record the AgentGateway operational metrics
through the process-wide OpenTelemetry `MeterProvider`. The default is `false`.
This surface is independent from `TELEMETRY_ENABLED` and the product-event
pipeline; it never reads or emits request/response bodies, identifiers, hosts,
addresses, or error text.

- `http.server.request.duration` (seconds): bounded method, route, and status class.
- `agentgateway.request.outcome_total` (`{request}`): `plane`, `route`, and `outcome`.

Planes are `admin`, `proxy`, and `mcp`. Routes are `health`, `version`,
`admin.gateways`, `admin.catalog`, `admin.config_sync`, `admin.docs`,
`proxy.forward`, `mcp.rpc`, `mcp.oauth`, `mcp.subscription`, and `other`. Outcomes are `allowed`,
`denied_auth`, `denied_forbidden`, `denied_throttled`, `denied_policy`,
`client_error`, `server_error`, and `probe`.

Collector/exporter setup is deployment-owned; enabling this flag does not
change product telemetry exporters.

## Dual-era MCP protocol

These instruments are no-ops unless `OPS_METRICS_ENABLED=true`. Labels are
closed enums only: no origin URL, credentials, tokens, client metadata,
headers, bodies, or tool arguments.

### Northbound

`mcp.northbound.protocol.validation_total` (`{failure}`): HTTP 400 protocol
rejections before product MCP events. Auth and path failures still skip
product metrics and do **not** increment this counter.

| Label | Values |
|-------|--------|
| `validation_class` | `header_mismatch`, `unsupported_version`, `acceptance_denied`, `invalid_request`, `invalid_params`, `parse_error`, `method_not_found` |
| `era` | `legacy`, `modern` (omitted when unknown) |

`acceptance_denied` is the consumer gate (`protocol_acceptance=legacy_only`
rejecting a modern request). It is distinct from `unsupported_version`.

`mcp.northbound.mrtr.outcome_total` (`{outcome}`): one sample per mediated
multi round-trip `tools/call` outcome, plus one per accepted modern
`notifications/cancelled`. Tickets, `inputResponses`, and tool arguments are
never labels and never logged.

| Label | Values |
|-------|--------|
| `outcome` | `input_required`, `complete`, `cancelled`, `policy_denied`, `timeout`, `round_limit`, `replay_rejected` |
| `era` | `legacy`, `modern` |
| `round` | `1`, `2`, `3+` (every round past the second collapses into `3+`) |

`replay_rejected` covers HMAC, expiry, and binding mismatches (`-32023`);
`round_limit` is the 8-round cap (`-32024`). Oversized or malformed
continuations are `-32602` shape rejections and are not counted here: no
mediation round happened.

`mcp.northbound.tasks.outcome_total` (`{outcome}`): one sample per mediated
`tasks/get`, `tasks/update`, or `tasks/cancel`. Task handles, upstream task ids,
`inputResponses`, and task results are never labels and never logged.

| Label | Values |
|-------|--------|
| `operation` | `get`, `update`, `cancel` |
| `outcome` | `accepted`, `working`, `input_required`, `completed`, `cancelled`, `failed`, `handle_rejected`, `capability_required`, `policy_denied` |
| `era` | `legacy`, `modern` |

`handle_rejected` is every handle refusal collapsed into one label — tamper,
expiry, a detached registry, a toolkit change, a principal change, an unknown or
purged upstream task, and credential failure all record it and all answer
`-32602` with one constant message, so neither the wire nor telemetry can be used
as an existence oracle. `capability_required` is a client that issued `tasks/*`
without declaring `io.modelcontextprotocol/tasks` (`-32025`). `policy_denied` is a
plugin blocking the tool output a completed task carried. A task's own status is
reported as the outcome for a successful operation.

`mcp.northbound.subscriptions.outcome_total` (`{outcome}`): one sample per
`subscriptions/listen` lease lifecycle event. Subscription ids, JSON-RPC ids,
resource URIs, notification payloads, principals, credentials, and consumer slugs
are never labels and never logged.

| Label | Values |
|-------|--------|
| `outcome` | `opened`, `acked`, `emitted`, `deadline`, `revoked`, `refused`, `degraded`, `shutdown`, `disconnected`, `oversize` |
| `kind` | `toolsListChanged`, `promptsListChanged`, `resourcesListChanged` (present only on `emitted`) |
| `era` | `modern` only — a legacy-era listen never reaches this path |

`opened` is one honoured claim and `refused` one capacity refusal (`-32026`,
whichever cap was hit — the label does not say). The remaining outcomes are the
one termination cause per lease: `deadline` is the jittered lifetime expiring,
`revoked` a failed re-authorization pass, `degraded` three consecutive
inconclusive passes, `oversize` a frame over
`MCP_SUBSCRIPTIONS_MAX_EVENT_BYTES`, `shutdown` the drain, `disconnected` a write
error against a gone peer, and `acked` a lease whose honoured subset was empty and
which therefore closed straight after the acknowledgement. Every one of them puts
the same terminal frame on the wire; the discriminator exists in telemetry only. A
recovered panic in the writer is deliberately **not** in this enumeration — it is
dropped rather than emitted, and surfaces only as `outcome=server_error` on
`agentgateway.request.outcome_total`.

`mcp.northbound.subscriptions.live` (`{stream}`): up/down counter of live
streams, labelled by `era` (always `modern`) only. It is incremented on an honoured claim and
decremented by that stream's writer, so it returns to zero after every
termination path, including shutdown and a recovered panic.

Streamed listens report `route: mcp.subscription` on
`agentgateway.request.outcome_total` and `http.server.request.duration`, recorded
by the stream writer when the lease closes rather than when the handler returns.
MCP-plane latency for that route is therefore the **true stream duration** — up to
`MCP_SUBSCRIPTIONS_MAX_LIFETIME` (290 s against a 300 s write timeout), not a few
milliseconds. Chart it separately from `mcp.rpc` or it will dominate any shared
percentile. On shutdown the drain has a 5 s budget for every live lease together;
leases that do not finish inside it are logged and their streams are cut by the
router shutdown that follows.

### Southbound

Subscription source metrics are emitted only when
`OPS_METRICS_ENABLED=true` and use no target, origin, pool, credential, or
subscriber identity labels:

| Instrument | Labels and fixed values |
|------------|-------------------------|
| `mcp.upstream.subscriptions.listeners.live` | No labels. Up/down counter incremented when a physical listener supervisor starts and decremented when it joins. |
| `mcp.upstream.subscriptions.listener.lifecycle_total` | `outcome`: `unsupported`, `open_failed`, `opened`, `reused`, `joined` |
| `mcp.upstream.subscriptions.fanout_total` | `kind`: the three `*ListChanged` values; `outcome`: `authorized`, `denied`, `revoked`, `transient`, `rejected` |
| `mcp.upstream.subscriptions.reconnect_total` | `outcome`: `attempted`, `succeeded`, `failed`, `exhausted`, `source_changed`, `cancelled`, `terminal` |
| `mcp.upstream.subscriptions.queue_total` | `kind`: the three `*ListChanged` values; `outcome`: `enqueued`, `full` |
| `mcp.upstream.subscriptions.listener.terminal_total` | `outcome`: `last_detach`, `shutdown`, `reconnect_exhausted`, `source_changed`, `authentication`, `protocol_failure`, `transport_failure` |

An unsupported preparation or failed open never increments the live listener
counter. Last detach, reconnect exhaustion, shutdown, and every other joined
terminal path return it to zero. Queue `full` means that northbound stream was
terminated; it does not mean an event was silently dropped from an active
stream.

`mcp.upstream.protocol.decision_total` (`{decision}`): one sample per
negotiation outcome.

| Label | Values |
|-------|--------|
| `source` | `cache`, `probe`, `override`, `contradiction` |
| `mode` | `auto`, `modern`, `legacy` |
| `era` | `legacy`, `modern` (or unknown when the decision failed before an era) |
| `result` | `selected`, `failed` |
| `category` | present on failures only (`contradiction`, `timeout`, `incompatible`, …) |

`mcp.upstream.protocol.probe_latency_seconds`: recorded **only** when
`source=probe`. Cache hits and `protocol_mode` overrides must not inflate
this histogram.

See [Dual-era rollout](mcp/dual-era-rollout.md) for dashboards and rollback,
[MCP tasks extension](mcp/tasks-extension.md) for the task knobs and its rollback
lever, and [MCP subscriptions](mcp/subscriptions.md) for the lease knobs, the
ephemeral-stream contract, and its rollback lever.
