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
`proxy.forward`, `mcp.rpc`, `mcp.oauth`, and `other`. Outcomes are `allowed`,
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

### Southbound

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

See [Dual-era rollout](mcp/dual-era-rollout.md) for dashboards and rollback.
