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
