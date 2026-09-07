# Operational metrics and traces

## Metrics

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

## Traces

Set `OPS_TRACES_ENABLED=true` to emit one server span per request, with the same
bounded classification the metrics carry and no request URL. The default is
`false`.

### Sampling

| Variable | Applies to | Default |
| --- | --- | --- |
| `OPS_TRACES_SAMPLING_RATIO` | every route except the probes | `1.0` |
| `OPS_TRACES_PROBE_SAMPLING_RATIO` | the `health` route only | `0.01` |

Probes get their own budget because `/health`, `/healthz` and `/readyz` are
registered on all three planes and polled on a fixed period by every replica. At
one shared ratio those spans outnumber the request traces an incident actually
needs, and nothing consumes them: Kubernetes acts on a failed probe itself, and
freshness monitoring reads metrics rather than spans.

The two knobs clamp differently, deliberately. `0` on the main ratio is treated as
a typo and falls back to `1.0`, since silencing traces entirely is spelled
`OPS_TRACES_ENABLED=false`. `0` on the probe ratio is honoured, because dropping
probe spans outright is the reason the knob exists.

An out-of-range value on either knob falls back to that knob's own default, so a
percentage typo such as `OPS_TRACES_PROBE_SAMPLING_RATIO=10` lands on `0.01`
rather than on the main ratio. Both effective values are logged at startup.

Sampling applies to root spans only. A child span inherits its parent's decision,
so a sampled request trace never loses a span in the middle.

### Propagation boundary

The gateway is always the **root** of its trace.

- **It never adopts inbound trace context.** A caller's `traceparent` is ignored,
  for the same reason a caller's `X-AG-Trace-Id` is ignored: this is an
  internet-facing edge, and honouring client-supplied trace identity would let
  any consumer collapse unrelated traffic into one trace or graft itself onto
  another tenant's. Because no remote parent can reach the sampler, the gateway
  needs no guard against an upstream caller sampling its traces away.
- **It injects W3C trace context into internal service calls only** — the
  TrustGuard evaluate call and the firewall complexity call. Each gets a client
  span named after a bounded label (`trustguard.evaluate`, `firewall.complexity`)
  rather than the request target, and a `peer.service` attribute so the edge
  appears in the service map.
- **It injects nothing into LLM provider calls.** The provider client pool is
  deliberately uninstrumented: those requests go to third parties who have no
  business receiving our trace identity, and their URLs come from consumer
  configuration.

`X-Trace-ID` is unaffected by any of this. It is the product-level trace id, it is
still sent on the TrustGuard call, and TrustGuard still prefers it over the trace
it adopted when resolving its own correlation id — which is what keeps the
cross-product join stable.

Injection is inert unless `OPS_TRACES_ENABLED=true`, because it depends on the
propagator that flag installs. With traces off, outbound requests are byte-for-byte
what they were before instrumentation.
