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

Traffic labeling (see [traffic labels](traffic-labels.md)) adds its own
instruments. `outcome` is their only label, so they stay bounded whatever the
number of gateways, consumers or label sets; per-request detail lives in the
`traffic_labels` events.

- `agentgateway.traffic_labels.intake_total` (`{request}`): what the request
  path offered. `accepted`, `sampled_out`, `body_too_large`, `buffer_full`
  (out of slots or bytes), `shutting_down`.
- `agentgateway.traffic_labels.enqueue_total` (`{request}`): what reached the
  queue. `queued`, `no_text`, `quota_exceeded`, `queue_error`.
- `agentgateway.traffic_labels.result_total` (`{request}`): how each queued
  request ended. `classified`, `cache_hit`, `failed`, `poison`, `unconfigured`
  (the selected registry or model cannot serve it: deleted, wrong gateway, no
  stored credentials, or the provider refused the request with a 4xx),
  `invalid`, `unpublishable` (its gateway is gone), `publish_retry` (left
  pending to be published again).
- `agentgateway.traffic_labels.call.duration` (seconds): each classifier LLM
  call. `ok`, `backpressure` (the provider answered 429 or 503), `error`.
- `agentgateway.traffic_labels.stream.length` and
  `agentgateway.traffic_labels.stream.pending` (`{entry}`): gauges read on
  every collection, so a backlog is visible without traffic. A growing length
  means requests arrive faster than they are labeled.

The product-event pipeline reports its own health:

- `agentgateway.telemetry.dropped_events` (`{event}`): events that never
  reached an exporter. `reason` is `closed` (after shutdown began),
  `queue_full` (the worker queue was full), or `panic` (an exporter task
  panicked).
- `agentgateway.telemetry.exporters.configured` (`{exporter}`): a gauge of the
  default exporters per `data_class` (`metadata`, `raw`). A class with no
  exporter reports `0`, so missing telemetry shows up as a value instead of
  an absence of data.

`trustgate_search`, the MCP gateway's search tool, reports how well it serves
the people who use it (see [gateway tools](mcp/gateway-tools.md)). Its labels
are bounded: never a query, a tool name, a gateway, a consumer or a person.
`surface` is `store` or `application` on all three.

- `trustgate.mcp.searches` (`{search}`): every `trustgate_search` call. `kind`
  is `tool`, `overview`, `detail` (a lookup by `name`), `catalog`, `agent`,
  `model`, or `unknown` (arguments that could not be read). `result` is
  `results`, `empty` (no tool matched), `catalog_only` (no tool matched but the
  Store catalog or an agent did), `found` and `not_found` for a lookup,
  `answered` for the other kinds, or `invalid`. A tool search adds `match`:
  `ranked`, `substring` (the ranking scored nothing and the substring fallback
  answered) or `listing` (no query).
- `trustgate.mcp.search.follow_ups` (`{call}`): the first tool call a caller
  makes within 10 minutes of a tool search with a query, by where that search
  put the tool called. `result` is `hit_1`, `hit_3` (2nd–3rd), `hit_10`
  (4th–10th), `hit_later` or `not_returned`; `via` is `direct`,
  `trustgate_call` or `trustgate_call_tool`. Read against
  `trustgate.mcp.searches{kind="tool",match!="listing"}`: the share of
  searches followed by a call, and how far down the page that call was. The
  last search is kept per replica, so with several replicas the counts are a
  lower bound.
- `trustgate.mcp.unknown_tool_calls` (`{call}`): tool calls naming a tool
  nobody serves, by `via` and `after_search` (whether the caller searched in
  the 10 minutes before).

MCP Code Mode (see [Code Mode](mcp/code-mode.md)) reports its programs, with
the same bounded labels plus `tool` (`trustgate_execute`; `trustgate_query`
for a call to the retired tool).
A program's calls also count in `trustgate.mcp.search.follow_ups`, with `via`
naming the program's tool.

- `trustgate.mcp.code.programs` (`{program}`): programs, by how they ended.
  `result` is `ok`, `thrown`, `timeout`, `compute` (its compute budget ran
  out), `memory`, `call_limit`, `output_limit`, `code_limit`, `stalled`,
  `crashed`, `busy` (no slot on the replica, or none of its gateway's, within
  the wait), `aborted` (a consent or a rate limit
  stopped it), `invalid` (no code) or `not_offered` (the gateway's Code Mode
  does not offer the tool).
- `trustgate.mcp.code.program_duration` (seconds): how long a program ran,
  its tool calls included.
- `trustgate.mcp.code.program_calls` (`{call}`): how many tool calls one
  program made.
- `trustgate.mcp.code.bytes_read` (bytes): what programs' calls handed them,
  results and errors. The model did not read it.
- `trustgate.mcp.code.bytes_returned` (bytes): what programs handed back to
  clients, their logs included. This is what the model read instead.

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
