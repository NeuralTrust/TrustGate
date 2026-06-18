# Proposal: OTLP "events" exporter (business traces via OTel Collector)

## Intent

AgentGateway emits business `*events.Event` records (request/response, usage, cost,
latency, policy chain) through a pluggable exporter pipeline. Today the only
implemented exporter is **Kafka**, which feeds `kafka-connect → ClickHouse
(gateway_metrics) → data-plane-api`. Customers want to ship the same business
events to **their own observability stack via OpenTelemetry** without us building
per-vendor integrations. We add a new **`otlp` exporter** that emits events to an
**OTel Collector** (the Collector fans out to vendors), activated **opt-in
per-gateway**, while Kafka stays the default and the downstream contract is
untouched.

## Scope

### In Scope
- New `otlp` `ExporterTemplate` + `appmetrics.Exporter` under `pkg/infra/telemetry/otlp/`, registered with one `WithExporter("otlp", ...)` line in `newExporterFactory`.
- Map the existing sanitized `*events.Event` (schema v2) to an OTLP signal and ship it to a configurable OTel Collector endpoint.
- Per-gateway opt-in via the existing `telemetry.exporters` list (`ExporterConfig{Name:"otlp", Settings:{...}}`).
- `Settings` schema + env defaults (adopting standard `OTEL_EXPORTER_OTLP_*`), validated on gateway create/update via the existing `exporter_validation.go` path.
- Non-blocking batch export with bounded queue (drop-on-full) and graceful flush on `Close()`.
- New Go deps: `go.opentelemetry.io/otel`, `.../otel/sdk`, the chosen OTLP exporter module, and OTel semconv.

### Out of Scope
- Internal service observability (otelfiber, MeterProvider for endpoint latency, OTel SDK for service metadata). **Explicitly deferred to a separate SDD change.**
- Direct vendor integrations in the gateway (Datadog, Honeycomb, etc.) — the Collector owns fan-out.
- Changing the Kafka exporter, the `Event` schema, `Builder`, `Worker`, or the ClickHouse/data-plane-api contract.
- **TrustLens**: not implemented here (dead config flag). Mentioned only as confirmation the pluggable pattern supports future exporters.

## Capabilities

### New Capabilities
- `otlp-events-exporter`: the OTLP exporter template, its `Settings` schema, env defaults, OTLP signal mapping (semantic conventions), validation, and non-blocking export lifecycle.

### Modified Capabilities
- `metrics-telemetry`: the supported export set now includes `otlp` (B.1 spec only listed Kafka/TrustLens); per-gateway opt-in fan-out is preserved; Kafka remains the config-driven default; downstream JSON contract unchanged.

## Approach

Reuse the existing pluggable pattern unchanged: `Pipeline.resolveTargets` already
**merges per-gateway explicit exporters with global defaults** (explicit replaces
same-named default; unmatched defaults still fire), so "Kafka by default + OTLP on
top" needs **no pipeline change** — only a new template registered in the locator.
The new exporter consumes the **same already-sanitized `Event`** the Kafka exporter
receives, so no new PII surface is introduced. The exporter builds a **dedicated,
per-config OTel provider** (instantiated lazily through `ExporterCache`, keyed by
the `Settings` JSON) rather than the OTel global provider, so each gateway config
gets its own batch processor + connection and `Close()` shuts it down. Mapping to
OTLP is isolated in a single mapping function so a semconv bump is a one-file change.

## Open Decisions — Recommendations

| # | Decision | Recommendation | Why / Alternatives |
|---|----------|----------------|--------------------|
| 1 | **Signal: spans vs logs** | **OTel Logs (LogRecord)**, one record per request (`event.name="gateway.request"`), carrying `trace_id` for correlation. Keep `signal` a Setting so a future spans exporter is trivial. | Business events demand **completeness** (billing/usage/cost). Spans are subject to `TracerProvider` sampling → events would be lost unless `AlwaysSample` is forced. Logs are not SDK-sampled and GenAI events are increasingly modeled as Log events. Alternative (spans + AlwaysSample) gives richer parent/child correlation but adds sampling-loss risk. |
| 2 | **Transport: gRPC vs HTTP** | **gRPC (`:4317`) default**, `protocol` Setting allows `http/protobuf` (`:4318`). | Collector is typically co-located (sidecar/daemonset); gRPC is efficient/streaming. HTTP for restrictive networks/proxies. |
| 3 | **`Settings` schema + env defaults** | `endpoint`, `protocol` (grpc\|http/protobuf), `signal` (logs\|traces), `headers` (auth), `insecure` (bool), `tls` (ca/cert/key or skip_verify), `timeout`, `compression` (gzip default), `max_body_bytes`. Env fallbacks adopt standard `OTEL_EXPORTER_OTLP_ENDPOINT/HEADERS/PROTOCOL/TIMEOUT/INSECURE` via a new `config.OTLPConfig` in `TelemetryConfig`. Settings override env (mirrors Kafka brokers fallback). | Standard env names = least surprise for ops; per-gateway Settings give multi-tenant flexibility. |
| 4 | **Semantic conventions** | Adopt **OTel GenAI (`gen_ai.*`) + HTTP** conventions for standard fields (`gen_ai.system`, `gen_ai.request.model`, `gen_ai.usage.input_tokens/output_tokens`, `http.request.method`, `http.response.status_code`, `server.address`, `url.path`); namespace gateway-specific fields under a stable **`agentgateway.*`** prefix (gateway_id, team_id, consumer, cost, policy_chain, attempts). **Pin** the semconv version and document that `gen_ai.*` is Experimental; isolate mapping in one place. | Interop with vendor backends for the common fields; stable proprietary namespace for the rest; cost has no standard key. |
| 5 | **Backpressure / non-blocking** | Use the SDK **batch processor** with a bounded queue (drops on full, never blocks), tuned queue/batch/export-timeout/scheduled-delay. `Publish` runs in the existing worker pool (off hot path) and only enqueues. `Close()` = `ForceFlush` + `Shutdown` with a bounded timeout (mirror Kafka's 5s flush). | Matches the current worker's drop-on-full guarantee; the hot path is never blocked by Collector latency. |
| 6 | **PII / attribute size** | Consume the **already-sanitized** `Event` (`SanitizeBody`/`RedactHeaders` run in `Builder`). Additionally set provider attribute-value length limit and truncate body via `max_body_bytes`. | No new PII surface; respects OTLP attribute limits. |
| 7 | **Validation** | Template `ValidateConfig`: structural only (endpoint present or env fallback, protocol/signal enum, timeout > 0, TLS files exist). **No network I/O** at validate time (like Kafka). Wired automatically via `validateExporters` → `ExporterLocator.Validate` on gateway save. | Fast, safe gateway create/update; consistent with existing pattern. |
| 8 | **TrustLens** | **Out of scope.** Cite as proof the locator supports more exporters (future `WithExporter("trustlens", ...)`). | Avoids scope creep; confirms extensibility. |

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `pkg/infra/telemetry/otlp/` | New | Exporter, template, settings + semconv mapping, per-config provider lifecycle. |
| `pkg/container/modules/telemetry.go` | Modified | One `WithExporter("otlp", ...)` line in `newExporterFactory`. |
| `pkg/config/config.go` | Modified | `OTLPConfig` env defaults (`OTEL_EXPORTER_OTLP_*`) in `TelemetryConfig`. |
| `go.mod` / `go.sum` | Modified | Add OTel SDK + OTLP exporter + semconv (pure-Go; no new platform constraint). |
| `pkg/app/gateway/exporter_validation.go` | Unchanged | Already delegates to `factory.Validate`. |
| `pkg/app/metrics/pipeline.go` (`resolveTargets`) | Unchanged | Fan-out already supports Kafka default + OTLP opt-in. |
| Kafka exporter / `Event` schema / `Builder` / `Worker` | Unchanged | OTLP is purely additive; downstream contract preserved. |
| README / telemetry docs | Modified | Document new Settings + env vars. |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| `gen_ai.*` semconv is Experimental → attribute drift | Med | Pin semconv version; isolate mapping in one function; document policy. |
| Collector unavailable → events dropped / queue fills | Med | Non-blocking batch (drop-on-full); log/observe drops; Collector is the buffering layer; no request impact. |
| Per-gateway dynamic config vs process-global OTel providers | Med | Build a **dedicated** provider per cache entry (not the global SDK provider); `Close()` shuts it down. |
| High config cardinality → many providers/connections | Low | Cache dedups by Settings JSON; document expectation; idle eviction deferred. |
| Body truncation surprises new consumers | Low | Configurable `max_body_bytes`; Kafka path keeps full sanitized body. |
| New deps increase binary size / supply chain | Low | Pin versions; pure-Go modules. |

## Rollback Plan

The change is additive and opt-in (default = Kafka). To disable: remove the single
`WithExporter("otlp", ...)` registration (or gate it behind a flag) — `otlp`
becomes an unknown exporter, so new gateway saves with otlp settings fail
validation while all existing Kafka traffic and downstream ClickHouse ingestion are
unaffected. Full revert: drop the `pkg/infra/telemetry/otlp/` package, the
`config` env additions, and the new `go.mod` entries. No data migration, no schema
change to undo.

## Dependencies

- OTel Go SDK + OTLP exporter + semconv modules (to be pinned in `go.mod`).
- A reachable OTel Collector (deployment/ops prerequisite for any gateway that opts in).
- Decision recorded on semconv version (Decision #4).

## Success Criteria

- [ ] Creating a gateway **without** `telemetry.exporters` still exports via Kafka only (unchanged behavior).
- [ ] Adding `{name:"otlp", settings:{...}}` ships events to the Collector **and** Kafka still fires (fan-out).
- [ ] Invalid `otlp` settings are rejected at gateway create/update with a validation error.
- [ ] Hot-path latency is unchanged; with the Collector down, requests are unaffected and events are dropped/queued with a log, not blocked.
- [ ] ClickHouse `gateway_metrics` keeps populating via Kafka (schema_version=2 JSON intact).
- [ ] A future exporter can be added with one template + one `WithExporter` line (extensibility preserved).
- [ ] Graceful shutdown flushes pending OTLP batches within the configured timeout.

## Next Step

Run **sdd-spec** (specs for the modified `metrics-telemetry` capability + the new
`otlp-events-exporter` capability) and **sdd-design** (provider/exporter
construction, signal mapping, config wiring) — these can run in parallel.
