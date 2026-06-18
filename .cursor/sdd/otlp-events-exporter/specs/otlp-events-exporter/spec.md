# OTLP Events Exporter Specification

## Purpose

Define the new `otlp` business-events exporter that ships the existing
sanitized `*events.Event` (schema v2) to an external **OTel Collector**,
opt-in per-gateway via `telemetry.exporters`. This is a NEW capability:
it adds an `ExporterTemplate`/`appmetrics.Exporter` pair under
`pkg/infra/telemetry/otlp/`, its `Settings` schema and env defaults, the
Event→OTLP semantic mapping, structural validation, and a non-blocking
export lifecycle. The exporter is purely additive; it does not change the
`Event` schema, the Kafka exporter, the pipeline, or the downstream
contract.

## Requirements

### Requirement: Settings Schema

The `otlp` exporter MUST accept its configuration through the existing
`ExporterConfig.Settings` (`map[string]interface{}`) with the following
keys. Unknown keys MUST be ignored (forward-compat). Types and defaults:

| Key | Type | Required | Default | Enum / Notes |
|-----|------|----------|---------|--------------|
| `endpoint` | string | required unless env fallback present | — | host:port or URL of the Collector |
| `protocol` | string | optional | `grpc` | `grpc` \| `http/protobuf` |
| `signal` | string | optional | `logs` | `logs` \| `traces` |
| `headers` | map[string]string | optional | `{}` | auth/tenant headers |
| `insecure` | bool | optional | `false` | plaintext (no TLS) |
| `tls` | object | optional | — | `{ca, cert, key, skip_verify}` |
| `timeout` | duration/string | optional | `10s` | per-export deadline, MUST be > 0 |
| `compression` | string | optional | `gzip` | `gzip` \| `none` |
| `max_body_bytes` | int | optional | implementation default | request/response body truncation cap |

The exporter `Name()` MUST return `"otlp"`.

#### Scenario: Minimal valid settings

- GIVEN settings `{endpoint:"collector:4317"}`
- WHEN the exporter is built
- THEN it uses `protocol=grpc`, `signal=logs`, `compression=gzip`, and the default timeout
- AND `Name()` returns `"otlp"`

#### Scenario: Unknown setting key is tolerated

- GIVEN settings containing an unrecognized key alongside a valid `endpoint`
- WHEN the exporter is built
- THEN the unknown key is ignored and the build succeeds

### Requirement: Environment Fallback and Precedence

A new `config.OTLPConfig` MUST be added to `TelemetryConfig`, reading the
standard env vars `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`,
`OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_EXPORTER_OTLP_TIMEOUT`, and
`OTEL_EXPORTER_OTLP_INSECURE`. Per-gateway `Settings` MUST override the
env-derived values for any key present in `Settings` (mirroring the Kafka
brokers fallback). Env values MUST be used only for keys absent from `Settings`.

#### Scenario: Endpoint sourced from env

- GIVEN `OTEL_EXPORTER_OTLP_ENDPOINT=collector:4317` is set
- AND gateway settings omit `endpoint`
- WHEN the exporter is built
- THEN it targets `collector:4317`

#### Scenario: Settings override env

- GIVEN `OTEL_EXPORTER_OTLP_ENDPOINT=env-collector:4317` is set
- AND gateway settings include `endpoint:"gw-collector:4317"`
- WHEN the exporter is built
- THEN it targets `gw-collector:4317`

### Requirement: Structural Validation Without Network I/O

`ValidateConfig(settings)` MUST validate structure only and MUST NOT
perform any network I/O. It MUST reject configs where: `endpoint` is
empty AND no env fallback is present; `protocol` is not in {`grpc`,
`http/protobuf`}; `signal` is not in {`logs`, `traces`}; `timeout` is
present and `<= 0`; or a referenced TLS file (`ca`/`cert`/`key`) does not
exist on disk. Validation MUST be reachable through the existing
`validateExporters` → `ExporterLocator.Validate` path on gateway
create/update.

#### Scenario: Missing endpoint with no env fallback

- GIVEN settings with no `endpoint` and no `OTEL_EXPORTER_OTLP_ENDPOINT`
- WHEN the gateway is created or updated
- THEN validation fails with an error naming the `otlp` exporter
- AND the gateway is not persisted

#### Scenario: Invalid protocol enum

- GIVEN settings `{endpoint:"c:4317", protocol:"tcp"}`
- WHEN validation runs
- THEN it returns an error and no network call is attempted

#### Scenario: Missing TLS file

- GIVEN settings referencing a `tls.ca` path that does not exist
- WHEN validation runs
- THEN it returns a file-not-found validation error

### Requirement: Event to OTLP Mapping (Semantic Conventions)

When `signal=logs`, the exporter MUST emit exactly **one OTLP LogRecord
per request** with `event.name="gateway.request"`, carrying the Event's
`trace_id` as the record `TraceID` for correlation. Standard fields MUST
use OTel GenAI + HTTP semantic conventions; gateway-specific fields MUST
use the `agentgateway.*` namespace. The semconv version MUST be pinned and
the mapping MUST be isolated in a single function.

| Event field | OTLP attribute |
|-------------|----------------|
| `Request.Provider` | `gen_ai.system` |
| `Request.Model` | `gen_ai.request.model` |
| `Usage.PromptTokens` | `gen_ai.usage.input_tokens` |
| `Usage.CompletionTokens` | `gen_ai.usage.output_tokens` |
| `Request.Method` | `http.request.method` |
| `Response.StatusCode` | `http.response.status_code` |
| `Request.Path` | `url.path` |
| Collector endpoint host | `server.address` |
| `GatewayID` | `agentgateway.gateway_id` |
| `TeamID` | `agentgateway.team_id` |
| `Consumer.ID`/`Name` | `agentgateway.consumer` |
| `Cost.TotalUsd` | `agentgateway.cost` |
| `PolicyChain` | `agentgateway.policy_chain` |
| `Attempts` | `agentgateway.attempts` |

#### Scenario: One log record per request

- GIVEN a built `Event` with a non-empty `trace_id`
- WHEN it is exported with `signal=logs`
- THEN one LogRecord is produced with `event.name="gateway.request"`
- AND its TraceID equals the Event `trace_id`

#### Scenario: Standard and proprietary attributes coexist

- GIVEN an Event with provider, model, usage, status, and cost
- WHEN it is mapped
- THEN provider/model/usage/HTTP fields use `gen_ai.*`/`http.*`/`url.*`
- AND gateway_id, team_id, consumer, cost, policy_chain use `agentgateway.*`

### Requirement: PII and Attribute Size Limits

The exporter MUST consume the Event that the Builder already sanitized via
`SanitizeBody`/`RedactHeaders`; it MUST NOT introduce a new PII surface.
It MUST apply a provider attribute-value length limit and MUST truncate
request/response bodies to `max_body_bytes`.

#### Scenario: Body exceeds cap

- GIVEN an Event whose sanitized body is larger than `max_body_bytes`
- WHEN it is exported
- THEN the emitted body attribute is truncated to the cap
- AND the Kafka path still receives the full sanitized body (unaffected)

### Requirement: Non-Blocking Export

`Publish(ctx, evt)` MUST only enqueue into an SDK batch processor backed by
a bounded queue and MUST return without blocking on Collector latency. When
the queue is full, events MUST be dropped (drop-on-full), never blocking the
caller. `Publish` runs in the existing worker pool, off the request hot path.

#### Scenario: Collector is slow

- GIVEN a Collector that responds slowly or not at all
- WHEN `Publish` is called
- THEN it returns promptly without waiting for delivery
- AND the request hot path latency is unaffected

#### Scenario: Queue is full

- GIVEN the bounded export queue is full
- WHEN another event is enqueued
- THEN the event is dropped and the drop is observable via logs/metrics
- AND `Publish` does not block or error the caller

### Requirement: Lifecycle (Build / Cache / Close)

Each distinct `Settings` JSON MUST build a **dedicated** per-config OTel
provider (its own batch processor + connection), instantiated lazily via the
existing `ExporterCache` keyed by Settings JSON — NOT the OTel global
provider. `Close()` MUST `ForceFlush` then `Shutdown` within a bounded
timeout (mirroring Kafka's ~5s flush) and release the connection.

#### Scenario: Two gateways, two configs

- GIVEN two gateways with different `otlp` settings
- WHEN both publish
- THEN each uses its own provider/connection
- AND closing one does not affect the other

#### Scenario: Graceful shutdown flushes

- GIVEN pending batched events
- WHEN `Close()` is called
- THEN buffered events are flushed within the configured timeout
- AND shutdown completes even if the timeout elapses (bounded)

### Requirement: Error Handling

Build/connection failures MUST be surfaced through the existing cache build
path (logged, exporter skipped) without aborting other exporters. Export
failures (Collector down, timeout) MUST NOT propagate to the request path;
they MUST be logged/observed and the offending batch dropped or retried per
the batch processor, never blocking forwarding.

#### Scenario: Collector unreachable at runtime

- GIVEN a built `otlp` exporter and an unreachable Collector
- WHEN events are published
- THEN exports fail in the background, are logged, and requests succeed
- AND the Kafka exporter keeps delivering

### Requirement: Extensibility via Single Registration

Registering the exporter MUST require exactly one
`WithExporter("otlp", ...)` line in `newExporterFactory`
(`pkg/container/modules/telemetry.go`). Adding a future exporter MUST
likewise require only one new template plus one `WithExporter` line, with no
pipeline change.

#### Scenario: One-line registration

- GIVEN the `otlp` template implementing `ExporterTemplate`
- WHEN one `WithExporter("otlp", template)` line is added to the locator
- THEN `otlp` becomes a valid exporter name with no other wiring change

#### Scenario: Removing the registration disables otlp

- GIVEN the `WithExporter("otlp", ...)` line is removed
- WHEN a gateway is saved with `otlp` settings
- THEN validation fails with `unknown exporter "otlp"`
- AND all Kafka traffic and ClickHouse ingestion remain unaffected

## Non-Goals

- Internal service observability (otelfiber, MeterProvider/TracerProvider for service metrics) — deferred to a separate SDD change.
- Direct vendor integrations (Datadog, Honeycomb, etc.) — the Collector owns fan-out.
- Changes to the `Event` schema, `Builder`, `Worker`, or the Kafka exporter.
- Changes to the downstream contract (kafka-connect → ClickHouse `gateway_metrics` → data-plane-api).
- TrustLens — out of scope; cited only as proof the locator supports more exporters.
- `signal=traces` end-to-end emission — the Setting is reserved/validated now; a spans exporter is a future change.

## Edge Cases

- Empty `trace_id`: emit the record without a TraceID (no correlation), do not error.
- High config cardinality: cache dedups by Settings JSON; idle eviction is deferred.
- `compression=none`: valid; no compression applied.
- `insecure=true` together with `tls`: validation MUST reject the contradictory combination.
