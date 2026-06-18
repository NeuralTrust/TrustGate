# Design: OTLP "events" exporter (business events via OTel Collector)

> Source of truth: `.cursor/sdd/otlp-events-exporter/proposal.md` (Engram `sdd/propose/otlp-events-exporter` #99).
> Exploration: Engram `sdd/explore/opentelemetry-telemetry` #98.
> Scope: ONLY the new `otlp` business-events exporter (OTel **Logs**), opt-in per-gateway, Kafka stays default, downstream contract untouched.

## Technical Approach

Add a new `otlp` `ExporterTemplate` + `appmetrics.Exporter` under `pkg/infra/telemetry/otlp/`, registered with **one** `WithExporter("otlp", ...)` line in `newExporterFactory`. The exporter consumes the **already-sanitized** `*events.Event` (schema v2) that the Kafka exporter receives, maps it to a single OTel **LogRecord** (`event.name="gateway.request"`), and emits it through a **dedicated per-config `LoggerProvider`** (batch processor + OTLP client), built lazily by `ExporterCache` and shut down on `Close()`.

No pipeline change is required: `Pipeline.resolveTargets` already merges per-gateway explicit exporters with global defaults (explicit replaces same-named default; unmatched defaults still fire), so "Kafka by default + OTLP on top" is pure fan-out. `Publish` only enqueues into the SDK batch processor (bounded queue, drop-on-full), so the hot path is never blocked by Collector latency. The Event→LogRecord mapping lives in **one file** with a **pinned** semconv version so a semconv bump is a one-file change.

## Architecture Decisions

| # | Decision | Choice | Alternatives rejected | Rationale |
|---|----------|--------|-----------------------|-----------|
| 1 | Signal | OTel **Logs** (LogRecord), 1 per request; `signal` Setting (`logs`\|`traces`) reserved, only `logs` implemented | Spans + `AlwaysSample` | Business events need completeness (billing/usage/cost). Spans are subject to `TracerProvider` sampling → loss risk. Logs are not SDK-sampled; GenAI events are increasingly modeled as Logs. |
| 2 | Transport | **gRPC `:4317`** default; `http/protobuf :4318` via `protocol` Setting | HTTP-only | Collector is usually co-located (sidecar/daemonset); gRPC is efficient/streaming. HTTP kept for restrictive networks. |
| 3 | Provider scope | **Dedicated `LoggerProvider` per `ExporterCache` entry** (keyed by Settings JSON) | `otel.SetLoggerProvider` global | Per-gateway dynamic config conflicts with one process-global provider; a global would force one endpoint/queue for all gateways and a single `Shutdown`. A dedicated provider gives each config its own batch processor + connection and a scoped `Close()`. We NEVER call `otel.SetLoggerProvider`/`global.SetLoggerProvider`. |
| 4 | Config + env | `Settings` schema; env fallback via new `config.OTLPConfig` reading standard `OTEL_EXPORTER_OTLP_*`; Settings override env | Custom env names | Standard env names = least ops surprise (mirrors Kafka brokers fallback); per-gateway Settings give multi-tenant flexibility. |
| 5 | Semconv | `gen_ai.*` + HTTP/`server`/`url` for standard fields; `agentgateway.*` for proprietary; **pin `semconv/v1.41.0`** | Unpinned / custom-only | `gen_ai.*` is Experimental → pin + isolate mapping; proprietary namespace stable; cost/policy have no standard key. |
| 6 | Backpressure | SDK **batch processor**, bounded queue, drop-on-full; `Publish` only emits (runs in existing worker pool) | Blocking/simple processor | Matches worker's drop-on-full guarantee; Collector latency never reaches the hot path. |
| 7 | PII / size | Consume already-sanitized Event (`SanitizeBody`/`RedactHeaders` in `Builder`); provider attribute-value length limit + `max_body_bytes` truncation | Re-sanitize / unbounded | No new PII surface; respects OTLP attribute limits. |
| 8 | Validation | `ValidateConfig` structural only (endpoint present or env fallback, protocol/signal enum, `timeout>0`, TLS files exist) — **no network I/O** | Connect-on-validate | Fast/safe gateway create/update; consistent with Kafka. |

## Data Flow

```
request ─▶ metrics middleware ─▶ Worker.Process (enqueue, drop-on-full)
                                        │
                              worker goroutine
                                        ▼
                       Pipeline.publish ─▶ Builder.Build  ──▶ *events.Event (sanitized, schema v2)
                                        │
                       resolveTargets = [kafka default] + [otlp explicit]
                                        ▼
            ┌───────────────────────────┴───────────────────────────┐
   kafka.Exporter.Publish                               otlp.Exporter.Publish
   (JSON ─▶ Kafka ─▶ ClickHouse)                        eventToRecord(evt, maxBody)
                                                                 │ logger.Emit (non-blocking)
                                                                 ▼
                                              BatchProcessor (bounded queue, drop-on-full)
                                                                 │  background export (timeout/retry)
                                                                 ▼
                                          otlploggrpc | otlploghttp ─▶ OTel Collector ─▶ vendors

   Close(): provider.ForceFlush(ctx≤timeout) ─▶ provider.Shutdown(ctx≤timeout)
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `pkg/infra/telemetry/otlp/template.go` | Create | `Template` implements `ExporterTemplate` (`Name`/`ValidateConfig`/`WithSettings`); holds `*slog.Logger` + `config.OTLPConfig`. |
| `pkg/infra/telemetry/otlp/settings.go` | Create | `Settings` struct, `parseSettings` (mapstructure + env fallback), `validate` (structural). Enums `Protocol`/`Signal`. |
| `pkg/infra/telemetry/otlp/provider.go` | Create | `newLoggerProvider` builds dedicated `*sdklog.LoggerProvider` (batch processor + otlploggrpc/otlploghttp client + `resource`). |
| `pkg/infra/telemetry/otlp/mapping.go` | Create | `eventToRecord(evt, maxBodyBytes) otellog.Record` — the single semconv-pinned mapping. |
| `pkg/infra/telemetry/otlp/exporter.go` | Create | `Exporter` implements `appmetrics.Exporter` (`Name`/`Publish`/`Close`); wraps provider + `otellog.Logger`. |
| `pkg/infra/telemetry/otlp/{mapping,settings,exporter}_test.go` | Create | Unit tests (mapping, settings/validation, exporter via in-memory log exporter). |
| `pkg/container/modules/telemetry.go` | Modify | One line: `infratelemetry.WithExporter(otlp.ExporterName, otlp.NewTemplate(logger, cfg.Telemetry.OTLP))` in `newExporterFactory`. |
| `pkg/config/config.go` | Modify | Add `OTLPConfig` + `TelemetryConfig.OTLP` + `getOTLPConfig()` reading `OTEL_EXPORTER_OTLP_*`. |
| `go.mod` / `go.sum` | Modify | Add pinned OTel SDK + OTLP log exporters (see Dependencies). |
| `README.md` / telemetry docs | Modify | Document `otlp` Settings + env vars. |
| `pkg/app/metrics/pipeline.go`, `exporter_cache.go`, `exporter_validation.go`, Kafka exporter, Event schema, Builder, Worker | Unchanged | OTLP is purely additive; fan-out, cache, validation already support it. |

## Interfaces / Contracts (Go signatures)

```go
package otlp

const ExporterName = "otlp"

// Template builds otlp.Exporter instances from per-gateway settings, falling back
// to process-level OTEL_EXPORTER_OTLP_* defaults.
type Template struct {
	logger *slog.Logger
	envCfg config.OTLPConfig
}

func NewTemplate(logger *slog.Logger, envCfg config.OTLPConfig) *Template
func (t *Template) Name() string                                              // "otlp"
func (t *Template) ValidateConfig(settings map[string]interface{}) error      // structural, no network
func (t *Template) WithSettings(settings map[string]interface{}) (appmetrics.Exporter, error)
```

```go
type Protocol string // "grpc" | "http/protobuf"
type Signal string   // "logs" | "traces" (only "logs" implemented)

type TLSSettings struct {
	CAFile     string `mapstructure:"ca_file"`
	CertFile   string `mapstructure:"cert_file"`
	KeyFile    string `mapstructure:"key_file"`
	SkipVerify bool   `mapstructure:"skip_verify"`
}

type Settings struct {
	Endpoint     string            `mapstructure:"endpoint"`
	Protocol     Protocol          `mapstructure:"protocol"`      // default grpc
	Signal       Signal            `mapstructure:"signal"`        // default logs
	Headers      map[string]string `mapstructure:"headers"`       // e.g. auth
	Insecure     bool              `mapstructure:"insecure"`
	TLS          *TLSSettings      `mapstructure:"tls"`
	Timeout      time.Duration     `mapstructure:"timeout"`       // export + close bound
	Compression  string            `mapstructure:"compression"`   // default gzip
	MaxBodyBytes int               `mapstructure:"max_body_bytes"`// attribute body truncation
}

// parseSettings decodes raw settings, then applies env fallback (settings win).
func parseSettings(raw map[string]interface{}, env config.OTLPConfig) (Settings, error)
func (s Settings) validate() error
```

```go
// newLoggerProvider builds a dedicated logs provider; the OTLP client connects
// lazily so an unreachable Collector never blocks construction (mirrors Kafka).
func newLoggerProvider(ctx context.Context, s Settings) (*sdklog.LoggerProvider, error)

type Exporter struct {
	provider        *sdklog.LoggerProvider
	logger          otellog.Logger
	slog            *slog.Logger
	maxBodyBytes    int
	shutdownTimeout time.Duration // default 5s, mirrors Kafka flush
}

func (e *Exporter) Name() string { return ExporterName }
func (e *Exporter) Publish(ctx context.Context, evt *events.Event) error // emits, never blocks
func (e *Exporter) Close()                                               // ForceFlush + Shutdown, bounded
```

```go
// eventToRecord is the single, semconv-pinned Event→LogRecord mapping.
func eventToRecord(evt *events.Event, maxBodyBytes int) otellog.Record
```

```go
// config.go additions
type OTLPConfig struct {
	Endpoint    string
	Headers     map[string]string
	Protocol    string
	Timeout     time.Duration
	Insecure    bool
	Compression string
}
// TelemetryConfig gains: OTLP OTLPConfig
// getOTLPConfig() reads OTEL_EXPORTER_OTLP_{ENDPOINT,HEADERS,PROTOCOL,TIMEOUT,INSECURE,COMPRESSION}
```

Wiring (the only production wiring change):

```go
func newExporterFactory(logger *slog.Logger, cfg *config.Config) appmetrics.ExporterFactory {
	return infratelemetry.NewExporterLocator(
		infratelemetry.WithExporter(kafka.ExporterName, kafka.NewKafkaTemplate(logger, cfg.Kafka)),
		infratelemetry.WithExporter(otlp.ExporterName, otlp.NewTemplate(logger, cfg.Telemetry.OTLP)),
	)
}
```

## Event → OTLP mapping (semconv/v1.41.0; `agentgateway.*` for proprietary)

| Event source | OTLP target | Key | Notes |
|---|---|---|---|
| constant | `LogRecord.EventName` | `gateway.request` | one record per request |
| `OccurredOn` (ms) | `LogRecord.Timestamp` | — | request start |
| now | `LogRecord.ObservedTimestamp` | — | set on emit |
| `Status.Code` | `LogRecord.Severity` | — | <400 INFO, 4xx WARN, ≥500 ERROR |
| `Response.Body` (sanitized, truncated) | `LogRecord.Body` | — | empty if no body |
| `Request.Method` | attr | `http.request.method` | |
| `Response.StatusCode` | attr | `http.response.status_code` | int |
| `Request.Path` | attr | `url.path` | |
| `Request.Provider` | attr | `gen_ai.provider.name` | |
| `Request.Model` (served) | attr | `gen_ai.request.model` | |
| `Response.FinishReason` | attr | `gen_ai.response.finish_reasons` | single-element slice |
| `Usage.PromptTokens` | attr | `gen_ai.usage.input_tokens` | |
| `Usage.CompletionTokens` | attr | `gen_ai.usage.output_tokens` | |
| `Request.Stream`/`Response.Streaming` | attr | `gen_ai.request.stream` | bool |
| `SchemaVersion` | attr | `agentgateway.schema_version` | =2 |
| `TraceID` | attr | `agentgateway.trace_id` | correlation; see note |
| `GatewayID` / `TeamID` | attr | `agentgateway.gateway_id` / `agentgateway.team_id` | |
| `Consumer.ID` / `Consumer.Name` | attr | `agentgateway.consumer.id` / `.name` | |
| `SessionID` / `TurnID` / `FingerprintID` / `IP` | attr | `agentgateway.session_id` / `.turn_id` / `.fingerprint_id` / `.ip` | |
| `Request.RequestedModel` / `ModelLabel` | attr | `agentgateway.requested_model` / `.model_label` | requested vs served |
| `Usage.TotalTokens` / `CachedInputTokens` / `ReasoningOutputTokens` | attr | `agentgateway.usage.total_tokens` / `.cached_input_tokens` / `.reasoning_output_tokens` | no standard total key |
| `Cost.{Total,Prompt,Completion}Usd` / `Currency` | attr | `agentgateway.cost.total_usd` / `.prompt_usd` / `.completion_usd` / `.currency` | no standard cost key |
| `Latency.{Total,Provider,Policies,Routing,Gateway}Ms` | attr | `agentgateway.latency.*_ms` | |
| `IsFlagged` / `Security` | attr | `agentgateway.is_flagged` (bool) / `agentgateway.security` (string slice) | |
| `Request.Body` (sanitized, truncated) | attr | `agentgateway.request.body` | `max_body_bytes` |
| `PolicyChain` | attr | `agentgateway.policy_chain` | JSON string (nested) |
| `Attempts` | attr | `agentgateway.attempts` (JSON string) + `agentgateway.attempts.count` (int) | |

Notes: `server.address` / `url.scheme` have no source in Event v2 → omitted (documented). `TraceID` is gateway-generated and not guaranteed W3C-valid, so it is carried as an attribute rather than the record's native trace context; promote to native `SpanContext` only if a valid 16-byte trace id is later guaranteed (why: avoids emitting malformed trace correlation).

## Error handling & backpressure

- **Construction** (`WithSettings`): build provider; OTLP gRPC/HTTP clients connect lazily, so a down Collector does NOT fail `WithSettings` (mirrors Kafka's non-blocking start). Only hard config errors (bad TLS files, unparsable settings) return an error → `ExporterCache.get` logs a warn and skips that exporter; Kafka traffic is unaffected.
- **`Publish`**: builds the record and calls `logger.Emit`, which enqueues into the batch processor and returns immediately. Queue full → SDK drops (drop-on-full), never blocks the worker. `Publish` returns `nil` on the normal path (Emit has no error return); it returns an error only if the provider was already shut down.
- **Collector down / timeouts**: batch export runs in background with the configured export timeout; persistent failures drain into drops once the queue fills. No request-path impact. A process-level `otel.SetErrorHandler` MAY be set once at boot to log export errors/drops (optional; the only global OTel call we permit, and it is observability-only, not a provider).
- **`Close`** (on `pipeline.close` → `cache.CloseAll`): `ctx, cancel := context.WithTimeout(bg, shutdownTimeout)`; `provider.ForceFlush(ctx)` then `provider.Shutdown(ctx)`; bounded by `Timeout`/5s default so shutdown can never hang (mirrors Kafka `Flush(5s)`).

## Lifecycle / `ExporterCache` integration

Unchanged cache contract: `Resolve` dedups by Settings JSON, `get` builds once via `sync.Once` (lazy), `CloseAll` calls `Exporter.Close()` per entry. Each distinct `otlp` Settings JSON ⇒ one dedicated provider + connection. High config cardinality ⇒ many providers (documented expectation; idle eviction deferred per proposal).

## Testing Strategy

| Layer | What | Approach |
|-------|------|----------|
| Unit | `eventToRecord` | Table-driven over representative Events (full LLM, error, streaming, no-usage); collect attrs via `record.WalkAttributes` into a map; assert keys/values/severity/body/truncation. Pure function, no provider. |
| Unit | `parseSettings` / `validate` | Assert env fallback + Settings override; enum/`timeout>0`/TLS-file-exists errors; defaults (grpc, logs, gzip). |
| Unit | `Template.ValidateConfig` | Structural pass/fail cases; confirm no network (no Collector needed). |
| Unit | `Exporter.Publish`/`Close` | Inject an **in-memory `sdklog` exporter** (test double implementing the SDK log exporter interface) into a provider via a small seam (`newExporterWithProvider`), `Emit`, `ForceFlush`, assert recorded records; assert `Close` flushes within timeout. No real Collector. |
| Integration (optional, deferred) | gRPC/HTTP wire | Out of unit scope; can run later against a local Collector or `otlploggrpc` test server. |

## Dependencies (pin in `go.mod`)

| Module | Version | Purpose |
|--------|---------|---------|
| `go.opentelemetry.io/otel` | `v1.44.0` | API + bundled `semconv/v1.41.0` (no separate require; import path `.../otel/semconv/v1.41.0`) |
| `go.opentelemetry.io/otel/log` | `v0.20.0` | Logs API (`log.Record`, `log.Logger`) |
| `go.opentelemetry.io/otel/sdk` | `v1.44.0` | `resource` |
| `go.opentelemetry.io/otel/sdk/log` | `v0.20.0` | `LoggerProvider`, `NewBatchProcessor` |
| `go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc` | `v0.20.0` | gRPC `:4317` client |
| `go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp` | `v0.20.0` | HTTP `:4318` client |

All pure-Go (no new cgo/platform constraint; the existing `confluent-kafka-go` cgo pin is unaffected). Transitive `go.opentelemetry.io/proto/otlp` (already in `go.sum` at v0.7.0 via grpc) will be upgraded. Versions verified against the Go module proxy and `gen_ai.*` keys confirmed present in `semconv/v1.41.0` (`GenAIProviderNameKey`, `GenAIRequestModelKey`, `GenAIUsageInputTokensKey`, `GenAIResponseFinishReasonsKey`).

## Migration / Rollout

Additive and opt-in; default behavior (Kafka only) is unchanged. Enable per-gateway by adding `{name:"otlp", settings:{endpoint:...}}` to `telemetry.exporters`. **Rollback**: remove the single `WithExporter("otlp", ...)` line → `otlp` becomes an unknown exporter, so new saves with otlp settings fail validation while all Kafka traffic/ClickHouse ingestion is unaffected. Full revert: drop `pkg/infra/telemetry/otlp/`, the `config` env additions, and the `go.mod` entries. No data migration, no schema change.

## Open Questions

- [ ] Confirm `LogRecord.Body` should carry the sanitized **response** body (vs leaving Body empty and using only `agentgateway.response.body`). Default chosen: response body in Body, truncated by `max_body_bytes`.
- [ ] Should an optional global `otel.SetErrorHandler` be installed at boot to surface export drops, or rely on the Collector as the observability layer? Default: rely on Collector; optional handler is non-blocking and observability-only.
- [ ] `signal: "traces"` is reserved but unimplemented — confirm `ValidateConfig` should reject `traces` now (recommended) rather than accept-and-noop.
