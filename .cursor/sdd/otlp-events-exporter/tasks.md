# Tasks: OTLP "events" exporter (business events via OTel Collector)

> Source of truth: `design.md` (Engram `sdd/otlp-events-exporter/design` #101) and the two specs
> (`sdd/spec/otlp-events-exporter` #100). Scope: ONLY the new `otlp` Logs exporter, opt-in per-gateway,
> Kafka stays default, downstream contract untouched. NO production code is written in this phase.

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~1000–1400 total (≈600–800 prod + ≈500–650 tests + `go.sum` noise) |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1 → PR 2 → PR 3 → PR 4 |
| Delivery strategy | ask-on-risk (default; orchestrator did not override) |
| Chain strategy | pending (user decision) |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: pending
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Deps + `config.OTLPConfig` + `settings.go` (+ test) | PR 1 | Base = tracker branch. Pure parse/validate; no wiring. **Sensitive: config.** |
| 2 | `mapping.go` Event→LogRecord (+ table test) | PR 2 | Base = PR 1. Pure function; semconv pinned. |
| 3 | `provider.go` + `exporter.go` + seam (+ test) | PR 3 | Base = PR 2. In-memory sdklog exporter; no real Collector. |
| 4 | `template.go` + 1-line wiring + docs | PR 4 | Base = PR 3. **Sensitive: DI wiring + config docs.** |

If the team prefers `stacked-to-main`, each unit merges to `main` in order instead. `single-pr` requires a
`size:exception` (>400 lines). Recommendation: **feature-branch-chain** (additive feature, coordinated rollback).

## Phase 1: Foundation — dependencies + config

- [ ] 1.1 Add pinned OTel deps to `go.mod` (then `go mod tidy`): `go.opentelemetry.io/otel v1.44.0`, `otel/log v0.20.0`, `otel/sdk v1.44.0`, `otel/sdk/log v0.20.0`, `exporters/otlp/otlplog/otlploggrpc v0.20.0`, `otlploghttp v0.20.0`.
  - Files: `go.mod`, `go.sum`. Done: `go build ./...` resolves; versions match design Dependencies table; pure-Go (no new cgo). Spec: otlp-events-exporter §Dependencies.
- [ ] 1.2 Add `OTLPConfig{Endpoint,Headers,Protocol,Timeout,Insecure,Compression}`, `TelemetryConfig.OTLP`, and `getOTLPConfig()` reading `OTEL_EXPORTER_OTLP_{ENDPOINT,HEADERS,PROTOCOL,TIMEOUT,INSECURE,COMPRESSION}` + defaults consts; wire `getOTLPConfig()` into `getTelemetryConfig()`.
  - Files: `pkg/config/config.go`. Done: `go build` passes; env vars parsed (HEADERS as `k=v,k=v`). Spec: otlp-events-exporter §Environment Fallback. **Sensitive: config.**

## Phase 2: Settings + structural validation

- [ ] 2.1 Create `settings.go`: `Settings`, `TLSSettings`, `Protocol`/`Signal` enums, `parseSettings(raw, env)` (mapstructure + env fallback, settings win, defaults grpc/logs/gzip/10s), `validate()` structural-only.
  - Files: `pkg/infra/telemetry/otlp/settings.go`. Done: defaults applied; `validate()` rejects empty endpoint w/o env, bad protocol/signal enum, `timeout<=0`, missing TLS files, `insecure+tls` combo, and `signal:"traces"` (reserved). No network I/O. Spec: otlp-events-exporter §Settings Schema, §Env Fallback, §Structural Validation.
- [ ] 2.2 Create `settings_test.go`: table-driven over env-fallback vs override, defaults, each validation failure, unknown-key tolerance.
  - Files: `pkg/infra/telemetry/otlp/settings_test.go`. Done: covers scenarios "Minimal valid", "Unknown key tolerated", "Endpoint from env", "Settings override env", "Invalid protocol", "Missing TLS file". Testable in isolation (no Collector).

## Phase 3: Event → OTLP mapping

- [ ] 3.1 Create `mapping.go`: `eventToRecord(evt *events.Event, maxBodyBytes int) otellog.Record`, single semconv-pinned (`semconv/v1.41.0`) mapping per design table; severity from `Status.Code`; body = truncated sanitized response body; `agentgateway.*` for proprietary; empty `trace_id` → no TraceID (no error).
  - Files: `pkg/infra/telemetry/otlp/mapping.go`. Done: all keys per design.md mapping table; `policy_chain`/`attempts` JSON-encoded; `attempts.count` int. Spec: otlp-events-exporter §Event to OTLP Mapping, §PII/Size; Edge: empty trace_id.
- [ ] 3.2 Create `mapping_test.go`: table-driven over full LLM / error / streaming / no-usage / over-cap-body / empty-trace events; collect attrs via `record.WalkAttributes` into a map; assert keys/values/severity/body/truncation.
  - Files: `pkg/infra/telemetry/otlp/mapping_test.go`. Done: asserts standard+proprietary coexist, body cap, severity buckets (<400 INFO / 4xx WARN / ≥500 ERROR). Pure, no provider.

## Phase 4: Provider + Exporter

- [ ] 4.1 Create `provider.go`: `newLoggerProvider(ctx, Settings) (*sdklog.LoggerProvider, error)` — dedicated provider (batch processor drop-on-full + otlploggrpc/otlploghttp client by `Protocol` + `resource` + attr-value length limit); lazy connect (down Collector never blocks build); NEVER `otel.SetLoggerProvider`.
  - Files: `pkg/infra/telemetry/otlp/provider.go`. Done: grpc→:4317, http/protobuf→:4318; gzip/none, insecure/TLS honored. Spec: otlp-events-exporter §Lifecycle, §Non-Blocking.
- [ ] 4.2 Create `exporter.go`: `Exporter` impl `appmetrics.Exporter` (`Name`/`Publish`/`Close`); `Publish` = `eventToRecord` + `logger.Emit` (non-blocking, returns nil unless shut down); `Close` = `ForceFlush`+`Shutdown` bounded by `Timeout`/5s default; add `newExporterWithProvider` seam for tests.
  - Files: `pkg/infra/telemetry/otlp/exporter.go`. Done: matches `pipeline.Exporter` iface (`Close()` no return); never blocks hot path. Spec: otlp-events-exporter §Non-Blocking, §Lifecycle, §Error Handling.
- [ ] 4.3 Create `exporter_test.go`: inject in-memory sdklog exporter via `newExporterWithProvider`; `Publish` then `ForceFlush`, assert recorded records; assert `Close` flushes within timeout; nil-event no-op.
  - Files: `pkg/infra/telemetry/otlp/exporter_test.go`. Done: covers "One log record per request", "Graceful shutdown flushes". No real Collector.

## Phase 5: Template + wiring + docs

- [ ] 5.1 Create `template.go`: `const ExporterName="otlp"`; `Template{logger, envCfg}`; `NewTemplate(logger, envCfg)`; `Name`/`ValidateConfig` (delegates `parseSettings`+`validate`, no network)/`WithSettings` (build provider+exporter).
  - Files: `pkg/infra/telemetry/otlp/template.go`. Done: implements `infratelemetry.ExporterTemplate`; `Name()=="otlp"`. Spec: otlp-events-exporter §Settings Schema, §Validation.
- [ ] 5.2 Register exporter: one line `infratelemetry.WithExporter(otlp.ExporterName, otlp.NewTemplate(logger, cfg.Telemetry.OTLP))` in `newExporterFactory`.
  - Files: `pkg/container/modules/telemetry.go`. Done: `otlp` resolves through `validateExporters`→`ExporterLocator.Validate`; Kafka default unchanged. Spec: otlp-events-exporter §Extensibility; metrics-telemetry §Per-Gateway OTLP Opt-In, §Validation Wired. **Sensitive: DI wiring.**
- [ ] 5.3 Document `otlp` Settings + `OTEL_EXPORTER_OTLP_*` env vars + fan-out example.
  - Files: `README.md` (+ telemetry docs). Done: keys/defaults/enums table; "Kafka default + OTLP opt-in" example. Spec: proposal Affected Areas (docs).

## Phase 6: Verification & acceptance

- [ ] 6.1 License headers on every new `.go` file (`make license`) — CI runs `make license-check`.
- [ ] 6.2 Run the verification commands below; all must pass.
- [ ] 6.3 Verify acceptance criteria: no exporters → Kafka only; `{name:"otlp",...}` → Collector + Kafka fan-out; invalid settings rejected on create/update; Collector down → request unaffected (events dropped/logged); ClickHouse `gateway_metrics` keeps populating (`schema_version=2`); shutdown flushes within timeout. Spec: both specs §Acceptance Criteria.
- [ ] 6.4 Diff audit (unchanged surface): Kafka exporter, `Event` schema, `Builder`, `Worker`, `pipeline.resolveTargets`, `exporter_cache.go`, `exporter_validation.go` untouched. Spec: metrics-telemetry §Downstream Contract Unchanged.

## Isolated-test summary

| Test | Isolated? | Needs |
|------|-----------|-------|
| settings/validate (2.2) | Yes | none |
| mapping (3.2) | Yes | none (pure fn) |
| exporter Publish/Close (4.3) | Yes | in-memory sdklog exporter (seam) |
| fan-out / DI / e2e | No | manual/functional; Collector for live wire (deferred) |

## Verification commands

```bash
go mod tidy && go build ./...
make fmt          # gofmt -s -w . && go vet ./...
make lint         # golangci-lint run ./...
go test -race -coverprofile=coverage.out -covermode=atomic ./pkg/infra/telemetry/otlp/...
go test -race ./pkg/...
make license-check
make build
```

## Sensitive surfaces (review carefully)

- `pkg/config/config.go` (1.2) — new env contract `OTEL_EXPORTER_OTLP_*`.
- `pkg/container/modules/telemetry.go` (5.2) — DI wiring; one wrong line disables `otlp` or breaks factory.
- `provider.go` (4.1) — only place allowed to touch OTel SDK globals; MUST NOT call `otel.SetLoggerProvider`.

## Notes / gotchas

- **Semconv key discrepancy**: the spec table lists `gen_ai.system`, `agentgateway.consumer`, `agentgateway.cost`, `server.address`. Follow **design.md** (authoritative, pinned `semconv/v1.41.0`): `gen_ai.provider.name`, `agentgateway.consumer.id/.name`, `agentgateway.cost.total_usd`(+prompt/completion/currency); `server.address`/`url.scheme` omitted (absent in Event v2, documented).
- Mode = **hybrid** (this file + Engram `sdd/otlp-events-exporter/tasks`).
- Body in `LogRecord.Body` = sanitized response body, truncated by `max_body_bytes` (design default for the open question).
