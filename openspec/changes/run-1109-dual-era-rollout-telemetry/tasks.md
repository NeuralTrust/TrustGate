# Tasks: Dual-era rollout telemetry (RUN-1109)

## Review Workload Forecast

| Field | Value |
|---|---|
| Estimated changed lines | 1240–1520 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1 (340–390) → PR 2 (300–370) → PR 3 (380–460) → PR 4 (220–300) |
| Delivery strategy | auto-chain |
| Chain strategy | stacked-to-main |

Decision needed before apply: No
Chained PRs recommended: Yes
Chain strategy: stacked-to-main
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|---|---|---|---|
| 1 | Product attrs + validation counters | PR 1 | Current branch; base `origin/main` |
| 2 | Southbound dialer meters | PR 2 | Base PR 1 branch; merge after PR 1 |
| 3 | Consumer `protocol_acceptance` gate | PR 3 | Base PR 2; `size:exception` if >400 |
| 4 | OTLP/ops/runbook docs | PR 4 | Base PR 3; docs-only |

Each child PR must show only its slice; merge to `main` in order and retarget the next PR after its parent merges.

### Locks

- Gate reject uses distinct `validation_class=acceptance_denied` (not `unsupported_version`).
- New ops instruments no-op unless `OPS_METRICS_ENABLED` (same gate as `o11y.Provider`).
- Persist `protocol_acceptance` as nullable TEXT column like `fail_mode` (`ADD COLUMN IF NOT EXISTS`). Toolkit JSON is an array and cannot host the field.
- Enum/bounded labels only; never origin, credentials, tokens, client metadata, headers, bodies, or tool args.
- Default `protocol_acceptance` empty → `dual_era`. Do not remove legacy. Reuse registry `protocol_mode`.

## Phase 1: Attrs + validation counters (PR 1)

- [x] 1.1 RED: extend `pkg/app/metrics/builder_mcp_test.go` so success folds `protocol_era`/`protocol_version` and unknown revision → `unsupported`. Spec: Modern success attrs; Unknown revision bounded.
- [x] 1.2 GREEN: add fields + `SetMCPProtocol` on `pkg/infra/trace/span.go` `MCPAttrs`; JSON on `pkg/infra/metrics/events/event.go`; fold in `pkg/app/metrics/builder.go`. Bound version to handler known set else `unsupported`.
- [x] 1.3 GREEN: stamp era/version on success in `mcp_handler.go`, `rpc_dispatcher.go`, `server_discover.go`. Keep composer/raw exporters unchanged.
- [x] 1.4 RED: handler tests — protocol HTTP 400 increments bounded class; auth/path still `skipMetrics` with no protocol counter. Spec: Header mismatch countable; Auth still skips; Protocol failure emits outcome without composer; Boundary rejection.
- [x] 1.5 GREEN: add handler-local meter (`mcp.northbound.protocol.validation_total{validation_class,era?}`) gated on `OPS_METRICS_ENABLED`; nil recorder = no-op so `NewHandler` tests stay 2-arg. Emit before `skipMetrics` on protocol 400. Enum includes `header_mismatch`, `unsupported_version`, `acceptance_denied` (unused until PR 3). Map `-32020`/`-32022` plus other existing protocol codes to closed enums. Dig-wire from `cfg.Telemetry.OpsMetricsEnabled`. Spec: Forbidden fields absent.
- [x] 1.6 `clean-comments` on phase files; `/reviewer` + `/verifier`: `go test -race ./pkg/infra/trace ./pkg/app/metrics ./pkg/api/handler/http/mcp`, `go vet ./...`, `golangci-lint run`.

## Phase 2: Dialer meters (PR 2)

- [x] 2.1 RED: `negotiating_dialer_test.go` + fake meter — cache → `source=cache` and no probe histogram; probe → `source=probe` + latency; `modern`/`legacy` → `source=override` no probe; contradiction labeled; no origin/credential/tool-arg attrs. Spec: Steady-state cache; Probe without origin label; Override skips probe; Forbidden fields absent.
- [x] 2.2 GREEN: create `pkg/infra/mcp/client/protocol_metrics.go` (`otel.Meter("trustgate/mcp_upstream")`): `mcp.upstream.protocol.decision_total{source,mode,era,result,category?}`, `mcp.upstream.protocol.probe_latency_seconds` only when `source=probe`. Soft no-op if meter init fails or `OPS_METRICS_ENABLED` is false.
- [x] 2.3 GREEN: record from `logDecision`/`logSelection` in `negotiating_dialer.go`; inject recorder via ctor (nil no-op); wire in `pkg/container/modules/mcp.go`. Leave slog origin as-is. Do not change `protocol_mode` semantics.
- [x] 2.4 `clean-comments`; `/reviewer` + `/verifier`: `go test -race ./pkg/infra/mcp/client`, `go vet ./...`, `golangci-lint run`.

## Phase 3: Consumer gate (PR 3)

- [x] 3.1 RED: `toolkit_test.go` / `mcp_policy` tests — empty → `dual_era`; invalid rejected; `legacy_only`/`dual_era` accepted. Spec: Default preserves dual-era.
- [x] 3.2 GREEN: `ProtocolAcceptance` on `pkg/domain/consumer/mcp_policy.go`; accessor on `consumer.go`; default empty → `dual_era` in `Validate`.
- [x] 3.3 GREEN: API `protocol_acceptance` on `pkg/api/handler/http/consumer/request/*.go` + `response/`; thread through `pkg/app/consumer/creator.go` + `updater.go` like `fail_mode`.
- [x] 3.4 GREEN: goose migration `ADD COLUMN IF NOT EXISTS protocol_acceptance TEXT` (nullable, MCP-only like `fail_mode`); persist/scan in `pkg/infra/repository/consumer/repository.go` + `repository_test.go`. Snapshot/JSONB hydrate must round-trip without process restart. Spec: Config sync round-trip.
- [x] 3.5 GREEN: after `resolveMCPConsumer` and before dispatch in `mcp_handler.go`: `legacy_only` + modern → HTTP 400 bounded error, `validation_class=acceptance_denied`, `skipMetrics`, no composer/upstream; `legacy_only` + legacy unchanged; unset/`dual_era` keeps dual-era. Spec: Legacy-only rejects modern; Legacy-only accepts legacy; Default preserves dual-era.
- [x] 3.6 `clean-comments`; `/reviewer` + `/verifier`: `go test -race ./pkg/domain/consumer ./pkg/app/consumer ./pkg/api/handler/http/consumer ./pkg/api/handler/http/mcp ./pkg/infra/repository/consumer`, `go vet ./...`, `golangci-lint run`. If diff >400, add `size:exception`.

## Phase 4: Docs (PR 4)

- [x] 4.1 Document `trustgate.mcp.protocol_era` / `protocol_version` (bounded; unknown → `unsupported`) in `docs/telemetry/otlp-metadata-contract.md`.
- [x] 4.2 Document northbound `validation_total` and southbound decision/probe instruments + `OPS_METRICS_ENABLED` in `docs/operational-metrics.md`. Enum labels only; no origin/PII.
- [x] 4.3 Create `docs/mcp/dual-era-rollout.md`: dashboards (cache hits vs probes, validation classes including `acceptance_denied`), config rollback (`protocol_acceptance=legacy_only` and/or `protocol_mode=legacy`) without redeploy, deprecation exit (12 months, residual usage, notice, approval). MUST NOT remove legacy. Spec: Rollback without redeploy; Deprecation exit published.
- [x] 4.4 Link the runbook from `docs/mcp/testing-guide.md`. No e2e unless already covered.
