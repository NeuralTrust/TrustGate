# Design: Dual-era rollout telemetry (RUN-1109)

## Technical Approach

Extend Approach 1 on existing Dig-wired seams: product attrs via `MCPAttrs` → `events.MCP` → `builder.foldMCPSpans`; protocol validation outcome counters beside (not instead of) `skipMetrics` for auth/path; southbound meters at `negotiatingDialer.logDecision`/`logSelection`; consumer `protocol_acceptance` via MCP JSONB + API/snapshot (same pattern as `fail_mode` / registry `protocol_mode`). Specs: `mcp-dual-era-rollout-telemetry`, `mcp-dual-era-northbound`.

## Architecture Decisions

| Decision | Options | Choice | Rationale |
|----------|---------|--------|-----------|
| Product attrs | New package vs extend MCPAttrs | Extend `MCPAttrs` + `events.MCP` + builder | Matches OTLP `trustgate.mcp.*`; no second event shape |
| Validation outcomes | Full product event vs ops counter before skip | Ops/protocol counter + keep `skipMetrics` for product MCP event on protocol 400 | Spec: countable without composer; auth/path still skip |
| Gate timing | During classify vs after consumer resolve | After `resolveMCPConsumer` / before dispatch | Validate stays consumer-agnostic; acceptance lives on `MCPPolicy` |
| Allowlist | ID list vs per-consumer enum | Per-consumer `protocol_acceptance`; ops “allowlist” = dual_era on approved, `legacy_only` elsewhere | Avoids new cardinality/sync; matches locked default dual_era |
| Southbound meters | Extend `o11y.Provider` vs dialer-local meter | Dialer-local instruments (`otel.Meter("trustgate/mcp_upstream")`), mirror ratelimit | Dialer already has decision enums; avoid bloating HTTP ops provider |
| Probe latency | Always vs source=probe only | Histogram only when `source=probe` | Steady-state cache must not inflate latency |
| Labels | origin/version raw vs enums | Enums only; version → known set or `unsupported`; **no origin label** | Cardinality + PII |
| Southbound control | New field vs reuse | Reuse registry `protocol_mode` | Already synced; RUN-1108 |

## Data Flow

```
Northbound success:
  classify/validate → resolve consumer → [gate] → dispatch
       │                                      │
       └─ SetMCPProtocol(era, boundedVer) ────┴─→ MCPAttrs → builder → events.MCP

Northbound protocol 400:
  classify/validate fail → RecordValidationClass(enum) → skipMetrics → HTTP 400
  (no composer; auth/path still skip-only)

Northbound gate reject (legacy_only + modern):
  resolve consumer → reject → validation_class=acceptance_denied (or peer enum) → skipMetrics

Southbound:
  negotiatingDialer decision → slog (unchanged, may keep origin)
                            → Counter(source,mode,era,result[,category])
                            → Histogram(probe_latency) iff source=probe
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `pkg/infra/trace/span.go` | Modify | `ProtocolEra`, `ProtocolVersion` on `MCPAttrs`; `SetMCPProtocol` |
| `pkg/infra/metrics/events/event.go` | Modify | JSON fields `protocol_era`, `protocol_version` |
| `pkg/app/metrics/builder.go` (+ `_mcp_test.go`) | Modify | Fold new attrs into `events.MCP` |
| `pkg/api/handler/http/mcp/mcp_handler.go` | Modify | Set protocol attrs on success paths; emit outcome before skip on protocol 400; gate after resolve |
| `pkg/api/handler/http/mcp/server_discover.go` / initialize path | Modify | Stamp era/version on local success spans |
| `pkg/api/handler/http/mcp/*_test.go` | Modify | Outcomes vs skip; gate matrix |
| `pkg/infra/mcp/client/protocol_metrics.go` | Create | Thin meter wrapper (counter + probe histogram); no-op if meter init fails soft |
| `pkg/infra/mcp/client/negotiating_dialer.go` | Modify | Record from `logDecision`/`logSelection`; inject meter via ctor |
| `pkg/container/modules/mcp.go` | Modify | Wire meter into `NewNegotiatingDialer` |
| `pkg/domain/consumer/mcp_policy.go` (+ fail-mode peer type file if needed) | Modify | `ProtocolAcceptance` enum; default `dual_era` when empty |
| `pkg/domain/consumer/consumer.go` + hydrate tests | Modify | Accessor / JSONB round-trip |
| `pkg/api/handler/http/consumer/request/*.go` + `response/` | Modify | API field `protocol_acceptance` |
| `docs/telemetry/otlp-metadata-contract.md` | Modify | Document `trustgate.mcp.protocol_*` |
| `docs/operational-metrics.md` | Modify | Southbound + validation instruments |
| `docs/mcp/dual-era-rollout.md` | Create | Dashboards, rollback, deprecation exit |

Unchanged: composer, raw-body exporters, registry `protocol_mode` semantics, legacy transport.

## Interfaces / Contracts

```go
// MCPPolicy addition (default when empty = dual_era)
ProtocolAcceptance ProtocolAcceptance `json:"protocol_acceptance,omitempty"`
// dual_era | legacy_only

// Ops (enum labels only)
// mcp.upstream.protocol.decision_total{source,mode,era,result,category?}
// mcp.upstream.protocol.probe_latency_seconds — only source=probe
// mcp.northbound.protocol.validation_total{validation_class,era?}
```

Bounded `protocol_version`: known modern revisions from handler support set; else `unsupported`. Never label raw client strings, origins, credentials, tool args.

## Testing Strategy

| Layer | What | Approach |
|-------|------|----------|
| Unit | Builder folds era/version; unknown → unsupported | Extend `builder_mcp_test` |
| Unit | Handler: protocol 400 increments class; auth skips | Table-driven handler tests |
| Unit | Gate: empty→dual_era; legacy_only rejects modern, accepts legacy | Consumer + handler |
| Unit | Dialer: cache→no probe hist; probe→hist; override→source=override; no origin attr | `negotiating_dialer_test` + fake meter |
| Unit | API/JSONB round-trip `protocol_acceptance` | Request/response + consumer rehydrate |
| Integration | Optional: config snapshot applies gate without restart | Existing snapshot tests if present |
| E2E | Out of slice unless multi-agent-tests already cover dual-era | Docs/runbook only in PR4 |

## Migration / Rollout

No DB migration beyond JSONB field on existing MCP policy blob. Empty → `dual_era` (no wire change). Opt-in restrict via API `legacy_only` and/or `protocol_mode=legacy`. Chained PRs (~400-line budget):

1. **Attrs + validation counters** (trace/events/builder/handler)
2. **Dialer meters** (client + Dig)
3. **Consumer gate** (domain/API/handler gate)
4. **Docs** (OTLP/ops/runbook)

Rollback: config flip first; code revert reverse order. Legacy not removed.

## Open Questions

- [x] Northbound default — locked `dual_era`
- [ ] Exact `validation_class` enum set for gate deny (`acceptance_denied` vs reuse `unsupported_version`) — prefer distinct `acceptance_denied`
- [ ] Whether validation counters gate on `OPS_METRICS_ENABLED` or always-on lightweight meter — prefer same ops flag as other operational instruments for consistency
