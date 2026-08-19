# Proposal: Dual-era rollout telemetry (RUN-1109)

## Intent

Make MCP dual-era rollout observable and optionally controllable **without changing today's wire defaults**. Era/revision never reach product events; validation failures `skipMetrics`; southbound probe/cache/fallback are slog-only. Need bounded metrics, dashboards, rollback docs, and a config-synced northbound kill-switch/allowlist that defaults to current dual-era acceptance.

## Scope

### In Scope
- `protocol_era` + bounded `protocol_version` on successful MCP product traces/events post-validation.
- Protocol validation outcome counters (`header_mismatch`, `unsupported_version`, …) on HTTP 400; auth/path still skip.
- Southbound ops meters: probe/cache/override, fallback/incompatible, probe latency; enum labels only.
- Optional consumer northbound gate (`dual_era|legacy_only` + allowlist), **default `dual_era`** (locked).
- Reuse registry `protocol_mode` (`auto|modern|legacy`).
- Docs: OTLP/ops contract, dashboards, rollback, legacy deprecation exit (12 months, residual usage, notice, approval).

### Out of Scope
- Removing legacy; tightening default to `legacy_only`; new telemetry stack / env-only primary controls; composer or raw-body exporter changes.

## Capabilities

### New Capabilities
- `mcp-dual-era-rollout-telemetry`: Era attrs, validation counters, southbound ops meters, PII/cardinality rules, rollout runbooks.

### Modified Capabilities
- `mcp-dual-era-northbound`: Optional config-synced modern acceptance gate; default dual-era; restriction opt-in.

## Approach

**Approach 1** (locked): extend MCPAttrs/events/builder; emit protocol outcomes before skip; meter dialer decisions; consumer gate via API/JSONB/snapshot; southbound stays `protocol_mode`; document dashboards/rollback/deprecation. Chain PRs: attrs → dialer meters → gate → docs.

## Affected Areas

| Area | Impact |
|------|--------|
| `pkg/infra/trace`, `pkg/infra/metrics/events`, `pkg/app/metrics/builder.go` | Protocol product fields |
| `pkg/api/handler/http/mcp/`, `mcp_metrics` middleware | Attrs + outcomes vs skip |
| `pkg/infra/mcp/client/` | Ops counters/histograms |
| `pkg/domain/consumer/` + API/snapshot | Northbound acceptance |
| Registry `protocol_mode` | Reuse only |
| `docs/operational-metrics.md`, `docs/telemetry/`, `docs/mcp/` | Contract + runbooks |

## Risks

| Risk | Mitigation |
|------|------------|
| Cardinality (origin, raw versions) | Enums; known revisions or `unsupported` |
| Secrets in labels | No credentials/tokens/client metadata/tool args |
| Events on auth failures | Narrow skip change to protocol classes |
| PR > 400 lines | Chained slices |

## Rollback Plan

Config: consumer `legacy_only` and/or `protocol_mode=legacy` (no redeploy). Code: revert slices reverse-order; RUN-1103 classify path remains.

## Dependencies

RUN-1103/1108/1105 on tip. Blocks RUN-1104/1101/1107/1106/1102.

## Success Criteria

- [ ] Success events carry era + bounded revision; validation failures countable without secrets.
- [ ] Cache vs probe vs fallback/latency observable; steady-state = cache hits.
- [ ] Default dual-era; opt-in gate can restrict modern.
- [ ] Docs: dashboards, rollback, deprecation exit; legacy not removed.
- [ ] Ready for `sdd-spec` / `sdd-design`.
