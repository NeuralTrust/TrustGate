# Dual-era MCP rollout

TrustGate accepts MCP `2026-07-28` and legacy ≤`2025-06-18` on the same
northbound plane. The default stays **dual-era**. Legacy is not removed in
this rollout.

## Quick path

1. Leave consumer `protocol_acceptance` empty (defaults to `dual_era`) and
   registry `protocol_mode` at `auto`.
2. Enable `OPS_METRICS_ENABLED=true` to see protocol counters.
3. Restrict a consumer or upstream with a config write — no binary redeploy.

For subscriptions, first enable and observe
`MCP_SUBSCRIPTIONS_ENABLED=true` with
`MCP_SUBSCRIPTIONS_UPSTREAM_ENABLED=false`. After northbound lease, capacity,
and terminal outcomes are stable, enable the upstream flag on one instance,
verify listener/reconnect/queue metrics, then expand the rollout. Upstream
listeners are process-local; there is no cross-pod sharing.

## Controls

| Knob | Where | Default | Effect |
|------|-------|---------|--------|
| `protocol_acceptance` | MCP consumer (`dual_era` \| `legacy_only`) | empty → `dual_era` | `legacy_only` rejects modern northbound with HTTP 400 / RPC `-32021` / `validation_class=acceptance_denied`. No composer or upstream. |
| `protocol_mode` | Registry MCP target (`auto` \| `modern` \| `legacy`) | `auto` | Southbound: `auto` probes once then caches; `modern`/`legacy` skip the probe (`source=override`). |
| `MCP_SUBSCRIPTIONS_UPSTREAM_ENABLED` | Process environment | `false` | Enables bounded modern `2026-07-28` subscription listeners only when northbound subscriptions are also enabled. A legacy target or an incomplete capability negotiation contributes no honoured kind. |

Config sync applies both fields without a process restart.

## Dashboards

Require `OPS_METRICS_ENABLED=true`. Product events carry
`trustgate.mcp.protocol_era` / `protocol_version` on success only
([OTLP contract](../telemetry/otlp-metadata-contract.md)).

| Question | Signal |
|----------|--------|
| Are clients still on legacy? | Product events: `trustgate.mcp.protocol_era=legacy` vs `modern` |
| Unknown revisions leaking? | `trustgate.mcp.protocol_version=unsupported` |
| Protocol 400s by class | `mcp.northbound.protocol.validation_total` by `validation_class` (include `acceptance_denied`) |
| Steady-state vs first contact | `mcp.upstream.protocol.decision_total` `source=cache` vs `source=probe` |
| Probe cost | `mcp.upstream.protocol.probe_latency_seconds` (probe-only) |
| Forced southbound era | `source=override` with `mode=modern` or `mode=legacy` |
| Header/body era fights | `source=contradiction` |

Do not chart origin, credentials, tokens, or tool arguments — those labels
are not emitted.

## Rollback without redeploy

To stop modern northbound for a consumer, set
`protocol_acceptance=legacy_only` on that consumer. Legacy clients keep
working. To force a legacy upstream, set registry `protocol_mode=legacy`.
Either change lands through config sync.

To restore dual-era, set `protocol_acceptance=dual_era` (or clear it) and
`protocol_mode=auto`.

To roll back only southbound subscription fan-out, set
`MCP_SUBSCRIPTIONS_UPSTREAM_ENABLED=false` and restart. This closes and joins
physical listeners before northbound drain, retains the public stream shape, and
returns to Slice 1 polling. No legacy session, GET SSE route, cursor, or
persisted state needs cleanup.

## Deprecation exit

Legacy support stays until **all** of the following are true:

| Criterion | Bar |
|-----------|-----|
| Migration window | At least 12 months after dual-era GA |
| Residual usage | Sustained near-zero `protocol_era=legacy` and `source` decisions that still need legacy |
| Notice | Customers notified of the planned cutover |
| Approval | Explicit product and engineering sign-off |

This document does **not** authorize removing the legacy transport.

## Checklist

- [ ] Cache hits dominate `decision_total` after warmup
- [ ] `acceptance_denied` only appears on consumers set to `legacy_only`
- [ ] A config flip to `legacy_only` / `protocol_mode=legacy` takes effect without redeploy
- [ ] Metric cardinality stays on the enums above

## Next step

Bounded `subscriptions/listen` streaming on the modern plane, off by default, is
documented in [MCP subscriptions](subscriptions.md).
Exercise the plane with the [MCP testing guide](testing-guide.md).
Instrument names live in [Operational metrics](../operational-metrics.md).
