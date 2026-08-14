# Exploration: RUN-1109 dual-era rollout telemetry

## Current State

### Source of truth and worktree

- Linear: [RUN-1109](https://linear.app/neuraltrust/issue/RUN-1109/featmcp-roll-out-dual-era-support-with-protocol-telemetry) — In Progress, assignee Edu, parent RUN-1100, blocked by RUN-1105 (now merged on this tip), blocks RUN-1104/1101/1107/1106/1102.
- Worktree: `/Users/edu/Neuraltrust/TrustGate-run-1109`.
- Branch: `feat/run-1109-dual-era-rollout-telemetry` (dual-era stack tip including RUN-1103/1108/1105; HEAD includes merge of RUN-1105 conformance).
- Artifact mode: hybrid. Repo has `openspec/` but no `openspec/config.yaml`; follow shared OpenSpec layout + Engram `sdd/run-1109-dual-era-rollout-telemetry/explore` under Engram project `edu`.

### What already exists (post RUN-1103 / RUN-1108)

| Layer | Present today | Instrumentable? |
|---|---|---|
| Northbound era classify + modern validation | `protocol_era.go`, `modern_validation.go` in `pkg/api/handler/http/mcp/` — always on after auth | Logic yes; **no era/revision attrs emitted** |
| Modern validation failures | Header/body mismatch (`-32020`), unsupported version (`-32022`), etc. | Failures call `skipMetrics(c)` → **product events dropped** |
| Successful MCP RPC telemetry | `MCPMetricsMiddleware` → spans → `events.MCP` via `builder.go` | Method/op/upstream/host/tool/status/latency only |
| Local `server/discover` | Span with method=`server/discover`, operation=`discovery` | No era/revision fields |
| Southbound `protocol_mode` | Registry `MCPTarget.ProtocolMode` = `auto\|modern\|legacy`, default `auto`; JSONB + config snapshot round-trip | **Config control exists**; not a metric |
| Southbound negotiation | `eraCoordinator` + `negotiatingDialer` + probe cache/singleflight | Structured **slog only** (`component=mcp_upstream_protocol`, origin/mode/era/source/result/version/latency_ms/category) |
| Ops metrics | `OPS_METRICS_ENABLED` → `http.server.request.duration` + `agentgateway.request.outcome_total` with plane/route/outcome | MCP plane coarse (`mcp.rpc`); **no protocol dims**; intentionally no hosts/bodies |
| Docs | `docs/mcp/testing-guide.md` documents `protocol_mode` matrix; `docs/operational-metrics.md` + `docs/telemetry/otlp-metadata-contract.md` lack protocol-era fields | Runbooks/dashboards/deprecation exit criteria **missing** |

### Product telemetry contract today

`trace.MCPAttrs` / `events.MCP` fields:

`method`, `operation`, `server_name`, `registry_id`, `host`, `catalog_code`, `transport`, `tool`, `upstream_tool`, `prompt`, `resource_uri`, `targets`, `upstream_status`, `upstream_latency_ms`, `rpc_error_code`.

**Absent:** `protocol_era`, `protocol_version` / revision, validation failure class, southbound mode, decision source (`cache|probe|override`), probe/fallback counters.

### Northbound rollout control today

Modern northbound is **unconditionally available** on every MCP consumer once a request carries modern signals. Absent modern signals → legacy path (legacy-compatible default for existing clients). There is **no** consumer/gateway flag to allowlist modern northbound or force legacy-only acceptance.

`consumer.MCPPolicy` only has `toolkit` + `fail_mode` — no protocol acceptance field.

### Southbound rollout control today

Registry-level `protocol_mode` already satisfies the Linear “registry-level auto|modern|legacy” requirement and syncs through existing registry/config-snapshot paths (no env redeploy to flip a target). Default `auto` probes once per origin then caches for process lifetime.

### Observability gap vs RUN-1109 QA checklist

| QA item | Status |
|---|---|
| Steady-state calls perform no protocol probe | **Behavior exists** (era cache); **not observable as a metric** (only slog when dialer logs) |
| Probe duration and fallback rates observable | **Partial** — slog latency; **no counters/histograms** |
| Rollout disabled without incompatible redeploy | Southbound: yes via `protocol_mode`. Northbound: **no control** |
| Metric cardinality bounded | Ops path safe; product events already label `host`/tool; new dims must stay enums |
| Legacy default until approval | Wire behavior legacy-compatible for non-modern clients; modern still globally accepted |
| Rollback + deprecation criteria documented | **Missing** |

## Gaps vs RUN-1109 scope

1. **Northbound protocol telemetry after validation** — era + revision must appear on successful traces/events; validation failures currently skip the entire product metrics pipeline.
2. **Southbound probe/fallback/cache/version-failure metrics** — upgrade slog decisions into bounded OTel/ops (or product) counters + latency histograms without credentials/tool args/client metadata.
3. **Header/body mismatch / version failure counters** — need emission even when HTTP 400 is returned (today `skipMetrics`).
4. **Northbound opt-in control** — missing; needed so modern can be enabled per consumer (or gateway) while others stay legacy-only.
5. **Dashboards/queries + rollback criteria** — docs only.
6. **Legacy deprecation exit criteria** — 12-month window, residual usage threshold, customer notice, explicit approval — docs only; out of scope to remove legacy.

## Affected Areas

### Direct implementation surface

| Area | Why |
|---|---|
| `pkg/infra/trace/span.go` (`MCPAttrs`, setters) | Add bounded protocol fields (era, revision, optional validation_class / southbound_source). |
| `pkg/infra/metrics/events/event.go` + `pkg/app/metrics/builder.go` | Export new MCP fields into product events / `trustgate.mcp.*`. |
| `pkg/api/handler/http/mcp/mcp_handler.go` (+ validation/discover paths) | Record era/revision after classify/validate; stop blindly skipping all metrics on protocol errors (or emit a lightweight protocol outcome before skip). |
| `pkg/api/middleware/mcp_metrics.go` / ops metrics | Possibly gate emission; keep bodies out of ops path. |
| `pkg/infra/mcp/client/negotiating_dialer.go`, `era.go`, `probe.go` | Emit counters/histograms on probe vs cache vs override, fallback/incompatible/unreachable categories; keep slog; never label credentials. |
| `pkg/domain/consumer/mcp_policy.go` (+ API request/response + repository/config snapshot) | Northbound acceptance opt-in (e.g. `protocol_acceptance: legacy_only\|dual_era`, default `legacy_only` **or** `dual_era` with explicit product decision — see Approaches). |
| `pkg/domain/registry/mcp_target.go` | Southbound `protocol_mode` already present — document + expose in runbooks; maybe metric label `mode`. |
| `docs/operational-metrics.md`, `docs/telemetry/otlp-metadata-contract.md`, `docs/mcp/` runbook | Dashboards, queries, rollback, deprecation exit criteria. |
| Tests: handler/metrics/client/functional | Prove no probe in steady state via metrics; cardinality; opt-in defaults; PII absence. |

### Coupled, normally unchanged

| Area | Constraint |
|---|---|
| Composer / RPC gateway | Stay version-neutral; do not push protocol wire types into app layer. |
| Raw OTLP / request body exporters | Must not gain tool arguments or credentials via protocol labels. |
| Config sync worker | Reuse snapshot JSON for consumer/registry fields; no new transport. |

## Approaches

### 1. Extend MCPAttrs + ops meters + consumer northbound gate (recommended)

Add bounded protocol fields to the existing MCP product-event path; emit protocol validation outcomes instead of silent `skipMetrics` for classify/validate failures; add a small ops Meter for southbound negotiation (`source`, `era`, `mode`, `result` enums + probe latency histogram); add consumer-level northbound acceptance synced via config; write runbooks.

- Pros:
  - Reuses Dig-wired middleware, builder, OTLP metadata contract, and config sync.
  - Matches RUN-1103/1108 seams without a second telemetry stack.
  - Bounded enum labels keep cardinality under control.
  - Southbound control already exists; northbound fills the real gap.
- Cons:
  - Must carefully redefine `skipMetrics` so auth failures still skip while protocol failures become countable.
  - Product decision required on default for northbound acceptance (`legacy_only` vs keep today’s always-on dual-era).
- Effort: Medium.

### 2. Standalone protocol telemetry package + env feature flags only

New `pkg/infra/mcp/protocolmetrics` with its own meters; northbound gate via process env (`MCP_MODERN_NORTHBOUND=true`).

- Pros: Isolated; fast kill-switch via redeploy/env.
- Cons: Violates “disable without incompatible redeploy” for per-consumer rollout; duplicates patterns; env is global not allowlist; harder multi-tenant staged rollout.
- Effort: Medium-High (integration + dual config stories).

### 3. Logs-only observability + documentation

Rely on negotiating dialer slog + HTTP status; document LogQL/Cloud Logging queries; no schema changes.

- Pros: Lowest code risk.
- Cons: Fails Linear counters/latency/cardinality QA; validation failures still invisible in product telemetry; no structured northbound era on success path.
- Effort: Low (insufficient).

## Recommendation

**Approach 1.**

Concrete shape for proposal/design:

1. **Northbound telemetry (after validation success):** set `protocol_era` (`legacy|modern`) and `protocol_version` (bounded known revisions only; unknown → `unsupported` / omit free-form client strings as labels).
2. **Northbound validation failures:** emit a protocol-outcome counter (and optionally a minimal MCP span/event) with `validation_class` enum (`header_mismatch`, `unsupported_version`, `missing_meta`, `method_not_found`, …) **before** or instead of full skip; never attach headers/body/tool args.
3. **Southbound metrics:** meter from dialer decisions already logged — `source` ∈ {cache,probe,override,contradiction}, `result` ∈ {selected,failed,incompatible,unclassified,…}, histogram `probe_latency` only when `source=probe`; do **not** use `origin` as a metric label (cardinality); optional log-only origin remains.
4. **Rollout controls:**
   - Southbound: keep registry `protocol_mode` (document staged enable: internal registries → `modern`/`auto`, others `legacy`).
   - Northbound: add consumer (or gateway) opt-in, default **legacy-compatible**. Prefer default that preserves current dual-era acceptance for already-shipped RUN-1103 unless product explicitly wants a breaking tighten to `legacy_only` — **propose must decide**. Safest rollout narrative matching Linear wording: default `legacy_only` for *new* semantics only if product accepts a temporary reject of modern clients until allowlisted; otherwise keep dual-era on and use telemetry + southbound staging first.
5. **Docs:** extend operational-metrics + OTLP contract; add MCP dual-era rollout runbook with dashboards, rollback (flip consumer acceptance / `protocol_mode` via config sync), and legacy deprecation exit criteria (12 months, residual threshold, notice, explicit approval). **Do not remove legacy.**

## Risks

- **Cardinality:** labeling `origin`, raw version strings, tool names, or consumer IDs on ops counters will blow series; keep enums + maybe `registry_id` only on product events (already present).
- **PII / secrets:** `MCPMetricsMiddleware` still copies request headers/bodies into product `RequestContext` today — protocol work must not add credentials, tokens, client metadata, or tool arguments as **labels**; prefer not expanding raw capture.
- **Default behavior:** tightening northbound to `legacy_only` by default would break modern clients already hitting dual-era tip; loosening documentation without a gate leaves Linear “controlled internal consumers first” unmet.
- **skipMetrics semantics:** changing skip behavior can accidentally emit events for unauthenticated or path-resolution failures.
- **Probe observability vs steady-state:** metrics must distinguish cache hits from probes so dashboards can prove “steady-state no probe.”
- **PR size:** telemetry + consumer config + docs likely exceeds 400-line budget → chain (schema/attrs → dialer meters → northbound gate → docs).
- **Engram project naming:** TrustGate SDD artifacts live under Engram project `edu` (no `TrustGate` project in store).

## Ready for Proposal

Yes. Orchestrator should run **sdd-propose** for `run-1109-dual-era-rollout-telemetry` and force an explicit product decision on northbound default (`keep dual-era always-on` vs `legacy_only until allowlisted`) before design locks the consumer field.
