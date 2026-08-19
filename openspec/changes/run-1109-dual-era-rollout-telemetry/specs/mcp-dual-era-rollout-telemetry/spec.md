# MCP Dual-Era Rollout Telemetry Specification

## Purpose

Bounded dual-era rollout observability. Defaults stay dual-era; legacy not removed.

## Requirements

### Requirement: Success-path protocol product attributes

Success MCP traces/events MUST include `protocol_era` (`legacy|modern`) and bounded `protocol_version` from known revisions; unknowns MUST map to `unsupported`, never free-form labels.

#### Scenario: Modern success attrs
- GIVEN validated modern request with known revision
- WHEN product telemetry emits
- THEN `protocol_era=modern` and matching `protocol_version`

#### Scenario: Unknown revision bounded
- GIVEN non-enumerated revision
- WHEN recorded
- THEN value is `unsupported`

### Requirement: Protocol validation outcome counters

HTTP 400 protocol failures MUST emit countable outcome with bounded `validation_class` (`header_mismatch`, `unsupported_version`, …). Auth/path MUST still skip product metrics. MUST NOT label credentials, tokens, client metadata, headers, bodies, or tool args.

#### Scenario: Header mismatch countable
- GIVEN modern validation HTTP 400
- WHEN rejected
- THEN matching `validation_class` increments without sensitive labels

#### Scenario: Auth still skips
- GIVEN unauthenticated request
- WHEN rejected
- THEN no product MCP event; auth alone does not increment protocol counters

### Requirement: Southbound negotiation ops meters

Meters MUST use `source` ∈ {`cache`,`probe`,`override`,`contradiction`} and bounded `result`. Probe latency ONLY when `source=probe`. `protocol_mode` MAY be enum label. Origin MUST NOT be a metric label.

#### Scenario: Steady-state cache
- GIVEN cached decision
- WHEN dialing
- THEN `source=cache`; no probe-latency sample

#### Scenario: Probe without origin label
- GIVEN `auto` and no cache
- WHEN probe runs
- THEN `source=probe` + latency; no origin/credentials/tool-arg labels

#### Scenario: Override skips probe
- GIVEN `modern` or `legacy` mode
- WHEN dialing
- THEN `source=override`; no probe

### Requirement: Label and log safety

New protocol telemetry MUST use enum/bounded values only; MUST NOT label credentials, tokens, client metadata, tool args, bodies, or origin URL.

#### Scenario: Forbidden fields absent
- GIVEN any protocol telemetry path
- WHEN inspecting labels
- THEN forbidden fields above are absent

### Requirement: Rollout documentation

Docs MUST cover OTLP/ops contract, dashboards (cache hits, validation failures), config rollback (`protocol_acceptance` / `protocol_mode`) without redeploy, and deprecation exit (12 months, residual usage, notice, approval). MUST NOT remove legacy.

#### Scenario: Rollback without redeploy
- GIVEN dual-era live
- WHEN config sets `legacy_only` and/or `protocol_mode=legacy`
- THEN modern paths restrict without binary redeploy

#### Scenario: Deprecation exit published
- GIVEN rollout docs
- WHEN reading exit criteria
- THEN 12-month window, residual usage, notice, approval stated; legacy not removed
