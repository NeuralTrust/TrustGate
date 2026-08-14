# Delta for MCP Dual-Era Northbound

## ADDED Requirements

### Requirement: Northbound protocol acceptance gate

Consumer MCP policy MUST support config-synced `protocol_acceptance` ∈ {`dual_era`,`legacy_only`}. Absent MUST default `dual_era`. `legacy_only` MUST reject modern (HTTP 400, bounded error) and MUST accept legacy. Opt-in per consumer; MUST round-trip API/JSONB/snapshot. Env-only primary controls MUST NOT be required.

#### Scenario: Default preserves dual-era
- GIVEN unset acceptance
- WHEN valid modern request
- THEN modern classify/validate proceeds

#### Scenario: Legacy-only rejects modern
- GIVEN `legacy_only`
- WHEN modern signals present
- THEN HTTP 400 bounded error; no composer/upstream

#### Scenario: Legacy-only accepts legacy
- GIVEN `legacy_only`
- WHEN legacy/legacy-precedence request
- THEN legacy handling unchanged

#### Scenario: Config sync round-trip
- GIVEN API sets enum
- WHEN loaded from JSONB/snapshot
- THEN same value applies without process restart

## MODIFIED Requirements

### Requirement: Validation isolation

Modern parsing/validation MUST finish before consumer lookup, role scoping, routing, rate limiting, plugins, composer, or upstream discovery. Failures MUST create no composer span. Auth/path failures MUST skip operation metrics. Protocol HTTP 400 failures MUST emit countable bounded protocol-outcome (per `mcp-dual-era-rollout-telemetry`) and MUST NOT run downstream collaborators.
(Previously: all modern parse/validation failures skipped operation metrics with no countable protocol outcome.)

#### Scenario: Boundary rejection
- GIVEN modern parse/validation failure
- WHEN rejected
- THEN no downstream collaborators or policy effects

#### Scenario: Protocol failure emits outcome without composer
- GIVEN header mismatch or unsupported version
- WHEN HTTP 400
- THEN protocol-outcome increments; no composer span; auth/path skip unchanged for non-protocol failures
