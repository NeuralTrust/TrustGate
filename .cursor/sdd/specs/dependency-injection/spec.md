# Dependency Injection Specification

## Purpose
Container composes admin/proxy from disjoint modules, supports test overrides, reuses singletons in single-binary mode.

## Requirements

### Requirement: Context Composition
Admin and proxy MUST each compose only their modules. Unsatisfied dependencies MUST be detected at boot, not on first request.

#### Scenario: Admin-only
GIVEN `--server admin`; WHEN gateway starts; THEN proxy modules absent, admin services resolve.

#### Scenario: Missing dep
GIVEN module needing unregistered dep; WHEN startup; THEN exit non-zero with container error before binding.

### Requirement: Test Overrides
Tests MUST replace any provided dependency without rebuilding the full graph or touching production wiring.

#### Scenario: Override
GIVEN test substitutes DB client with fake; WHEN service under test resolves; THEN it gets the fake, other deps untouched.

#### Scenario: No override
GIVEN test omits override; WHEN service resolves; THEN production binding is used unchanged.

### Requirement: Shared Singleton Reuse
Both contexts in one process MUST share singletons (config, DB pool, telemetry); MUST NOT instantiate twice.

#### Scenario: Single-binary
GIVEN `--server all`; WHEN both contexts start; THEN one DB pool serves both.

#### Scenario: Conflicting providers
GIVEN two modules both provide a singleton; WHEN container builds; THEN exit non-zero with duplicate-provider error.

_Source Linear issues: RUN-300, RUN-301, RUN-302_
