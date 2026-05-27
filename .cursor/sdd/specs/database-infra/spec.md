# Database Infrastructure Specification

## Purpose
Postgres pool, idempotent migrations, panic-safe transactions.

## Requirements

### Requirement: Connection Pool
Pool MUST expose tunable max-connections and lifetime. Gateway MUST fail-fast at boot when DB is unreachable.

#### Scenario: Healthy
GIVEN reachable Postgres; WHEN gateway boots; THEN pool ready, health checks pass.

#### Scenario: Unreachable
GIVEN Postgres down; WHEN gateway boots; THEN exit non-zero before binding.

### Requirement: Migrations Runner
Runner MUST be idempotent and MUST support `up`/`down`. Failures MUST NOT leave the schema partially applied.

#### Scenario: Re-run when applied
GIVEN all migrations applied; WHEN `up` runs; THEN no statements execute, exit zero.

#### Scenario: Mid-run failure
GIVEN later statement raises; WHEN `up` runs; THEN migration rolls back, version reflects prior state.

### Requirement: Transaction Helpers
Helpers MUST commit only on nil return; MUST roll back on error or panic and re-raise the panic.

#### Scenario: Success
GIVEN wrapped function returns nil; WHEN helper runs; THEN tx commits.

#### Scenario: Panic
GIVEN wrapped function panics; WHEN helper runs; THEN tx rolls back, panic propagates.

_Source Linear issues: RUN-327_
