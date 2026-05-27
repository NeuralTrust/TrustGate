# Developer Tooling Specification

## Purpose
Fresh clone is reproducibly buildable, testable, locally runnable, and gated by CI; layout documented for agents.

## Requirements

### Requirement: Make Test Bootstrap
`make test` MUST pass on a fresh clone with no manual setup. It MUST run lint and unit tests and exit non-zero on any failure.

#### Scenario: Fresh clone
GIVEN clean clone; WHEN `make test`; THEN lint and tests pass, exit zero.

#### Scenario: Lint violation
GIVEN lint violation; WHEN `make test`; THEN exit non-zero, names offending file.

### Requirement: Local Compose Stack
`docker compose up` MUST bring Postgres, Redis, Kafka, ClickHouse to a healthy state before the gateway starts.

#### Scenario: Healthy stack
GIVEN compose started; WHEN datastores become healthy; THEN gateway connects to all four and serves.

#### Scenario: Warming up
GIVEN compose started; WHEN a datastore is unhealthy; THEN gateway waits before binding.

### Requirement: CI Gate
Every PR MUST trigger lint, test, and build jobs. Any failure MUST block merge.

#### Scenario: Passing PR
GIVEN PR with green tests; WHEN CI runs; THEN all jobs pass, PR is mergeable.

#### Scenario: Failing PR
GIVEN PR with failing test; WHEN CI runs; THEN job fails, PR not mergeable.

### Requirement: Layout Convention
Repo MUST document a hexagonal `pkg/` skeleton in `AGENT.md`, naming each layer and the allowed import direction.

#### Scenario: Documented
GIVEN agent reads `AGENT.md`; WHEN it adds a domain entity; THEN file lands in documented layer.

#### Scenario: Missing convention
GIVEN `AGENT.md` lacks layer doc; WHEN repo audit runs; THEN audit fails, gap reported.

_Source Linear issues: RUN-329, RUN-330, RUN-331, RUN-332, RUN-333_
