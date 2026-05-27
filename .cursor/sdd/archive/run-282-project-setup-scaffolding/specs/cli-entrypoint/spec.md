# CLI Entrypoint Specification

## Purpose
Binary CLI exposing gateway lifecycle via subcommands.

## Requirements

### Requirement: Subcommand Surface
Binary MUST expose `run-server`, `run-migrations`, `version`. Unknown subcommands MUST exit non-zero with usage hint.

#### Scenario: Known
GIVEN binary; WHEN `run-server` invoked; THEN exits zero on shutdown.

#### Scenario: Unknown
GIVEN binary; WHEN `frobnicate` invoked; THEN usage on stderr, exit non-zero.

### Requirement: Server Selection
`run-server` MUST accept `--server admin|proxy|all`. Unknown values MUST abort before binding.

#### Scenario: Valid
GIVEN `--server admin`; WHEN startup; THEN admin listener binds.

#### Scenario: Invalid
GIVEN `--server bogus`; WHEN startup; THEN no listener, exit non-zero.

### Requirement: Config Discovery
Binary MUST accept `--config <path>`. Missing or unreadable paths MUST fail-fast before binding.

#### Scenario: Loaded
GIVEN valid path; WHEN startup; THEN gateway boots.

#### Scenario: Missing
GIVEN `/missing.yaml`; WHEN startup; THEN exit non-zero before binding.

### Requirement: Version Reporting
`version` MUST print build version and commit SHA; SHOULD include build date.

#### Scenario: Printed
GIVEN binary built with metadata; WHEN `version` invoked; THEN stdout shows version and commit, exit zero.

#### Scenario: Stripped
GIVEN binary built without metadata; WHEN `version` invoked; THEN placeholders printed, exit zero.

### Requirement: Boot Failure Reporting
Any boot-time failure (config validation, datastore ping, container build, missing dependency, migration error) MUST emit a structured ERROR log identifying the failing component and the wrapped error BEFORE the process exits non-zero. Servers MUST NOT bind a listener if any required boot step has failed.

#### Scenario: Datastore unreachable
GIVEN Postgres is down; WHEN `run-server` boots; THEN one structured ERROR log records `component=database` with the wrapped error, no listener binds, exit non-zero.

#### Scenario: Container build error
GIVEN a module declares a dependency no provider satisfies; WHEN `run-server` boots; THEN one structured ERROR log records `component=container` with the dig error, no listener binds, exit non-zero.

_Source Linear issues: RUN-326, RUN-300, RUN-327_
