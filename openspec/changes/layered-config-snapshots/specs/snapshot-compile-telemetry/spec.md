# Specification: snapshot-compile-telemetry

## Purpose

Per-stage timing of each config snapshot compile on the admin, so we can see
where compile time goes before and after incremental compile. It also records
whether each compile was full or incremental, and why.

## Requirements

### Requirement: Stage timings on the publish log

Every compile that publishes a snapshot MUST add these fields to the existing
`published config snapshot` log line:

- the compile mode: `full` or `incremental`;
- the reason for a full compile: `boot`, `lkg_restore`, `backstop`,
  `unnamed_marker`, `shared_change`, `signal` (a write-triggered full compile
  before the incremental switch exists), `switch_off` or `cache_miss`;
- the number of dirty gateways;
- the duration of each stage:
  - `read` (Postgres reads, with the entity kinds read);
  - `validate` (consumer admission and smart-routing validation);
  - `encode`;
  - `merge`;
  - `hash`.

The existing `compile` field MUST still report the total duration, so log
queries that already use it keep working.

#### Scenario: Incremental compile logs its stages

- GIVEN incremental compile is on
- WHEN one gateway is written and the next compile publishes
- THEN the log line has mode `incremental`, one dirty gateway, and a non-zero
  duration for each stage that ran
- AND `compile` equals the total duration

#### Scenario: Full compile logs its reason

- GIVEN the admin has just started
- WHEN its first compile publishes
- THEN the log line has mode `full` and reason `boot`

### Requirement: Stage duration histogram

The admin MUST record each stage's duration in a histogram metric, labelled by
stage and mode. A failed compile MUST still record the stages it completed,
labelled as failed, and MUST NOT log a publish.

#### Scenario: Failed compile still measured

- GIVEN Postgres fails during the `read` stage
- WHEN the compile aborts
- THEN the `read` stage duration is recorded with outcome failed
- AND no `published config snapshot` line is logged

### Requirement: Telemetry never changes the snapshot

Recording timings MUST NOT change the bytes, the version, or which scopes are
notified.

#### Scenario: Same bytes with telemetry

- GIVEN the same config
- WHEN two compiles run, one with the metrics exporter on and one with it off
- THEN both publish the same bytes and the same version
