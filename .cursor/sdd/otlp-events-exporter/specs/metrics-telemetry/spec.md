# Delta for Metrics Telemetry

This delta extends the `metrics-telemetry` capability (originally specified
in run-280, B.1) so the supported export set includes the new `otlp`
exporter. Per-gateway opt-in fan-out, the Kafka config-driven default, and
the downstream JSON contract are all preserved.

## ADDED Requirements

### Requirement: Per-Gateway OTLP Opt-In Fan-Out

A gateway MAY opt into the `otlp` exporter by adding
`{name:"otlp", settings:{...}}` to `telemetry.exporters`. When present,
events MUST fan out to the OTLP Collector **in addition to** the Kafka
default, because `resolveTargets` merges per-gateway explicit exporters
with global defaults (explicit replaces same-named default; unmatched
defaults still fire). Enabling `otlp` MUST NOT require any change to
`Pipeline.resolveTargets`.

#### Scenario: No exporters configured

- GIVEN a gateway with an empty `telemetry.exporters`
- WHEN a request completes
- THEN the event is exported via the Kafka default only

#### Scenario: OTLP added on top of Kafka default

- GIVEN a gateway with `telemetry.exporters` containing `{name:"otlp", settings:{...}}`
- WHEN a request completes
- THEN the event is delivered to the OTLP Collector AND the Kafka default still fires

#### Scenario: Explicit Kafka replaces the same-named default

- GIVEN a gateway whose explicit exporters include `kafka`
- WHEN a request completes
- THEN the explicit `kafka` exporter is used and the default `kafka` is not duplicated

### Requirement: Downstream Contract Unchanged

Adding the `otlp` exporter MUST NOT alter the Kafka exporter, the `Event`
schema (`schema_version=2`), the `Builder`, or the `Worker`. The
ClickHouse `gateway_metrics` ingestion path (kafka-connect → ClickHouse →
data-plane-api) MUST keep populating exactly as before.

#### Scenario: ClickHouse keeps populating

- GIVEN the `otlp` exporter is enabled on a gateway
- WHEN requests complete
- THEN the Kafka JSON payload retains `schema_version=2` and its existing shape
- AND ClickHouse `gateway_metrics` continues to be populated

#### Scenario: Diff audit on unchanged areas

- GIVEN the change that introduces `otlp`
- WHEN the diff is inspected
- THEN the Kafka exporter, `Event` schema, `Builder`, and `Worker` are unchanged

### Requirement: Validation Wired Through Existing Path

Saving a gateway with an `otlp` exporter MUST validate it through the
existing `validateExporters` → `ExporterLocator.Validate` route, with no
new validation entry point. Invalid `otlp` settings MUST be rejected at
create/update.

#### Scenario: Invalid otlp settings rejected on create

- GIVEN a create/update request with structurally invalid `otlp` settings
- WHEN the gateway is saved
- THEN validation returns an error naming the `otlp` exporter
- AND the gateway is not persisted

## MODIFIED Requirements

### Requirement: B.1 Exporter Scope

The telemetry subsystem MUST support Kafka and `otlp` export paths when
configured, and MAY support TrustLens in the future via the same locator.
Prometheus, detection exporters, and audit SDK glue MUST NOT be activated.
Kafka remains the config-driven default exporter.
(Previously: only Kafka and TrustLens were listed as supported export paths;
`otlp` did not exist.)

#### Scenario: Kafka is configured

- GIVEN Kafka telemetry configuration is enabled
- WHEN metrics events are produced
- THEN the configured Kafka exporter receives those events

#### Scenario: OTLP is configured

- GIVEN a gateway with an `otlp` exporter configured
- WHEN metrics events are produced
- THEN the `otlp` exporter receives those events alongside Kafka

#### Scenario: Deferred exporter is absent

- GIVEN proxy telemetry is running
- WHEN metrics events are produced
- THEN no Prometheus, detection, or audit SDK event is emitted

## Acceptance Criteria (capability-level)

- [ ] Gateway without `telemetry.exporters` → Kafka only (unchanged).
- [ ] Gateway with `{name:"otlp",settings}` → Collector + Kafka (fan-out).
- [ ] Invalid `otlp` settings → rejected at create/update.
- [ ] Collector down → request unaffected; events dropped/queued with a log.
- [ ] ClickHouse `gateway_metrics` keeps populating (`schema_version=2` intact).
- [ ] New exporter addable with one template + one `WithExporter` line.
- [ ] Graceful shutdown flushes pending OTLP batches within the timeout.
