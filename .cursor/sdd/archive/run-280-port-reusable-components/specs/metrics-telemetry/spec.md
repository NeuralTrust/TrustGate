# Metrics Telemetry Specification

## Purpose

Metrics collection and exporter lifecycle for proxy traffic and reusable runtime components.

## Requirements

### Requirement: Proxy Metrics Collection

The telemetry subsystem MUST record proxy request outcomes with method, route or path, status, latency, and request id. It SHOULD record provider and cache outcomes when those collaborators report them.

#### Scenario: Proxy request completes

- GIVEN a proxy request is handled
- WHEN the response is produced
- THEN one metrics event records method, path or route, status, latency, and request id

#### Scenario: Collaborator reports outcome

- GIVEN a provider or cache operation reports success or failure
- WHEN metrics are collected
- THEN the outcome is associated with the current proxy request when context is available

### Requirement: Exporter Lifecycle

Configured exporters MUST start before proxy traffic is accepted and MUST stop during graceful shutdown. Export failures MUST be observable without blocking request forwarding.

#### Scenario: Exporters start successfully

- GIVEN telemetry exporters are configured
- WHEN the proxy starts
- THEN exporters are ready before proxy traffic is accepted

#### Scenario: Exporter fails during runtime

- GIVEN an exporter cannot deliver an event
- WHEN proxy traffic continues
- THEN the failure is reported and request forwarding is not blocked by the exporter failure

### Requirement: B.1 Exporter Scope

The telemetry subsystem MUST support Kafka and TrustLens export paths when configured. Prometheus, detection exporters, and audit SDK glue MUST NOT be activated in B.1.

#### Scenario: Kafka or TrustLens is configured

- GIVEN Kafka or TrustLens telemetry configuration is enabled
- WHEN metrics events are produced
- THEN the configured exporter receives those events

#### Scenario: Deferred exporter is absent

- GIVEN B.1 proxy telemetry is running
- WHEN metrics events are produced
- THEN no Prometheus, detection, or audit SDK event is emitted
