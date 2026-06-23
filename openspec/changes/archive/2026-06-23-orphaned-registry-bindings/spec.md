# Delta for Registry Deletion Dependency Guard

Bug fix (ENG-882). Corrects the registry-deletion dependency guard so it only
protects legitimate, routable dependents, and cleans up cross-gateway junction
rows that should never have existed. No new product capability is introduced.

## ADDED Requirements

### Requirement: Dependency guard is scoped to the registry's gateway

The fallback-chain dependency guard MUST only count consumers that belong to the
SAME `gateway_id` as the registry being deleted. A consumer in any other gateway
whose `fallback.chain` references the registry's UUID MUST NOT block deletion.

#### Scenario: Cross-gateway fallback reference does not block deletion

- GIVEN a registry in gateway A
- AND a consumer in gateway B whose `fallback.chain` contains the registry's UUID
- WHEN a delete is requested for the registry in gateway A
- THEN deletion succeeds and no `has_dependents` (409) error is returned

### Requirement: Dependency guard ignores inactive consumers

The guard MUST exclude consumers with `active = FALSE`. An inactive (non-routable)
consumer whose fallback chain references the registry MUST NOT block deletion.

#### Scenario: Inactive same-gateway consumer does not block deletion

- GIVEN a registry in gateway A
- AND a same-gateway consumer with `active = FALSE` whose `fallback.chain` references the registry
- WHEN a delete is requested for the registry
- THEN deletion succeeds and no `has_dependents` (409) error is returned

### Requirement: Active same-gateway dependents still block deletion

The guard MUST continue to block deletion when an ACTIVE consumer in the SAME
gateway references the registry in its fallback chain. Legitimate dependents
remain protected (no regression).

#### Scenario: Active same-gateway dependent blocks deletion

- GIVEN a registry in gateway A
- AND an active same-gateway consumer whose `fallback.chain` references the registry
- WHEN a delete is requested for the registry
- THEN deletion is rejected with `ErrHasDependents` (HTTP 409 `has_dependents`)
- AND the registry and the binding remain intact

### Requirement: Deleting a consumer removes its registry bindings

Deleting a consumer MUST remove all of that consumer's `consumer_registry` rows
via `ON DELETE CASCADE`. This guarantee MUST hold and be covered by regression.

#### Scenario: Consumer deletion cascades binding rows

- GIVEN a consumer in gateway A with one or more `consumer_registry` rows
- WHEN the consumer is deleted
- THEN no `consumer_registry` rows remain for that `consumer_id`
- AND no foreign-key violation is raised

### Requirement: Cross-gateway junction rows are cleaned by migration

A data-cleanup migration (timestamp after `20260622120000`) MUST delete every
`consumer_registry` row whose consumer's `gateway_id` differs from the
registry's `gateway_id`. The migration MUST be idempotent.

#### Scenario: Migration removes cross-gateway rows once

- GIVEN `consumer_registry` rows where the consumer and registry are in different gateways
- WHEN the cleanup migration runs
- THEN all such cross-gateway rows are removed
- AND re-running the migration removes nothing further and does not error

#### Scenario: Same-gateway bindings are preserved

- GIVEN `consumer_registry` rows where the consumer and registry share a gateway
- WHEN the cleanup migration runs
- THEN those same-gateway rows remain untouched

## End-to-End Requirements

### Requirement: Create → attach → delete-consumer → registry deletable

The full lifecycle MUST leave the registry deletable after its only same-gateway
dependent is removed.

#### Scenario: Lifecycle leaves registry deletable

- GIVEN a consumer and a registry in the same gateway
- AND the registry is attached to the consumer
- WHEN the consumer is deleted
- THEN the registry has no remaining dependents
- AND a subsequent delete of the registry succeeds

#### Scenario: Notion-style orphan repro is deletable

- GIVEN a registry referenced ONLY by a cross-gateway or inactive consumer's fallback chain
- WHEN a delete is requested for the registry in its own gateway
- THEN deletion succeeds and no `has_dependents` (409) error is returned
