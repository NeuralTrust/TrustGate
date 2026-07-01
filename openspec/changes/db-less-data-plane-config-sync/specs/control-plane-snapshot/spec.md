# Delta for Control-Plane Snapshot (admin/run plane)

This change adds a control-plane capability: the admin/run plane compiles a
fleet-wide, content-hash-versioned read-model snapshot (State-of-the-World) over
the live Postgres repositories, holds it in memory, serves it at an internal
authenticated HTTP endpoint (ETag/304/200), and publishes version bumps to a
Redis Stream. Admin write use cases signal recompiles after commit. All behavior
is additive: with the snapshot module absent the admin plane behaves exactly as
today (existing `gateway_events` pub/sub untouched). Maps to ENG-950 QA:
"admin writes bump the snapshot version; DP converges over Redis Streams + HTTP+ETag".

## ADDED Requirements

### Requirement: Snapshot compilation and versioning

The control plane MUST compile a fleet-wide read-model snapshot from the live
repositories covering every entity the data-plane hot path reads (gateways,
consumers, registries, policies, auths, roles, and catalog pricing), indexed by
gateway id and by slug. Each compiled snapshot MUST carry a deterministic
content-hash version: identical config MUST yield an identical version, and any
config change MUST yield a different version. Recompilation MUST be debounced so
a burst of writes coalesces into a bounded number of recompiles.

#### Scenario: Version is stable for unchanged config
- GIVEN a compiled snapshot at version V
- WHEN the snapshot is recompiled with no underlying config change
- THEN the resulting version MUST equal V

#### Scenario: Version changes when config changes
- GIVEN a compiled snapshot at version V
- WHEN any covered entity is created, updated, or deleted and a recompile runs
- THEN the resulting version MUST differ from V

#### Scenario: Bursts coalesce
- GIVEN multiple admin writes within the debounce window
- WHEN recompilation is triggered per write
- THEN the number of full recompiles MUST be bounded (not one per write)

### Requirement: Admin writes signal a version bump

Every admin write use case that mutates config (gateway/registry/auth create,
update, delete; consumer create/update/delete/associate; policy
create/update/delete/duplicate/set-global; role create/update/delete/associate;
catalog sync/provider-auth/mcp-servers) MUST invoke the snapshot signaler AFTER
a successful commit, alongside the existing `gateway_events` invalidation. The
signaler MUST be optional: when absent (the data-plane graph) signalling MUST be
a no-op and MUST NOT affect the write.

#### Scenario: Successful write triggers a signal
- GIVEN the control plane with the snapshot signaler wired
- WHEN an admin write use case commits successfully
- THEN the signaler MUST be invoked exactly once for that write

#### Scenario: Failed write does not signal
- GIVEN an admin write use case whose commit fails
- WHEN the use case returns
- THEN the signaler MUST NOT be invoked

#### Scenario: Nil signaler is a no-op
- GIVEN a graph where no snapshot signaler is present
- WHEN an admin write use case commits
- THEN the write MUST succeed and no signalling error MUST surface

### Requirement: Authenticated HTTP snapshot endpoint with ETag semantics

The control plane MUST expose the current snapshot over an internal HTTP endpoint
that returns the encoded snapshot body with an `ETag` set to the snapshot
version. When a client presents `If-None-Match` equal to the current version the
endpoint MUST respond `304 Not Modified` with no body; otherwise it MUST respond
`200 OK` with the encoded body and the current `ETag`. The endpoint MUST be
guarded by transport authentication (see config-sync-security).

#### Scenario: Fresh client receives the snapshot
- GIVEN an authenticated client with no or stale `If-None-Match`
- WHEN it requests the snapshot endpoint
- THEN the response MUST be `200 OK` with the encoded body and an `ETag` equal to the current version

#### Scenario: Up-to-date client is told not-modified
- GIVEN an authenticated client presenting `If-None-Match` equal to the current version
- WHEN it requests the snapshot endpoint
- THEN the response MUST be `304 Not Modified` with an empty body

### Requirement: Version bumps published to a Redis Stream

On every version change the control plane MUST publish the new version to a
configured Redis Stream (`CONFIG_SYNC_STREAM_KEY`) using at-least-once semantics,
so subscribed data planes are notified to re-pull. Publication failures MUST NOT
roll back or fail the originating admin write.

#### Scenario: New version notified
- GIVEN a recompile that produces a new version
- WHEN the holder is updated
- THEN a message carrying the new version MUST be appended to the configured Redis Stream

#### Scenario: Publish failure is non-fatal to writes
- GIVEN Redis is unavailable at publish time
- WHEN a version bump occurs after a committed write
- THEN the admin write MUST remain committed and the failure MUST be logged, not propagated to the client
