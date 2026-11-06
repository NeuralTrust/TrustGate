# Specification: snapshot-dirty-tracking

## Purpose

How an admin write tells every admin replica what it changed. Each write
commits an outbox marker in the same transaction. The marker names the gateway
it affects, or the kind of shared data it affects. Every replica reads the
markers through its own cursor. A marker that names nothing forces a full
compile, so an unmigrated writer is never missed.

## Requirements

### Requirement: Markers name what they dirty

`config_snapshot_outbox` MUST gain nullable `gateway_id` and `kind` columns in
an additive migration. Every writer that dirties one gateway MUST stamp that
gateway's id. A writer that only knows a child id (a consumer, auth, policy or
registry) MUST resolve the owning gateway in the same transaction. A writer
that changes the shared catalog MUST stamp `kind=catalog`. Shared inputs that
every compile re-reads (tenant caps, session revocations) only need a marker
that starts a cycle, so their writers stamp the gateway they belong to. The
kinds are `gateway`, `catalog` and `all`; an unknown kind reads as `all`.

A writer that affects several gateways MUST stamp one marker per gateway or
`kind=all`.

#### Scenario: Consumer write names its gateway

- GIVEN consumer C belongs to gateway G
- WHEN an auth is detached from C
- THEN the committed marker has `gateway_id=G`

#### Scenario: Registry secret rotation shared by gateways

- GIVEN a registry secret is used by gateways G1 and G2
- WHEN the secret is rotated
- THEN markers for G1 and G2 commit, or one marker with `kind=all`

#### Scenario: Marker commits with the write

- GIVEN a write whose transaction rolls back
- WHEN the rollback completes
- THEN no marker for that write is visible

### Requirement: Unnamed markers force a full compile

A marker with neither a `gateway_id` nor a gateway-scoped `kind` MUST make the
next compile a full compile. Markers written by an older admin build, which
has no such columns, MUST be treated the same way.

#### Scenario: Legacy writer

- GIVEN a writer that does not stamp a gateway yet
- WHEN it commits a marker
- THEN the next compile on every replica is full, with reason
  `unnamed_marker`

#### Scenario: Mixed admin versions during rollout

- GIVEN an old admin replica and a new one share the outbox
- WHEN the old replica commits a marker without the new columns
- THEN the new replica runs a full compile for it

### Requirement: Per-replica cursor with lookback

Each replica MUST read markers through its own cursor and MUST NOT delete
markers after it compiles. Markers MUST be removed only by the existing
retention prune (age and row bound).

Each read MUST re-scan a lookback window behind the cursor, because a marker
with a lower seq can become visible after a higher one (seq is assigned at
INSERT, not COMMIT). The replica MUST dedupe markers by seq so none is applied
twice. The lookback window MUST be configurable and MUST be longer than the
longest expected write transaction.

#### Scenario: Late-committing lower seq

- GIVEN the cursor is at seq 100
- AND the marker with seq 98 commits after the marker with seq 100 was read
- WHEN the next read runs within the lookback window
- THEN seq 98 is picked up and its gateway is marked dirty
- AND seq 100 is not applied again

#### Scenario: Another replica's compile does not hide a marker

- GIVEN replicas R1 and R2 and an unseen marker for gateway G
- WHEN R1 compiles G
- THEN the marker is still there and R2 also compiles G

#### Scenario: Retention bounds the table

- GIVEN markers older than the retention period
- WHEN the prune runs
- THEN they are deleted whatever the cursors say

### Requirement: Fast-path dirty signal

The cross-replica `SnapshotDirtyEvent` MAY carry the dirty gateway ids so
peers start compiling without waiting for an outbox read. Peers MUST still
treat the outbox as the source of truth. An event with no ids, or a lost
event, MUST NOT lose a change: the replica MUST read the outbox when it
receives any dirty event and on its own periodic read.

#### Scenario: Lost Redis event

- GIVEN a write on gateway G whose dirty event never reaches replica R2
- WHEN R2 next reads the outbox
- THEN R2 compiles G
