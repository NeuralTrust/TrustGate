# Delta for config-snapshot-metrics

Change `llm-store` (RUN-1763), slice S6. New capability. Every create, rotate or revoke of a personal key, and every attach, detach or attribute change of one of its links, recompiles the snapshot and flushes DP caches. Personal keys grow it: ~405 B per key, plus ~150 B per link (a ~39 B `auth_ids` entry and a ~110 B `auth_links` entry on the consumer), and a user with N grants has N links. Today the size is only logged ("published config snapshot"). This capability emits it, and the entity counts behind it, as OTel instruments. It measures the cost and does not reduce it.

## ADDED Requirements

### Requirement: Encoded bytes per flavour on publish

On every publish, `Dispatcher` (`pkg/app/configsnapshot/dispatcher.go`) MUST record the encoded size in bytes on the meter `trustgate/configsnapshot`, as the instrument `trustgate.configsnapshot.encoded_bytes`, with the attribute `flavour` = `catalog`, `global` or `scoped`. On `scoped` it MUST add the attribute `stat` = `max` (the largest scoped snapshot) or `total` (the sum over every scoped snapshot), and it MUST record the number of scoped snapshots as the instrument `trustgate.configsnapshot.scopes`. On the non-partitioned path it MUST record the single snapshot as `global` only. The values MUST derive from the lengths of the bytes actually published. The existing "published config snapshot" log line MUST carry `scopes`, `largest_scope` (its id) and `largest_scope_bytes`.

No instrument of this capability MAY carry a gateway, tenant or scope identifier as an attribute.

#### Scenario: Partitioned publish

- GIVEN a dispatcher with an in-memory OTel reader, a catalog and two scopes of `a` and `b` published bytes
- WHEN a snapshot is published
- THEN the reader has `catalog` and `global` equal to their published lengths, `scoped`/`max` = max(a, b), `scoped`/`total` = a + b, and `scopes = 2`

#### Scenario: Bounded series

- GIVEN a published snapshot with three scopes
- WHEN one scope is removed and the snapshot is published again
- THEN `encoded_bytes` still has exactly 4 attribute sets, and `scopes = 2`

### Requirement: Entity counts on publish

On every publish the dispatcher MUST record, as the instrument `trustgate.configsnapshot.entities` on the same meter, the number of auths, of owned auths (`owner_id` set), of personal consumers (`audience = personal`) and of personal links (the total of `auth_links` entries over personal consumers) in the published data, with the attribute `kind` = `auths`, `owned_auths`, `personal_consumers` or `personal_links`. The counts MUST cover every published scope, so every gateway is counted once, hybrid gateways included (they are absent from the global snapshot).

#### Scenario: Counts

- GIVEN a snapshot with three application keys, two owned keys, four application consumers and two personal consumers, the first owned key linked to both and the second to one
- WHEN it is published
- THEN the reader has `auths = 5`, `owned_auths = 2`, `personal_consumers = 2` and `personal_links = 3`

#### Scenario: Hybrid gateway

- GIVEN a partitioned publish with a hosted gateway and a hybrid gateway that has one personal consumer linked to one owned key
- WHEN it is published
- THEN that consumer, its key and its link are counted

#### Scenario: OSS data

- GIVEN a snapshot with application keys and consumers only
- WHEN it is published
- THEN the reader has `owned_auths = 0`, `personal_consumers = 0` and `personal_links = 0`

### Requirement: Metrics never block a publish

A failure to create or record an instrument MUST be logged and MUST NOT fail, delay or change the publish, nor skip the other instruments. The existing "published config snapshot" log line MUST stay.

#### Scenario: No meter provider

- GIVEN the global no-op meter provider
- WHEN a snapshot is published
- THEN the publish succeeds and broadcasts exactly as without the metrics, and `TestDispatch_BroadcastsOnceThenDedupsIdenticalData` passes unchanged
