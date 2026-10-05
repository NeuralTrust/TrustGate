# Delta for config-snapshot-metrics

Change `llm-store` (RUN-1763), slice S6. New capability. Every create, rotate or revoke of a personal key, and every attach, detach or attribute change of one of its links, recompiles the snapshot and flushes DP caches. Personal keys grow it: ~405 B per key, plus ~150 B per link (a ~39 B `auth_ids` entry and a ~110 B `auth_links` entry on the consumer), and a user with N grants has N links. Today the size is only logged ("published config snapshot"). This capability emits it, and the entity counts behind it, as OTel instruments. It measures the cost and does not reduce it.

## ADDED Requirements

### Requirement: Encoded bytes per flavour on publish

On every publish, `Dispatcher` (`pkg/app/configsnapshot/dispatcher.go`) MUST record the encoded size in bytes of each flavour on the meter `trustgate/configsnapshot`, as the instrument `trustgate.configsnapshot.encoded_bytes`, with the attribute `flavour` = `catalog`, `global` or `scoped`, and the attribute `scope` on `scoped`. On the non-partitioned path it MUST record the single snapshot as `global`. The values MUST equal the lengths of the bytes actually published.

#### Scenario: Partitioned publish

- GIVEN a dispatcher with an in-memory OTel reader, a catalog and two scopes
- WHEN a snapshot is published
- THEN the reader has one `catalog` value, one `global` value and one `scoped` value per scope, each equal to the length of the published bytes

### Requirement: Entity counts on publish

On every publish the dispatcher MUST record, as the instrument `trustgate.configsnapshot.entities` on the same meter, the number of auths, of owned auths (`owner_id` set), of personal consumers (`audience = personal`) and of personal links (the total of `auth_links` entries over personal consumers) in the published data, with the attribute `kind` = `auths`, `owned_auths`, `personal_consumers` or `personal_links`.

#### Scenario: Counts

- GIVEN a snapshot with three application keys, two owned keys, four application consumers and two personal consumers, the first owned key linked to both and the second to one
- WHEN it is published
- THEN the reader has `auths = 5`, `owned_auths = 2`, `personal_consumers = 2` and `personal_links = 3`

#### Scenario: OSS data

- GIVEN a snapshot with application keys and consumers only
- WHEN it is published
- THEN the reader has `owned_auths = 0`, `personal_consumers = 0` and `personal_links = 0`

### Requirement: Metrics never block a publish

A failure to create or record an instrument MUST be logged and MUST NOT fail, delay or change the publish. The existing "published config snapshot" log line MUST stay.

#### Scenario: No meter provider

- GIVEN the global no-op meter provider
- WHEN a snapshot is published
- THEN the publish succeeds and broadcasts exactly as without the metrics, and `TestDispatch_BroadcastsOnceThenDedupsIdenticalData` passes unchanged
