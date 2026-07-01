# Delta for DB-less Data Plane (proxy/mcp read path)

This change makes the `proxy` and `mcp` planes boot and serve with no Postgres:
all config reads resolve from the in-memory snapshot via snapshot-backed
`domain.Repository` adapters, preserving the existing `DataFinder`, `*.Finder`,
`PricingResolver`, TTL caches, slug normalization, and gateway scoping exactly.
Write methods return a read-only error. Cost plugins resolve pricing from the
embedded catalog. Maps to ENG-950 QA: "proxy and mcp boot and serve with no
Postgres"; "DP resolves all config reads from the snapshot; write methods return
`configsync.ErrReadOnly`"; "multi-gateway indexing + slug normalization + gateway
scoping match the Postgres behavior".

## ADDED Requirements

### Requirement: Boot without Postgres

When the DB-less data-plane mode is enabled for `proxy`/`mcp`, the plane MUST boot
and serve without any Postgres dependency: database migrations MUST be skipped, no
pgx connection pool MUST be constructed, and `DB_*` environment variables MUST NOT
be required. Redis and Kafka MUST remain available as today.

#### Scenario: Proxy/mcp start with DB unset
- GIVEN `CONFIG_SYNC_DATA_PLANE_ENABLED` is on and `DB_HOST`/`DB_USER`/`DB_NAME` are unset
- WHEN the `proxy` or `mcp` plane boots
- THEN it MUST start successfully, MUST NOT run migrations, and MUST NOT open a Postgres pool

#### Scenario: Redis/Kafka still required
- GIVEN the DB-less data plane
- WHEN required Redis or Kafka configuration is missing
- THEN startup validation MUST still fail for those dependencies

### Requirement: Config read parity with the Postgres path

The data plane MUST resolve every hot-path config read from the in-memory snapshot
with results equivalent to the Postgres-backed path: gateways resolvable by
normalized slug (proxy) and by id (mcp); consumers, registries, policies, auths,
and roles resolvable within their gateway; and API-key/enabled-type lookups
resolvable. A resource absent from the snapshot MUST return `domain.ErrNotFound`,
matching the Postgres behavior.

#### Scenario: Gateway resolves by slug and id
- GIVEN a snapshot containing gateway G with slug S
- WHEN the proxy resolves by slug S and the mcp plane resolves by id
- THEN both MUST return G, using the same slug normalization as the Postgres path

#### Scenario: Missing resource returns not-found
- GIVEN a snapshot that does not contain entity X
- WHEN a finder looks up X
- THEN the adapter MUST return `domain.ErrNotFound`

### Requirement: Gateway-scoped isolation

Snapshot-backed adapters MUST enforce gateway scoping: a lookup for a resource
that belongs to a different gateway MUST return `domain.ErrNotFound`, never a
cross-gateway resource. This MUST match the `scopeToGateway` semantics of the
Postgres path so the DB-less plane neither leaks nor denies cross-gateway
resources differently.

#### Scenario: Cross-gateway lookup is denied
- GIVEN a resource R owned by gateway A present in the snapshot
- WHEN a lookup scoped to gateway B requests R by id
- THEN the adapter MUST return `domain.ErrNotFound`

### Requirement: Read-only write rejection

On the DB-less data plane every `domain.Repository` write method (save, update,
delete, attach/detach, set-global) MUST return `configsync.ErrReadOnly` and MUST
NOT mutate any state.

#### Scenario: Write is rejected
- GIVEN a snapshot-backed adapter on the data plane
- WHEN any write method is invoked
- THEN it MUST return `configsync.ErrReadOnly` and change nothing

### Requirement: Pricing from the embedded catalog

Cost plugins (`costcap`, `tokenratelimit`) MUST resolve model pricing from the
catalog embedded in the snapshot via the `PricingResolver`, with no Postgres
access. A model present in the embedded catalog MUST resolve its pricing fields;
a model absent MUST behave as the Postgres path does on a catalog miss.

#### Scenario: Pricing resolves DB-less
- GIVEN a snapshot whose embedded catalog contains model M for a provider
- WHEN a cost plugin resolves pricing for M
- THEN the pricing fields MUST be returned without any database access

#### Scenario: Unknown model misses consistently
- GIVEN a model not present in the embedded catalog
- WHEN a cost plugin resolves its pricing
- THEN the resolver MUST report a miss equivalent to the Postgres-backed lookup
