# Specification: secret-resolution

## Purpose

How a customer-operated plane turns references into values at runtime: where
values may live, cache and refresh behaviour, rotation, failure behaviour and
what is observable.

A plane resolves only when it has loaded a store file:
- **Data planes** resolve in hybrid, in self-hosted and in the central and
  remote clusters.
- **The admin** resolves only in self-hosted and on the central cluster, for its
  own test-connection, model listing and store test.

## Requirements

### Requirement: Values never leave plane memory

A resolved value MUST NOT be written to any of these:
- Postgres or Redis;
- a config snapshot or an LKG file;
- a heartbeat;
- logs or metric labels;
- any API response.

The snapshot compiler MUST copy references verbatim. A plane without a store
file MUST NOT resolve references.

#### Scenario: Snapshot carries the reference

- GIVEN registry R with `api_key` `secret://corp-vault/ai-gateway/openai#api_key` on a hybrid gateway
- WHEN the scoped snapshot is compiled and decoded
- THEN R's auth holds the reference string, and the snapshot bytes do not contain the value

#### Scenario: NeuralTrust admin never resolves

- GIVEN NeuralTrust's SaaS admin, which has no store file
- WHEN any admin feature reads a registry that holds a reference
- THEN no secret store is contacted, and the reference stays a string

### Requirement: Reference-shaped values are never forwarded

A plane that has this code MUST NOT forward a value that parses as a
reference, at a declared location, as a credential to an upstream. This holds
in all of these cases:
- `SECRET_STORES_ENABLED` is off;
- the plane has no store file;
- the store is unknown;
- the gateway is not eligible.

In each case the entity MUST be marked credential-unavailable, and the request
MUST fail with `secret_unavailable`.

#### Scenario: Feature turned off after adoption

- GIVEN a hybrid plane that resolved `secret://corp-vault/ai-gateway/openai#api_key`, and an operator who sets `SECRET_STORES_ENABLED=false`
- WHEN a request is routed to that registry
- THEN the client receives 503 `secret_unavailable`, and the upstream receives no request

### Requirement: No cost and no change without references

When no value at a declared location starts with `secret://`, materialization
MUST return its input unchanged, with no copy, no allocation and no store
access.

Credential-keyed caches MUST keep today's keys for literal credentials. Only
reference-derived credentials get new keys:
- the Bedrock runtime pool key;
- the MCP dial revision.

When a reference-derived value changes, the Bedrock pool MUST delete the
previous entry for that registry, so rotation never grows the pool.

#### Scenario: Deploy without references

- GIVEN a plane running this change, with no reference configured anywhere
- WHEN traffic flows
- THEN `DataFinder` output, Bedrock pool keys and MCP revisions are identical to the previous release

#### Scenario: Rotation does not grow the Bedrock pool

- GIVEN a Bedrock registry whose secret key comes from a reference
- WHEN the referenced value rotates 100 times
- THEN the pool holds one client for that registry

### Requirement: Materialization in the runtime read model

Every plane that has a store file MUST substitute references with values where
a gateway's runtime model is built: in `consumer.DataFinder` and in
`registry.Finder`.
- Every other runtime reader of a credential-bearing entity MUST go through the
  materializer. On an admin with a catalog, this includes test-connection and
  model listing.
- Materialization MUST NOT mutate the stored or snapshot copy of the entity.
- Admin read and response paths MUST NOT materialize.

#### Scenario: Provider receives the value (self-hosted)

- GIVEN a self-hosted gateway whose registry R references a secret with value `sk-live-123`
- WHEN a request is routed to R by the in-cluster proxy
- THEN the upstream receives `Authorization: Bearer sk-live-123`

#### Scenario: Test-connection on a self-hosted admin

- GIVEN the same registry R
- WHEN the console runs test-connection for R through the admin
- THEN the admin resolves the reference from its own catalog, the provider sees the real key, and the response carries no value

### Requirement: An unresolved reference is never sent upstream

When a reference cannot be resolved and no stale value is allowed:
- the field MUST be set to empty;
- the entity MUST be marked credential-unavailable;
- the invoker MUST fail with 503 `secret_unavailable` before contacting the
  upstream, unless failover selects another registry.

The reference string MUST NOT be sent upstream. The client-facing error MUST
NOT name the store or the path.

#### Scenario: Missing secret

- GIVEN registry R references a path that does not exist, and R has no failover
- WHEN a request is routed to R
- THEN the client receives 503 `secret_unavailable`, and the upstream receives no request

### Requirement: Cache, refresh and stale-on-error

Each resolving plane MUST cache payloads in memory, keyed by store, path and
version, and follow the store's policy:
- **TTL:** default 5 min, minimum 30 s.
- **Refresh-ahead:** from 80 % of the TTL, with jitter, for entries used in the
  last hour.
- **Stale-on-error:**
  - on `unavailable` or `auth_failed`, the last good value MUST be served until
    `ttl + max_stale` (default 24 h);
  - after that, resolution MUST fail.
- **Negative cache:** `not_found`, `access_denied`, `field_not_found` and
  `invalid_payload` MUST be cached for `negative_ttl` (default 30 s).
- **Singleflight:** concurrent misses for the same key MUST share one fetch.
- **Timeout:** each fetch MUST time out after `SECRET_STORES_FETCH_TIMEOUT`
  (default 2 s).
- **Pinned versions:** a reference with an explicit version MUST NOT be
  refreshed.

#### Scenario: Vault outage

- GIVEN registry R resolved at T, with TTL 5 min and `max_stale` 24 h
- WHEN the vault is unreachable from T+4 min to T+2 h
- THEN requests to R keep succeeding, and the stale-served counter increases

#### Scenario: Outage beyond max_stale

- GIVEN the same registry, with `max_stale` 1 h
- WHEN the vault stays unreachable past T+1 h 5 min
- THEN requests to R fail with `secret_unavailable`

#### Scenario: Concurrent cold start

- GIVEN an empty cache
- WHEN 100 concurrent requests need the same reference
- THEN the backend receives exactly one fetch

### Requirement: Rotation propagates without an admin write

When a refresh returns a payload whose hash differs from the cached one, the
plane MUST invalidate the runtime data of every gateway that used it, and the
next request MUST use the new value. Credential-keyed clients (the Bedrock pool
and the MCP dial revision) MUST change key when the value changes.

#### Scenario: Secret rotated in the vault

- GIVEN registry R uses K1, and the vault value changes to K2
- WHEN the refresher next fetches it
- THEN later upstream requests for R carry K2, with no TrustGate change

### Requirement: Forced refresh on upstream rejection

When an upstream answers 401 or 403 and the credential came from a reference,
the plane MUST force a refresh of that reference, at most once per reference
every 30 s. If the value changed, the plane MUST retry the request once on the
same registry, provided nothing has been streamed to the client yet.

#### Scenario: First request after a rotation

- GIVEN the cache holds K1, and the provider has revoked K1 in favour of K2
- WHEN a request receives 401
- THEN the plane fetches K2, retries once, and the client gets the successful response

### Requirement: Prewarm

After a snapshot apply, a store-file reload or a first Postgres load, the plane
MUST resolve every reference of the eligible gateways it serves. It MUST do so
in the background, with bounded concurrency. With
`SECRET_STORES_READINESS_GATE=true`, readiness MUST wait until every reference
has either resolved or failed with a non-transient class.

#### Scenario: Readiness gate

- GIVEN `SECRET_STORES_READINESS_GATE=true` and a vault that answers after 3 s
- WHEN the plane starts
- THEN it reports ready only after the references have been fetched

### Requirement: Observability

Every resolving plane MUST export these metrics:
- `trustgate_secret_fetch_total{store_type,result}`;
- `trustgate_secret_fetch_duration_seconds{store_type}`;
- `trustgate_secret_stale_served_total{store_type}`;
- `trustgate_secret_forced_refresh_total{changed}`;
- `trustgate_secret_unresolved_references`.

Labels MUST NOT include a path, a field or a value.

From Phase 2, failing references MUST also be reported, capped at 50:
- data planes report them in the heartbeat;
- the admin reports them for its own catalog.

#### Scenario: Unresolved reference is visible

- GIVEN a reference whose secret was deleted from the vault
- WHEN the next health report is produced (Phase 2)
- THEN it lists that reference with class `not_found`, and the console flags the entity that uses it
