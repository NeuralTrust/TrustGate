# Specification: secret-resolution

## Purpose

How a plane turns references into values at runtime. This covers:
- where values may live;
- cache, refresh and stale behaviour;
- reaction to rotation;
- what happens when a reference cannot be resolved.

## Requirements

### Requirement: Values never leave process memory

A resolved secret value MUST NOT be written to Postgres, Redis, the config
snapshot, the LKG file, logs, metrics labels or any API response. The control
plane MUST store and distribute references only. The snapshot compiler MUST NOT
resolve references.

#### Scenario: Snapshot carries the reference

- GIVEN registry R with `api_key` `secret://corp-vault/ai-gateway/openai#api_key`
- WHEN the snapshot is compiled and decoded
- THEN R's auth holds the reference string and the snapshot bytes do not contain the secret value

### Requirement: Materialization in the runtime read model

Every plane MUST substitute references with values where a gateway's runtime
model is built: `consumer.DataFinder` and `registry.Finder`. Other runtime
readers of credential-bearing entities MUST do the same through the
materializer. The admin read path MUST NOT materialize. Materialization MUST
NOT mutate the repository or snapshot copy of the entity.

#### Scenario: Provider receives the value

- GIVEN registry R references a secret whose value is `sk-live-123`
- WHEN a request is routed to R
- THEN the upstream receives `Authorization: Bearer sk-live-123`

#### Scenario: Admin read is not materialized

- GIVEN the same registry R
- WHEN R is read through the Admin API on a `run` plane
- THEN the response holds the reference, not `sk-live-123`

### Requirement: An unresolved reference is never sent upstream

When a reference cannot be resolved and no stale value is allowed:
- the field MUST be set to empty;
- the entity MUST be marked credential-unavailable;
- the invoker MUST fail with 503 `secret_unavailable` before contacting the
  upstream, unless failover selects another registry.

The reference string MUST NOT be sent upstream.

#### Scenario: Missing secret

- GIVEN registry R references a path that does not exist and R has no failover
- WHEN a request is routed to R
- THEN the client receives 503 `secret_unavailable` and the upstream receives no request

### Requirement: Cache, refresh and stale-on-error

Each plane MUST cache fetched payloads in memory, keyed by store, path and
version. The cache MUST follow the store's policy:
- **TTL:** default 5 min, minimum 30 s.
- **Refresh-ahead:** from 80 % of the TTL, with jitter, for entries used in the
  last hour.
- **Stale-on-error:** when a fetch fails with a transient class (`unavailable`,
  `auth_failed`), the last good value MUST be served until `ttl + max_stale`
  (default 24 h). After that, resolution MUST fail.
- **Negative cache:** `not_found`, `access_denied`, `field_not_found` and
  `invalid_payload` MUST be cached for `negative_ttl` (default 30 s).
- **Singleflight:** concurrent misses for the same key MUST share one fetch.
- **Timeout:** a fetch MUST time out after `SECRET_STORES_FETCH_TIMEOUT`
  (default 2 s).
- **Pinned versions:** a reference with an explicit `version` MUST NOT be
  refreshed.

#### Scenario: Vault outage

- GIVEN registry R resolved its key at time T, with TTL 5 min and `max_stale` 24 h
- WHEN the vault is unreachable from T+4 min to T+2 h
- THEN requests to R keep succeeding with the cached key, and the stale-served counter increases

#### Scenario: Outage beyond max_stale

- GIVEN the same registry with `max_stale` 1 h
- WHEN the vault stays unreachable past T+1 h 5 min
- THEN requests to R fail with `secret_unavailable`

#### Scenario: Concurrent cold start

- GIVEN an empty cache
- WHEN 100 concurrent requests need the same reference
- THEN the backend receives exactly one fetch

### Requirement: Rotation propagates without an admin write

When a refresh returns a payload whose hash differs from the cached one, the
plane MUST invalidate the runtime data of every gateway that used it. The next
request MUST be served with the new value. Cached clients keyed on credentials
(the Bedrock runtime pool, the MCP dial revision) MUST change key when the value
changes.

#### Scenario: Secret rotated in the vault

- GIVEN registry R uses a referenced key K1 and the vault value changes to K2
- WHEN the refresher next fetches it
- THEN subsequent upstream requests for R carry K2 with no TrustGate configuration change

### Requirement: Forced refresh on upstream rejection

When an upstream answers 401 or 403 and the registry's credential came from a
reference, the plane MUST force a refresh of that reference. This MUST happen
at most once per reference every 30 s. If the value changed, the plane MUST
retry the request once on the same registry, provided nothing has been streamed
to the client yet.

#### Scenario: Rotated key, first request after rotation

- GIVEN the cache still holds K1 and the provider has revoked K1 in favour of K2
- WHEN a request receives 401 from the provider
- THEN the plane fetches K2, retries once, and the client receives the successful response

### Requirement: Observability

Every plane MUST export:
- `trustgate_secret_fetch_total{store_type,location,result}`;
- `trustgate_secret_fetch_duration_seconds{store_type}`;
- `trustgate_secret_stale_served_total{store_type}`;
- `trustgate_secret_forced_refresh_total{changed}`;
- `trustgate_secret_unresolved_references` (gauge).

Labels MUST NOT include the path, the field or any value. A data plane MUST
report the state of its local stores in the config-sync heartbeat. From Phase 3
it MUST also report its failing references, capped at 50.

#### Scenario: Unresolved reference is visible

- GIVEN a hybrid data plane with a reference to a missing local store
- WHEN the next heartbeat is sent
- THEN it reports that store with state `store_missing`, and the console shows the store as unhealthy
