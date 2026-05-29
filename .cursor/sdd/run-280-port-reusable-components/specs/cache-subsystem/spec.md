# Cache Subsystem Specification

## Purpose

Redis-backed cache behavior for reusable proxy components, including TTLs, pub/sub, and invalidation.

## Requirements

### Requirement: Cache Availability

The cache subsystem MUST expose cache operations only after its backing Redis connection is ready. Startup MUST fail before serving proxy traffic when cache is required and unavailable.

#### Scenario: Redis is reachable

- GIVEN valid Redis configuration
- WHEN the proxy starts
- THEN cache operations are available to dependent components

#### Scenario: Required Redis is unreachable

- GIVEN cache is required and Redis cannot be reached
- WHEN the proxy starts
- THEN startup fails before proxy traffic is accepted

### Requirement: TTL-Aware Entries

The cache subsystem MUST support setting, retrieving, and deleting entries with explicit TTLs. Expired entries MUST NOT be returned.

#### Scenario: Entry is within TTL

- GIVEN an entry was stored with an unexpired TTL
- WHEN a component reads the same key
- THEN the stored value is returned

#### Scenario: Entry is expired

- GIVEN an entry TTL has elapsed
- WHEN a component reads the same key
- THEN the entry is treated as missing

### Requirement: Pub/Sub Invalidation

The cache subsystem MUST publish and consume invalidation events for cache keys or namespaces used by proxy collaborators.

#### Scenario: Invalidation event is received

- GIVEN a cached entry matches an invalidation event
- WHEN the event is consumed
- THEN subsequent reads do not return the stale entry

#### Scenario: Subscriber is stopped

- GIVEN the cache subscriber is running
- WHEN the proxy shuts down
- THEN subscription processing stops without accepting new invalidation work
