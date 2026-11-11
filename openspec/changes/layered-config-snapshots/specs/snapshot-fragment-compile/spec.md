# Specification: snapshot-fragment-compile

## Purpose

Incremental compile of the config snapshot on the admin. The admin caches each
entity's encoded proto element, grouped by gateway. On a write it re-reads and
re-encodes only the dirty gateways, then merges the cached runs in the same
order a full compile uses. The bytes and versions served stay identical to a
full compile, so data planes see no difference. A config switch turns it on.
Full compiles remain the safety net.

## Requirements

### Requirement: Byte-identical to a full compile

For the same database state, an incremental compile MUST produce the same
bytes and the same version as a full compile:

- the global snapshot;
- every scoped snapshot;
- the catalog encoding.

It MUST also notify the same scopes.

#### Scenario: One dirty gateway

- GIVEN about 600 gateways compiled in full
- WHEN gateway G changes and an incremental compile runs
- THEN the global and every scoped blob are byte-equal to a fresh full compile
  of the same state
- AND only G's scope and the global snapshot get a new version

#### Scenario: Randomized write sequence

- GIVEN a random sequence of creates, updates and deletes across gateways,
  consumers, auths, policies and registries
- WHEN each step is compiled incrementally
- THEN after every step the result equals a full compile of the same state

#### Scenario: Gateway deleted

- GIVEN gateway G is cached
- WHEN G is deleted
- THEN its elements leave the merged blobs and its scope is dropped, exactly
  as in a full compile

### Requirement: Only dirty gateways hit Postgres and the encoder

An incremental compile MUST read from Postgres and re-encode only:

- the dirty gateways;
- the shared kinds named by the markers.

It MUST reuse the cached elements of every other gateway. For each dirty
gateway it MUST re-run every validation that a full compile runs on that
gateway's data, including consumer admission against registries and
smart-routing validation. A change to data that other gateways' validation
depends on MUST mark those gateways dirty, or force a full compile.

#### Scenario: Clean gateways untouched

- GIVEN gateways G1 to G600 are cached
- WHEN only G7 is dirty
- THEN Postgres is queried for G7's entities and the shared kinds only

#### Scenario: Registry change revalidates consumers

- GIVEN a consumer of G references registry R
- WHEN R changes in a way that fails that consumer's admission
- THEN the next compile excludes or flags that consumer exactly as a full
  compile would

### Requirement: Compile while dirty

The dispatcher MUST compile immediately when a change arrives and no compile
is running. Changes that arrive during a compile MUST be folded into one
compile that starts as soon as the current one ends. The dispatcher MUST NOT
add any timer delay before a compile. Every replica MUST compile
independently; there is no leader.

#### Scenario: Idle write

- GIVEN no compile is running
- WHEN gateway G is written
- THEN a compile starts at once, without waiting on a debounce

#### Scenario: Write lands mid-compile

- GIVEN a compile for G1 is running
- WHEN G2 and G3 are written before it ends
- THEN exactly one more compile runs, covering G2 and G3, as soon as the
  first ends
- AND neither write is lost

#### Scenario: Write lands between reading markers and compiling

- GIVEN the dispatcher has read the dirty set {G1}
- WHEN G2's marker commits before G1's compile publishes
- THEN G2 is compiled by the next cycle

### Requirement: Full compile as the safety net

A full compile MUST run:

- at boot;
- after an LKG restore, before the cache is trusted;
- when the incremental switch is off;
- on any unnamed marker or shared `global` marker;
- when the cache is missing or inconsistent;
- on the periodic backstop (default 5 min).

The backstop MUST compare its result with the cache-based state. On any
difference it MUST log the differing scopes, increment a drift counter,
replace the cache with the full result, and publish the full result.

#### Scenario: LKG restore then compile

- GIVEN the admin starts and serves a restored LKG snapshot
- WHEN the first compile runs
- THEN it is a full compile, and it seeds the cache

#### Scenario: Backstop finds drift

- GIVEN the cache disagrees with Postgres for gateway G
- WHEN the backstop full compile runs
- THEN the drift counter increments, G's scope is logged, the full result is
  published, and the cache is rebuilt

#### Scenario: Backstop finds no drift

- GIVEN the cache matches Postgres
- WHEN the backstop runs
- THEN nothing is republished and the drift counter does not change

### Requirement: Incremental switch

A config switch MUST choose between incremental and full compile. It MUST
default to off on the first deploy and be turned on per environment, DEV
first. When it is off, every compile MUST be full and behave as it does today.
Turning it off MUST NOT need a rollback, a migration or a restart of data
planes.

#### Scenario: Switch off

- GIVEN the incremental switch is off
- WHEN gateway G is written
- THEN a full compile runs and publishes the same bytes as today

#### Scenario: Switch flipped off at runtime config reload or restart

- GIVEN the switch was on and is turned off
- WHEN the admin next compiles
- THEN it compiles in full and the served versions do not change for
  unchanged data

### Requirement: Bounded cache memory

The element cache MUST hold at most one encoded copy of each entity, plus the
assembled blobs that are being served. It MUST release a deleted gateway's
elements.

#### Scenario: Deleted gateways release memory

- GIVEN gateway G with cached elements
- WHEN G is deleted and compiled
- THEN no cache entry for G remains
