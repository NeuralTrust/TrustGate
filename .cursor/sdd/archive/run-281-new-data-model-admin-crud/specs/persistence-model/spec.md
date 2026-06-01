# Persistence Model Specification

## Purpose

Define the Postgres schema, migrations, and pgx repositories that
persist the B.2 aggregates and their many-to-many associations.

## Requirements

### Requirement: In-Code Migrations

Every schema change MUST be a Go file under
`pkg/infra/database/migrations/` registered via `init()` calling
`database.RegisterMigration`. The filename MUST start with a unix
timestamp prefix that orders the file globally.

#### Scenario: A new migration is applied

- GIVEN a migration file with ID `<unix_ts>_create_gateways_table`
- WHEN the migration manager runs on an empty database
- THEN the table is created and `migration_version` records the ID

#### Scenario: A previously applied migration is skipped

- GIVEN the same migration ID is already present in `migration_version`
- WHEN the manager runs again
- THEN no DDL is executed for that ID

#### Scenario: A migration fails mid-flight

- GIVEN a migration whose `Up` returns an error
- WHEN the manager applies it
- THEN the transaction is rolled back and `migration_version` is not
  updated for that ID
- AND no subsequent migrations are applied

### Requirement: Schema Ordering

Schema migrations MUST land in two ordered phases:

1. Aggregate tables (`gateways`, `backends`, `consumers`, `policies`,
   `auths`).
2. Join tables (`consumer_backend`, `consumer_policy`, `consumer_auth`).

#### Scenario: Join tables follow aggregate tables

- GIVEN the file system order of migration files
- WHEN the unix-timestamp prefix is examined
- THEN every join-table migration's timestamp is strictly greater than
  every aggregate-table migration's timestamp it references via FK

### Requirement: Referential Integrity

All foreign keys from join tables to aggregate tables MUST be declared
`ON DELETE CASCADE`. The `Backend.gateway_id` FK MUST be declared
`ON DELETE RESTRICT` (a gateway cannot be deleted while it owns
backends).

#### Scenario: Deleting a Consumer removes its join rows

- GIVEN a Consumer linked to two Backends, one Policy, and one Auth
- WHEN the Consumer row is deleted
- THEN the three join rows referencing the Consumer are also removed

#### Scenario: Deleting a Gateway with backends is rejected

- GIVEN a Gateway with one or more Backends pointing at it
- WHEN a deletion is attempted
- THEN Postgres returns a foreign key violation
- AND the repository propagates it as `gateway.ErrHasDependents`

### Requirement: Transactional Multi-Statement Writes

Repository writes that touch more than one row MUST execute inside
`database.WithTx`. This applies in particular to `Consumer` updates
that diff the three join sets.

#### Scenario: Consumer.Update diffs joins atomically

- GIVEN a persisted Consumer with backends `{A, B}` and an updated
  Consumer with backends `{A, C}`
- WHEN `consumer.Repository.Update` is called
- THEN the inserts (`C`) and deletes (`B`) commit together
- AND a failure in either statement rolls back both, leaving the
  persisted set unchanged

### Requirement: Listing Pagination

Repository `List` calls MUST accept `ListFilter{ NameContains,
Page, Size }` where `Page >= 1`, `1 <= Size <= 200`, and return
`(items, total, err)`. `total` MUST reflect the unfiltered-by-page
match count.

#### Scenario: Listing with default pagination

- GIVEN 25 rows in the table and `Page = 1, Size = 20`
- WHEN `List` is called
- THEN exactly 20 items are returned and `total = 25`

#### Scenario: Listing with name filter

- GIVEN rows named `alpha`, `beta`, `alphabet` and `NameContains = "alph"`
- WHEN `List` is called
- THEN exactly the rows matching the substring are returned
- AND `total` equals their count regardless of `Page` / `Size`

### Requirement: Backend Type Discriminator at Rest

The `backends` table MUST encode `type` as a `TEXT` column with a
`CHECK` constraint accepting only `('llm', 'a2a', 'mcp')`. The
`config` column MUST be `JSONB NOT NULL`.

#### Scenario: Inserting a Backend with an unknown type

- GIVEN an INSERT with `type = 'rest'`
- WHEN the statement runs
- THEN Postgres rejects it via the CHECK constraint
- AND the repository surfaces it as `backend.ErrInvalidType`

### Requirement: Repository Constructor Signature Stability

Each `*Repository` constructor MUST take exactly `(*database.Connection)`
in B.2. No cache client, no event bus, no logger parameter beyond what
already exists in B.0.

#### Scenario: A future cache wrapper is added

- GIVEN RUN-299 introduces a cache decorator
- WHEN the decorator wraps the pgx repository
- THEN the pgx repository's constructor signature does not change
- AND DI rewires the `domain.Repository` provider to return the
  decorator instead

### Requirement: Error Mapping at the Repository Boundary

Repositories MUST translate `pgx.ErrNoRows` to the domain
`ErrNotFound`, Postgres unique-violation `23505` to `ErrAlreadyExists`,
and FK-violation `23503` to `ErrHasDependents` (or the entity's
equivalent).

#### Scenario: FindByID returns ErrNotFound

- GIVEN a non-existing ID
- WHEN `FindByID` queries the database
- THEN the returned error satisfies `errors.Is(err, ErrNotFound)`

#### Scenario: Save returns ErrAlreadyExists

- GIVEN a unique-key conflict on insert
- WHEN `Save` runs
- THEN the returned error satisfies `errors.Is(err, ErrAlreadyExists)`
