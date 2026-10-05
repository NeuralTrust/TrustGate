# Delta for personal-llm-consumers

Change `llm-store` (RUN-1763), slice S3 (decisions B1, D3, D5, D6). New capability. A consumer gains an `audience`: `application` (today's consumers) or `personal`. A personal consumer is an ordinary LLM consumer (registries, ModelPolicies, policies, budget) whose only credentials are personal keys, and it is reached only through `/store/v1/*` (`llm-store-gateway`), where it is one of possibly several consumers a key is linked to (`store-consumer-selection`). Which users are linked to which personal consumers, and at which level and priority, is decided by the app (Prisma `LlmStoreGrant`); TrustGate stores only the resulting links (`owned-key-attachment`). Hybrid gateways are out of v1.

## ADDED Requirements

### Requirement: `audience` column

An in-code migration (`20261002…`, template `20260922120000_add_auth_expires_at.go`) MUST add `consumers.audience text NOT NULL DEFAULT 'application'` with `CHECK (audience IN ('application','personal'))`. The migration MUST be idempotent, its up and down MUST each run in one transaction, and it MUST NOT create a table. Every Postgres read, insert and update of `consumers` MUST carry the column.

#### Scenario: Existing rows

- GIVEN a database with LLM, MCP and A2A consumers
- WHEN the migration runs, and then runs again
- THEN every existing row has `audience = 'application'`, and the second run is a no-op

#### Scenario: Invalid value refused by the database

- GIVEN the migrated schema
- WHEN a row with `audience = 'team'` is inserted directly
- THEN the insert fails on the CHECK constraint

### Requirement: Domain, wire form and admin DTO

`Consumer` MUST gain `Audience`, whose zero value means `application`. The snapshot wire form MUST carry `"audience":"personal"` only for a personal consumer (`omitempty`), so an application consumer MUST encode byte-identically to its encoding before the change. The admin consumer create request MUST accept an optional `audience` (`application` or `personal`; absent means `application`), and the admin consumer response MUST carry `audience`. Any other value MUST answer 422.

#### Scenario: Codec round trip

- GIVEN a personal LLM consumer
- WHEN it is encoded into a snapshot and decoded on the DP
- THEN the decoded consumer has `Audience = personal`

#### Scenario: Application consumer bytes

- GIVEN an application consumer fixture
- WHEN it is encoded after the change
- THEN the bytes are identical to the golden encoding taken before the change, with no `audience` key

#### Scenario: Default audience

- GIVEN an admin create request without `audience`
- WHEN the consumer is created
- THEN the response has `audience = application`

### Requirement: Only LLM consumers can be personal

`Consumer.Validate` MUST reject `audience = personal` unless `Type == TypeLLM`. Create MUST answer 422 and store nothing.

#### Scenario: Personal MCP consumer

- GIVEN a create request with `type: mcp` and `audience: personal`
- WHEN it is sent to the admin API
- THEN 422, and no consumer is created

#### Scenario: Personal LLM consumer

- GIVEN a create request with `type: llm`, `audience: personal`, one LLM registry and a ModelPolicy with a concrete `default`
- WHEN it is sent
- THEN 201 with `audience = personal`, and the registry and ModelPolicy are stored as for any LLM consumer

### Requirement: A personal consumer has a default model

`Consumer.Validate` MUST require, for `audience = personal`, a concrete (non-glob) `ModelPolicies[r].Default` for at least one registry `r` in `RegistryIDs`; fallback backends MUST NOT count. Create and update that break the rule MUST answer **422** and store nothing. Detaching from a personal consumer the last registry that carries a default MUST answer 422 and detach nothing. Application consumers MUST keep today's rules.

#### Scenario: Personal consumer without a default

- GIVEN a create request with `type: llm`, `audience: personal`, one registry R and a ModelPolicy on R with `allowed: ["gpt-4o*"]` and no `default`
- WHEN it is sent
- THEN 422, and no consumer is created

#### Scenario: Glob default does not count

- GIVEN the same request with `default: "gpt-4o*"`
- WHEN it is sent
- THEN 422

#### Scenario: Detaching the only registry with a default

- GIVEN a personal consumer P with registries R1 (default `gpt-4o`) and R2 (no default)
- WHEN R1 is detached from P, and then R2 is
- THEN the first answers 422 and R1 stays attached, and the second succeeds

### Requirement: `audience` is immutable

`audience` MUST be set at create only. A `PUT /consumers/:id` that carries an `audience` different from the stored one MUST answer 422 and change nothing. A `PUT` that omits `audience` or repeats the stored value MUST behave as today.

#### Scenario: Switch refused

- GIVEN a personal consumer P
- WHEN `PUT /consumers/P` is sent with `audience: application`
- THEN 422, and P is still personal with its keys still linked

#### Scenario: Same value accepted

- GIVEN a personal consumer P
- WHEN `PUT /consumers/P` is sent with `audience: personal` and a new name
- THEN 200 and the name changes

### Requirement: Personal consumers do not take bulk `auths`

Create with `audience = personal` and a non-empty `auths` MUST answer 422. A `PUT /consumers/:id` on a personal consumer that carries the `auths` field (an empty list included) MUST answer 422 and leave every `consumer_auth` row of the consumer untouched, because `replaceAuthLinks` would otherwise drop every user's link and its attributes. Personal links change only through the attach and detach of `owned-key-attachment` and the revoke of `personal-key-endpoints`. Application consumers MUST keep accepting `auths` as today.

#### Scenario: Create with keys

- GIVEN a create request with `audience: personal` and `auths: [K]`
- WHEN it is sent
- THEN 422, and no consumer is created

#### Scenario: Update with an empty list

- GIVEN a personal consumer P with three owned keys linked
- WHEN `PUT /consumers/P` is sent with `auths: []`
- THEN 422, and the three links remain

### Requirement: Deleting a personal consumer keeps the keys

Deleting a personal consumer MUST behave as today: its `consumer_auth` rows cascade and the owned keys MUST survive with their other links. A key left with no links MUST keep authenticating on `/store/v1/*` and be served nothing (`llm-store-gateway`).

#### Scenario: Delete

- GIVEN personal consumers P1 and P2 with `alice`'s key K linked to both
- WHEN P1 is deleted through the admin API
- THEN K still exists with the same id and `owner_id`, `GET /principal/llm-key` for `alice` shows `consumer_ids = [P2]`, and after the next snapshot apply `/store/v1/models` lists only P2's models

### Requirement: The admin consumer response keeps listing auth ids

`GET /consumers/:id` and the consumer list on a personal consumer MUST return every attached auth id, owned keys included, in `auth_ids`, as for any consumer. Auth secrets MUST NOT appear.

#### Scenario: Large personal consumer

- GIVEN a personal consumer P with 500 owned keys linked
- WHEN `GET /consumers/P` is called
- THEN `auth_ids` has 500 entries equal to the linked auth ids, and the body has no `auth_links`

### Requirement: No personal consumers on hybrid gateways

Creating a personal consumer on a gateway for which `ServedByHybridDataPlane()` is true MUST answer 422 and store nothing. Application consumers on hybrid gateways MUST be created as today.

#### Scenario: Hybrid gateway

- GIVEN a gateway H served by a hybrid data plane
- WHEN a consumer with `type: llm` and `audience: personal` is created on H
- THEN 422, and no consumer is created

#### Scenario: Application consumer on a hybrid gateway

- GIVEN the same gateway H
- WHEN a consumer with `type: llm` and no `audience` is created on H
- THEN 201, as today
