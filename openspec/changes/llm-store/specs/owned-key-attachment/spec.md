# Delta for owned-key-attachment

Change `llm-store` (RUN-1763), slice S3 (decisions B4, B5, D3, D4). New capability. A personal key is linked through `consumer_auth` to **every** personal consumer of its gateway that the app granted to its owner (N ≥ 0). The links complement each other: none is exclusive, and there is no move. Each personal link carries `level`, `priority` and `granted_at`, which `store-consumer-selection` uses to order the consumers. The app reconcile attaches and detaches through the existing admin API. `consumer_auth` keeps its PK `(consumer_id, auth_id)`, `auth_id` RESTRICT and same-gateway trigger; application links are unchanged.

## ADDED Requirements

### Requirement: Link columns

An in-code migration (`20261006100200_add_consumer_auth_grant`) MUST add `consumer_auth.level text NULL`, `consumer_auth.priority integer NULL` and `consumer_auth.granted_at timestamptz NULL`, with one CHECK: either none of the three is set (application link), or all three are set with `level IN ('user','group','all')`, `priority >= 0` and a finite `granted_at` (personal link). A row with only some of the three set MUST be refused. The migration MUST be idempotent, its up and down MUST each run in one transaction, and it MUST NOT create a table.

#### Scenario: Existing links untouched

- GIVEN a database with application links
- WHEN the migration runs, and then runs again
- THEN every existing row has the three columns `NULL`, and the second run is a no-op

#### Scenario: Half-filled link refused

- GIVEN the migrated schema
- WHEN a row with `level = 'group'` and `granted_at IS NULL` is inserted directly
- THEN the insert fails on the CHECK constraint

### Requirement: Domain and wire form of links

`Consumer` MUST gain `AuthLinks map[AuthID]AuthLink` (`json:"auth_links,omitempty"`), where `AuthLink` is `{level, priority, granted_at}`. Every Postgres read of consumers MUST fill it from the personal links (`level IS NOT NULL`), and the snapshot codec MUST round-trip it. A consumer without personal links MUST encode byte-identically to its encoding before the change. `auth_ids` MUST keep listing every linked auth id. The admin consumer response MUST NOT expose `auth_links`.

#### Scenario: Codec round trip

- GIVEN personal consumer P with `alice`'s key linked as `{level: group, priority: 2, granted_at: 2026-10-01T09:00:00Z}`
- WHEN it is encoded into a snapshot and decoded on the DP
- THEN the decoded consumer has that `AuthLinks` entry and `auth_ids` contains the key

#### Scenario: Application consumer bytes

- GIVEN an application consumer with application links
- WHEN it is encoded after the change
- THEN the bytes equal the golden encoding taken before the change, with no `auth_links` key

### Requirement: Keys and consumers must share an audience

`ValidateAuthConfig` (`pkg/domain/consumer/auth_rules.go`) MUST enforce: a personal consumer accepts only owned keys, and an application consumer accepts only unowned auths. A mismatch MUST answer **422** and write nothing, on admin attach (`POST /consumers/:id/auths/:auth_id`), on consumer create and on `PUT /consumers/:id` with `auths` for an application consumer. Application keys on application consumers MUST attach exactly as today.

#### Scenario: Owned key onto an application consumer

- GIVEN an application LLM consumer X and `alice`'s owned key K on the same gateway
- WHEN K is attached to X, or X is updated with `auths: [K]`
- THEN 422, and X's `auth_ids` do not contain K

#### Scenario: Application key onto a personal consumer

- GIVEN a personal consumer P and an application key A on the same gateway
- WHEN A is attached to P
- THEN 422, and P's `auth_ids` do not contain A

#### Scenario: Application attach unchanged

- GIVEN an application consumer X and an application key A
- WHEN A is attached to X with no body
- THEN the status and body are the same as before the change, and the link's three columns are `NULL`

### Requirement: Attach carries the link attributes

Admin `POST /consumers/:id/auths/:auth_id` MUST accept an optional JSON body `{level, priority, granted_at}`. For an owned key on a personal consumer, `level` (`user`, `group` or `all`) and `granted_at` (RFC 3339) MUST be present and `priority`, when present, MUST be an integer ≥ 0; an absent `priority` MUST default to 1. Anything else MUST answer **422** and write nothing. For an application consumer, a body carrying any of the three fields MUST answer 422; an empty body MUST behave as today. The write MUST touch only the link of that consumer and that key, MUST produce one snapshot write, and MUST NOT change the auth id or the secret.

#### Scenario: First attach

- GIVEN personal consumer P1 and `alice`'s key K with no links
- WHEN admin `POST /consumers/P1/auths/K` is called with `{"level": "group", "priority": 3, "granted_at": "2026-10-01T09:00:00Z"}`
- THEN 204, and K is linked to P1 with those attributes

#### Scenario: Links are complementary

- GIVEN K linked to P1
- WHEN admin `POST /consumers/P2/auths/K` is called with `{"level": "user", "granted_at": "2026-10-02T09:00:00Z"}`
- THEN 204, K is linked to both P1 and P2, P1's attributes are unchanged, and P2's priority is 1

#### Scenario: Missing level

- GIVEN personal consumer P1 and key K
- WHEN admin `POST /consumers/P1/auths/K` is called with no body, and then with `{"granted_at": "2026-10-01T09:00:00Z"}`
- THEN both answer 422 and K has no link to P1

#### Scenario: Link fields on an application consumer

- GIVEN application consumer X and application key A
- WHEN admin `POST /consumers/X/auths/A` is called with `{"level": "group", "granted_at": "2026-10-01T09:00:00Z"}`
- THEN 422, and A is not linked to X

### Requirement: Re-attach updates the attributes

Re-attaching a key to a consumer it is already linked to MUST replace that link's `level`, `priority` and `granted_at` with the new values (an upsert) and MUST leave the key's other links untouched. Re-sending the same values MUST succeed and leave the link unchanged.

#### Scenario: Priority change

- GIVEN K linked to P1 with priority 3 and to P2 with priority 1
- WHEN admin `POST /consumers/P1/auths/K` is called with `{"level": "group", "priority": 0, "granted_at": "2026-10-01T09:00:00Z"}`
- THEN K's link to P1 has priority 0, its link to P2 still has priority 1, and the next selection prefers P1 at equal level

### Requirement: Detach removes one link

Admin `DELETE /consumers/:id/auths/:auth_id` on an owned key MUST remove that one link and keep the key and its other links. A key with no links left MUST still authenticate on `/store/v1/*` and be served nothing (`llm-store-gateway`).

#### Scenario: Detach one of two

- GIVEN K linked to P1 and P2
- WHEN admin `DELETE /consumers/P1/auths/K` is called
- THEN 204, K exists and is linked only to P2, and after the next snapshot apply on a DB-less proxy `/store/v1/models` lists only P2's models

#### Scenario: Detach the last one

- GIVEN K linked only to P1
- WHEN admin `DELETE /consumers/P1/auths/K` is called
- THEN 204, K exists with no link, and after the next snapshot apply `/store/v1/models` answers 200 with an empty list

### Requirement: Cross-gateway attach is refused as today

Attaching an owned key to a consumer of another gateway MUST be refused with the status today's attach returns for an auth outside the consumer's gateway, and MUST write nothing.

#### Scenario: Other gateway

- GIVEN `alice`'s key K on gateway G and a personal consumer Q on gateway H
- WHEN admin `POST /consumers/Q/auths/K` is called on H with valid link attributes
- THEN it is refused with today's status for an auth outside the gateway, and K's links on G are unchanged
