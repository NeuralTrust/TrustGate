# Delta for owned-api-keys

Change `llm-store` (RUN-1763), slice S3 (decisions B3, D7). New capability. An `api_key` auth can have an owner: a personal key. It is a normal row of the existing `auths` table with a nullable `owner_id` (the platform user id, the console token `sub`), it rides the config snapshot like any auth, and the owner, not the admin, manages it. An auth without an owner is an application key and behaves exactly as today. Where an owned key is linked, and with which attributes, is in `owned-key-attachment`; the owner's endpoints are in `personal-key-endpoints`.

## ADDED Requirements

### Requirement: `owner_id` column and one key per user per gateway

An in-code migration (`20261002…`) MUST add `auths.owner_id text NULL` and the partial unique index `auths_gateway_owner_uniq (gateway_id, owner_id) WHERE owner_id IS NOT NULL`. `NULL` MUST mean an application key. The migration MUST be idempotent, its up and down MUST each run in one transaction, and it MUST NOT create a table.

#### Scenario: Existing rows untouched

- GIVEN a database with application keys
- WHEN the migration runs, and then runs again
- THEN every existing row has `owner_id IS NULL`, and the second run is a no-op

#### Scenario: Second owned key for the same user

- GIVEN an owned key with `owner_id = alice` on gateway G
- WHEN another auth with `owner_id = alice` is inserted on G
- THEN the insert fails on `auths_gateway_owner_uniq`, and the same insert on gateway H succeeds

### Requirement: Domain, repository and wire form

`Auth` MUST gain `OwnerID` (`json:"owner_id,omitempty"`) and `IsOwned()` (true when `OwnerID != ""`). Every Postgres read, insert and update of `auths` MUST carry the column. The repository port MUST gain `FindByOwner(ctx, gatewayID, ownerID)`, and `ListFilter` MUST gain `ExcludeOwned bool` and `OwnerID string`. The snapshot codec MUST round-trip `owner_id`, and an application key MUST encode byte-identically to its encoding before the change.

#### Scenario: Codec round trip

- GIVEN an owned auth with `owner_id = alice`
- WHEN it is encoded into a snapshot and decoded on the DP
- THEN the decoded auth has `OwnerID = alice` and `IsOwned()` is true

#### Scenario: Application key bytes

- GIVEN an application key fixture
- WHEN it is encoded after the change
- THEN the bytes equal the golden encoding taken before the change, with no `owner_id` key

#### Scenario: Find by owner

- GIVEN `alice`'s owned key on G and none on H
- WHEN `FindByOwner(G, alice)` and `FindByOwner(H, alice)` are called against Postgres (`PG_TEST_URL`)
- THEN the first returns the key and the second returns not-found

### Requirement: Owned keys ride the snapshot

The compiler MUST read auths through the unfiltered `List`, in both the bulk and the per-gateway paths, so owned keys MUST be in the snapshot, and the read model MUST index them in `AuthByAPIKeyHash`. `ExcludeOwned` MUST default to `false`, and only the admin list handler MUST set it.

#### Scenario: Compiler includes owned keys

- GIVEN gateway G with one application key and one owned key
- WHEN the snapshot for G is compiled
- THEN both auths are in it, and `AuthByAPIKeyHash` finds the owned key by its hash

### Requirement: The admin list hides owned keys unless asked by owner

`GET /v1/gateways/{gw}/auths` MUST exclude owned keys from its items and from its total. With `?owner_id=<sub>` it MUST return only that owner's key on the gateway (one item, or none), so the app reconcile (which then links the key to the owner's granted consumers) and offboarding can find it. Without the parameter the response for a gateway without owned keys MUST be identical to today's.

#### Scenario: List hides owned keys

- GIVEN gateway G with three application keys and two owned keys
- WHEN `GET /v1/gateways/G/auths` is called
- THEN it returns the three application keys and `total = 3`

#### Scenario: List by owner

- GIVEN the same gateway and `alice` owning one of the two keys
- WHEN `GET /v1/gateways/G/auths?owner_id=alice` is called
- THEN it returns exactly `alice`'s key with `owner_id = alice` and `total = 1`

### Requirement: The admin cannot edit an owned key, only revoke it

Admin `GET /v1/gateways/{gw}/auths/{id}` on an owned key MUST answer 200 with `owner_id` and never the raw key or its hash. Admin `PUT` and `POST …/rotate` on an owned key MUST answer **422** with `error = owned_key` and change nothing. Admin `DELETE` on an owned key MUST be allowed as the admin revocation: 204, removing every link through the existing deleter, with the same TTL eviction, `invalidation.GatewayData` and `Signal` as any auth delete. An admin create MUST NOT produce an owned key: an `owner_id` in the create body MUST be ignored, and an admin update MUST never write `owner_id`.

#### Scenario: Get shows the owner

- GIVEN `alice`'s owned key K on G
- WHEN admin `GET /v1/gateways/G/auths/K` is called
- THEN 200 with `owner_id = alice`, and the body has neither the raw key nor its hash

#### Scenario: Update and rotate refused

- GIVEN the same key K
- WHEN admin `PUT` and `POST …/rotate` are called on `/v1/gateways/G/auths/K`
- THEN each answers 422 `owned_key`, and K's secret, name, expiry and enabled flag are unchanged

#### Scenario: Admin revocation

- GIVEN K linked to personal consumers P1 and P2
- WHEN admin `DELETE /v1/gateways/G/auths/K` is called
- THEN 204, the row and both `consumer_auth` links are gone, and after the next snapshot apply on a DB-less proxy K answers 401 on `/store/v1/models`

#### Scenario: Owner in an admin create body

- GIVEN an admin create request for an `api_key` auth with `"owner_id": "alice"`
- WHEN it is sent
- THEN the created auth has no `owner_id`

### Requirement: Policy warnings ignore owned keys

The api-key reach computed for policy warnings (`pkg/app/policy/warnings.go`, `apiKeyAuths`) MUST skip owned keys, so a consumer whose only enabled `api_key` auths are owned MUST NOT be named in the api-key warning. Application keys MUST keep being counted as today.

#### Scenario: Owned keys only

- GIVEN a fake auth repository returning only owned enabled `api_key` auths for a consumer reached by a policy with `groups`
- WHEN the warnings are computed
- THEN no api-key warning names that consumer
