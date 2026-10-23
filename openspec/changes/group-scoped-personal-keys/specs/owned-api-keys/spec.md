# Delta for owned-api-keys

Change `group-scoped-personal-keys` (ENG-2610), slice K1 (G1, G2). A personal key may be held for one of its owner's directory groups. The owner still holds one personal key with no group, and now also at most one key per group.

## MODIFIED Requirements

### Requirement: `owner_id` column and one key per user per gateway

The one-key-per-owner rule MUST become one key per owner and group. An in-code migration (`20261022120000_add_auth_key_group`) MUST add `auths.group_id text NULL` and `auths.group_name text NULL`, create `auths_gateway_owner_group_uniq ON auths (gateway_id, owner_id, COALESCE(group_id, '')) WHERE owner_id IS NOT NULL` and drop `auths_gateway_owner_uniq`. A violation of either index MUST map to `ErrOwnedKeyExists` (409). The down migration MUST delete every group key with its `consumer_auth` rows before it restores the old index and drops the columns. Up and down MUST each be idempotent and run in one transaction.

#### Scenario: A personal key and group keys side by side

- GIVEN alice's personal key on gateway G
- WHEN keys for alice with `group_id` `g-eng` and `g-sre` are inserted on G
- THEN both inserts succeed

#### Scenario: Second key for the same group

- GIVEN alice's key for `g-eng` on G
- WHEN another key for alice and `g-eng` is inserted on G
- THEN the insert fails on `auths_gateway_owner_group_uniq`, and the same insert for bob succeeds

#### Scenario: Second personal key

- GIVEN alice's personal key on G
- WHEN another key for alice with no group is inserted on G
- THEN the insert fails on `auths_gateway_owner_group_uniq`

## ADDED Requirements

### Requirement: The group of a key

`Auth` MUST gain `GroupID` (`json:"group_id,omitempty"`) and `GroupName` (`json:"group_name,omitempty"`). `group_id` MUST be set at create only and never change. `group_name` MUST be set with `group_id` and only with it (422 otherwise), trimmed, at most 256 characters, and MAY be renamed later on a group key only: a rename asked of a key with no group MUST answer `ErrPersonalKey` (422 `personal_key`). The snapshot codec MUST round-trip both fields, and a key without a group MUST encode as before.

#### Scenario: Rename the group of a group key

- GIVEN alice's key for `g-eng` named `engineering`
- WHEN `PUT /auths/{id}/groups` sends `group_name: "platform engineering"`
- THEN the key keeps `group_id = g-eng` and answers `group_name = platform engineering`

#### Scenario: Rename asked of a personal key

- GIVEN alice's personal key
- WHEN `PUT /auths/{id}/groups` sends a `group_name`
- THEN the answer is 422 `personal_key` and nothing changes

### Requirement: Lookups by owner and group

The repository port MUST replace `FindByOwner` with `FindByOwnerAndGroup(ctx, gatewayID, ownerID, groupID)` (an empty group finds the personal key) and add `ListByOwner(ctx, gatewayID, ownerID)` (every key of the owner, newest first). The snapshot read model MUST answer both on DB-less planes.

#### Scenario: Personal key found among group keys

- GIVEN alice's personal key and her key for `g-eng`
- WHEN `FindByOwnerAndGroup(G, alice, "")` and `FindByOwnerAndGroup(G, alice, "g-eng")` are called
- THEN the first returns the personal key and the second the group key

### Requirement: The admin list by owner lists every key

`GET /v1/gateways/{gw}/auths?owner_id=<sub>` MUST list every key of that owner on the gateway, the personal key and each group key, each with `group_id` and `group_name` when it has a group.

#### Scenario: Owner with three keys

- GIVEN alice's personal key and her keys for `g-eng` and `g-sre`
- WHEN the admin lists `?owner_id=alice`
- THEN the total is 3 and the group keys carry their `group_name`
