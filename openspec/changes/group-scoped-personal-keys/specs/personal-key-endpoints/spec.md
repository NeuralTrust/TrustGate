# Delta for personal-key-endpoints

Change `group-scoped-personal-keys` (ENG-2610), slices K2 and K3 (G3, G4). Expiry becomes optional and longer; the admin create can issue a group key; new self routes manage every key of the caller by id. The `…/llm-key` routes keep acting on the personal key, the one with no group.

## MODIFIED Requirements

### Requirement: Expiry is required and capped at 90 days

A personal key's `expires_at` MUST be optional: absent, `null` or empty issues a key that never expires. When set it MUST be in the future and at most 366 days away (`MaxOwnedKeyLifetime`), else 422. A rotation without `expires_at` and without `never_expires` MUST keep the current expiry (a key that never expires stays so) unless it has passed (422). `"never_expires": true` MUST renew the key with no expiry, and together with `expires_at` MUST answer 422. The MCP Store's personal key page MUST keep issuing and renewing its key for 90 days. The `PersonalKeys` gRPC service MUST read `expires_at_unix = 0` as no expiry.

#### Scenario: Create without an expiry

- GIVEN alice without a personal key
- WHEN she posts `…/llm-key` with an empty body
- THEN the answer is 201 and the key has no `expires_at`

#### Scenario: Bounds on create

- GIVEN alice without a personal key
- WHEN she posts `expires_at` 367 days away, then one in the past
- THEN both answer 422, and one 366 days away answers 201

#### Scenario: Renew an expired key with no expiry

- GIVEN alice's expired key
- WHEN she rotates it with `{"never_expires": true}`
- THEN the answer is 200 with a new secret and no `expires_at`; rotating it with an empty body would have answered 422

#### Scenario: Both expiry fields

- WHEN a rotation sends `expires_at` and `never_expires: true`
- THEN the answer is 422 and nothing changes

### Requirement: One key per user per gateway

The admin create `POST /v1/gateways/{gw}/store/users/{user_id}/llm-key` MUST take optional `group_id` and `group_name`: with them it issues the user's key for that group, without them the personal key. It MUST answer 409 `already_exists` when the user already holds a key for that group (or a personal key, when none is named), and 422 when one of `group_id` and `group_name` comes without the other. The response (`IssuedPersonalKeyResponse`) and every personal key response MUST carry `group_id` and `group_name` (`omitempty`). The self create `POST …/store/principal/llm-key` MUST keep issuing the personal key only.

#### Scenario: Group key for a user

- GIVEN alice with a personal key
- WHEN an admin posts `{"group_id": "g-eng", "group_name": "engineering"}` for alice
- THEN the answer is 201 with `group_id = g-eng`, and the same post again answers 409

## ADDED Requirements

### Requirement: The caller manages every key of theirs by id

Under the same guard as the personal key routes (signed-in tenant user, interactive identity):

- `GET /v1/gateways/{gw}/store/principal/llm-keys` MUST answer 200 `{"items": [PersonalKeyResponse]}` with every key of the caller on the gateway, newest first, never a secret.
- `POST …/store/principal/llm-keys/{auth_id}/rotate` MUST take the personal key rotation's body (`expires_at`, `never_expires`) and answer 200 `IssuedPersonalKeyResponse`.
- `DELETE …/store/principal/llm-keys/{auth_id}` MUST revoke the key and its links and answer 204.

A key that is not the caller's on the gateway (another user's, an application key, another gateway's, an unknown id) MUST answer 404 on both, as an unknown id does.

#### Scenario: List

- GIVEN alice's personal key, then her keys for `g-eng` and `g-sre`
- WHEN she lists `…/llm-keys`
- THEN the items are `g-sre`, `g-eng`, personal, in that order

#### Scenario: Another user's key

- GIVEN alice's key for `g-eng`
- WHEN bob rotates or revokes it by id
- THEN both answer 404 and the key is unchanged

#### Scenario: The personal key routes ignore group keys

- GIVEN alice's key for `g-sre` and no personal key
- WHEN she calls `GET …/llm-key`
- THEN the answer is 404
