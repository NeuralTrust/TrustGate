# Delta for personal-key-endpoints

Change `llm-store` (RUN-1763), slice S4 (decision D8). New capability. Self-only admin API endpoints for the caller's own personal key on a gateway: read, create, rotate and revoke. They live under the existing `/v1/gateways/{gw}/store` group and its `RequireGatewayAccess(ResourceRegistries)` guard, which the Portal already passes. Create attaches the key to nothing: the app reconcile links it to every personal consumer the owner has a grant for (`owned-key-attachment`). The admin revocation is the existing `DELETE /auths/:id` (`owned-api-keys`).

## ADDED Requirements

### Requirement: The endpoints act on the caller only

`GET`, `POST` and `DELETE /v1/gateways/{gw}/store/principal/llm-key` and `POST /v1/gateways/{gw}/store/principal/llm-key/rotate` MUST act on `callerSubject(c)` only, the same rule as `ConnectLink`. They MUST NOT read an owner from the path, query or body: a `principal_sub` or `owner_id` in the body MUST be ignored. They MUST run behind `RequireInteractiveIdentity()`, so a service credential MUST get 403 and cannot hold a personal key. An empty caller subject MUST answer 403. A caller without registries access on the gateway MUST get 403 from the group guard.

#### Scenario: Service credential

- GIVEN a service credential with registries access on gateway G
- WHEN it calls `POST /v1/gateways/G/store/principal/llm-key`
- THEN 403, and no auth is created

#### Scenario: Body owner ignored

- GIVEN console user `alice` without a key on G
- WHEN she calls `POST …/llm-key` with `{"expires_at": <now + 30 d>, "principal_sub": "bob"}`
- THEN the key created has `owner_id = alice`, and `bob` has no key

#### Scenario: No registries access

- GIVEN a console user without registries access on G
- WHEN they call `GET …/llm-key`
- THEN 403

### Requirement: Create makes an unlinked key

`POST …/llm-key` with `{expires_at}` MUST create an enabled `api_key` auth on the gateway with `owner_id = caller` and no `consumer_auth` link, then run the creator's side effects (TTL eviction, `invalidation.GatewayData`, `Signal`). It MUST answer 201 with the auth id, the raw key, `consumer_ids: []` and `expires_at`. A `consumer_id` in the body MUST be ignored. The raw key MUST NOT be returned by any endpoint other than create and rotate. On a gateway served by a hybrid data plane, create MUST answer 422.

#### Scenario: First key

- GIVEN `alice` without a key on G, which has an active personal consumer P
- WHEN she calls `POST …/llm-key` with `{"expires_at": <now + 30 d>}`
- THEN 201 with the raw key and `consumer_ids: []`, the auth has `owner_id = alice` and that expiry, and after the next snapshot apply on a DB-less proxy the key answers 200 with an empty list on `/store/v1/models`

#### Scenario: Linked by the reconcile

- GIVEN `alice`'s new key K and the admin attaching it to P with valid link attributes
- WHEN she calls `GET …/llm-key`, and calls `/store/v1/models` after the next snapshot apply
- THEN `consumer_ids = [P]`, and the listing holds P's models

#### Scenario: Hybrid gateway

- GIVEN a gateway H served by a hybrid data plane
- WHEN `alice` calls `POST /v1/gateways/H/store/principal/llm-key` with a valid expiry
- THEN 422 and no auth is created

### Requirement: One key per user per gateway

A `POST …/llm-key` from a caller who already has a key on the gateway MUST answer **409** and leave the existing key and its links unchanged. The check MUST be backed by the partial unique index (`owned-api-keys`), so two concurrent creates MUST end with exactly one 201 and one 409. The same user MAY hold one key on each of several gateways.

#### Scenario: Second key

- GIVEN `alice` with a key on G
- WHEN she calls `POST …/llm-key` again
- THEN 409, and her existing key keeps working

#### Scenario: Concurrent creates

- GIVEN `alice` without a key on G
- WHEN two `POST …/llm-key` run at once
- THEN exactly one answers 201 and the other 409

#### Scenario: Another gateway

- GIVEN `alice` with a key on G
- WHEN she calls `POST /v1/gateways/H/store/principal/llm-key` with a valid expiry
- THEN 201

### Requirement: Expiry is required and capped at 90 days

`expires_at` MUST be required on create and MUST satisfy `now < expires_at ≤ now + 90 d`, with `now` read from an injected clock. On rotate it MAY be omitted (the current expiry stays), except on a key whose expiry has passed (see Rotate); when present it MUST satisfy the same bounds. Anything else MUST answer **422** and write nothing.

#### Scenario: Bounds on create

- GIVEN a clock fixed at `2026-10-02T12:00:00Z`
- WHEN `alice` creates her key with no `expires_at`, with `2026-10-02T12:00:00Z`, with `2026-12-31T12:00:01Z`, and with `2026-12-31T12:00:00Z`
- THEN the first three answer 422 and the last answers 201

### Requirement: Read

`GET …/llm-key` MUST answer 200 with the key's metadata: auth id, recognition prefix and suffix, `consumer_ids` (every linked consumer, `[]` when none), `expires_at`, enabled flag and timestamps. It MUST NOT return the raw key, its hash or the link attributes. A caller without a key MUST get 404.

#### Scenario: Metadata without the secret

- GIVEN `alice` with key K linked to P1 and P2
- WHEN she calls `GET …/llm-key`
- THEN 200 with id K and `consumer_ids` equal to `{P1, P2}`, and the body contains neither the raw key nor its hash

#### Scenario: No key

- GIVEN `bob` without a key
- WHEN he calls `GET …/llm-key`
- THEN 404

### Requirement: Rotate keeps the auth id and the links

`POST …/llm-key/rotate` with `{expires_at?}` MUST issue a new secret through `Auth.RotateAPIKey` and the rotator's side effects, keep the **same auth id**, the same owner and **every** `consumer_auth` link with its attributes, and set `expires_at` to the new value when given. It MUST answer 200 with the new raw key. The old secret MUST stop authenticating on DB-less proxies at the next snapshot apply and on full-plane proxies at the next `InvalidateGatewayDataEvent` (`llm-store-gateway`). Rotating an expired key MUST be allowed when the request carries a valid `expires_at`. Without one it MUST answer **422** and write nothing: keeping the passed expiry would hand out a secret that is dead on arrival. A caller without a key MUST get 404.

#### Scenario: Rotate

- GIVEN `alice` with key id K, secret S1, links to P1 and P2 and `expires_at = now + 5 d`
- WHEN she rotates with `expires_at = now + 90 d` and receives S2
- THEN the auth id is still K, the links to P1 and P2 and their attributes are unchanged, `expires_at = now + 90 d`, S2 answers 200 on `/store/v1/models` and S1 answers 401 after the next snapshot apply on a DB-less proxy

#### Scenario: Rotate an expired key

- GIVEN `alice`'s key with `expires_at` one day in the past
- WHEN she rotates with `expires_at = now + 30 d`
- THEN 200, and the new secret authenticates on `/store/v1/models`
- AND the same rotation without `expires_at` answers 422, and the key, its secret and its expiry are unchanged

#### Scenario: Nothing to rotate

- GIVEN `bob` without a key
- WHEN he calls `POST …/llm-key/rotate`
- THEN 404

### Requirement: Revoke

`DELETE …/llm-key` MUST delete the caller's key through the existing deleter (which also removes every link): 204, after which the key MUST NOT authenticate and the caller MAY create a new one. A caller without a key MUST get 404.

#### Scenario: Revoke and re-create

- GIVEN `alice` with a key linked to P1 and P2
- WHEN she calls `DELETE …/llm-key`, then `GET …/llm-key`, then `POST …/llm-key` with valid input
- THEN 204, then 404, then 201 with a new auth id and `consumer_ids: []`, no `consumer_auth` row of the old id remains, and the old key answers 401 on `/store/v1/models` after the next snapshot apply

#### Scenario: Nothing to revoke

- GIVEN `bob` without a key
- WHEN he calls `DELETE …/llm-key`
- THEN 404

### Requirement: Contract declared in OpenAPI

The four endpoints MUST be declared in the OpenAPI document with their request and response DTOs and status codes. The regeneration (`make docs`) MUST land in its own commit.

#### Scenario: Paths in the document

- GIVEN the regenerated OpenAPI document
- WHEN it is read
- THEN it declares `GET`, `POST` and `DELETE` on `…/store/principal/llm-key` and `POST` on `…/store/principal/llm-key/rotate`, with 201, 409 and 422 on the `POST`
