# Delta for llm-store-gateway

Change `llm-store` (RUN-1763), slice S5 (decisions B6, B8, B9, D1, D2, D10, D12, D14). New capability. `/store/v1/*` on the proxy plane serves personal keys. The key leads to all of its owner's personal consumers on the gateway (its links); for each request one of them is selected (`store-consumer-selection`) and serves it through its normal registries, ModelPolicies, load balancer, fallback and policies. There is no synthetic consumer and no computed view. Hybrid gateways are out of v1.

## ADDED Requirements

### Requirement: The store branch slots in after the path is resolved

In `AuthMiddleware` (`pkg/api/middleware/auth.go`), right after `ResolveProxyPath`, a path slug equal to `store` MUST take the store branch instead of today's `FindByGateway` → `MatchSlug` flow. The branch MUST run, in order: the hybrid check, the gateway's `Data` load (`FindByGateway`), the personal-consumer check, the key check. Every other slug MUST follow today's flow. `store` MUST NOT collide with a consumer slug, which is exactly 8 alphanumerics.

#### Scenario: Other slugs unchanged

- GIVEN an application LLM consumer X with an application key
- WHEN the key calls `/<X slug>/v1/chat/completions`
- THEN the request is served as before the change

### Requirement: 404 before any key lookup

The store branch MUST answer **404** `not_found`, before any key lookup, when the gateway is served by a hybrid data plane (`ServedByHybridDataPlane()`) or when the gateway's `Data` holds no active personal consumer (`Data.HasPersonalConsumers()` is false). That path MUST NOT call `APIKeyFinder`, a repository, a cache or Redis for the key, so an unknown-key probe never reaches Postgres on the full plane. The 404 MUST be the same response today's `MatchSlug` miss gives.

#### Scenario: Gateway without personal consumers

- GIVEN a gateway with only application consumers and an `APIKeyFinder` fake that counts calls
- WHEN `/store/v1/chat/completions` is called with any key, or with none
- THEN 404 `not_found`, identical to today's response for an unknown slug, and the finder was called zero times

#### Scenario: Only inactive personal consumers

- GIVEN a gateway whose only personal consumer has `active = false`
- WHEN `/store/v1/models` is called with a valid personal key linked to it
- THEN 404, and the finder was called zero times

#### Scenario: Hybrid gateway

- GIVEN a gateway served by a hybrid data plane whose snapshot holds a personal consumer and a valid personal key linked to it
- WHEN `/store/v1/models` is called with that key
- THEN 404, and the finder was called zero times

### Requirement: Key resolution and checks

On a gateway with active personal consumers, the key MUST be resolved with `APIKeyFinder.FindByAPIKey` (SHA-256; the snapshot `AuthByAPIKeyHash` index on a DB-less proxy, the in-process TTL plus Postgres on the full plane). The branch MUST then require all of: `Enabled`, `Type == api_key`, `OwnerID != ""`, `GatewayID ==` the resolved gateway (the hash index spans tenants), and not expired at `now`. A missing key, an unknown key or any failed check MUST answer **401**, never 403. Key resolution MUST NOT add a gRPC method or a Redis call.

#### Scenario: Valid personal key

- GIVEN gateway G with personal consumer P and `alice`'s enabled key K linked to P
- WHEN `/store/v1/models` is called with K in `X-AG-API-Key`, and again in `Authorization: Bearer`
- THEN both answer 200

#### Scenario: Rejected keys

- GIVEN the same gateway G
- WHEN `/store/v1/models` is called with no key, an unknown key, a disabled personal key, an expired personal key, a deleted personal key, an application key of G attached to an application consumer, and a personal key of gateway H
- THEN each answers 401

### Requirement: Key to links in O(1)

`NewData` MUST build `Data.StoreLinks(authID)`, a `map[AuthID][]StoreLink` over the gateway's **active** personal consumers and their `auth_links`, each slice sorted once by level (`user`, `group`, `all`), then `priority` ascending, then `granted_at` ascending, then consumer id. The handler MUST read the key's links only through that index. `Data` is immutable after `NewData`, so the slices MUST be shared without a lock. A key with no links MUST still authenticate (N = 0 is valid): a chat call MUST answer **403** `model_not_allowed` and `/store/v1/models` MUST answer 200 with an empty list. Because the index lives in `Data`, a link removed in another process MUST NOT keep routing once `Data` is rebuilt.

#### Scenario: Index order

- GIVEN `alice`'s key linked to P1 (`group`, priority 2, granted day 1), P2 (`group`, priority 1, granted day 3), P3 (`all`, priority 0, granted day 0) and P4 (`user`, priority 5, granted day 9)
- WHEN `Data.StoreLinks(K)` is read
- THEN the order is P4, P2, P1, P3

#### Scenario: No links

- GIVEN `alice`'s valid key K with no `consumer_auth` link, on a gateway with an active personal consumer
- WHEN K calls `/store/v1/models`, and then `/store/v1/chat/completions` with `model: gpt-4o`
- THEN 200 with `data: []`, and 403 `model_not_allowed` without an upstream call

#### Scenario: Inactive consumer is not a link

- GIVEN K linked to personal consumers P1 (`active = false`) and P2 (active), both allowing `gpt-4o`
- WHEN K calls `/store/v1/chat/completions` with `model: gpt-4o`
- THEN P2 serves it

#### Scenario: Stale key cache after a detach

- GIVEN a full-plane proxy whose `auth_key` TTL holds K, and K detached from P1 (keeping P2) in another process
- WHEN the proxy receives `InvalidateGatewayDataEvent` for G and K then calls `/store/v1/models`
- THEN it lists P2's models and none that only P1 offered

### Requirement: Personal principal and auth context

An accepted key MUST produce `Principal{Subject: owner_id, Method: api_key}` and `AuthContext{AuthID, OwnerID}`, attached through the existing `attach` without a consumer. Once the handler selects a consumer, `AuthContext.ConsumerID` MUST be set to it before the forwarder runs. `RequestContext` MUST carry the auth id and owner id (`token-budget-key-partition`). No new principal method MUST be introduced.

#### Scenario: Context of a personal request

- GIVEN `alice`'s key K linked to P, which admits `gpt-4o`
- WHEN K calls `/store/v1/chat/completions` with `model: gpt-4o`
- THEN the principal has subject `alice` and method `api_key`, the auth context has `AuthID = K`, `OwnerID = alice`, `ConsumerID = P`, and the request context carries `K` and `alice`

### Requirement: The selected consumer serves the request as its own route would

A `/store/v1/*` request other than the model listing MUST be served by the consumer `store-consumer-selection` picks, exactly as a request on that consumer's own route would be (registries, `ModelPolicies`, routing, provider enforcement, fallback, policies), except that registries of providers substituted for that request MUST NOT be used, fallback backends included. When no consumer admits the request, the answer MUST be 403 `model_not_allowed` before any upstream call.

#### Scenario: Allowed and denied models

- GIVEN `alice`'s key linked only to P, with registry R and a ModelPolicy allowing `gpt-4o*` on R
- WHEN she calls `/store/v1/chat/completions` with `model: gpt-4o-mini`, and then with `model: claude-sonnet-4-5`
- THEN the first reaches R, and the second gets 403 `model_not_allowed` without an upstream call

### Requirement: The model listing is the union after substitution

`/store/v1/models` MUST list the union, deduplicated by id and sorted, of the models each effective link's consumer offers through today's model listing, restricted to its primary registries that survive substitution (`store-consumer-selection`). Fallback backends MUST NOT contribute. `/store/v1/models/{id}` MUST answer 200 for a listed id and 404 otherwise. The listing MUST stamp no consumer on the trace.

#### Scenario: Union with substitution (worked example)

- GIVEN `ana`'s key linked to A (`group`, OpenAI, no allow-list, fallback DeepSeek), B (`group`, Anthropic, no allow-list), C (`group`, Anthropic `["opus-5.5"]`) and D (`user`, OpenAI `["gpt6"]`), with a catalog listing `gpt-4.1` and `gpt6` for OpenAI, `opus-5.5` and `opus-4.8` for Anthropic, and `deepseek-chat` for DeepSeek
- WHEN she calls `/store/v1/models`
- THEN it lists exactly `gpt6`, `opus-4.8` and `opus-5.5`, and neither `gpt-4.1` nor `deepseek-chat`

#### Scenario: Union without a user link

- GIVEN the same links without D
- WHEN she calls `/store/v1/models`
- THEN it lists `gpt-4.1`, `gpt6`, `opus-4.8` and `opus-5.5`, and not `deepseek-chat`

### Requirement: Load balancer, fallback and policies are unchanged per consumer

The selected consumer MUST use today's load balancer key `gw:consumerID`, shared by every user it serves, and today's fallback, which applies only to requests it serves. Its policies MUST be its attached ones plus the gateway globals, through the non-MCP branch of `plansFor`, with a non-nil `PolicyPlan`. MCP-wide policies MUST NOT reach it.

#### Scenario: Shared balancer

- GIVEN `alice` and `bob` both linked to P, and P selected for both of their zero-intent requests
- WHEN both send them
- THEN one balancer keyed `G:P` serves both

#### Scenario: Policies of the selected consumer

- GIVEN a policy attached to P1, a policy attached to P2, a gateway global policy and an MCP-wide policy, and P1 selected for `alice`'s request
- WHEN the request runs
- THEN the plan holds P1's policy and the global one, and neither P2's nor the MCP-wide one

### Requirement: Telemetry of a store request

A `/store/v1/*` usage event MUST carry `consumer.id` = the selected personal consumer's id, `auth_id` = the personal key's id and `principal_subject` = `owner_id` (`usage-auth-id-telemetry`). A refusal after authentication (403, 400, 405, 429) MUST carry the key and the owner and no consumer; a 401 MUST carry neither.

#### Scenario: Event fields

- GIVEN `alice`'s key K linked to P1 and P2, and P2 selected for her chat call
- WHEN the call completes
- THEN the event has `consumer.id = P2`, `auth_id = K` and `principal_subject = alice`

### Requirement: A store request belongs to the key owner

On `/store/v1/*` the usage event's end user MUST be the key's owner: `X-NeuralTrust-End-User`, the `X-TG-User-*` and Open WebUI end-user headers and the body's `user` field MUST be ignored, and a request carrying them MUST NOT be refused for them. A session id MUST name a conversation in the scope of the key's owner: two owners sending the same session id MUST NOT continue each other's conversation, and a `previous_response_id` recorded for another owner MUST read as unknown. On `/<slug>/v1/*` end users and sessions MUST behave as today. The Files API MUST NOT be a store route: with a valid key, `/store/v1/files` and `/store/v1/files/{id}` MUST answer the 404 of an unknown store route, because file operations would run on the registry's shared credential for every user.

#### Scenario: End-user headers ignored

- GIVEN `alice`'s key and a chat call carrying `X-NeuralTrust-End-User: mallory`, `X-TG-User-Id: mallory` and `"user": "mallory"`
- WHEN the call completes
- THEN 200, and the usage event has `end_user.id = alice` and no `mallory`

#### Scenario: Same session id, two owners

- GIVEN `alice` and `bob` on the same gateway, both sending `X-Session-Id: S` to `/store/v1/responses`, `alice` first
- WHEN `bob` sends his first turn and then `alice` her second
- THEN `bob`'s upstream request carries no `previous_response_id`, and `alice`'s carries her own first turn's id

#### Scenario: Files API refused

- GIVEN `alice`'s valid key
- WHEN she calls `GET /store/v1/files`, `POST /store/v1/files` or `GET /store/v1/files/{id}`
- THEN each answers 404, byte-identical to an unknown store route, with no upstream call

### Requirement: Warm requests and freshness

A warm `/store/v1/*` request on a DB-less proxy MUST make zero DB and zero gRPC calls, and no Redis call except a budget counter. An attach, detach, link-attribute change, rotation or revocation MUST take effect on a DB-less proxy at the next snapshot apply, and on the full plane at the next `InvalidateGatewayDataEvent` for the gateway.

#### Scenario: Warm request on DB-less

- GIVEN a DB-less proxy with counting fakes for DB and gRPC, after one request by `alice`
- WHEN she sends a second request
- THEN the fakes record zero calls for it

#### Scenario: Priority change on DB-less

- GIVEN `alice`'s key linked to P1 and P2, both `group` and both allowing `gpt-4o`, P1 with priority 1 and P2 with priority 2
- WHEN the admin re-attaches K to P2 with priority 0, the DB-less proxy applies the next snapshot, and she calls with `model: gpt-4o`
- THEN P2 serves it

### Requirement: The key cache is evicted across processes

`InvalidateGatewayDataEventSubscriber` MUST clear the `auth_key` TTL map and the unknown-key TTL map (an unknown digest is remembered for 30 s), as it clears the `auth` TTL map, so a rotated or revoked secret MUST stop resolving on every full-plane replica at the next `InvalidateGatewayDataEvent`, not after the TTL.

#### Scenario: Rotation seen by another replica

- GIVEN an admin process and a full-plane proxy process sharing Postgres and the cache event bus, and the proxy has resolved `alice`'s secret S1
- WHEN the admin process rotates her key to S2 and publishes `InvalidateGatewayDataEvent`
- THEN after the proxy handles the event, S1 answers 401 there and S2 answers 200
