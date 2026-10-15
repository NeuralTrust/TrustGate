# Delta for personal-key-isolation

Change `llm-store` (RUN-1763), slice S5 (decisions B7, D11). New capability. Personal keys and personal consumers are reachable only through `/store/v1/*`, and `/store/v1/*` accepts only personal keys. One grant has one entry point. Personal keys on MCP and the playground on personal consumers are out of scope.

## ADDED Requirements

### Requirement: Personal consumers are not slug-routable

`indexBySlug` (`pkg/app/consumer/consumer_data.go`) MUST skip personal consumers, so `/<personal consumer slug>/v1/*` MUST answer 404 with any key, exactly as an unknown slug does. Application consumers MUST keep being indexed as today.

#### Scenario: Personal consumer by slug

- GIVEN personal consumer P with slug `pslug001` and `alice`'s key linked to it
- WHEN `alice`'s key calls `/pslug001/v1/chat/completions`
- THEN 404, the same response as an unknown slug

### Requirement: A personal key on an application route answers as an unknown key

A personal key presented on `/<application slug>/v1/*` MUST answer exactly as an unknown key does, with the same status and body. It MUST never get the 403 that a valid key of another application consumer gets. `apiKeyAttachedElsewhere` (`pkg/api/middleware/auth.go`) MUST skip personal consumers, so it also stops scanning their owned keys, and an application consumer's loaded credentials MUST NOT include owned keys. An application key attached to another application consumer MUST keep getting 403, as today.

#### Scenario: Personal key on an application consumer

- GIVEN application consumer X with an application key, and `alice`'s key linked to personal consumer P on the same gateway
- WHEN `alice`'s key calls `/<X slug>/v1/chat/completions`
- THEN the same status and body as an unknown key, which is 401 here

#### Scenario: Personal key on an OAuth-only application consumer

- GIVEN application consumer Z with only an OAuth2 credential, and `alice`'s key linked to personal consumer P on the same gateway
- WHEN `alice`'s key and an unknown key each call `/<Z slug>/v1/chat/completions`
- THEN both get the same status and body

#### Scenario: Application key of another consumer

- GIVEN application consumers X and Y with application keys on one gateway
- WHEN Y's key calls `/<X slug>/v1/chat/completions`
- THEN 403, as today

### Requirement: Application keys do not work on `/store/v1`

An application key MUST answer 401 on `/store/v1/*`, even when the gateway has personal consumers and the key is valid on its own consumer (`llm-store-gateway`).

#### Scenario: Application key on the store

- GIVEN a gateway with personal consumer P and application consumer X with key A
- WHEN A calls `/store/v1/models`
- THEN 401, and A still answers 200 on `/<X slug>/v1/models`

### Requirement: Personal keys are unknown on the MCP plane

On the MCP plane, `chainIdentityResolver.resolveAPIKey` (`auth_chain.go`) and `apiKeyConsumers.ForAPIKey` (`pkg/app/consumer/api_key_consumers.go`) MUST treat an auth with `IsOwned()` as an unknown key: the request MUST be unauthenticated (401), even when no path scope narrows the candidates. The `whoami` key lookup on a host that names no gateway and the api-key check of the connection endpoints (`validAPIKeyAuth`) MUST refuse an owned key as they refuse an unknown one. Application keys on MCP MUST behave as today.

#### Scenario: Personal key on MCP

- GIVEN `alice`'s valid personal key and an MCP consumer on the same gateway
- WHEN the key is presented on an MCP request to that gateway, with and without a consumer path
- THEN each answers 401

#### Scenario: Application key on MCP

- GIVEN an MCP consumer with an application key
- WHEN that key calls it
- THEN the request is authenticated as today
