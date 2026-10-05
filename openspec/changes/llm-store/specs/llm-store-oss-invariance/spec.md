# Delta for llm-store-oss-invariance

Change `llm-store` (RUN-1763), all slices (decision B8). New capability. OSS runs the same binary without the app: nobody creates personal consumers and nobody mints personal keys, so nothing personal exists. This capability gathers what MUST stay exactly as today in that setting, so each slice can be checked against one list. There is no feature flag. The only intended OSS-visible change is the expiry check of `proxy-api-key-expiry`.

## ADDED Requirements

### Requirement: `/store/v1` is inert without personal consumers

On a gateway without personal consumers, `/store/v1/*` MUST answer exactly what today's unknown slug answers (404), with no key lookup (`llm-store-gateway`). A configuration, flag or migration MUST NOT create a personal consumer by itself.

#### Scenario: Fresh OSS gateway

- GIVEN a gateway created through the OSS admin API after the change, with application consumers and keys
- WHEN `/store/v1/chat/completions` is called with any of its keys
- THEN 404, byte-identical to the response for `/zzzzzzzz/v1/chat/completions`

#### Scenario: Migrations create nothing personal

- GIVEN an existing database
- WHEN the change's migrations run
- THEN no consumer has `audience = 'personal'`, no auth has `owner_id` set, and every `consumer_auth` row has `level`, `priority` and `granted_at` `NULL`

### Requirement: Snapshot bytes of existing entities are identical

`audience`, `owner_id` and `auth_links` MUST be omitted from the wire form at their defaults, so a snapshot compiled from data without personal consumers and owned keys MUST encode byte-identically to the same data before the change, and its version hash MUST NOT change. `snapshot.proto` MUST NOT change. No store table and no gateway metadata key MUST change.

#### Scenario: Golden snapshot

- GIVEN a fixture with gateways, LLM, MCP and A2A consumers, application keys, registries, policies, MCP grants and MCP access policies
- WHEN it is compiled and encoded after the change and after the migrations
- THEN the bytes and the version equal the golden ones taken before the change

### Requirement: Admin contracts are unchanged for application data

For application keys, the request and response bodies and status codes of `/v1/gateways/{gw}/auths` (list, create, get, update, rotate, delete), consumer `auth_ids`, and attach (with no body) and detach of auths MUST stay as today, and application links MUST keep the new `consumer_auth` columns `NULL`. The only addition to the consumer response MUST be the `audience` field (`personal-llm-consumers`). The MCP Store endpoints MUST NOT change.

#### Scenario: Existing handler tests

- GIVEN the existing handler tests for auths, consumer associations and the MCP Store
- WHEN they run after the change
- THEN they pass without edits to their expected bodies, and consumer response tests differ only by `audience: application`

### Requirement: Budgets and MCP behave as today without the new options

A `token_rate_limiter` config without `partition` MUST keep its keys, windows, fail-open and unpriced handling. The MCP Store, MCP consumers and MCP-wide placements MUST behave as today.

#### Scenario: Existing plugin and MCP tests

- GIVEN the existing `tokenratelimit`, `storeaccess`, store and MCP tests
- WHEN they run after the change
- THEN they pass unchanged

### Requirement: The bundled frontend does not change

Files under `frontend/` MUST NOT change. The bundled console MUST keep working against the admin API.

#### Scenario: Frontend diff

- GIVEN the change's diff against `origin/develop`
- WHEN it is filtered to `frontend/`
- THEN it is empty

### Requirement: The suites stay green

`go test -race ./...` and `go vet -tags functional ./...` MUST pass on every PR of the change.

#### Scenario: CI

- GIVEN each PR of the change
- WHEN CI runs
- THEN both commands succeed
