# Delta for llm-store-oss-invariance

Change `llm-store` (RUN-1763), all slices (decision B8). New capability. OSS runs the same binary without the app: nobody creates personal consumers and nobody mints personal keys, so nothing personal exists. This capability gathers what MUST stay exactly as today in that setting, so each slice can be checked against one list. There is no feature flag. The intended OSS-visible changes are exactly the ones listed under "Intended OSS-visible changes" below, which match the release notes in `docs/llm-store.md`; everything else MUST stay as today.

## ADDED Requirements

### Requirement: Intended OSS-visible changes

A deployment that never creates a personal consumer or a personal key MUST see only these changes, and the release notes MUST list each of them:

| # | Change | Capability |
|---|---|---|
| a | An application key past its `expires_at` gets 401 on `/<slug>/v1/*`; an expired key attached to another consumer gets 401 instead of 403 | `proxy-api-key-expiry` |
| b | `InvalidateGatewayDataEvent` clears the whole `auth_key` cache and the unknown-key cache (30 s) on every full-plane replica, so a rotation or a revocation propagates at once | `llm-store-gateway` |
| c | Usage events carry `auth_id` and OTLP records `trustgate.auth.id` on LLM proxy requests authenticated by an API key | `usage-auth-id-telemetry` |
| d | The admin consumer response always carries `audience` | `personal-llm-consumers` |
| e | `whoami` on the fixed host resolves a gateway only from an enabled, unexpired application key; a disabled, expired or personal key answers like an unknown key | `personal-key-isolation` |
| f | `POST /consumers/:id/auths/:auth_id` parses a non-empty body as link attributes (malformed JSON → 422); no body behaves as today | `owned-key-attachment` |
| g | Deleting a registry that holds a personal consumer's last primary default answers 422 | `personal-llm-consumers` |
| h | The MCP connect ticket re-check refuses an expired or personal key | `personal-key-isolation` |
| i | `token_rate_limiter` gains `partition: key`, calendar windows and hard limits, all opt-in | `token-budget-key-partition` |

#### Scenario: Release notes match

- GIVEN `docs/llm-store.md`
- WHEN its release notes are compared with the table above
- THEN they list the same changes, and no other OSS-visible change ships

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
