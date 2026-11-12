# Specification: secret-references

## Purpose

How a credential field holds a pointer to a secret instead of the secret
itself. This covers:
- the grammar;
- where a reference is accepted;
- which gateways may hold one;
- what the admin API validates when a reference is written;
- how references appear in responses.

## Requirements

### Requirement: Reference grammar

A reference MUST have the form
`secret://<store>/<path>[?version=<version>][#<field>]`:
- `store` is a slug of 1–63 characters matching `[a-z0-9][a-z0-9_-]*`,
  compared case-insensitively;
- `path` is one or more percent-encoded segments, with no `.` or `..`
  segments;
- the whole reference is at most 1 KiB.

A value without the `secret://` scheme MUST be treated as a literal. A value
with the scheme that does not match the grammar MUST be refused with 400
`invalid_secret_reference`, and MUST NOT be stored as a literal.

#### Scenario: Valid reference with field and version

- GIVEN the value `secret://aws/prod/llm/anthropic?version=AWSPREVIOUS#key`
- WHEN it is parsed
- THEN the store is `aws`, the path `prod/llm/anthropic`, the version `AWSPREVIOUS` and the field `key`

#### Scenario: Malformed reference is refused, not stored

- GIVEN a registry update whose `api_key` is `secret://corp-vault` (no path)
- WHEN it is submitted
- THEN the response is 400 `invalid_secret_reference` and the stored registry is unchanged

### Requirement: References are recognised only at declared locations

A reference MUST be resolved only at a location listed in
`secretref.Locations`:
- **Phase 1:** registry auth secret fields, `provider_options.headers.*`, and
  MCP target `auth.value`, `auth.client_secret` and `headers.*`.
- **Phase 2:** health-check headers, inbound IdP client secrets, plugin
  `CredentialPaths()`, consumer embedding auth, and telemetry exporter headers
  and DSN.

Anywhere else, the string MUST be treated as plain text.

#### Scenario: Reference in a non-secret field stays literal

- GIVEN a policy whose prompt template contains `secret://corp-vault/ai/openai#api_key`
- WHEN a request runs through the policy
- THEN the text is used verbatim and no store is contacted

### Requirement: Gateway eligibility

Every plane MUST read `SECRET_STORES_GATEWAYS` (`hybrid` or `all`, default
`hybrid`):
- under `hybrid`, only gateways whose `Entitlements.DataPlane` is `hybrid` are
  eligible;
- under `all`, every gateway is eligible.

The admin API MUST refuse a reference on an ineligible gateway with 422
`secret_references_not_supported`.

#### Scenario: NeuralTrust SaaS hosted gateway

- GIVEN an admin with the default `SECRET_STORES_GATEWAYS=hybrid` and a hosted gateway G
- WHEN a registry in G is written with a reference
- THEN the response is 422 `secret_references_not_supported`

#### Scenario: Dedicated gateway on NeuralTrust SaaS

- GIVEN the same admin and a dedicated gateway G
- WHEN a reference is written on any of G's entities
- THEN the response is 422 `secret_references_not_supported`

#### Scenario: Self-hosted gateway

- GIVEN a self-hosted admin with `SECRET_STORES_GATEWAYS=all` and a gateway G that is not hybrid
- WHEN a registry in G is written with a reference to a store in the admin's catalog
- THEN the write succeeds

### Requirement: Validation against the gateway's store source

When a reference is written at a declared location of an eligible gateway G,
the admin API MUST check the following, in order:

1. `SECRET_STORES_ENABLED` is true. Otherwise: 422 `secret_references_disabled`.
2. The caller holds `secret_stores:read` on G. Otherwise: 403.
3. The reference matches G's store source.
   - **Source `control_plane`** (G is not served by its own data plane):
     - the admin's own catalog has the store. Otherwise: 422 `unknown_secret_store`.
     - the store's `gateways` allowlist admits G. Otherwise: 422 `unknown_secret_store`.
     - the path is within the store's `allowed_paths`. Otherwise: 422 `secret_path_not_allowed`.
   - **Source `data_plane`** (G is served by its own data plane), with at least
     one live connection:
     - some live connection reports the store and its allowlist admits G.
       Otherwise: 422 `unknown_secret_store`.
     - the path is within the store's reported `allowed_paths`. Otherwise: 422
       `secret_path_not_allowed`.
     - every live connection reports at least the minimum version. Otherwise:
       422 `data_plane_too_old`.
   - **Source `data_plane`** with no live connection: the admin MUST refuse
     the reference with 422 `secret_store_unverified`, unless the request
     carries `?allow_unverified_secret_refs=true`. In that case it MUST accept
     the reference and log the opt-in.

#### Scenario: Unknown store while the data plane is connected

- GIVEN hybrid gateway G whose live data plane reports only `corp-vault`
- WHEN a registry in G is written with `secret://corp-valt/ai-gateway/openai#api_key`
- THEN the response is 422 `unknown_secret_store`

#### Scenario: Store restricted to another team's gateway

- GIVEN a self-hosted admin whose catalog has store `team-a-vault` with `gateways: [A]`
- WHEN a registry in gateway B is written with `secret://team-a-vault/llm/openai#key`
- THEN the response is 422 `unknown_secret_store`

#### Scenario: Path outside the allowed prefixes

- GIVEN store `corp-vault` with `allowed_paths: ["ai-gateway/"]` in G's store source
- WHEN a registry is written with `secret://corp-vault/payments/db#password`
- THEN the response is 422 `secret_path_not_allowed`

#### Scenario: No data plane connected

- GIVEN hybrid gateway G with no live data plane
- WHEN a registry is written with `secret://corp-vault/ai-gateway/openai#api_key`
- THEN the response is 422 `secret_store_unverified` and nothing is stored

#### Scenario: Config-as-code before the data plane exists (explicit opt-in)

- GIVEN hybrid gateway G with no live data plane
- WHEN the same write is sent with `?allow_unverified_secret_refs=true`
- THEN the write succeeds, the opt-in is logged, and the store is listed with status `not_reported`

#### Scenario: Caller without store scope

- GIVEN a service credential with `registries:write` and without `secret_stores:read`
- WHEN it writes a registry whose `api_key` is a reference
- THEN the response is 403 and names the missing scope

### Requirement: No behaviour change with the feature off

While `SECRET_STORES_ENABLED` is false:
- admin responses, masking and write paths MUST behave exactly as they do
  today for every value that does not start with `secret://`;
- the admin MUST refuse new values that start with `secret://` at declared
  locations, with 422 `secret_references_disabled`. Nothing else changes.

#### Scenario: Existing literal credential

- GIVEN the flag is off and a registry whose `api_key` is `sk-live-123`
- WHEN the registry is read and updated
- THEN the response masks the key as today, and the update behaves as today

### Requirement: References are returned verbatim

While the feature is enabled, a stored reference MUST be returned unchanged by
every admin response.
`secret.Mask`, `MaskSettings` and `ResolveSettings` MUST leave it untouched. An
update that echoes back the stored reference MUST keep it.

#### Scenario: Read-modify-write keeps the reference

- GIVEN a registry whose `api_key` is `secret://corp-vault/ai-gateway/openai#api_key`
- WHEN a client GETs it and PUTs the same body back
- THEN the GET shows the reference in clear, and the reference is still stored

### Requirement: Retargeting a referenced credential needs store scope

When an entity declares `CredentialDestinations` and its credential is a
reference, a change to any destination MUST require `secret_stores:read`.

#### Scenario: Retargeting a referenced credential

- GIVEN an Azure Content Safety policy whose `api_key` is a reference
- WHEN a caller with only `policies:write` changes `endpoint`
- THEN the update is refused with 403

### Requirement: Reference changes are audited

Every write that adds, changes or removes a reference MUST emit a
`secret_reference_set` event. The event MUST carry the gateway, the entity
kind and id, the field, the store, the path and the actor.

#### Scenario: Audit event

- WHEN an admin sets a registry's `api_key` to a reference
- THEN a `secret_reference_set` event carries the store and the path, and no secret value
