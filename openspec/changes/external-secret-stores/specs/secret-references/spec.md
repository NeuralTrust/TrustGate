# Specification: secret-references

## Purpose

How a credential field holds a pointer to a secret instead of the secret. This
spec covers:
- the grammar;
- where a reference is accepted;
- what the admin API validates when one is written;
- how references appear in responses.

In Phases 1–2 references are supported only on hybrid gateways.

## Requirements

### Requirement: Reference grammar

A reference MUST have the form
`secret://<store>/<path>[?version=<version>][#<field>]`.
- `store` is a slug of 1–63 characters, `[a-z0-9][a-z0-9_-]*`, compared
  case-insensitively.
- `path` is one or more percent-encoded segments. `.` and `..` segments are not
  allowed.
- The whole reference is at most 1 KiB.
- A value without the `secret://` scheme MUST be treated as a literal.
- A value with the scheme that does not match the grammar MUST be refused with
  400 `invalid_secret_reference`, and MUST NOT be stored as a literal.

#### Scenario: Valid reference with field and version

- GIVEN the value `secret://aws/prod/llm/anthropic?version=AWSPREVIOUS#key`
- WHEN it is parsed
- THEN store is `aws`, path is `prod/llm/anthropic`, version is `AWSPREVIOUS` and field is `key`

#### Scenario: Malformed reference is refused, not stored

- GIVEN a registry update whose `api_key` is `secret://corp-vault`, which has no path
- WHEN the update is submitted
- THEN the response is 400 `invalid_secret_reference` and the stored registry is unchanged

### Requirement: References are recognised only at declared locations

A reference MUST be resolved only at a location listed in
`secretref.Locations`.
- **Phase 1:**
  - registry auth secret fields;
  - `provider_options.headers.*`;
  - MCP target `auth.value`, `auth.client_secret` and `headers.*`.
- **Phase 2:**
  - health-check headers;
  - inbound IdP client secrets;
  - plugin `CredentialPaths()`;
  - consumer embedding auth;
  - telemetry exporter headers and DSN.

Anywhere else, the same string MUST be treated as plain text and never
resolved.

#### Scenario: Reference in a non-secret field stays literal

- GIVEN a policy whose prompt template contains `secret://corp-vault/ai/openai#api_key`
- WHEN a request runs through the policy
- THEN the template text is used verbatim and no secret store is contacted

### Requirement: References only on hybrid gateways

In Phases 1–2 the admin API MUST refuse a reference on a gateway whose
`Entitlements.DataPlane` is not `hybrid`, with 422
`secret_references_not_supported`.

#### Scenario: Hosted gateway

- GIVEN gateway G is hosted
- WHEN a registry in G is written with `api_key: secret://corp-vault/ai/openai#api_key`
- THEN the response is 422 `secret_references_not_supported`

#### Scenario: Dedicated gateway

- GIVEN gateway G is dedicated, served by a data plane NeuralTrust runs
- WHEN a reference is written on any of G's entities
- THEN the response is 422 `secret_references_not_supported`

### Requirement: Validation against the stores the data plane reports

When a reference is written at a declared location of a hybrid gateway G, the
admin API MUST check, in order:
1. `SECRET_STORES_ENABLED` is true. Otherwise: 422 `secret_references_disabled`.
2. The caller holds `secret_stores:read` on G. Otherwise: 403.
3. If at least one data plane of G is live (a heartbeat within 3× the
   heartbeat interval):
   - some live connection reports the store. Otherwise: 422
     `unknown_secret_store`.
   - the path lies within that store's reported `allowed_paths`. Otherwise:
     422 `secret_path_not_allowed`.
   - every live connection reports at least the minimum version. Otherwise:
     422 `data_plane_too_old`.
4. If no data plane of G is live, the reference MUST be accepted.

#### Scenario: Unknown store while the data plane is connected

- GIVEN hybrid gateway G whose live data plane reports only store `corp-vault`
- WHEN a registry in G is written with `secret://corp-valt/ai-gateway/openai#api_key`
- THEN the response is 422 `unknown_secret_store`

#### Scenario: Path outside the reported prefixes

- GIVEN G's data plane reports `corp-vault` with `allowed_paths: ["ai-gateway/"]`
- WHEN a registry is written with `secret://corp-vault/payments/db#password`
- THEN the response is 422 `secret_path_not_allowed`

#### Scenario: Config-as-code before the data plane exists

- GIVEN hybrid gateway G with no live data plane
- WHEN a registry is written with `secret://corp-vault/ai-gateway/openai#api_key`
- THEN the write succeeds, and the store is listed for G with status `not_reported`

#### Scenario: Caller without store scope

- GIVEN a service credential with `registries:write` and without `secret_stores:read`
- WHEN it writes a registry whose `api_key` is a reference
- THEN the response is 403 and names the missing scope

### Requirement: References are returned verbatim

A reference is not a secret.
- Every admin response MUST return a stored reference unchanged, without
  masking.
- `secret.Mask`, `MaskSettings` and `ResolveSettings` MUST leave references
  untouched.
- When an update echoes back a reference that is already stored, the stored
  reference MUST be kept.

#### Scenario: Read-modify-write keeps the reference

- GIVEN a registry whose `api_key` is `secret://corp-vault/ai-gateway/openai#api_key`
- WHEN a client GETs the registry and PUTs the body back unchanged
- THEN the GET shows the reference in clear and the stored value is still that reference

### Requirement: Retargeting a referenced credential needs store scope

When an entity declares credential destinations (`CredentialDestinations`) and
its credential is a reference, a change to any of those destinations MUST
require `secret_stores:read`.

#### Scenario: Retargeting a referenced credential

- GIVEN an Azure Content Safety policy whose `api_key` is a reference
- WHEN a caller with only `policies:write` changes `endpoint`
- THEN the update is refused with 403

### Requirement: Reference changes are audited

Every write that adds, changes or removes a reference MUST emit a structured
`secret_reference_set` event. The event carries:
- the gateway;
- the entity kind and id;
- the field;
- the store and the path;
- the actor.

#### Scenario: Audit event

- WHEN an admin sets a registry's `api_key` to a reference
- THEN a `secret_reference_set` event is logged with the store and path, and with no secret value
