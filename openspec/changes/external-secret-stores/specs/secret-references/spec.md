# Specification: secret-references

## Purpose

How a credential field holds a pointer to a secret in a secret store instead
of the secret itself. This covers the grammar, where a reference is accepted,
what the admin API validates, and how references appear in responses.

## Requirements

### Requirement: Reference grammar

A reference MUST have the form
`secret://<store>/<path>[?version=<version>][#<field>]`.
- `store` is a slug of 1–63 characters, `[a-z0-9][a-z0-9_-]*`, compared case-insensitively.
- `path` is one or more percent-encoded segments. `.` and `..` segments are not allowed.
- The whole reference is at most 1 KiB.
- A value without the `secret://` scheme MUST be treated as a literal.
- A value with the scheme that does not match the grammar MUST be refused with
  400 `invalid_secret_reference`, and MUST NOT be stored as a literal.

#### Scenario: Valid reference with field and version

- GIVEN the value `secret://aws-prod/prod/llm/anthropic?version=AWSPREVIOUS#key`
- WHEN it is parsed
- THEN store is `aws-prod`, path is `prod/llm/anthropic`, version is `AWSPREVIOUS` and field is `key`

#### Scenario: Malformed reference is refused, not stored

- GIVEN a registry update whose `api_key` is `secret://corp-vault`, which has no path
- WHEN the update is submitted
- THEN the response is 400 `invalid_secret_reference` and the stored registry is unchanged

### Requirement: References are recognised only at declared locations

A reference MUST be resolved only at a location listed in `secretref.Locations`:
- registry auth secret fields;
- `provider_options.headers.*`;
- MCP target `auth.value`, `auth.client_secret` and `headers.*`;
- from Phase 3: health-check headers, inbound IdP client secrets, plugin
  `CredentialPaths()`, consumer embedding auth, and telemetry exporter headers
  and DSN.

Anywhere else, the same string MUST be treated as plain text and never resolved.

#### Scenario: Reference in a non-secret field stays literal

- GIVEN a policy whose prompt template contains `secret://corp-vault/ai/openai#api_key`
- WHEN a request runs through the policy
- THEN the template text is used verbatim and no secret store is contacted

### Requirement: Admin validation of a reference

When a reference is written at a declared location, the admin API MUST check
all of the following, in this order:
1. `SECRET_STORES_ENABLED` is true. Otherwise: 422 `secret_references_disabled`.
2. The caller holds `secret_stores:read` on the gateway. Otherwise: 403.
3. A store with that name exists in the same gateway. Otherwise: 422 `unknown_secret_store`.
4. For a managed store, the path is within the store's `allowed_paths`. Otherwise: 422 `secret_path_not_allowed`.
5. For a hybrid or dedicated gateway, every connected data plane reports a
   version that resolves references. Otherwise: 422 `data_plane_too_old`.

#### Scenario: Store of another gateway

- GIVEN store `corp-vault` exists only in gateway G2
- WHEN a registry in gateway G1 is written with `secret://corp-vault/x#k`
- THEN the response is 422 `unknown_secret_store`

#### Scenario: Path outside the allowed prefixes

- GIVEN managed store `corp-vault` with `allowed_paths: ["ai-gateway/"]`
- WHEN a registry is written with `secret://corp-vault/payments/db#password`
- THEN the response is 422 `secret_path_not_allowed`

#### Scenario: Caller without store scope

- GIVEN a service credential with `registries:write` and without `secret_stores:read`
- WHEN it writes a registry whose `api_key` is a reference
- THEN the response is 403 and names the missing scope

### Requirement: References are returned verbatim

A reference is not a secret. Every admin response MUST return a stored
reference unchanged, without masking. `secret.Mask`, `MaskSettings` and
`ResolveSettings` MUST leave references untouched. When an update echoes back a
reference that is already stored, it MUST keep the reference.

#### Scenario: Read-modify-write keeps the reference

- GIVEN a registry whose `api_key` is `secret://corp-vault/ai-gateway/openai#api_key`
- WHEN a client GETs the registry and PUTs the body back unchanged
- THEN the GET shows the reference in clear and the stored value is still that reference

### Requirement: Destination changes need store scope

When an entity declares credential destinations (`CredentialDestinations`) and
its credential is a reference, a change to any of those destinations MUST
require `secret_stores:read`. This keeps parity with the current rule that a
credential the caller has not seen cannot be aimed at a new destination.

#### Scenario: Retargeting a referenced credential

- GIVEN an Azure Content Safety policy whose `api_key` is a reference
- WHEN a caller with only `policies:write` changes `endpoint`
- THEN the update is refused with 403
