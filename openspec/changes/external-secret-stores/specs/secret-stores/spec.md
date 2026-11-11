# Specification: secret-stores

## Purpose

The lifecycle of a secret store. A store is a named connection from one
gateway to an external secret manager.
- A **managed** store is configured entirely through the Admin API and works on
  any plane.
- A **local** store is declared by name through the API and configured on a
  hybrid, dedicated or self-hosted data plane. It may use that plane's ambient
  identity, environment or files.

## Requirements

### Requirement: Store scope and identity

A store MUST belong to exactly one gateway, and its name MUST be unique within
that gateway, compared case-insensitively.
- A managed store MUST declare at least one `allowed_paths` prefix. The value
  `*` means all paths and MUST be given explicitly.
- Store types are `hashicorp_vault`, `aws_secrets_manager`,
  `gcp_secret_manager`, `azure_key_vault`, `env` and `file`.
- `env` and `file` MUST be local.

#### Scenario: Duplicate name

- GIVEN gateway G has a store named `corp-vault`
- WHEN a store named `Corp-Vault` is created in G
- THEN the response is 409

#### Scenario: Managed store without allowed paths

- WHEN a managed store is created with no `allowed_paths`
- THEN the response is 400

### Requirement: Store credentials are sealed and masked

A managed store's credential fields MUST be sealed at rest with `FieldSealer`
under purpose `secret-stores/v1`. The fields are:
- Vault `token` and AppRole `secret_id`;
- AWS `secret_access_key`;
- GCP `service_account_json`;
- Azure `client_secret`.

These fields MUST be masked in every response. On update, an omitted value or
an echoed mask MUST keep the stored value. If the address, vault URL, region,
endpoint or auth method changes, the update MUST re-enter the credential;
otherwise it MUST be refused.

#### Scenario: Address change without re-entering the secret

- GIVEN managed Vault store S with address `https://vault-a.example.com` and AppRole credentials
- WHEN S is updated to address `https://attacker.example.net` and `secret_id` echoes the mask
- THEN the update is refused and the stored `secret_id` is unchanged

### Requirement: Local stores never run on shared planes

The admin API MUST accept `location: local` only for gateways whose data plane
is hybrid or dedicated. A data plane MUST honour local stores only when
`SECRET_STORES_ALLOW_LOCAL=true`. A data plane MUST NOT use ambient identity
(cloud metadata, workload identity, Kubernetes service account token), process
environment or files on behalf of a managed store.

#### Scenario: Local store on a hosted gateway

- GIVEN gateway G is hosted
- WHEN a local store is created in G
- THEN the response is 422 `secret_store_local_not_allowed`

#### Scenario: Shared plane ignores a local store

- GIVEN a hosted data plane without `SECRET_STORES_ALLOW_LOCAL`
- WHEN it receives a snapshot that declares a local store
- THEN no reference to that store resolves, and every such reference reports state `not_allowed`

### Requirement: Local store configuration

A data plane with local stores enabled MUST load them from `SECRET_STORES_FILE`
at boot and on file change. A store in that file whose name matches a managed
store of the same gateway MUST NOT resolve, and MUST report state
`name_conflict`. A `file` store MUST refuse any path that, once cleaned and
with symlinks evaluated, falls outside its `root`. An `env` store MUST refuse a
variable without its configured `prefix`.

#### Scenario: File store path traversal

- GIVEN local file store `k8s` with root `/var/run/tg-secrets`
- WHEN `secret://k8s/../../etc/passwd` is resolved
- THEN resolution fails with class `invalid_payload` and no file outside the root is read

### Requirement: Outbound hardening for managed stores

On a plane where `OUTBOUND_ALLOW_PRIVATE_NETWORKS` is not set:
- a managed Vault address MUST use HTTPS and MUST be dialed through `netguard`;
- a managed Azure `vault_url` MUST match a Key Vault DNS suffix;
- a managed AWS store MUST NOT set a custom endpoint.

#### Scenario: Vault address on a private network

- GIVEN a hosted plane
- WHEN a managed Vault store with address `https://10.0.0.5:8200` is resolved
- THEN the dial is blocked and the store reports `unavailable`

### Requirement: Delete protection and usages

`GET /secret-stores/:id/usages` MUST list every entity field in the gateway that
references the store. `DELETE` on a referenced store MUST be refused with 409
`secret_store_in_use` and the same list.

#### Scenario: Deleting a store in use

- GIVEN registry R references `secret://corp-vault/ai-gateway/openai#api_key`
- WHEN store `corp-vault` is deleted
- THEN the response is 409 `secret_store_in_use` and lists R with field `auth.api_key.api_key`

### Requirement: Testing a managed store never reveals the value

`POST /secret-stores/:id/test` MUST authenticate against the backend. When a
path is given, it MUST also fetch it. The response MUST carry only:
- the auth outcome;
- the read outcome and its error class;
- the version;
- the latency.

The response MUST NOT contain the secret value. For a local store the endpoint
MUST answer 409 `test_runs_on_data_plane`.

#### Scenario: Successful test

- GIVEN managed store S and a secret at `ai-gateway/openai` with field `api_key`
- WHEN S is tested with that path and field
- THEN the response has `auth: ok`, `read: ok` and the version, and no field holds the secret
