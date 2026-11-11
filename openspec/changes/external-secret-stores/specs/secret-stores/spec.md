# Specification: secret-stores

## Purpose

What a secret store is and where it is configured. A store is a named
connection from a hybrid data plane to the customer's secret manager. It is
configured on the data plane itself (Helm values rendered into
`SECRET_STORES_FILE`) and reported to the control plane. NeuralTrust never
receives a store's address, auth configuration or credentials.

## Requirements

### Requirement: Store file

A data plane with `SECRET_STORES_ENABLED=true` and `SECRET_STORES_FILE` set MUST
load its stores from that file at boot.
- Each store MUST have:
  - a unique name matching the store-name grammar;
  - a type, one of `hashicorp_vault`, `aws_secrets_manager`,
    `gcp_secret_manager`, `azure_key_vault`, `file` or `env`;
  - a non-empty `allowed_paths`, in which `*` means all paths and MUST be
    written explicitly.
- Decoding MUST be strict: an unknown key MUST fail the load.
- The file MUST NOT carry a credential inline. Vault `token`, `secret_id` and
  `jwt` MUST be given as `*_file` paths, and an inline value MUST fail the load.

#### Scenario: Inline secret is refused

- GIVEN a store file whose Vault store has `auth: { method: approle, role_id: r, secret_id: s3cr3t }`
- WHEN the data plane boots
- THEN loading fails with an error that names the store and the offending key, and the data plane does not start

#### Scenario: Missing allowed paths

- GIVEN a store without `allowed_paths`
- WHEN the file is loaded
- THEN loading fails

### Requirement: Store file reload

The data plane MUST watch the store file.
- On a valid change, it MUST swap the stores atomically and refresh the entries
  of the stores that changed.
- On an invalid change, it MUST keep the previous stores, log the error, and
  report state `config_error` for the affected stores.

#### Scenario: Broken edit keeps serving

- GIVEN a running data plane with store `corp-vault`
- WHEN the file is replaced with invalid YAML
- THEN references to `corp-vault` keep resolving, and the next heartbeat reports `config_error`

### Requirement: Local stores never run on NeuralTrust planes

Three guards MUST hold independently:
1. A data plane with `INSTANCE_DEPLOYMENT_TYPE=saas` MUST refuse to start when
   `SECRET_STORES_FILE` is set.
2. A data plane MUST use its stores only to resolve references of gateways
   whose entitlements say `data_plane=hybrid`. Any other reference MUST stay
   unresolved, with class `not_allowed`.
3. The admin API MUST refuse references on gateways that are not hybrid (see
   `secret-references`).

#### Scenario: SaaS plane with a store file

- GIVEN `INSTANCE_DEPLOYMENT_TYPE=saas` and `SECRET_STORES_FILE=/etc/trustgate/secret-stores.yaml`
- WHEN the data plane boots
- THEN it exits with a configuration error

#### Scenario: Non-hybrid gateway on a plane with stores

- GIVEN a data plane with store `env` and a snapshot gateway G stamped `data_plane=hosted` whose registry holds `secret://env/TG_SECRET_X`
- WHEN G's runtime data is built
- THEN the reference is unresolved with class `not_allowed` and no environment variable is read

### Requirement: Backend authentication

| Type | Methods the store MUST support |
|---|---|
| `hashicorp_vault` | `kubernetes` (the pod's ServiceAccount token), `jwt`, `approle` and `token` |
| `aws_secrets_manager` | the SDK default credential chain, with an optional assume-role |
| `gcp_secret_manager` | Application Default Credentials |
| `azure_key_vault` | workload identity or managed identity |

A Vault client token MUST be renewed before its lease expires. The data plane
MUST log in again when renewal fails or Vault answers 403.

#### Scenario: Vault Kubernetes auth

- GIVEN store `corp-vault` with `auth.method: kubernetes`, `role: trustgate`
- WHEN the first reference to it is resolved
- THEN the data plane logs in at `auth/kubernetes/login` with its projected ServiceAccount token, and reads the secret with the returned client token

### Requirement: File and env stores are confined

- A `file` store MUST refuse any path that, once cleaned and with symlinks
  evaluated, falls outside its `root`.
- An `env` store MUST refuse any variable that does not start with its
  `prefix`.
- `allowed_paths` MUST apply to both.

#### Scenario: Path traversal

- GIVEN file store `k8s` with root `/var/run/trustgate/secrets`
- WHEN `secret://k8s/../../etc/passwd` is resolved
- THEN resolution fails with class `invalid_payload` and no file outside the root is read

#### Scenario: Env prefix

- GIVEN env store `env` with prefix `TG_SECRET_`
- WHEN `secret://env/SERVER_SECRET_KEY` is resolved
- THEN resolution fails with class `path_not_allowed` and the variable is not read

### Requirement: Stores are reported in the heartbeat

Every heartbeat of a data plane with stores MUST carry, for each store:
- name;
- type;
- `allowed_paths`;
- state (`ok`, `auth_failed`, `unavailable`, `config_error` or `not_allowed`);
- the last error class;
- the time of the last check.

State MUST combine two inputs:
- a credential-level probe that needs no secret permission, run every
  `SECRET_STORES_PROBE_INTERVAL`: Vault token lookup-self, AWS
  `GetCallerIdentity`, token acquisition for GCP and Azure, or readability of
  the root or prefix;
- the outcome of the last real fetch.

The heartbeat MUST NOT carry addresses, credentials or secret values. The admin
MUST persist the latest report on the connection's `config_sync_connections`
row.

#### Scenario: Report contents

- GIVEN store `corp-vault` whose last login succeeded
- WHEN the data plane sends a heartbeat
- THEN it lists `corp-vault` with type, allowed paths and state `ok`, and nothing else about the store

### Requirement: Admin listing and usages

`GET /v1/gateways/:gateway_id/secret-stores` MUST return the union of stores
reported by the gateway's live connections. For each store it MUST return:
- the per-instance state;
- `consistent=false` when instances disagree on the type or the allowed paths;
- the usages count.

A store that is referenced but reported by no live connection MUST appear with
status `not_reported`.

`GET …/secret-stores/:name/usages` MUST list every entity field of the gateway
that references the store. Both routes MUST require `secret_stores:read`.

#### Scenario: Two instances, one degraded

- GIVEN gateway G with two live data-plane instances, where one reports `corp-vault` as `ok` and the other as `auth_failed`
- WHEN the stores of G are listed
- THEN `corp-vault` has status `degraded` and both instance states are shown

### Requirement: Diagnostics test on the data plane

The data plane MUST serve `POST /__diagnostics/gateways/:gateway_id/secret-stores/:name/test`.
- It MUST be authorized by the same diagnostics token as registry
  test-connection.
- It MUST enforce `allowed_paths`.
- It MUST answer with the auth outcome, the read outcome or error class, the
  version and the latency.
- The response MUST NOT contain the secret value.

#### Scenario: Successful test

- GIVEN store `corp-vault` and a secret at `ai-gateway/openai` with field `api_key`
- WHEN the console tests that path and field on the data plane
- THEN the response has `auth: ok`, `read: ok` and the version, and the secret string does not appear in the body
