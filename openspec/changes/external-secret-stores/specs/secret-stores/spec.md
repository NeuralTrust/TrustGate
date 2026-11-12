# Specification: secret-stores

## Purpose

What a secret store is, where it is configured, and how the control plane
learns which stores a gateway may use.

A store is a named connection from customer-operated TrustGate planes to the
customer's secret manager. It is configured in the customer's Helm values,
which are rendered into `SECRET_STORES_FILE`:
- in **hybrid**, the file goes on proxy and MCP;
- in **self-hosted (`external`)** and in the **central control plane**, it goes
  on admin, proxy and MCP.

No TrustGate database stores a store's address or credentials.

## Requirements

### Requirement: Store file

A plane with `SECRET_STORES_ENABLED=true` and `SECRET_STORES_FILE` set MUST load
its stores from that file at boot. Each store MUST have:
- a unique name;
- a type: `hashicorp_vault`, `aws_secrets_manager`, `gcp_secret_manager`,
  `azure_key_vault`, `file` or `env`;
- a non-empty `allowed_paths`, where `*` means all paths and MUST be written
  explicitly.

It MAY also have a `gateways` allowlist of gateway ids.

Decoding MUST be strict. Credentials MUST NOT appear inline: Vault `token`,
`secret_id` and `jwt` MUST be given as `*_file` paths. An unknown key or an
inline credential MUST fail the load.

#### Scenario: Inline secret is refused

- GIVEN a Vault store with `auth: { method: approle, role_id: r, secret_id: s3cr3t }`
- WHEN the plane boots
- THEN loading fails, the error names the store and the key, and the plane does not start

### Requirement: Store file reload

The plane MUST watch the file.
- **Valid change:** swap the stores atomically and refresh the affected
  entries.
- **Invalid change:** keep the previous stores and report `config_error`.

#### Scenario: Broken edit keeps serving

- GIVEN a running plane with store `corp-vault`
- WHEN the file is replaced with invalid YAML
- THEN references to `corp-vault` keep resolving, and the store's state becomes `config_error`

### Requirement: Stores never run on NeuralTrust planes

Three guards MUST hold independently:
1. A plane with `INSTANCE_DEPLOYMENT_TYPE=saas` MUST refuse to start when
   `SECRET_STORES_FILE` is set.
2. Before resolving, every plane MUST check that the gateway is eligible under
   its own `SECRET_STORES_GATEWAYS`, and that the store's `gateways` allowlist
   admits the gateway. Otherwise the reference MUST stay unresolved, with class
   `not_allowed`.
3. The admin API MUST refuse references on ineligible gateways (see
   `secret-references`).

#### Scenario: SaaS plane with a store file

- GIVEN `INSTANCE_DEPLOYMENT_TYPE=saas` and `SECRET_STORES_FILE` set
- WHEN the plane boots
- THEN it exits with a configuration error

#### Scenario: Ineligible gateway on a plane with stores

- GIVEN a plane with `SECRET_STORES_GATEWAYS=hybrid`, store `env`, and a hosted gateway G whose registry holds `secret://env/TG_SECRET_X`
- WHEN G's runtime data is built
- THEN the reference is unresolved with class `not_allowed`, and no environment variable is read

### Requirement: Gateways allowlist

When a store declares `gateways`, it MUST be used only by those gateways. The
admin MUST enforce this in validation and listing, and every plane MUST
enforce it in resolution. An empty or absent list means every eligible gateway
served by that plane.

#### Scenario: Shared cluster, two teams

- GIVEN a self-hosted install with store `team-a-vault` (`gateways: [A]`) and gateways A and B on the same proxy
- WHEN gateway B holds `secret://team-a-vault/llm/openai#key`, written before the allowlist existed
- THEN the proxy leaves it unresolved with class `not_allowed`, and B's requests to that registry fail with `secret_unavailable`

### Requirement: Backend authentication

| Type | Methods the store MUST support |
|---|---|
| `hashicorp_vault` | `kubernetes` (the pod's ServiceAccount token), `jwt`, `approle`, `token` |
| `aws_secrets_manager` | the SDK default chain, with optional assume-role |
| `gcp_secret_manager` | ADC |
| `azure_key_vault` | workload or managed identity |

A Vault client token MUST be renewed before its lease ends. The plane MUST log
in again when renewal fails or Vault answers 403.

#### Scenario: Vault Kubernetes auth

- GIVEN store `corp-vault` with `auth.method: kubernetes`, `role: trustgate`
- WHEN the first reference to it is resolved
- THEN the plane logs in at `auth/kubernetes/login` with its projected ServiceAccount token, and reads the secret with the returned client token

### Requirement: File and env stores are confined

- A `file` store MUST refuse any path that, after cleaning and evaluating
  symlinks, falls outside its `root`.
- An `env` store MUST refuse any variable that lacks its `prefix`.

#### Scenario: Path traversal

- GIVEN file store `k8s` with root `/var/run/trustgate/secrets`
- WHEN `secret://k8s/../../etc/passwd` is resolved
- THEN resolution fails with class `invalid_payload`, and nothing outside the root is read

#### Scenario: Env prefix

- GIVEN env store `env` with prefix `TG_SECRET_`
- WHEN `secret://env/SERVER_SECRET_KEY` is resolved
- THEN resolution fails with class `path_not_allowed`, and the variable is not read

### Requirement: Store source per gateway

The admin MUST derive each gateway's store source as follows:
- **Gateway served by its own data plane** (`ServedByOwnDataPlane()`): the
  union of the stores reported by its live config-sync connections. The source
  is `data_plane`.
- **Any other gateway:** the admin's own catalog, loaded from its own
  `SECRET_STORES_FILE`. The source is `control_plane`.

Stores whose `gateways` allowlist excludes the gateway MUST be filtered out.
`supported` MUST be true only when all of these hold:
- `SECRET_STORES_ENABLED` is true;
- the gateway is eligible;
- the gateway is served by its own data plane, or the admin has a catalog.

#### Scenario: NeuralTrust SaaS

- GIVEN NeuralTrust's admin (no store file, `SECRET_STORES_GATEWAYS=hybrid`)
- WHEN the stores of a hosted gateway and of a hybrid gateway are listed
- THEN the hosted gateway gets `supported: false`, and the hybrid gateway gets `supported: true, source: data_plane`

#### Scenario: Self-hosted

- GIVEN an `external` admin with a store file and `SECRET_STORES_GATEWAYS=all`
- WHEN the stores of any gateway are listed
- THEN the response has `supported: true, source: control_plane` and lists the admin catalog's stores that the gateway may use

#### Scenario: Central control plane

- GIVEN a customer central admin with a store file, a central-cluster gateway C, and a remote-cluster gateway R
- WHEN both are listed
- THEN C has source `control_plane`, and R has source `data_plane` with the stores R's remote cluster reports

### Requirement: Stores are reported in the heartbeat

Every heartbeat from a plane that has stores MUST carry, for each store:
- name;
- type;
- `allowed_paths`;
- `gateways`;
- state (`ok`, `auth_failed`, `unavailable`, `config_error` or `not_allowed`);
- the last error class;
- the time of the last check.

The state MUST combine a credential-level probe that needs no secret
permission with the outcome of the last fetch. The heartbeat MUST NOT carry
addresses, credentials or values. The admin MUST persist the latest report on
the connection's `config_sync_connections` row.

#### Scenario: Report contents

- GIVEN store `corp-vault` whose last login succeeded
- WHEN the plane sends a heartbeat
- THEN it lists `corp-vault` with its type, allowed paths, gateways and state `ok`, and nothing else about the store

### Requirement: Admin listing, usages and test

- `GET /v1/gateways/:gateway_id/secret-stores` MUST return `supported`,
  `source` and the stores of the gateway's store source. Each store MUST have:
  - a per-instance state;
  - `consistent=false` when instances disagree on the type, the paths or the
    allowlist;
  - a usages count.

  A store that is referenced but missing from the source MUST appear with
  status `not_reported`.
- `GET …/:name/usages` MUST list every entity field of the gateway that
  references the store.
- `POST …/:name/test` MUST run against the admin's catalog only when the source
  is `control_plane`. Otherwise it MUST answer 409 `test_runs_on_data_plane`.

All three routes MUST require `secret_stores:read`. Test responses MUST carry
only the auth outcome, the read outcome or error class, the version and the
latency. They MUST NOT carry the secret value.

A connection that does not advertise `accepts_secret_refs` MUST be listed with
state `too_old`.

#### Scenario: Two instances, one degraded

- GIVEN hybrid gateway G with two live instances, one reporting `corp-vault` as `ok` and the other as `auth_failed`
- WHEN G's stores are listed
- THEN `corp-vault` has status `degraded`, and both instance states are shown

#### Scenario: Self-hosted test

- GIVEN source `control_plane` and store `corp-vault`
- WHEN `ai-gateway/openai#api_key` is tested on the admin
- THEN the response has `auth: ok, read: ok` and the version, and the secret string is absent from the body

### Requirement: Snapshots with references are served only to planes that understand them

Planes that implement this change MUST advertise `accepts_secret_refs` in
`Hello` and in every `GetSnapshotRequest` and `GetManifestRequest`, whatever
their `SECRET_STORES_ENABLED` setting. The compiler MUST record, for each scope
and version, whether the snapshot holds any reference-shaped value at a
declared location.

For a snapshot version that holds references, the config-sync server MUST:
- not send a `VersionNotice` to a connection without the capability;
- answer `GetSnapshot` or `GetManifest` without the capability with
  `FailedPrecondition` and detail `secret_refs_unsupported`;
- mark that instance `too_old`, log `secret_refs_on_old_data_plane` and
  increment a metric.

Snapshots without references MUST be served exactly as today.

#### Scenario: Old instance joins a gateway that uses references

- GIVEN hybrid gateway G whose registry R holds a reference, served by two capable instances
- WHEN a third instance that predates this change connects and requests the snapshot
- THEN it gets `FailedPrecondition`, keeps serving its previous configuration (or its LKG), never sends `secret://…` upstream, and the listing shows it as `too_old`

#### Scenario: Fresh old pod without LKG

- GIVEN the same gateway G
- WHEN a pod that predates this change and has no LKG starts
- THEN it never applies a configuration, stays not-ready, and receives no traffic

#### Scenario: Gateways without references are unaffected

- GIVEN hybrid gateway H whose entities hold no reference
- WHEN an instance that predates this change requests H's snapshot
- THEN it is served exactly as today

#### Scenario: References removed

- GIVEN the frozen instance from the first scenario
- WHEN every reference of G is replaced with a literal and the snapshot recompiles
- THEN the next request from that instance is served, and it leaves `too_old`

### Requirement: Diagnostics test on the data plane

The data plane MUST serve
`POST /__diagnostics/gateways/:gateway_id/secret-stores/:name/test`. The route:
- MUST be authorized by the same diagnostics token as registry test-connection;
- MUST enforce `allowed_paths` and the `gateways` allowlist;
- MUST answer with the same contract as the admin test.

#### Scenario: Hybrid test

- GIVEN hybrid gateway G and its data plane's store `aws`
- WHEN the console tests `prod/llm/openai#key` through the data-plane route
- THEN the response reports the outcome and the version, and never the value
