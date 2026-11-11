# Proposal: External secret stores for hybrid gateways (vault references)

## Intent

Customers who run a **hybrid** gateway want the gateway to read credentials
from their own secret manager instead of pasting them into TrustGate. Those
credentials are LLM provider keys, MCP server tokens and guardrail API keys.
Supported managers would be HashiCorp Vault, AWS Secrets Manager, GCP Secret
Manager, Azure Key Vault and Kubernetes Secrets. LiteLLM, Kong and Portkey all
offer this (`exploration.md` §2–3).

Today every credential an admin configures is stored in NeuralTrust's database
and compiled in plaintext into the config snapshot. For a hybrid gateway, that
snapshot is then shipped to the customer's own data plane. So a credential that
never needed to leave the customer's network makes a round trip through
NeuralTrust's SaaS (`exploration.md` §1.2).

A hybrid data plane already runs inside the customer's infrastructure. It can
reach their vault, including a private one, and it can authenticate with its
own pod identity (IRSA, GKE/AKS Workload Identity, Vault Kubernetes auth).
This change lets a credential field hold a **reference**, such as
`secret://corp-vault/ai-gateway/openai#api_key`. The hybrid data plane resolves
it locally.

**Neither the secret nor the vault's credentials ever reach NeuralTrust.** The
vault is configured in the customer's Helm values, and the console only lists
what the data plane reports.

Hosted (SaaS) and dedicated gateways run on NeuralTrust's infrastructure. For
them the same feature still requires NeuralTrust to hold something that can
read the customer's vault, unless we build keyless federation first. They are
a later phase with their own design review.

Linear: _pending_. Research: `exploration.md`.

## Goals

- **G1. References instead of values.** Any declared credential field of a
  hybrid gateway can hold a reference instead of a value. One grammar covers
  typed fields (registry auth, MCP auth) and plugin settings
  (`CredentialPaths()`).
- **G2. Backends.** HashiCorp Vault and OpenBao (KV v1/v2), AWS Secrets
  Manager, GCP Secret Manager and Azure Key Vault. Kubernetes Secrets are read
  as mounted files (`file` store), which also covers the CSI driver and
  External Secrets Operator. Environment variables are an `env` store.
- **G3. Nothing sensitive reaches NeuralTrust.**
  - The secret value never reaches the control plane, its database, the
    snapshot, the LKG file, logs or API responses.
  - Neither does the vault's address-level configuration or its credentials.
  - The control plane only sees reference strings and store metadata reported
    by the data plane: name, type, allowed paths and health.
- **G4. Keyless by default.** The recommended auth for every backend is the
  data plane's own workload identity. Where a static credential is unavoidable
  (Vault AppRole or token), it is read from a mounted Kubernetes Secret and
  never written inline.
- **G5. Rotation without a TrustGate write.**
  - Background refresh-ahead within the store TTL (default 5 min).
  - Immediate re-fetch when the upstream rejects a referenced credential
    (401/403).
- **G6. Fail static, fail loud.**
  - A vault outage keeps serving the last good value up to `max_stale`.
  - An unresolved reference is never sent upstream.
  - Failures are visible in metrics, error codes and the console.
- **G7. A console that does the hard part.** A "Secret stores" tab lists what
  each data plane reports and tests a secret on the data plane. Its guided
  generator produces the Helm values and least-privilege policy templates.
  Every secret input switches between "Value" and "From secret store".

## Scope

### In scope

**Phase 1: hybrid MVP (TrustGate, chart, console)**
- **Domain:**
  - `secretref` (grammar, declared locations);
  - `secretstore` (store config, `Backend` port, error classes).
- **Local stores** loaded by the data plane from `SECRET_STORES_FILE`, which the
  Helm chart renders from `agentgateway.secretStores`.
  - The loader refuses inline secrets.
  - It reloads when the file changes.
  - Three guards keep local stores off NeuralTrust-run planes (design D13).
- **Backends:**
  - HashiCorp Vault/OpenBao: Kubernetes, JWT, AppRole and token auth; KV v1/v2.
  - AWS Secrets Manager: default credential chain (IRSA, Pod Identity),
    optional assume-role, optional VPC endpoint.
  - `file` and `env`.
- **Resolution on the data plane:** an in-process cache with refresh-ahead,
  stale-on-error, a negative cache, singleflight and forced refresh on 401/403.
- **Materializer** in the runtime finders (`consumer.DataFinder`,
  `registry.Finder`). Unresolved references fail with `secret_unavailable`
  before dialing.
- **First reference sites:**
  - registry LLM `auth` (E1);
  - `provider_options.headers` (E2);
  - MCP target auth and headers (E4).
- **Discovery:**
  - `Heartbeat.secret_stores` (name, type, allowed paths, state), persisted on
    `config_sync_connections`;
  - admin `GET /v1/gateways/:gateway_id/secret-stores` and `…/:name/usages`.
- **Write-time validation** of references against the stores the gateway's
  data planes report.
- **Data-plane diagnostics route** `POST /__diagnostics/gateways/:gateway_id/secret-stores/:name/test`,
  next to the existing test-connection and model routes.
- **Console:**
  - the "Secret stores" tab, with list, detail, usages and test;
  - the "Add a secret store" generator;
  - `SecretInput` in the LLM provider and MCP server forms.
- **Rollout:** behind `SECRET_STORES_ENABLED` (default off), with data-plane
  version gating.

**Phase 2: complete hybrid coverage**
- GCP Secret Manager (ADC / GKE Workload Identity) and Azure Key Vault
  (workload or managed identity).
- **Remaining reference sites:**
  - inbound IdP client secrets (E5);
  - plugin `CredentialPaths()` (E6);
  - consumer embedding key (E7);
  - telemetry exporter headers and DSN (E8);
  - health-check headers (E3).
- Per-reference health in the heartbeat, shown on entity cards. An optional
  readiness gate on prewarm.
- `SecretInput` in policy and telemetry forms.

**Phase 3: hosted and dedicated (separate change, design review first)**
- Keyless federation: a per-gateway OIDC identity issued by TrustGate, trusted
  by AWS `AssumeRoleWithWebIdentity`, GCP WIF, Azure federated credentials and
  Vault JWT auth.
- API-managed stores, if federation is not enough. §9 of `design.md` outlines
  this phase.

### Out of scope

- Mirroring consumer API keys into a vault, as LiteLLM's `store_virtual_keys`
  does. They are hashed, so there is nothing to mirror.
- Per-user MCP OAuth tokens (`pkg/domain/vault`).
- Platform secrets: `SERVER_SECRET_KEY`, `CONFIG_SYNC_TOKEN`, DB/Redis
  passwords. Operators keep injecting them through env, `/etc/secrets/*`, CSI or
  ESO. We document this.
- A NeuralTrust-hosted vault, or per-tenant KMS / BYOK encryption of the
  credentials pasted into the console. This would be a separate hardening
  change; it would not change how references work.
- Write-through (TrustGate writing pasted secrets into the customer's vault),
  Vault dynamic secrets and leases, and CyberArk, Infisical, 1Password or
  Doppler. The `Backend` port keeps these cheap to add later.

## Capabilities

### New
- **`secret-references`:** grammar, declared locations, admin validation and
  response semantics.
- **`secret-stores`:** the local store file, its guards, backends, heartbeat
  discovery, the admin listing and usages, and the diagnostics test.
- **`secret-resolution`:** runtime semantics on the data plane: materialization,
  cache, rotation, failure behaviour and observability.
- **`secret-stores-console`:** the settings tab, the generator and
  `SecretInput`.

### Modified
- **Config snapshot:** carries references verbatim. The compiler never
  resolves them. The proto is unchanged.
- **Config-sync `Heartbeat`:** gains `secret_stores` (Phase 1) and `secret_refs`
  (Phase 2). `config_sync_connections` gains the matching column.
- **Credential masking** (`pkg/common/secret`): a reference is returned
  verbatim, because it is not a secret.

## Approach (summary; see design.md)

1. **The customer configures the vault where it runs.** `agentgateway.secretStores`
   in Helm values becomes `SECRET_STORES_FILE`, and the data plane's
   ServiceAccount carries the cloud identity. The console helps write the
   snippet but stores nothing.
2. **The data plane reports, and the control plane validates.** Each heartbeat
   lists the data plane's stores and their health. When a reference is written,
   the admin checks it against that list.
3. **Only references travel.** The admin stores them, the compiler copies them,
   and the snapshot carries them.
4. **The data plane materializes.** It swaps each reference for the cached
   value where a gateway's runtime model is built. Downstream code is
   unchanged.
5. **Tests run where the vault is reachable.** The console calls the data
   plane's diagnostics routes, exactly as hybrid test-connection and model
   listing already do.

## Affected areas

| Area | Change |
|---|---|
| `pkg/domain/secretref`, `pkg/domain/secretstore` (new) | grammar, locations, store config, ports, errors |
| `pkg/app/secretref` (new) | resolver, cache, refresher, materializer, collector, validator |
| `pkg/infra/secretstore/{hashicorp,awssm,gcpsm,azurekv,filestore,envstore,localfile}` (new) | backends, file loader |
| `pkg/app/consumer/data_finder.go`, `pkg/app/registry/finder.go`, §6 readers | materialization + invalidation |
| `pkg/app/proxy/provider.go`, `pkg/app/mcp/*`, `pkg/infra/providers/bedrock/client.go` | `secret_unavailable`, forced refresh, cache keys |
| `pkg/infra/configsnapshot/proto/configsync.proto`, `pkg/infra/configsync/grpc`, `pkg/domain/dataplane`, `pkg/infra/repository/configsyncconn`, migration | heartbeat `secret_stores` |
| `pkg/api/handler/http/secretstore` (new), `pkg/api/handler/http/diagnostics`, routers, `admin_scopes.go` | listing, usages, diagnostics test, scope |
| `pkg/domain/registry`, `pkg/app/registry`, `pkg/app/policy`, `pkg/common/secret` | write-time validation, masking pass-through |
| `pkg/config`, `.env.example`, `downloads/docker-compose.yml` | variables, compose example |
| neuraltrust-platform Helm chart (outside these repos) | `agentgateway.secretStores` → ConfigMap, Secret mounts, env |
| `NeuralTrust/app` | settings tab, generator, `SecretInput`, server actions, i18n |

## Risks

| Risk | Mitigation |
|---|---|
| **A tenant uses NeuralTrust's pod identity, env or files.** | Three independent guards (design D13): the admin accepts references only on hybrid gateways; a data plane uses local stores only for gateways stamped `data_plane=hybrid`, which never appear in the shared snapshot; a plane with `INSTANCE_DEPLOYMENT_TYPE=saas` refuses to start with `SECRET_STORES_FILE`. |
| **Exfiltration through references.** An editor references a secret and points its registry at their own host. | `allowed_paths` is required on every store and enforced on the data plane. Writing a reference needs `secret_stores:read`. The generator emits least-privilege vault policies. Every reference added is audited. |
| **A console admin aims the pod's identity at a host they control.** | Impossible by construction. Store addresses and auth exist only in the customer's Helm values. |
| **Vault outage takes traffic down.** | Refresh-ahead, stale-on-error up to `max_stale` (24 h default), and registry failover. |
| **Hot-path latency.** | Fetches happen only on a cold cache. Singleflight and a 2 s timeout. Prewarm after each snapshot apply. |
| **A reference string sent upstream (LiteLLM #26151).** | An unresolved reference becomes an empty value plus `CredentialUnavailable`. The invoker fails before dialing. |
| **An old data plane ignores references.** | Version gating at write time, using the heartbeat version. An old data plane reports no stores, so its references fail validation. |
| **The Helm values and the console disagree.** | Discovery means the console only lists what the data plane actually loaded. The generator polls until the new store is reported. |

## Rollback plan

- Set `SECRET_STORES_ENABLED=false` on the admin and the data planes. Then:
  - the admin refuses new references;
  - stored references stay;
  - data planes stop resolving, and affected routes fail with
    `secret_unavailable`.
- To fully roll back a gateway, replace its references with literal values.
  `GET …/secret-stores/:name/usages` lists them.
- The migration (a nullable column) and the proto fields are additive.

## Dependencies

- New Go modules: `aws-sdk-go-v2/service/secretsmanager` (Phase 1) and
  `azure-sdk-for-go/sdk/security/keyvault/azsecrets` (Phase 2).
- Vault and GCP go through REST on TrustGate's HTTP client (design D12).
- **Helm chart:** the `agentgateway.secretStores` keys must be agreed with the
  chart owners. The console snippet follows them, as `privateDeployValues.ts`
  already does for the firewall keys.
- Console work in `NeuralTrust/app`.

## Success criteria

- [ ] **Keyless resolution.** On a hybrid data plane in EKS with IRSA, a
  registry with `api_key: secret://aws/prod/llm/openai#key` serves traffic.
  - The value is never in Postgres, the snapshot, the LKG file, logs or any API
    response.
  - No AWS credential exists outside the customer's cluster.
- [ ] **The same with Vault.** HashiCorp Vault with Kubernetes auth, and
  Kubernetes Secrets through the `file` store.
- [ ] **Rotation.** A secret rotated in the vault is picked up within the TTL
  with no TrustGate write, and immediately after an upstream 401.
- [ ] **Outage.** With the vault unreachable, traffic continues on the last
  good value until `max_stale`, and a metric fires.
- [ ] **Failure behaviour.** An unresolved reference fails the request with
  `secret_unavailable`, and the reference string never goes upstream.
- [ ] **Guards.** A hosted or dedicated gateway cannot hold a reference. A
  `saas` plane refuses `SECRET_STORES_FILE`.
- [ ] **Console.** The console lists the stores the data plane reports. It
  tests a path on the data plane without showing its value. It generates Helm
  values and a policy template that work as written.
