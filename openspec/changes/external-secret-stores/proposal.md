# Proposal: External secret stores (vault references) for customer-operated deployments

## Intent

Customers want TrustGate to read the credentials they configure from their own
secret manager instead of pasting them into the console: LLM provider keys, MCP
server tokens, guardrail API keys and exporter headers. The managers in scope
are HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault
and Kubernetes Secrets. LiteLLM, Kong and Portkey all offer this
(`exploration.md` §2–3). The public deployment docs even tell self-hosted
customers to keep credentials in "an approved secret manager", but nothing in
the product reads provider keys from one.

NeuralTrust's public docs define four deployment models (`exploration.md` §1.6):

| Model | Control plane | Data plane | Chart `global.deploymentMode` |
|---|---|---|---|
| SaaS | NeuralTrust | NeuralTrust | — |
| Hybrid | NeuralTrust | customer | `hybrid` |
| Self-hosted | customer | customer, one cluster | `external` |
| Central control plane | customer | customer, several clusters | `saas` (the chart value, not NeuralTrust SaaS) |

In **hybrid, self-hosted and central**, the planes that call providers run in
the customer's own infrastructure. They can reach the customer's vault, private
ones included, and authenticate with the pod's own workload identity (IRSA,
GKE/AKS Workload Identity, Vault Kubernetes auth).

Today a credential still has to be pasted into the console and stored in a
TrustGate database. In hybrid it then travels from NeuralTrust's SaaS to the
customer's data plane.

This change lets any declared credential field hold a **reference**, such as
`secret://corp-vault/ai-gateway/openai#api_key`. The customer-operated plane
that needs the value resolves it.

**Neither the secret nor the vault's credentials are written to any TrustGate
database, snapshot or log.** The vault is configured in the customer's Helm
values. The console lists what the planes report.

In **NeuralTrust SaaS and dedicated**, the planes are NeuralTrust's. The same
feature would need NeuralTrust to hold something that can read the customer's
vault, unless we build keyless federation first. They are a later phase, with
their own design review.

Linear: _pending_. Research: `exploration.md`.

## Goals

- **G1. References instead of values.** On every gateway served by a
  customer-operated plane, any declared credential field can hold a reference.
  That is every gateway of a self-hosted or central install, and hybrid
  gateways on NeuralTrust's control plane. One grammar covers typed fields and
  plugin settings.
- **G2. Backends.** HashiCorp Vault and OpenBao (KV v1/v2), AWS Secrets
  Manager, GCP Secret Manager and Azure Key Vault. Mounted files (`file`)
  cover Kubernetes Secrets, the CSI driver and External Secrets Operator.
  Environment variables are an `env` store.
- **G3. Nothing sensitive at rest in TrustGate.**
  - The secret value lives only in the memory of the customer-operated planes
    that use it.
  - Store addresses and credentials live only in the customer's Helm values and
    Kubernetes Secrets.
  - Control planes, databases, snapshots, LKG files, heartbeats, logs and API
    responses carry reference strings and store metadata only: name, type,
    allowed paths, allowed gateways and health.
- **G4. Keyless by default.** Every backend's recommended auth is the pod's
  workload identity, reusing the chart's existing ServiceAccount and identity
  settings. Static Vault credentials (AppRole, token) come only from mounted
  Kubernetes Secrets.
- **G5. Rotation without a TrustGate write.**
  - Background refresh-ahead within the store TTL (default 5 min).
  - Immediate re-fetch when the upstream rejects a referenced credential (401/403).
- **G6. Fail static, fail loud.**
  - The last good value is served through a vault outage, up to `max_stale`.
  - An unresolved reference is never sent upstream.
  - Failures are visible in metrics, error codes and the console.
- **G7. One console experience in every model.** The same "Secret stores" tab,
  generator and `SecretInput` in hybrid, self-hosted and central. Only where a
  test runs and which values file the snippet goes into differ.
- **G8. Multi-team safety in shared installs.** In a self-hosted or central
  cluster, every team's gateways share the proxy and the store file. A store
  can be restricted to the gateways allowed to use it.

## Scope

### In scope

**Phase 1: every customer-operated model (TrustGate, chart, console, docs)**
- **Domain:**
  - `secretref`: grammar, declared locations.
  - `secretstore`: store config, `Backend` and `Catalog` ports, error classes.
- **Store file.** `SECRET_STORES_FILE` is rendered by the chart from
  `agentgateway.secretStores` and mounted on every agentgateway workload the
  mode deploys:
  - hybrid: proxy and MCP;
  - external and central: admin, proxy and MCP.

  The loader is strict, refuses inline secrets and reloads on change.
- **Backends.**
  - Vault/OpenBao: Kubernetes, JWT, AppRole and token auth.
  - AWS Secrets Manager: default chain, assume-role, VPC endpoint.
  - `file` and `env`.
- **Gateway eligibility.** `SECRET_STORES_GATEWAYS=hybrid|all`, read by every
  plane:
  - NeuralTrust SaaS keeps the default `hybrid`;
  - the chart sets `all` in `external` and central installs.

  Three independent guards keep stores off NeuralTrust-run planes (design D13).
- **Resolution on customer-operated planes.**
  - Data planes always resolve.
  - The admin resolves only when it has a store file, which happens only in
    external and central installs.
  - The resolver is an in-process cache with refresh-ahead, stale-on-error,
    negative caching, singleflight and forced refresh on 401/403.
- **Materializer** in the runtime finders. An unresolved reference fails the
  request with `secret_unavailable` before any upstream call.
- **First reference sites:** registry LLM `auth` (E1),
  `provider_options.headers` (E2), MCP target auth and headers (E4).
- **Store discovery for each gateway.**
  - Gateway served by its own data plane: the stores its live config-sync
    connections report in `Heartbeat.secret_stores`.
  - Gateway served by the control plane's own cluster: the admin's own store
    catalog.
- **Admin API.**
  - `GET /v1/gateways/:gateway_id/secret-stores`, with `supported` and `source`.
  - `GET …/:name/usages`.
  - `POST …/:name/test`, admin catalog only.
  - Write-time validation of references.
- **Data-plane diagnostics.** `POST /__diagnostics/gateways/:gateway_id/secret-stores/:name/test`.
- **Per-store `gateways` allowlist (G8).**
- **Console.** The "Secret stores" tab, the "Add a secret store" generator and
  `SecretInput` in the LLM provider and MCP server forms. They are shown
  whenever the admin reports `supported`.
- **Public docs.** New pages in the deployment section: Secrets and
  Configuration, Hybrid and Self-hosted, plus a "Secret stores" guide.
- **Rollout.** Behind `SECRET_STORES_ENABLED` (default off), with capability
  gating of snapshots (`accepts_secret_refs`, design D19).

**Phase 2: complete coverage**
- GCP Secret Manager (ADC / GKE Workload Identity, reusing
  `global.gcpIdentity`) and Azure Key Vault (workload or managed identity).
  Either can move into Phase 1 if a customer needs it first.
- **Remaining reference sites:** health-check headers (E3), IdP secrets (E5),
  plugin `CredentialPaths()` (E6), consumer embedding (E7) and telemetry
  exporters (E8).
- **Per-reference health** in the heartbeat. An admin-side report for the
  admin catalog. Warnings on entity cards. An optional readiness gate on
  prewarm.

**Phase 3: NeuralTrust SaaS and dedicated (separate change, design review first)**
- Keyless federation: a per-gateway OIDC identity issued by TrustGate and
  trusted by AWS, GCP, Azure and Vault.
- API-managed stores, only if federation is not enough. See `design.md` §10.

### Out of scope

- Mirroring consumer API keys into a vault, as LiteLLM's `store_virtual_keys`
  does. They are hashed.
- Per-user MCP OAuth tokens (`pkg/domain/vault`).
- **Platform secrets.** `SERVER_SECRET_KEY`, DB/Redis passwords, config-sync
  tokens and the Firewall JWT keep using `existingSecret`, ESO or CSI, as the
  deployment docs describe.
- A NeuralTrust-hosted vault, or per-tenant KMS / BYOK encryption of pasted
  credentials. That is a separate hardening change.
- Write-through to the customer's vault, Vault dynamic secrets and leases, and
  CyberArk, Infisical, 1Password or Doppler. The `Backend` port keeps them cheap
  to add.

## Capabilities

### New
- **`secret-references`:** grammar, declared locations, gateway eligibility,
  admin validation, response semantics.
- **`secret-stores`:** store file, guards, backends, the per-gateway store
  source (heartbeat or admin catalog), admin listing, usages and tests, data
  plane diagnostics.
- **`secret-resolution`:** runtime semantics on customer-operated planes.
- **`secret-stores-console`:** settings tab, generator, `SecretInput`.

### Modified
- **Config snapshot:** carries references verbatim and never resolves them.
  The proto is unchanged.
- **Config-sync `Heartbeat`:** gains `secret_stores` (Phase 1) and
  `secret_refs` (Phase 2). `config_sync_connections` gains matching columns.
- **Credential masking** (`pkg/common/secret`): references are returned
  verbatim.

## Approach (summary; see design.md)

1. **The customer configures the vault where it runs.**
   - `agentgateway.secretStores` in the chart values becomes
     `SECRET_STORES_FILE` on each agentgateway workload of that cluster.
   - The cloud identity is the agentgateway ServiceAccount the chart already
     manages.
   - The console generates the snippet and stores nothing.
2. **Each gateway has exactly one store source**, the planes that serve it:
   - **Own data plane** (hybrid, or a remote cluster of a central install): its
     config-sync connections report their stores in the heartbeat.
   - **The control plane's own cluster** (self-hosted, or the central
     cluster): the admin loads the same file and reports its own catalog.

   The admin validates references against that source.
3. **Only references travel.** Databases, snapshots and heartbeats never hold a
   value.
4. **The serving plane materializes.** It swaps each reference for the cached
   value where the gateway's runtime model is built. Downstream code is
   unchanged.
5. **Tests run where the vault is reachable.** The console already routes
   test-connection and model listing by gateway type: hybrid gateways go to the
   data plane's diagnostics routes, others to the admin. Secret tests follow
   the same routing.

## Affected areas

| Area | Change |
|---|---|
| `pkg/domain/secretref`, `pkg/domain/secretstore` (new) | grammar, locations, store config, ports, errors |
| `pkg/app/secretref` (new) | resolver, cache, refresher, materializer, collector, validator, eligibility |
| `pkg/app/secretstore` (new) | store source per gateway, listing, usages, admin test |
| `pkg/infra/secretstore/{hashicorp,awssm,gcpsm,azurekv,filestore,envstore,localfile}` (new) | backends, file loader |
| `pkg/app/consumer/data_finder.go`, `pkg/app/registry/finder.go`, runtime readers | materialization + invalidation (any plane with a catalog) |
| `pkg/app/proxy/provider.go`, `pkg/app/mcp/*`, `pkg/infra/providers/bedrock/client.go` | `secret_unavailable`, forced refresh, cache keys |
| `pkg/infra/configsnapshot/proto/configsync.proto`, `pkg/infra/configsync/grpc`, `pkg/domain/dataplane`, `pkg/infra/repository/configsyncconn` + migration | heartbeat `secret_stores` |
| `pkg/api/handler/http/secretstore`, `pkg/api/handler/http/diagnostics`, routers, `admin_scopes.go` | admin listing, usages and test; diagnostics test; scope |
| `pkg/domain/registry`, `pkg/app/registry`, `pkg/app/policy`, `pkg/common/secret` | write-time validation, masking pass-through |
| `pkg/config`, `.env.example`, `downloads/docker-compose.yml` | variables, compose example |
| `NeuralTrust/neuraltrust-platform` (chart) | `agentgateway.secretStores` → ConfigMap, volume mounts on admin, proxy and MCP, Secret mounts, `SECRET_STORES_*` env per mode |
| `NeuralTrust/app` | settings tab, generator, `SecretInput`, server actions, i18n |
| `NeuralTrust/docs` | deployment Secrets / Configuration pages, Secret stores guide |

## Risks

| Risk | Mitigation |
|---|---|
| **A tenant of NeuralTrust SaaS uses NeuralTrust's pod identity, environment or files.** | Three independent guards (design D13): eligibility `hybrid` on NeuralTrust's control plane; every plane checks eligibility itself; a plane with `INSTANCE_DEPLOYMENT_TYPE=saas` refuses `SECRET_STORES_FILE`. NeuralTrust never ships a store file to its own planes. |
| **One team reads another team's secrets in a shared self-hosted or central cluster.** | A per-store `gateways` allowlist, enforced by the admin and by every plane. Separate stores per team, with disjoint `allowed_paths`. The generator prefills the allowlist with the current gateway. |
| **Exfiltration through references.** An editor points a referenced secret at their own host. | `allowed_paths` is required and enforced where the store lives. Writing or retargeting a reference needs `secret_stores:read`. The generator emits least-privilege policies. Every reference write is audited. |
| **A console admin aims the pod identity at a host they control.** | Impossible by construction: store addresses and auth exist only in Helm values. |
| **Vault outage.** | Refresh-ahead, stale-on-error up to `max_stale` (24 h default), and registry failover. |
| **A reference string is sent upstream (LiteLLM #26151).** | An unresolved reference becomes an empty value plus `CredentialUnavailable`. The request fails before any upstream call. |
| **A plane that predates this change receives a reference.** It forwards `secret://…` literally as the API key: the upstream answers 401 and that registry is down (LiteLLM #26151). | Planes with this code advertise `accepts_secret_refs`. The config-sync server never serves a snapshot that contains references to a plane without it. Such a plane keeps its previous or LKG configuration, or stays not-ready if it has none; it never sends `secret://…`. Write-time validation is strict: no reference while any live plane lacks the capability or none is connected, unless the request explicitly opts in with `allow_unverified_secret_refs`. Old planes are reported as `too_old`, logged and counted. Self-hosted planes read Postgres, so the gate does not apply to them; they rely on the downgrade procedure. Downgrade procedure: replace references before downgrading a plane or rolling back the chart. |
| **Deploying the code changes behaviour for existing customers.** | With the flag off, the materializer is a no-op unless a value starts with `secret://`. Masking, write paths and cache keys for literal credentials stay unchanged. The chart renders nothing new, and the console treats a 404 as unsupported. A pre-deploy scan (`secret-refs-scan`) confirms that no stored credential starts with `secret://`. Golden tests prove all of this (design §13). |
| **Chart and console drift.** | Discovery: the console lists only what the planes actually loaded. The generator polls until the store is reported. |

## Rollback plan

**Feature rollback (always safe).** Set `SECRET_STORES_ENABLED=false` on the
admin and the planes.
- The admin refuses new references.
- The planes stop resolving and never forward a reference-shaped value.
- Only the routes that use references fail, with `secret_unavailable`.

**Version rollback.** This means downgrading a hybrid data plane, or rolling
back a self-hosted or central chart, below the first version that resolves
references. First replace every reference with a literal, using
`GET …/secret-stores/:name/usages`. Otherwise the older plane forwards
`secret://…` upstream. The console shows this checklist when a plane reports
`too_old`.

The schema change (nullable columns, explicit column lists) and the proto
change (additive fields) are safe to roll back.

## Dependencies

- **New Go modules:** `aws-sdk-go-v2/service/secretsmanager` (Phase 1),
  `azure-sdk-for-go/sdk/security/keyvault/azsecrets` (Phase 2).
- **Chart (`NeuralTrust/neuraltrust-platform`).** New templates are needed
  because the `agentgateway` subchart has no `extraVolumes`. The value keys
  must be agreed with the chart owners (OQ3).
- **Console (`NeuralTrust/app`) and public docs (`NeuralTrust/docs`).**

## Success criteria

- [ ] **Hybrid (EKS, IRSA).** A registry with
  `api_key: secret://aws/prod/llm/openai#key` serves traffic. The value is never
  in any TrustGate database, snapshot, LKG, log or API response. No AWS
  credential exists outside the customer's cluster.
- [ ] **Self-hosted (`external`, Vault with Kubernetes auth).** The same
  registry serves traffic through the in-cluster proxy. Test-connection and
  model listing work from the console through the admin.
- [ ] **Central control plane.** A central-cluster gateway resolves on the
  central cluster. A remote-cluster gateway resolves on its remote cluster.
  Each validates against its own store source.
- [ ] **Rotation.** A secret rotated in the vault is picked up within the TTL
  with no TrustGate write, and immediately after an upstream 401.
- [ ] **Outage.** With the vault unreachable, traffic continues until
  `max_stale`, and a metric fires.
- [ ] **No leak upstream.** An unresolved reference fails with
  `secret_unavailable`, and the reference string never goes upstream.
- [ ] **NeuralTrust SaaS and dedicated.** Their gateways cannot hold
  references. A `saas` plane refuses `SECRET_STORES_FILE`.
- [ ] **Multi-team.** A store restricted to gateway A cannot be referenced or
  resolved for gateway B in the same cluster.
- [ ] **Compatibility.** Deploying with the flag off is a no-op for
  existing gateways in SaaS, hybrid and self-hosted. Golden tests and an
  identical chart render prove it.
- [ ] **Old planes.** No reference can be written for a gateway whose live
  planes are too old, or which has no live plane, without the explicit opt-in.
  An old plane that joins later never receives the snapshot with references.
  It keeps its previous configuration, or stays not-ready, and is reported as
  `too_old`.
- [ ] **Console.** It shows the same tab, generator and `SecretInput` in
  hybrid, self-hosted and central. Tests run on the plane that can reach the
  vault and never show a value.
