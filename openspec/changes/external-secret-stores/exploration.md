# Exploration: External secret stores (vault references)

Research input for `proposal.md` and `design.md`. Three parts: how TrustGate
handles secrets today, how LiteLLM supports secret managers, and what Kong and
Portkey do. Every finding cites code. TrustGate paths are relative to the repo
root. LiteLLM was read at `BerriAI/litellm@8b8ec4e3` (`main`, 2026-11-11).

> **Naming collision.** "Vault" already means something in this code base:
> `pkg/domain/vault` is the store for per-user MCP OAuth credentials. This
> change calls the new concept a **secret store** and its pointers **secret
> references**. "HashiCorp Vault" always means the product.

---

## 1. Secrets in TrustGate today

### 1.1 Inventory

| # | Secret | Where it lives | At rest | Read at request time by |
|---|---|---|---|---|
| E1 | LLM upstream auth (`TargetAuth`). Fields: api_key / header_value / param_value; AWS access_key_id / secret_access_key / session_token (+ role); Azure api_key / client_secret; oauth2 client_secret / refresh_token / password; GCP service-account JSON. | `pkg/domain/registry/target.go:44-96`, column `registries.auth` (TEXT) | Whole JSON blob encrypted with `crypto.Cipher` (`SHA256("trustgate-vault:"+SERVER_SECRET_KEY)`). No AAD and no key id. `pkg/infra/repository/registry/repository.go:488-497` | `providers.CredentialsFromTargetAuth` (`pkg/infra/providers/credentials.go:26-74`), called from `registryCredentials` (`pkg/app/proxy/provider.go:762`). Also catalog live availability, the Bedrock model lister and the traffic-label classifier. |
| E2 | `provider_options.headers` | `registries.provider_options` JSONB | `FieldSealer` per value, AAD = field + registry id (`pkg/infra/repository/registry/secrets.go:290-334`) | `openaicompat.applyUpstreamAuth` (`pkg/infra/providers/openaicompat/headers.go:23-56`) |
| E3 | Health-check headers | `registries.health_checks` JSONB | **Plaintext** (masked in responses) | Health checker |
| E4 | MCP upstream: `auth.value`, `auth.client_secret`, `headers.*` | `registries.mcp_target` JSONB (`pkg/domain/registry/mcp_target.go:108-174`) | `FieldSealer` (`pkg/infra/repository/registry/secrets.go:59-254`) | `StaticTarget` (`pkg/app/mcp/target.go:111-129`), `credentialResolver.Apply` (`pkg/app/mcp/credentials.go:176-195`) |
| E5 | Inbound IdP `oauth2.client_secret`, `exchange_client_secret` | `auths.config` JSONB (`pkg/domain/auth/config.go:61-96`) | `FieldSealer` (`pkg/infra/repository/auth/secrets.go:33-117`) | `ExchangeCredentials` (`pkg/domain/auth/config.go:107-125`) |
| E6 | Policy plugin credentials at `CredentialPaths()`: azure content safety, OpenAI moderation, Bedrock guardrail, Model Armor, semantic cache | `policies.settings` JSONB | **Plaintext** (`pkg/infra/plugins/googlemodelarmor/config.go:63-66` says so) | Decoded into the plugin config at execution, e.g. `pkg/infra/plugins/bedrockguardrail/client.go:50` |
| E7 | Consumer semantic-LB embedding key | `consumers.lb_config` JSONB (`pkg/domain/registry/embedding_config.go:11-14`) | **Plaintext** | Embedding client |
| E8 | Gateway telemetry exporter credentials: OTLP `headers`, Postgres `dsn` | `gateways.telemetry` JSONB (`pkg/domain/telemetry/telemetry.go:25-40`) | **Plaintext, and returned unmasked by `GET /v1/gateways/:id`** (`pkg/api/handler/http/gateway/response/gateway_response.go:42,74`) | Exporter construction |
| E9 | Consumer API keys, including personal and group keys | `auths.key_hash` | SHA-256 hash | Inbound auth. **Not a candidate:** they are inbound and TrustGate never needs the plaintext. |
| E10 | Per-user MCP OAuth tokens | `vault_credentials` table, or Redis on DB-less planes | `crypto.Cipher` | MCP credential resolver. **Out of scope:** per user, written at runtime. |
| E11 | Platform secrets: `SERVER_SECRET_KEY`, `STS_SIGNING_KEY`, `DB_PASSWORD`, `REDIS_PASSWORD`, `CONFIG_SYNC_*`, `TRUSTGUARD_CLIENT_SECRET`, `FIREWALL_*` | Environment (`pkg/config/config.go`). `godotenv` also loads `/etc/secrets/.env` and `/etc/secrets/secrets` (`cmd/trustgate/main.go:77-82`). | Operator-managed. Hosted SaaS mounts them from GCP Secret Manager through the GKE CSI driver (`k8s/overlays/*/secretproviderclass/agentgateway-secrets.yaml`). | Boot |

There are two encryption schemes. E1 still uses the legacy `crypto.Cipher`.
E2, E4 and E5 use `FieldSealer` (`enc:v1:<kid>:`, HKDF-derived per purpose,
AAD-bound). E3, E6, E7 and E8 are plaintext.

### 1.2 How credentials reach the data plane

- **Hosted SaaS** runs proxy and mcp **DB-less**
  (`k8s/base/deployment/agentgateway-proxy.yaml:42-48`). The admin plane
  compiles a protobuf snapshot from the Postgres repositories, so secrets are
  already decrypted when they enter it (`pkg/app/configsnapshot/compiler.go`).
  Each registry is a JSON blob **that includes the plaintext `auth`**
  (`pkg/infra/configsnapshot/codec.go:109`), and
  `codec_secret_test.go:17-68` asserts that this survives.
- **Hybrid gateways** (`Entitlements.DataPlane`,
  `pkg/domain/gateway/entitlements.go:40-54`) run their data plane in the
  customer's environment. **Dedicated** gateways get a data plane that
  NeuralTrust runs for that gateway alone, so for this feature they behave like
  hosted. It pulls a scoped snapshot over gRPC
  (`pkg/infra/configsync/grpc`). **Today every upstream credential of a hybrid
  gateway is stored in NeuralTrust's database and travels from the SaaS control
  plane to the customer's network.** This is the strongest argument for the
  feature: with a reference, the customer's data plane reads its own vault and
  the value never leaves their network.
- The data-plane worker swaps an in-memory store and writes an LKG file
  encrypted with `CONFIG_SYNC_LKG_KEY`.
- The config-sync stream is bidirectional (`pkg/infra/configsnapshot/proto/configsync.proto`).
  `Heartbeat` already reports `deployment_type` and the TrustGuard client id,
  never its secret. It is the natural channel for a data plane to report the
  health of its secret stores.
- **Admin features that need a credential already follow the deployment mode.**
  - **Hybrid gateways:** the console calls the data plane directly. It uses
    `POST /__diagnostics/gateways/:id/registries/test-connection` and
    `GET /__diagnostics/gateways/:id/registries/:rid/models`, with a diagnostics
    token it mints (`pkg/server/router/proxy_router.go:25-32`;
    `app/[locale]/v2/features/registry/actions/testRegistryConnectionAction.ts`;
    `app/server/lib/gateway/registryModelCatalog.ts`). Model listing falls back
    to the admin's `/v1/models-catalog` if the data plane does not answer.
  - **Hosted and dedicated gateways:** the same features run on the admin
    (`POST /v1/gateways/:id/registries/test-connection`, `GET /v1/models-catalog`).

### 1.3 The hot-path read model

- `consumer.DataFinder.FindByGateway` (`pkg/app/consumer/data_finder.go:91-191`)
  loads a gateway's consumers, registries, auths and policies into one `*Data`.
  It caches the result in a TTL map (1 h) keyed by gateway and generation, and
  collapses concurrent loads with singleflight.
- `registry.Finder` keeps a 5-minute map (`pkg/app/registry/finder.go:48-62`).
- Redis pub/sub `InvalidateGatewayDataEvent` / `InvalidateRegistryCacheEvent`
  (`pkg/app/invalidation/invalidation.go`) and the snapshot worker's
  `ClearAllTTLMaps` drop these caches.
- Both finders sit **above** the repository port, so they behave the same over
  Postgres (admin, run, flag-off proxy) and over the snapshot adapters (DB-less).
  **This makes them the single place where references can be substituted for
  every plane.**

### 1.4 Rotation hazards in the current code

- The Bedrock runtime client pool key leaves out the secret key and session
  token (`pkg/infra/providers/bedrock/client.go:386-397`). An AWS key rotation
  normally changes the access key id too, so this is low risk. A rotated
  session token under the same id would still be missed.
- The MCP dial revision is registry id + `UpdatedAt` (`pkg/app/mcp/target.go:123`).
  A secret that changes without a registry write does not force a redial.
- The GCP SA token cache is keyed by a hash of the JSON
  (`pkg/infra/providers/gcpauth/token.go:63-82`), so rotation already works there.

### 1.5 Building blocks we can reuse

- **Masking contract:** `pkg/common/secret` (`Mask`, `Resolve`,
  `MaskSettings`, `ResolveSettings`) plus plugin `CredentialPaths()` /
  `CredentialDestinations()` (`pkg/app/plugins/plugin.go:155-214`). These
  already declare *where* a secret may sit, so they also declare where a
  reference may sit.
- **At-rest sealing:** `crypto.FieldSealer` with per-purpose HKDF keys. The new
  store's bootstrap credentials get the purpose `secret-stores/v1`.
- **SSRF guard:** `pkg/infra/netguard` for tenant-supplied URLs (a Vault
  address, an Azure vault URL).
- **Confused-deputy precedent:** Model Armor refuses ambient pod identity on
  shared planes unless `MODEL_ARMOR_ALLOW_AMBIENT_IDENTITY` is set
  (`pkg/infra/plugins/googlemodelarmor/config.go:45-62`). The telemetry
  Postgres `dsn_env` is refused in tenant settings
  (`pkg/infra/telemetry/postgres/tenant.go:138-156`). Ambient identity, `env`
  and `file` stores follow the same rule.
- **Cloud SDKs already in `go.mod`:** aws-sdk-go-v2 (config, credentials,
  sts), Azure `azcore` + `azidentity`, `golang.org/x/oauth2/google`, and the
  `gcpauth` helpers (`adc.go`, `impersonate.go`). Missing: `service/secretsmanager`,
  `security/keyvault/azsecrets`, and a HashiCorp Vault client.
- **Signer and JWKS:** an RS256 signer (`pkg/infra/identity/sts/signer.go`) and
  `/.well-known/jwks.json` on the MCP plane are a starting point for a keyless
  federation issuer (Phase 4).
- **Admin scopes:** `AdminResource` + `RequiredScope` (`pkg/api/middleware/admin_scopes.go`)
  give `<resource>:read|write` scopes. A new `secret_stores` resource fits as is.
- **Console UI:** provider and MCP forms are schema-driven. Fields carry
  `secret: true` from the TrustGate catalog
  (`app/[locale]/v2/features/registry/lib/flattenProvidersCatalog.ts`,
  `RegistrySchemaFieldRenderer.tsx`). One "value or reference" input therefore
  covers every form. Gateway settings already use tabs (General, Credentials,
  Machine identity, Deployment), so "Secret stores" becomes a new tab.

### 1.6 Deployment models (public docs and chart)

Source: https://docs.neuraltrust.ai/neuraltrust/deployment/overview and its
sub-pages `external`, `central`, `configuration` and `secrets`, plus the
`NeuralTrust/neuraltrust-platform` chart.

| Model | Control plane (console + TrustGate admin) | Data plane | Chart `global.deploymentMode` |
|---|---|---|---|
| SaaS | NeuralTrust | NeuralTrust | — |
| Hybrid | NeuralTrust | customer | `hybrid` |
| Self-hosted | customer | customer, same cluster | `external` |
| Central control plane | customer | customer, several clusters (each a hybrid install of the customer's own control plane) | `saas` (chart value) |

Facts that shape the design:

- **Self-hosted (`external`) runs everything in one release:**
  - the console (`control-plane-app` and `-api`);
  - the TrustGate admin (`agentgateway-admin`), proxy and MCP;
  - TrustGuard, DataCore and ClickHouse.
- **In `external`, the proxy reads Postgres directly.** "Each product's data
  plane reads its configuration directly from that product's database." In the
  `agentgateway` subchart, `configSync.enabled: null` turns config-sync on for
  hybrid and off for external. So there is **no heartbeat** in a self-hosted
  install. Its gateways are served by the in-cluster proxy, not by a data plane
  of their own.
- **The `agentgateway` subchart shapes how stores can be wired:**
  - it renders `controlPlane` (the admin) only in external mode;
  - one `serviceAccount` with `annotations` is shared by all workloads;
  - a shared env ConfigMap (`config`) plus per-workload `extraEnv`;
  - **no `extraVolumes`**, so mounting a store file needs new templates;
  - `existingSecret` blocks hold platform credentials.
- **Identity hooks already exist in the chart:**
  - `global.gcpIdentity.method: workload-identity` and per-service
    `serviceAccount.annotations` (GKE);
  - IRSA for RDS/ElastiCache IAM auth (AWS);
  - `global.azureIdentity.method`.

  Stores can reuse the same identities.
- **The chart does not set `INSTANCE_DEPLOYMENT_TYPE`** (organisation-wide code
  search), so every customer install runs with the default `self-hosted`.
  NeuralTrust's own overlays set `saas` (`k8s/overlays/*/config.env`).
- **The public Secrets page leaves provider keys open.** It covers platform
  secrets (`agentgateway-secrets` with `SERVER_SECRET_KEY`/`STS_SIGNING_KEY`,
  database, Redis, config-sync, enrolment). It mentions Vault and ESO only in
  passing, and recommends "an approved secret manager". Provider API keys
  (OpenAI and so on) are **not covered**: they are pasted in the console. This
  change fills that gap.
- **The console detects on-prem through `DEPLOYMENT_MODE=external`**
  (`app/constants/deployment.ts`). On-prem resolves unrestricted entitlements
  (`app/server/lib/entitlements/resolveTeamEntitlements.ts`).

---

## 2. LiteLLM

### 2.1 What it offers

| `key_management_system` | Auth | Ops | Gate |
|---|---|---|---|
| `hashicorp_vault` | AppRole, then TLS client cert, then static token. No Kubernetes, JWT or cloud auth. KV v2 only, fixed `key` field. | read, write, delete, rotate | Enterprise |
| `aws_secret_manager` (v2, raw SigV4) | default chain or static keys; `aws_role_name` + `aws_external_id`; IRSA web identity | read, write | none in code |
| `azure_key_vault` | `DefaultAzureCredential` + `AZURE_KEY_VAULT_URI` | read | none in code |
| `google_secret_manager` | SA file or ADC + project | read | Enterprise |
| `cyberark` | API key or client cert | read, write | Enterprise |
| `aws_kms` / `google_kms` | Decrypts base64 ciphertext in env vars | decrypt | partly Enterprise |
| `custom` | User subclass of `CustomSecretManager` | anything | none |

The docs say every backend needs an Enterprise license, but the code gates
only some of them. Sources: `litellm/secret_managers/*.py`, https://docs.litellm.ai/docs/secret_managers/overview.

### 2.2 Model

- **One global manager per proxy,** set in `config.yaml`
  (`general_settings.key_management_system` + `key_management_settings`).
  Credentials come from env vars (`HCP_VAULT_*`, `AWS_*`, ...). Vault and
  CyberArk can also be set from the Admin UI (`/config_overrides/hashicorp_vault`).
  Those settings are stored encrypted in the DB, and each pod rebuilds its
  client from them.
- **Reference syntax** is `os.environ/NAME` in any config value. `get_secret`
  asks the manager first (unless `hosted_keys` excludes the name) and falls back
  to `os.getenv` when the manager raises. NAME is used as the secret id
  verbatim. There is no per-reference store, field or version.
- **Read timing:**
  - `config.yaml` values are resolved once at load.
  - DB models are re-resolved on each DB-to-router sync.
  - Provider code calls `get_secret()` synchronously on the request path, so a
    cache miss blocks the event loop.
- **Caching** is in-process only. Vault and GSM default to a 24 h TTL
  (`SECRET_MANAGER_REFRESH_INTERVAL`). AWS and Azure are not cached at all.
  Nothing refreshes in the background, and there is no stale-on-error serving.
- **Write path:** with `store_virtual_keys: true`, LiteLLM mirrors its own
  virtual keys into the manager on create, rotate and delete. The name is
  `prefix + alias`. Failures are logged and swallowed, so the DB and the
  manager drift apart (#19445, #13667).
- **Credentials stored in the DB** are encrypted with the salt key (NaCl
  SecretBox, or AES-GCM opt-in). The salt key cannot be rotated (#12448).

### 2.3 Known issues worth learning from

- **#26151:** an unresolved `os.environ/...` string was sent upstream
  literally, and the call failed with a 401. *Lesson: an unresolved reference
  must never leave the gateway as a value.*
- **#35239:** split images never initialised the manager, so references
  silently became `None`. *Lesson: an unresolved reference must be loud: a
  metric, an error code and a readiness signal.*
- **#13076:** AWS returned `None` instead of raising, so there was no fallback
  and boot crashed. *Lesson: one error contract for every backend.*
- With a 24 h TTL and no refresher, rotated secrets are picked up only after a
  day. Blocking HTTP runs on async paths.

---

## 3. Other gateways

**Kong** ([secrets management](https://developer.konghq.com/gateway/secrets-management/))
- **Syntax:** `{vault://<vault-entity>/<secret>/<json-key>}`, with an optional
  version and per-reference `ttl`, `neg_ttl` and `resurrect_ttl`.
- **Vault entities:** named, each with its own credentials and TTLs. Only
  fields the schema marks as *referenceable* accept a reference.
- **Rotation:** a background timer (every 60 s) re-fetches values independent of
  traffic. `resurrect_ttl` keeps serving the last value while the backend is
  down.
- **HashiCorp backend:** KV v1 and v2; token, AppRole, Kubernetes, cert, JWT and
  cloud auth.
- **Licensing:** the `env` vault is open source; the cloud backends are
  Enterprise.

**Portkey** ([secret references](https://portkey.ai/docs/product/enterprise-offering/secret-references))
- **Backends:** AWS Secrets Manager, Azure Key Vault and HashiCorp Vault (token,
  AppRole, Kubernetes).
- **Mappings:** `secret_mappings` bind a `target_field` to a secret key, with a
  `value_format` of `json` or `string`.
- **Resolution:** the data plane fetches at runtime and caches for 5 min. The
  control plane never stores the value.

---

## 4. Takeaways for TrustGate

1. **Copy Kong's shape, not LiteLLM's.** Named stores scoped to a gateway, an
   explicit reference that carries store, path, field and version, references
   accepted only in fields declared as secret, background refresh, and
   stale-on-error.
2. **Resolve on the data plane.** For hybrid gateways this
   removes the customer's credentials from our DB and our snapshot entirely.
   LiteLLM has no equivalent, since it has no control-plane/data-plane split.
3. **Separate who chooses the store from who references it.**
   - Ambient pod identity (IRSA, GKE/AKS Workload Identity, Vault Kubernetes
     auth), `env` stores and `file` stores are safe only under two conditions:
     the store is declared by whoever runs the plane, and that plane is
     operated by the customer.
   - That holds for hybrid, self-hosted (`external`) and central installs
     (§1.6). It does not hold for NeuralTrust SaaS or dedicated, which would
     need keyless federation bound to the gateway.
4. **Fail static, fail loud.** Serve the last good value through a backend
   outage. Never send a reference string upstream. Expose metrics and report
   health to the console.
5. **Don't copy `store_virtual_keys`.** TrustGate's consumer keys are hashed,
   so there is nothing to mirror. A write-through mode ("TrustGate writes the
   pasted secret into your store") is a possible later addition, not the core.

## 5. Open questions (resolved in design.md)

- **Which deployments first?**
  - Every customer-operated model: hybrid, self-hosted and central.
  - NeuralTrust SaaS and dedicated come in phase 3 (D1).
- **How do planes know whether a gateway may use references?**
  - Through the explicit setting `SECRET_STORES_GATEWAYS=hybrid|all`, default
    `hybrid`. The chart sets `all` in external and central (D1).
  - Not from `data_plane` alone, and not from `INSTANCE_DEPLOYMENT_TYPE`.
- **Where is a store configured?** In the customer's Helm values, mounted on
  every agentgateway workload of the cluster. Never in a TrustGate database
  (D2).
- **How does the admin know a gateway's stores?** It depends on who serves the
  gateway (D3):
  - its own data plane → the stores that plane reports in the heartbeat;
  - anything else → the admin's own catalog, for example in external mode,
    which has no heartbeat.
- **How are teams isolated in a shared install?** Through a per-store
  `gateways` allowlist (D17).
- **Where are references substituted?** Once, in the runtime finders, not at
  each call site (D6).
- **Should the snapshot carry the list of references?** No. A walker computes
  it (D10).
- **Should resolved values survive a restart while the vault is down (LKG)?**
  No, by default (OQ2).
