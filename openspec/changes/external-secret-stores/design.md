# Design: External secret stores (vault references) for customer-operated deployments

## Linked artifacts

- **Proposal** (binding): [`proposal.md`](./proposal.md), goals G1–G8.
- **Research:** [`exploration.md`](./exploration.md). It covers the TrustGate
  secret inventory (E1–E11), the deployment models from the public docs
  (§1.6), LiteLLM, Kong and Portkey.
- **Specs:**
  [`secret-references`](./specs/secret-references/spec.md),
  [`secret-stores`](./specs/secret-stores/spec.md),
  [`secret-resolution`](./specs/secret-resolution/spec.md),
  [`secret-stores-console`](./specs/secret-stores-console/spec.md).
- **Linear:** _pending_.
- **Conventions:** `.agents/AGENTS.md`:
  - hexagonal layers;
  - one use case per file;
  - DI in `pkg/container/modules`;
  - one DTO per file;
  - mockery mocks;
  - environment variables read only through `pkg/config`.

## Scope by deployment model

| Model (docs) | Chart mode | Who runs the planes | Gateways that may hold references | Where stores are configured | Store source the admin validates against | Who resolves | Phase |
|---|---|---|---|---|---|---|---|
| Hybrid | `hybrid` | NT control plane, customer data plane | hybrid gateways | that data plane's values | heartbeats of the gateway's connections | data plane | 1 |
| Self-hosted | `external` | customer, one cluster | all gateways | the platform values, mounted on admin, proxy and MCP | the admin's own catalog | proxy and MCP; admin for tests, test-connection and model listing | 1 |
| Central control plane | `saas` (chart) | customer, central + remote clusters | all gateways | central values (admin, proxy, MCP) and each remote cluster's values (proxy, MCP) | central-cluster gateways: the admin catalog. Remote-cluster gateways: the heartbeats. | the plane that serves the gateway | 1 |
| SaaS | — | NeuralTrust | none | — | — | — | 3 |
| Dedicated | — | NeuralTrust | none | — | — | — | 3 |

## Technical approach

```
              ┌──────────────── customer infrastructure ────────────────────────────────────────────┐
              │                                                                                     │
 Helm values ─┼─► agentgateway.secretStores ─► ConfigMap ─► SECRET_STORES_FILE on each agentgateway workload
              │     + ServiceAccount identity (IRSA / GKE WI / AKS WI) + mounted Secrets            │
              │                                                                                     │
              │   ┌── hybrid / remote cluster ──────────┐   ┌── self-hosted / central cluster ─────┐ │
              │   │ proxy · mcp                          │   │ admin · proxy · mcp                   │ │
              │   │  catalog → resolver → materializer   │   │  catalog → resolver → materializer    │ │
              │   │  heartbeat: stores ───────────┐      │   │  admin lists its own catalog          │ │
              │   └──────────────┬───────────────│──────┘   └──────────────┬────────────────────────┘ │
              │                  ▼               │                         ▼                          │
              │        customer vault (Vault · AWS SM · GCP SM · Azure KV · K8s Secrets · env)       │
              └──────────────────────────────────│───────────────────────────────────────────────────┘
                                                 ▼
          control plane (NeuralTrust for hybrid; the customer's own for central):
          config_sync_connections.secret_stores → validates references of its hybrid gateways
```

1. **Stores are configured where they run.**
   - The customer's platform team declares stores in `agentgateway.secretStores`.
   - The chart renders them into `SECRET_STORES_FILE`, a ConfigMap mounted on
     every agentgateway workload of that cluster: proxy and MCP in hybrid;
     admin, proxy and MCP in external and central.
   - The chart mounts the Kubernetes Secrets a store needs. The cloud identity
     is the agentgateway ServiceAccount.
2. **Each gateway has exactly one store source.**
   - A gateway served by its own data plane (`Gateway.ServedByOwnDataPlane()`)
     takes the stores that its live config-sync connections report in the
     heartbeat.
   - Any other gateway is served by the control plane's own cluster, so it
     takes the admin's own catalog, which comes from the same file.
3. **Only references travel.** Admins write `secret://store/path#field`.
   Databases and snapshots carry that string verbatim.
4. **The serving plane resolves.** The `Materializer` substitutes cached values
   where the gateway's runtime model is built. Downstream code does not change.
5. **Tests run where the store lives.** For hybrid gateways the console calls
   the data plane's diagnostics routes; for any other gateway it calls the
   admin. This mirrors how test-connection and model listing are routed today
   (`testRegistryConnectionAction.ts`, `registryModelCatalog.ts`).

## Decisions

| # | Decision | Rejected | Rationale |
|---|---|---|---|
| D1 | **Only customer-operated planes.** Gateway eligibility comes from `SECRET_STORES_GATEWAYS=hybrid\|all`, which every plane reads (default `hybrid`). NeuralTrust's SaaS keeps the default, so only hybrid gateways are eligible. The chart sets `all` in `external` and central installs, where every plane belongs to the customer. Other gateways get 422 `secret_references_not_supported` until Phase 3 (§10). | Use the gateway's `data_plane` alone, which blocks self-hosted because its gateways are not hybrid. Infer it from `INSTANCE_DEPLOYMENT_TYPE`, which the chart does not set (default `self-hosted`). | What matters is who operates the plane that holds the identity and the value, not the gateway's tag. An explicit setting with a safe default cannot be enabled by accident. |
| D2 | **Stores are configured only in the customer's values.** The values become `SECRET_STORES_FILE`, mounted on every agentgateway workload of the cluster. No API creates a store. No TrustGate database stores an address or a credential. The console only generates snippets. | API-configured stores shipped in the snapshot. | This is what makes G3 hold. It also means a console admin can never aim the pod's identity at a host they control: only whoever deploys the pod chooses where that identity is presented. |
| D3 | **One store source per gateway.** `ServedByOwnDataPlane()` → the union of `Heartbeat.secret_stores` over the gateway's live connections. Otherwise → the admin's own catalog. The listing returns `supported` and `source` (`data_plane` \| `control_plane`). | Declare stores again in the console. Always use heartbeats. | Declaring stores twice drifts. In `external` mode config-sync is off and planes read Postgres directly, so there are no heartbeats; but the admin mounts the same file as the proxy, so its own catalog is authoritative. |
| D4 | **References are strings with a URI grammar**, `secret://store/path?version=v#field`, recognised only at declared secret locations (`secretref.Locations`). | A structured object in every DTO. | Every secret field is already a string, typed or in plugin maps. No DTO, snapshot or masking change. Same shape as Kong and LiteLLM. Restricting where references are recognised means one planted in a prompt template or an arbitrary header is just text. |
| D5 | **Only customer-operated planes resolve.** A plane resolves only when it loads a store file. Data planes always may. The admin loads one only in external and central, and then resolves for its own features: test-connection, `/v1/models-catalog` and the store test. NeuralTrust's SaaS admin never resolves. | Let the SaaS admin resolve too. | NeuralTrust's admin has neither network access nor identity in the customer's vault, and holding either is what G3 forbids. |
| D6 | **Materialize in the runtime finders:** `consumer.DataFinder.load` and `registry.Finder`, on every plane that has a catalog. Other runtime readers (§7) call the materializer explicitly. The admin read path never materializes. | Resolve at each call site. Decorate repositories. | About 10 call sites; missing one is the LiteLLM #35239 bug. The finders sit above both the Postgres and the snapshot repositories. A repository decorator would leak values into admin reads. |
| D7 | **In-process cache per replica.** Key: (store, path, version). TTL 5 min. Refresh-ahead from 80 % ± 10 % jitter. Stale-on-error up to `max_stale` (24 h). Negative TTL 30 s. Singleflight. Fetch timeout 2 s. Evicted after 1 h unused. A pinned version never refreshes. | A Redis cache. Persisting values in the LKG. A 24 h TTL with no refresher (LiteLLM). | Redis or the LKG would put plaintext at rest. One fetch per secret per replica per TTL is cheap. |
| D8 | **An unresolved reference becomes an empty value plus `CredentialUnavailable`.** The invoker fails with 503 `secret_unavailable` before dialing. Failover applies. | Forward the reference string. Fail the whole gateway load. | Avoids LiteLLM #26151 (a literal reference sent upstream). A single bad reference must not take down the whole gateway. |
| D9 | **A changed value invalidates only the gateways that use it.** Refresh compares SHA-256 hashes. The reverse index from reference to gateway drops those gateways from the `DataFinder` and `registry.Finder` caches. | Clear every cache. Wait for the 1 h TTL. | Reuses the existing invalidation path, scoped to what changed. |
| D10 | **No reference list in the snapshot.** `secretref.Collector` walks the declared locations. Usages, prewarm and health reporting all use it. | A `secret_refs` snapshot field. | One function, nothing to drift. |
| D11 | **Forced refresh on upstream 401/403**, at most once per reference per 30 s. If the value changed, invalidate and retry once on the same registry, provided nothing was streamed yet. Otherwise fall back to failover. | Wait for the TTL. | Rotation is picked up immediately (G5), and the vault is protected from retry storms. |
| D12 | **Backend clients.** Vault/OpenBao and GCP use REST on TrustGate's HTTP client; GCP reuses the `gcpauth` token cache. AWS uses `service/secretsmanager`. Azure uses `azsecrets`. | `hashicorp/vault/api`, `cloud.google.com/go/secretmanager`. | We need little of each API, and the GCP SDK pulls in the full gRPC client stack. The AWS and Azure modules are small and reuse dependencies we already have. |
| D13 | **Three independent guards keep stores off NeuralTrust-run planes.** (a) The admin validates eligibility (D1). (b) Every plane checks eligibility itself, plus the store's `gateways` allowlist, before resolving. A reference that fails either check stays unresolved with class `not_allowed`. (c) A plane with `INSTANCE_DEPLOYMENT_TYPE=saas` refuses to start with `SECRET_STORES_FILE` set. Our overlays set `saas` (`k8s/overlays/*/config.env`). On top of that, NeuralTrust never ships a store file to its own planes. | A single flag. | Pod identity, environment and files belong to whoever runs the pod. On our planes they are ours, so a single misconfiguration must not expose them. |
| D14 | **Write-time validation against the store source.** **Admin catalog:** the store must exist and allow the gateway and the path. **Heartbeats with at least one live connection:** some live connection must report the store as allowing the gateway and the path, and every live connection must meet the minimum version. **Heartbeats with no live connection:** accept, so config-as-code works before the data plane is deployed. The console shows the store as `not_reported`. | Always require a report. Never validate. | Strict whenever the source is known, permissive only when it cannot be. |
| D15 | **References are not secrets.** They are returned verbatim, and `Mask`/`MaskSettings` pass them through. Writing a reference, or retargeting one (`CredentialDestinations`), needs `secret_stores:read` in addition to the entity scope. | Mask references. Let anyone with entity write add one. | The console must show references and edit them. The scope check keeps parity with today's rule: only a caller who has seen a credential may aim it elsewhere. |
| D16 | **No inline secrets in the store file.** Vault `token`, `secret_id` and `jwt` are only accepted as `*_file` paths, mounted from Kubernetes Secrets. Inline values and unknown keys are refused. | Allow inline credentials. | The file is a ConfigMap; a secret in it leaks. Strict decoding turns typos into errors. |
| D17 | **Optional per-store `gateways` allowlist** (gateway ids). It is enforced by the admin (validation, listing) and by every plane (resolution), and reported in the heartbeat. Empty means every eligible gateway served by that plane. | Rely on `allowed_paths` alone. | In a shared self-hosted or central cluster, every team's gateways share the proxy and the file (G8). Paths limit *what* a store can read. The allowlist limits *who* may use the store. |
| D18 | **Field selection.** `#field` picks a top-level KV or JSON key. With no field, the whole payload is used; Vault KV requires exactly one key in that case. Non-string values are refused. The GCP service-account field takes whole JSON. | JSON pointers. | Covers the one-secret-many-keys layout. Nested paths can be added later in a backward-compatible way. |
| D19 | **Rollout.** Everything is behind `SECRET_STORES_ENABLED` (default off), with version gating through D14. | Docs only. | Old planes ignore references and would send empty credentials. |
| D20 | **Prewarm without a readiness gate.** The plane prewarms in the background after a snapshot apply, a store-file reload or a Postgres cache load. `SECRET_STORES_READINESS_GATE=true` makes readiness wait for it. | Always gate readiness. | A short vault blip must not stop pods from starting. Operators can opt in. |

## 1. Reference grammar

```
reference = "secret://" store "/" path [ "?" "version=" version ] [ "#" field ]
store     = [a-z0-9] *62( [a-z0-9_-] )          ; case-insensitive
path      = segment *( "/" segment )             ; percent-encoded, non-empty, no "." / ".."
field     = 1*( unreserved / pct-encoded )
version   = 1*( unreserved / pct-encoded )
```

- A value without the `secret://` scheme is a literal.
- A value with the scheme that does not match the grammar gets 400
  `invalid_secret_reference`. It is never stored as a literal.
- Maximum length: 1 KiB.

| Store type | `path` | `#field` | `?version=` | Default |
|---|---|---|---|---|
| `hashicorp_vault` KV v2 | under the mount → `GET /v1/<mount>/data/<path>` | key in `data.data` (required unless the secret has exactly one key) | KV version | latest |
| `hashicorp_vault` KV v1 | under the mount → `GET /v1/<mount>/<path>` | key in `data` | refused | — |
| `aws_secrets_manager` | name or ARN | JSON key of `SecretString` | `VersionId` or staging label | `AWSCURRENT` |
| `gcp_secret_manager` | secret id, or `projects/<p>/secrets/<s>` | JSON key | version or alias | `latest` |
| `azure_key_vault` | secret name | JSON key | version id | current |
| `file` | `<k8s-secret>/<key>` under `root` | JSON key | refused | — |
| `env` | variable; must start with `prefix` | JSON key | refused | — |

`allowed_paths` are prefixes of the normalised `path`. `*` must be explicit.

### Declared locations (`secretref.Locations`)

| Entity | Paths | Phase |
|---|---|---|
| Registry (LLM) `auth` | `api_key.api_key`, `api_key.header_value`, `api_key.param_value`, `aws.access_key_id`, `aws.secret_access_key`, `aws.session_token`, `azure.api_key`, `azure.client_secret`, `oauth2.client_secret`, `oauth2.refresh_token`, `oauth2.password`, `gcp_service_account` | 1 |
| Registry `provider_options` | `headers.*` | 1 |
| Registry `mcp_target` | `auth.value`, `auth.client_secret`, `headers.*` | 1 |
| Registry `health_checks` | `headers.*` | 2 |
| Auth (inbound IdP) `config` | `oauth2.client_secret`, `oauth2.exchange_client_secret` | 2 |
| Policy `settings` | plugin `CredentialPaths()` | 2 |
| Consumer `lb_config` | `embedding.auth.*` secret fields | 2 |
| Gateway `telemetry` | `exporters[*].settings.headers.*`, `exporters[*].settings.dsn` | 2 |

Two literal-only checks are skipped for references: `gcpkey.Validate`, and the
AWS "keys or role" check. A reference that resolves to an invalid payload counts
as unresolved (`invalid_payload`).

## 2. Store file and chart

### 2.1 File format (`SECRET_STORES_FILE`)

```yaml
version: 1
stores:
  - name: corp-vault
    type: hashicorp_vault
    allowed_paths: ["ai-gateway/"]
    gateways: []                            # optional allowlist of gateway ids (D17); empty = all eligible
    cache: { ttl: 5m, max_stale: 24h, negative_ttl: 30s }   # optional
    hashicorp_vault:
      address: https://vault.internal:8200
      namespace: admin/ai                   # optional
      mount: kv
      kv_version: 2
      ca_cert_file: /etc/trustgate/secret-stores/corp-vault/ca.crt   # optional
      auth:
        method: kubernetes                  # kubernetes | jwt | approle | token
        role: trustgate
        mount: kubernetes
        # approle: role_id + secret_id_file · token: token_file · jwt: role + jwt_file
  - name: aws
    type: aws_secrets_manager
    allowed_paths: ["prod/llm/"]
    gateways: ["0193f0c2-…-team-a-gateway"]
    aws_secrets_manager: { region: eu-west-1, endpoint: "", assume_role_arn: "" }
  - name: gcp                               # Phase 2
    type: gcp_secret_manager
    allowed_paths: ["llm-"]
    gcp_secret_manager: { project_id: acme-ai }
  - name: azure                             # Phase 2
    type: azure_key_vault
    allowed_paths: ["llm-"]
    azure_key_vault: { vault_url: https://acme-ai.vault.azure.net, client_id: "" }
  - name: k8s
    type: file
    allowed_paths: ["*"]
    file: { root: /var/run/trustgate/secrets }
  - name: env
    type: env
    allowed_paths: ["*"]
    env: { prefix: TG_SECRET_ }
```

**Loader** (`pkg/infra/secretstore/localfile`):
- Decoding is strict: unknown keys are refused, and so are inline `token`,
  `secret_id` and `jwt` (D16).
- Names must be unique, and `allowed_paths` is required.
- The loader refuses to run under `INSTANCE_DEPLOYMENT_TYPE=saas` (D13c).
- It watches the file with `fsnotify`. A valid change swaps the stores
  atomically. An invalid change keeps the previous stores and reports
  `config_error`.

**Auth.** Every method is keyless except Vault AppRole and Vault token.

| Type | Methods |
|---|---|
| Vault/OpenBao | **kubernetes:** the projected ServiceAccount token → `auth/<mount>/login`. **jwt:** `jwt_file`. **approle:** `role_id` + `secret_id_file`. **token:** `token_file`. The token is renewed at 2/3 of its lease; on failure or a 403, the plane logs in again. |
| AWS Secrets Manager | The SDK default chain (IRSA, EKS Pod Identity, instance profile), plus an optional `sts:AssumeRole`. |
| GCP Secret Manager | ADC: GKE Workload Identity, or the key the chart already mounts under `global.gcpIdentity`. |
| Azure Key Vault | `azidentity` workload identity (with `client_id`), else managed identity. |
| `file` | None. Confined to `root` after `Clean` and `EvalSymlinks`. |
| `env` | None. Only variables starting with `prefix`. |

### 2.2 Chart (`NeuralTrust/neuraltrust-platform`)

The `agentgateway` subchart today has:
- one shared `serviceAccount` with `annotations`;
- a shared env ConfigMap (`config`);
- per-workload `extraEnv`;
- no `extraVolumes`.

The admin (`controlPlane`) renders only in external mode. So this needs new
templates. **The key names below are a proposal to agree with the chart
owners (OQ3).**

```yaml
agentgateway:
  secretStores:
    enabled: true            # SECRET_STORES_ENABLED + SECRET_STORES_FILE on admin (external/central), proxy, mcp
    gateways: ""             # SECRET_STORES_GATEWAYS; empty = mode default: hybrid → "hybrid", external/saas → "all"
    readinessGate: false
    stores:
      - name: corp-vault
        type: hashicorp_vault
        allowedPaths: ["ai-gateway/"]
        gateways: []
        hashicorpVault:
          address: https://vault.internal:8200
          mount: kv
          kvVersion: 2
          caCert: { secretName: vault-ca, key: ca.crt }
          auth: { method: kubernetes, role: trustgate }
      - name: k8s
        type: file
        allowedPaths: ["*"]
        file: { secrets: [llm-provider-keys, mcp-tokens] }   # mounted at <root>/<secret>/<key>
  serviceAccount:
    annotations:
      eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/trustgate-secrets
      # GKE: reuse global.gcpIdentity (method: workload-identity) / iam.gke.io/gcp-service-account
      # AKS: azure.workload.identity/client-id
```

What the chart does:
- It renders `stores` into a ConfigMap. It mounts that ConfigMap at
  `/etc/trustgate/secret-stores.yaml` on every agentgateway workload the mode
  deploys.
- It mounts each Secret named under `caCert`, `secretIdSecret`, `tokenSecret`
  and `file.secrets`, and rewrites each one to the matching `*_file` path.
- It derives `SECRET_STORES_GATEWAYS` from `global.deploymentMode` unless set
  explicitly.

For Docker Compose (`downloads/docker-compose.yml`, hybrid), the operator
mounts the file and the referenced files and sets the variables.

### 2.3 Store source per gateway

```
source(G) =
  G.ServedByOwnDataPlane()  → union over G's live config-sync connections of Heartbeat.secret_stores
                              (filtered by each store's gateways allowlist)            source = data_plane
  otherwise                 → the admin's own catalog, if it loaded SECRET_STORES_FILE
                              (filtered by gateways allowlist)                         source = control_plane
  supported(G) = SECRET_STORES_ENABLED ∧ eligible(G) ∧ (own data plane ∨ admin has a catalog)
```

On NeuralTrust's SaaS admin, a hosted gateway is neither eligible nor has a
catalog, so `supported=false`. A hybrid gateway is `supported`, with source
`data_plane`.

On a customer `external` admin, every gateway is `supported`, with source
`control_plane`.

On a customer central admin:
- central-cluster gateways → `control_plane`;
- remote-cluster gateways → `data_plane`.

**Additive heartbeat fields** in `configsync.proto`:

```proto
message Heartbeat {
  // … existing fields 1–5 …
  repeated SecretStoreStatus secret_stores = 6;   // Phase 1
  SecretRefHealth secret_refs = 7;                // Phase 2
}
message SecretStoreStatus {
  string name = 1;
  string type = 2;
  repeated string allowed_paths = 3;
  string state = 4;            // ok | auth_failed | unavailable | config_error | not_allowed
  string error_class = 5;
  string checked_at = 6;       // RFC3339
  repeated string gateways = 7;
}
message SecretRefHealth {
  uint32 total = 1;
  uint32 unresolved = 2;
  repeated SecretRefFailure failing = 3;   // capped at 50
}
message SecretRefFailure { string gateway_id = 1; string store = 2; string path = 3; string field = 4; string error_class = 5; }
```

**State.** The plane combines a credential-level probe with the outcome of the
last fetch. The probe runs every 60 s and needs no secret permission:
- Vault: `lookup-self`;
- AWS: `GetCallerIdentity`;
- GCP and Azure: acquiring a token;
- `file` and `env`: checking that the root or prefix is readable.

**Persistence.** `config_sync_connections` gains `secret_stores JSONB` and
`secret_refs JSONB` (additive migration). They are written by
`configsyncconn.Repository.MarkHeartbeat`
(`pkg/infra/repository/configsyncconn/repository.go:115`).

The admin's own catalog is probed the same way and served from memory.

## 3. Data flows

### 3.1 Write a reference (admin)

```
PUT /v1/gateways/G/registries/R  { auth: { type: api_key, api_key: { api_key: "secret://corp-vault/ai-gateway/openai#api_key" } } }
  secretref.Validator
    ├─ SECRET_STORES_ENABLED                         else 422 secret_references_disabled
    ├─ declared location?                            else literal (D4)
    ├─ Parse                                         else 400 invalid_secret_reference
    ├─ eligible(G) (D1)                              else 422 secret_references_not_supported
    ├─ caller holds secret_stores:read               else 403
    └─ source(G):
         control_plane → store in catalog, allows G, path allowed          else 422 unknown_secret_store / secret_path_not_allowed
         data_plane, ≥1 live → reported by a live connection, allows G, path allowed; every live ≥ min version
                                                                          else 422 unknown_secret_store / secret_path_not_allowed / data_plane_too_old
         data_plane, none live → accept (store shown "not_reported")
  repository: as today; outbox marker for G
  log "secret_reference_set" {gateway, entity, field, store, path, actor}
```

### 3.2 Distribution

**Hybrid and remote clusters.** The compiler copies the reference verbatim into
the gateway's scoped snapshot. The proto is unchanged.

**External and the central cluster.** Proxy and MCP read Postgres directly
(config-sync is off in external). The reference is the stored string.

### 3.3 Serve

```
request ─► DataFinder.FindByGateway(G)
             hit  ─► *Data (already materialized)
             miss ─► load(G) raw ─► Materializer
                       per reference: eligible(G) on this plane? store loaded? store allows G? path allowed?
                                                         else unresolved (not_allowed | store_missing | path_not_allowed)
                       Resolver.Resolve ─► cache | singleflight fetch (≤ 2 s)
                       ok → substitute; reverse index ref → G   ·   err → "" + CredentialUnavailable
             ─► provider.prepare: CredentialUnavailable → 503 secret_unavailable (failover may apply)
                                  else CredentialsFromTargetAuth(materialized) ─► upstream
```

On an external or central admin, test-connection and model listing go through
`registry.Finder`, so they resolve the same way. On NeuralTrust's SaaS admin
there is no catalog: every reference stays unresolved there, and those features
never run there for hybrid gateways anyway.

### 3.4 Rotation

| Trigger | Behaviour |
|---|---|
| Refresher tick (15 s) | Re-fetch entries at `age ≥ 0.8·ttl ± jitter` that were used in the last hour. A new hash invalidates the dependent gateways (D9). |
| Upstream 401/403 on a registry with `SecretRefs` | `ForceRefresh`, at most once per reference per 30 s. If the value changed: invalidate and retry once (D11). |
| `SECRET_STORES_FILE` changed | Swap the stores, rebuild the clients of the changed stores, refresh their entries. |
| Pinned `?version=` | Never refreshed. |

The Bedrock pool key hashes the secret key and the session token
(`pkg/infra/providers/bedrock/client.go:386`). The MCP dial revision hashes the
materialized credential (`pkg/app/mcp/target.go:123`).

### 3.5 Cache states and error classes

```
  (miss) ─ok─► FRESH ─age ≥ 0.8·ttl─► REFRESHING ─ok─► FRESH
     │ error                              │ error
     ▼                                    ▼
  NEGATIVE (neg_ttl)                  STALE (< ttl + max_stale): serve  ·  DEAD (≥): secret_unavailable
```

| Class | Behaviour |
|---|---|
| `not_found`, `access_denied`, `field_not_found`, `invalid_payload` | Negative cache. Stale is served only for an entry that resolved before. |
| `unavailable`, `auth_failed` | Retried with backoff (5 s → TTL), or with a re-login for `auth_failed`. Stale is served. |
| `store_missing`, `not_allowed`, `path_not_allowed` | Unresolved. No fetch is attempted. |

## 4. Security model

| Threat | Control |
|---|---|
| A NeuralTrust SaaS tenant uses NeuralTrust's pod identity, environment or files. | The three guards of D13. NeuralTrust never ships a store file. |
| One team reads another team's secrets in a shared self-hosted or central cluster. | The `gateways` allowlist (D17), enforced by the admin and by every plane. Separate stores per team, with disjoint `allowed_paths`. The generator prefills the allowlist with the current gateway. |
| A console admin aims the pod identity at a host they control. | Addresses and auth exist only in Helm values (D2). |
| Exfiltration through references. | `allowed_paths` enforced where the store lives. `secret_stores:read` to write or retarget a reference (D15). `secret_reference_set` audit. Least-privilege policies from the generator. References are recognised only at declared locations (D4). |
| A value at rest or in transit through TrustGate storage. | Never in Postgres, Redis, snapshots, the LKG, heartbeats, logs or responses (G3). |
| A value in test output. | Admin and diagnostics tests return metadata only. |
| Path traversal or env harvesting. | `file` is confined to its root. `env` requires a prefix. `allowed_paths` applies to both. |
| Diagnostics route abuse. | The existing per-gateway, per-user diagnostics token. The route enforces `allowed_paths` and the `gateways` allowlist. |

## 5. Interfaces / contracts

```go
// pkg/domain/secretref
type Ref struct{ Store, Path, Field, Version string }

func Parse(s string) (Ref, bool, error) // ok=false: literal
func IsRef(s string) bool
func (r Ref) PayloadKey() string        // store|path|version

var Locations []Location

// pkg/domain/secretstore
type Type string
type Eligibility string // "hybrid" | "all"

type Store struct {
    Name         string
    Type         Type
    AllowedPaths []string
    Gateways     []ids.GatewayID
    Cache        CachePolicy
    Config       any
}

func (s *Store) Allows(gw ids.GatewayID, path string) error // ErrNotAllowed / ErrPathNotAllowed

type Status struct {
    Name, State, ErrorClass string
    Type                    Type
    AllowedPaths            []string
    Gateways                []ids.GatewayID
    CheckedAt               time.Time
}

//go:generate mockery --name=Backend ...
type Backend interface {
    Fetch(ctx context.Context, path, version string) (Secret, error)
    Probe(ctx context.Context) error
}

//go:generate mockery --name=Catalog ...
type Catalog interface {
    Get(name string) (*Store, Backend, bool)
    Statuses() []Status
}

func Eligible(e Eligibility, gw *gateway.Gateway) bool // all → true; hybrid → gw.Entitlements.DataPlane == hybrid

// pkg/app/secretref
type Resolver interface {
    Resolve(ctx context.Context, ref secretref.Ref) (string, error)
    ForceRefresh(ctx context.Context, refs []secretref.Ref) (bool, error)
    OnChange(fn func([]secretref.Ref))
}

type Materializer interface {
    Gateway(ctx context.Context, gw *gateway.Gateway, d *consumer.Data) (*consumer.Data, []Unresolved)
    Registry(ctx context.Context, gw *gateway.Gateway, r *registry.Registry) (*registry.Registry, []Unresolved)
}

type Collector interface {
    Collect(ctx context.Context, gatewayID ids.GatewayID) ([]Use, error)
}

type Validator interface {
    Validate(ctx context.Context, gw *gateway.Gateway, caller Caller, uses []Use) error
}

// pkg/app/secretstore (admin)
type SourceResolver interface { // §2.3
    Source(ctx context.Context, gw *gateway.Gateway) (Source, error) // Supported, Kind, Stores
}

type Lister interface {
    List(ctx context.Context, gatewayID ids.GatewayID) (Listing, error)
}

type UsagesFinder interface {
    Usages(ctx context.Context, gatewayID ids.GatewayID, store string) ([]secretref.Use, error)
}

type Tester interface { // admin catalog only
    Test(ctx context.Context, gatewayID ids.GatewayID, store string, in TestInput) (TestResult, error)
}
```

The materializer never mutates its input. It returns copies.

## 6. API

### Admin

Guarded by `RequireGatewayAccess(ResourceSecretStores)`, which maps to
`secret_stores:read`.

| Route | Behaviour |
|---|---|
| `GET /v1/gateways/:gateway_id/secret-stores` | Returns `{ supported, source: data_plane\|control_plane, stores: [{ name, type, allowed_paths, status: ok\|degraded\|down\|not_reported, consistent, instances: [{instance_id, version, state, error_class, checked_at}], usages }] }`. Stores whose allowlist excludes the gateway are omitted. With source `control_plane`, `instances` holds the admin replica. |
| `GET …/:name/usages` | `[{ entity, id, name, field, reference }]` |
| `POST …/:name/test` | Only when `source=control_plane`. Body `{ path?, field?, version? }`. Returns `{ auth, read, version, latency_ms }`, never the value. With `source=data_plane` it answers 409 `test_runs_on_data_plane`. |

### Data plane

| Route | Behaviour |
|---|---|
| `POST /__diagnostics/gateways/:gateway_id/secret-stores/:name/test` | Same contract as the admin test. Authorized by the existing diagnostics token. Registered before the transport, like the existing diagnostics routes. |

### Error codes

| Code | Status | Where |
|---|---|---|
| `invalid_secret_reference` | 400 | admin |
| `secret_references_disabled` | 422 | admin |
| `secret_references_not_supported` | 422 | admin |
| `unknown_secret_store` | 422 | admin |
| `secret_path_not_allowed` | 422 | admin |
| `data_plane_too_old` | 422 | admin |
| `test_runs_on_data_plane` | 409 | admin |
| `secret_unavailable` | 503 | serving plane; the body names neither store nor path |

## 7. Runtime readers that must materialize

| Reader | Location | Planes |
|---|---|---|
| `consumer.DataFinder.load` | `pkg/app/consumer/data_finder.go` | proxy, MCP |
| `registry.Finder` | `pkg/app/registry/finder.go:48-62` | proxy, MCP, admin with catalog |
| Admin test-connection, `/v1/models-catalog` (`pkg/container/modules/catalog.go:139,187`) | through `registry.Finder` | admin with catalog |
| Diagnostics test-connection and models | `pkg/api/handler/http/diagnostics/*` | data plane |
| MCP static target / credentials | `pkg/app/mcp/target.go`, `credentials.go` | MCP |
| Traffic-label classifier | `pkg/infra/labelllm/classifier.go:117` | worker (through `registry.Finder`) |
| Telemetry exporters, consumer embedding | `pkg/infra/telemetry`, `pkg/domain/consumer/lb_config.go` | Phase 2 |

A test in `pkg/app/secretref` wires the runtime modules with a reference and a
fake catalog. It asserts that no provider client, plugin or exporter ever
receives a `secret://` string.

## 8. Console (`NeuralTrust/app`)

The same code ships in SaaS and on-prem (`DEPLOYMENT_MODE=external`). Whether
the feature appears is driven by the admin's `supported` flag, never by the
console's own mode.

### 8.1 Settings → Gateway → "Secret stores" tab

- **Visibility.** The tab is shown when `GET …/secret-stores` returns
  `supported: true`:
  - hybrid gateways on NeuralTrust SaaS;
  - every gateway on a self-hosted or central console.
- **Header.** It names where the stores are configured:
  - `data_plane`: "in the Helm values of this gateway's data plane";
  - `control_plane`: "in your platform's Helm values".
- **Table.** Name, type, allowed paths, status (with an inconsistency warning),
  used-by count, last checked.
- **Row detail.**
  - Per-instance state and error-class hints, for example: `access_denied` →
    "check the vault policy for this path"; `auth_failed` → "check the auth role
    bound to the agentgateway ServiceAccount".
  - Usages.
  - **"Test a secret"**. Hybrid gateways call the data plane's diagnostics
    route. Every other gateway calls `POST /v1/gateways/:id/secret-stores/:name/test`.
    This is the same branching as `testRegistryConnectionAction`.
- **Empty state.** "No secret store is available to this gateway", with an
  **"Add a secret store"** button and a docs link.

### 8.2 "Add a secret store" generator

The generator saves nothing in NeuralTrust.

1. **Type.** Vault / OpenBao, AWS Secrets Manager, GCP Secret Manager (Phase 2),
   Azure Key Vault (Phase 2), Kubernetes Secrets or environment variables.
2. **Form.**
   - Common fields: *Name*, *Allowed paths* and *Gateways*, prefilled with the
     current gateway; the user can clear it to allow all eligible gateways.
     Under *Advanced*: cache TTL and max stale.
   - Type-specific fields (below). **No secret inputs.**

   | Type | Connection | Auth (default first) | Generated prerequisites |
   |---|---|---|---|
   | Vault / OpenBao | Address\*, Namespace, KV mount\* (`secret`), KV version (2), CA (Secret name/key) | **Kubernetes**: role\*, auth mount · JWT · AppRole: role ID\*, Secret with `secret_id`\* · Token: Secret\* | Policy HCL (`read` on `<mount>/data/<allowed>*`) and `vault write auth/kubernetes/role/<role> bound_service_account_names=agentgateway bound_service_account_namespaces=<ns> policies=<policy>` |
   | AWS Secrets Manager | Region\*, VPC endpoint, Role to assume | **IRSA / Pod Identity**: role ARN\* | IAM policy JSON (`secretsmanager:GetSecretValue` on `…:secret:<allowed>*`, `kms:Decrypt` if CMK) |
   | GCP Secret Manager | Project ID\* | **Workload Identity**: GSA email\* (or the existing `global.gcpIdentity`) | `gcloud secrets add-iam-policy-binding … roles/secretmanager.secretAccessor` |
   | Azure Key Vault | Vault URL\* | **AKS Workload Identity**: client ID\* | `az role assignment create --role "Key Vault Secrets User" …` |
   | Kubernetes Secrets | Secret names\* | — | — |
   | Environment | Prefix\* | — | — |

3. **Output.**
   - The `agentgateway.secretStores` snippet, plus the ServiceAccount
     annotation if one is needed.
   - The prerequisites.
   - The `helm upgrade` command.
   - A note on which values file it goes into: hybrid uses that data plane's
     values (reusing `privateDeployValues.ts`); `control_plane` uses the
     platform values.
   - A **"waiting for `<name>` to be reported"** poller on the listing, which
     ends in `ok` or in the reported error.

### 8.3 `SecretInput`

`SecretInput` covers every field with `secret: true`:
- `RegistrySchemaFieldRenderer`, `GcpServiceAccountField`, `McpServerConfigPanel`
  (Phase 1);
- policy credentials and telemetry headers (Phase 2).

```
API key   ( Value | From secret store )
  Store    [corp-vault ▾]  ● ok
  Path     ai-gateway/openai         allowed: ai-gateway/
  Key      api_key
  Version  latest                    ▸ advanced
  [Test]   ✓ Resolved · version 7 · 84 ms
  secret://corp-vault/ai-gateway/openai#api_key   [copy]
```

- **Visibility.** Shown only when `supported`.
- **Default mode.** *Value*, so existing flows are unchanged. *From secret
  store* is preselected when stores exist and the field is empty.
- **Editing.** A stored reference opens parsed, in *From secret store* mode.
- **Test.** Same routing as the tab.
- **No source yet.** With `source=data_plane` and no live connection, a
  free-text store name is allowed, with a warning (D14).
- **Badges and audit.** Cards show a "from `<store>`" badge. Server actions log
  `secret_reference.set` through `logV2AuditEvent`.

## 9. Configuration (`pkg/config`, `.env.example`)

| Variable | Default | Plane | Meaning |
|---|---|---|---|
| `SECRET_STORES_ENABLED` | `false` | all | Master switch. |
| `SECRET_STORES_GATEWAYS` | `hybrid` | all | Eligibility (D1). The chart sets `all` for external and central. |
| `SECRET_STORES_FILE` | — | admin (external, central), proxy, MCP | Store file (§2.1). Refused under `INSTANCE_DEPLOYMENT_TYPE=saas`. |
| `SECRET_STORES_FETCH_TIMEOUT` | `2s` | resolving planes | Per-fetch timeout. |
| `SECRET_STORES_REFRESH_INTERVAL` | `15s` | resolving planes | Refresher tick. |
| `SECRET_STORES_PROBE_INTERVAL` | `60s` | resolving planes | Health probe. |
| `SECRET_STORES_READINESS_GATE` | `false` | resolving planes | Readiness gate (D20). |
| `SECRET_STORES_MIN_DATA_PLANE_VERSION` | first release with the feature | admin | Version gating. |

## 10. Phase 3 outline: NeuralTrust SaaS and dedicated (not in this change)

These planes run on NeuralTrust's infrastructure, with no customer workload
identity. Two options, decided in their own design review:

1. **Keyless federation (preferred).**
   - TrustGate becomes an OIDC issuer: a discovery document and JWKS on a
     dedicated key. The STS signer and `/.well-known/jwks.json` are building
     blocks.
   - It mints short-lived tokens with `sub=gateway:<id>`.
   - Customers trust that subject in AWS IAM (`AssumeRoleWithWebIdentity`), GCP
     WIF, Azure federated credentials or Vault JWT auth.
   - A per-gateway subject avoids the confused deputy that a shared identity
     would create. That is the same reason Model Armor refuses ambient identity
     on shared planes.
2. **API-managed stores with sealed credentials**, only if federation is not
   enough.
   - `FieldSealer` under purpose `secret-stores/v1`.
   - Credentials masked in responses.
   - A changed destination requires re-entering the credential.
   - `netguard` on addresses, an allowlist of Azure URL suffixes, no custom AWS
     endpoint.

Eligibility would then widen on NeuralTrust's admin. Everything else carries
over: grammar, locations, resolver, materializer and console.

## 11. File changes

### TrustGate

| File | Change |
|---|---|
| `pkg/domain/secretref/{ref.go,locations.go}` (+ fuzz) | grammar, locations |
| `pkg/domain/secretstore/{store.go,config.go,backend.go,catalog.go,eligibility.go,errors.go}` + `mocks/` | model, ports, eligibility, errors |
| `pkg/app/secretref/{resolver.go,cache.go,refresher.go,materializer.go,collector.go,validator.go}` + `mocks/` | resolution core, validation |
| `pkg/app/secretstore/{source.go,lister.go,usages.go,tester.go}` + `mocks/` | store source, admin listing, usages, test |
| `pkg/infra/secretstore/{hashicorp,awssm,gcpsm,azurekv,filestore,envstore}/` | backends |
| `pkg/infra/secretstore/localfile/{loader.go,watch.go}` | loader, reload, `saas` guard |
| `configsync.proto` (+ generated), `pkg/infra/configsync/grpc/{heartbeat.go,hub.go}`, `pkg/domain/dataplane/heartbeat.go` | heartbeat fields |
| migration `<ts>_config_sync_connections_secret_stores.go`, `pkg/infra/repository/configsyncconn/repository.go` | persist reports |
| `pkg/app/consumer/data_finder.go`, `pkg/app/registry/finder.go`, §7 readers | materializer + invalidation |
| `pkg/app/proxy/provider.go`, `pkg/app/mcp/*`, `pkg/infra/providers/bedrock/client.go` | `CredentialUnavailable`, forced refresh, cache keys |
| `pkg/common/secret/{secret.go,settings.go}` | reference pass-through |
| `pkg/domain/registry/{target.go,mcp_target.go}`, `pkg/app/registry`, `pkg/app/policy/updater.go` | validator calls |
| `pkg/api/handler/http/secretstore/{list,usages,test}_handler.go` + `response/…` | admin routes |
| `pkg/api/handler/http/diagnostics/secret_store_test_handler.go` | data-plane route |
| `pkg/api/middleware/admin_scopes.go`, `pkg/server/router/{admin,proxy}_router.go` | scope, routes |
| `pkg/container/modules/secretstore.go` | DI: catalog, resolver, refresher, probe (any plane with a file); source, lister, validator (admin) |
| `pkg/config/config.go`, `.env.example`, `downloads/docker-compose.yml` | variables, compose example |
| `docs/openapi.json`, `swagger.*` | API |

### Other repositories

| Repository | Change |
|---|---|
| `NeuralTrust/neuraltrust-platform` | `agentgateway.secretStores` templates (ConfigMap, mounts on admin, proxy and MCP per mode, Secret mounts, env); `VALUES_SCENARIOS.md`, `SECRETS.md`; render tests per mode |
| `NeuralTrust/app` | tab, generator, `SecretInput`, server actions, i18n |
| `NeuralTrust/docs` | `neuraltrust/deployment/secrets.mdx` ("Provider credentials from your secret manager"), `configuration.mdx` (`agentgateway.secretStores`), hybrid and external pages, a Secret stores guide per backend |

## 12. Testing strategy

- **Grammar:** table tests plus `FuzzParse`.
- **Eligibility and source:**
  - `hybrid` vs `all`;
  - each model's gateway (hosted, hybrid, dedicated) on a SaaS-style admin and
    on an external-style admin;
  - `ServedByOwnDataPlane` vs admin catalog;
  - `supported` flags;
  - the gateways allowlist.
- **Validator:**
  - every location accepts a reference; anything else is a literal;
  - catalog source: unknown store, path, allowlist;
  - heartbeat source: live vs none, version too old;
  - missing scope.
- **Masking:** references pass through; retargeting needs the scope.
- **Loader:**
  - strict decoding, no inline secrets, duplicates rejected;
  - the `saas` guard;
  - reload swaps on a valid file and keeps the old stores plus `config_error`
    on an invalid one.
- **Resolver** (fake clock and backend):
  - refresh, same hash vs new hash;
  - stale, then dead;
  - negative cache;
  - singleflight: 100 concurrent requests make 1 fetch;
  - forced-refresh rate limit;
  - pinned versions;
  - eviction;
  - run with `-race`.
- **Materializer:**
  - every location;
  - unresolved → empty plus `CredentialUnavailable`;
  - no mutation of the input;
  - guard D13b (eligibility, allowlist).
- **Backends:**
  - Vault KV v1/v2 with Kubernetes, AppRole and token login and renewal
    (`httptest`);
  - AWS through an injected client;
  - `file` traversal;
  - `env` prefix;
  - optional Vault dev container and LocalStack.
- **Discovery:**
  - heartbeat round trip;
  - `MarkHeartbeat` persistence;
  - listing union and `consistent`;
  - the admin catalog listing.
- **Tests (admin and diagnostics):**
  - token or scope required;
  - the value never appears in the body;
  - allowlist and paths enforced.
- **End to end:**
  - **Hybrid:** DB-less plane, store file, fake Vault, `httptest` upstream.
    Serve, rotate, 401 retry, outage. No value in the logs or the snapshot.
  - **External:** `run` with the admin catalog. Validation through
    `control_plane`; test-connection resolves on the admin; the proxy serves.

## 13. Rollout

1. Merge the TrustGate slices with `SECRET_STORES_ENABLED=false`. The schema
   and proto changes are additive.
2. Release the images, then the chart with `agentgateway.secretStores`. Render
   tests cover hybrid, external and central.
3. Validate on internal clusters:
   - hybrid on EKS with IRSA, connected to dev;
   - external on GKE with Vault Kubernetes auth;
   - central with one remote cluster.
4. Enable the console behind a feature flag for selected tenants and on-prem
   customers.
5. Publish the docs pages (§11).

**Rollback:** turn the flag off. The usages endpoint lists the references to
replace with literals.

## Rejected alternatives

- **R1. Resolve in the compiler and ship the values.** The values end up in
  snapshots, the admin cannot reach private vaults, and rotation depends on
  recompiles.
- **R2. API-managed stores as the primary model.** NeuralTrust or the admin
  database would hold vault credentials, and the pod identity could be aimed by
  console admins. This is kept as a Phase 3 fallback.
- **R3. Declaring stores in the console as well.** Double entry that drifts.
- **R4. Eligibility from `data_plane=hybrid` alone.** It excludes self-hosted
  and central installs (D1).
- **R5. Eligibility from `INSTANCE_DEPLOYMENT_TYPE`.** The chart does not set
  it, so it defaults to `self-hosted`. The variable describes the heartbeat, not
  who operates the plane, so it is used only as an extra guard (D13c).
- **R6. A structured reference object.** See D4.
- **R7. Resolving at each call site.** See D6.
- **R8. A Redis or LKG cache of values.** Plaintext at rest.
- **R9. Only documenting sidecars (ESO, CSI, Vault Agent).** One file or env
  var per secret, and restarts. Those mounts are still supported through the
  `file` and `env` stores, with no restart.
- **R10. `os.environ/NAME`.** No store, field or version, and it is ambiguous.

## Open questions

- **OQ1.** Default `max_stale`: 24 h (availability) or 1 h (revocation)?
- **OQ2.** Opt-in LKG persistence of resolved values on hybrid or remote planes
  (off by default)?
- **OQ3.** `agentgateway.secretStores` keys, mount conventions and the
  per-mode default of `SECRET_STORES_GATEWAYS`, to agree with the chart owners.
- **OQ4.** Packaging: is it gated behind a plan or entitlement? Note: on-prem
  consoles resolve unrestricted entitlements (`resolveTeamEntitlements.ts`).
- **OQ5.** Phase 3: federation issuer design, and whether API-managed stores
  are needed at all.
- **OQ6.** Should GCP Secret Manager and Azure Key Vault move into Phase 1 for
  self-hosted customers on GKE or AKS?
