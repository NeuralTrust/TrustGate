# Design: External secret stores for hybrid gateways (vault references)

## Linked artifacts

- **Proposal (binding):** [`proposal.md`](./proposal.md), goals G1–G7.
- **Research:** [`exploration.md`](./exploration.md). It covers the TrustGate
  secret inventory E1–E11, LiteLLM, Kong and Portkey.
- **Specs:**
  - [`secret-references`](./specs/secret-references/spec.md)
  - [`secret-stores`](./specs/secret-stores/spec.md)
  - [`secret-resolution`](./specs/secret-resolution/spec.md)
  - [`secret-stores-console`](./specs/secret-stores-console/spec.md)
- **Linear:** _pending_.
- **Conventions:** `.agents/AGENTS.md`.
  - Hexagonal layers.
  - One use case per file.
  - DI in `pkg/container/modules`.
  - One DTO per file.
  - mockery mocks.
  - Environment variables only through `pkg/config`.

## Technical approach

```
 CUSTOMER NETWORK                                                 NEURALTRUST SAAS
┌───────────────────────────────────────────────────────────┐    ┌───────────────────────────────────────────────┐
│ Helm values (platform team)                               │    │ Console (NeuralTrust/app)                     │
│   agentgateway.secretStores ─► ConfigMap ─► SECRET_STORES_FILE   │   Settings ▸ Gateway ▸ Secret stores         │
│   serviceAccount annotations (IRSA / Workload Identity)   │    │   "Add a secret store" → values snippet       │
│   Secret mounts (AppRole secret_id, CA, K8s secrets)      │    │   SecretInput in every secret field           │
│                                                           │    │        │ admin API          │ diagnostics      │
│ Hybrid data plane (proxy / mcp)                           │    │        ▼                    │ (HTTPS, token)   │
│   local stores ─► Resolver (cache) ─► Materializer        │◄───┼── snapshot: refs "secret://…" only           │
│        │                       ▲                          │    │                             │                  │
│        │                       └── runtime finders        │────┼─► heartbeat: stores {name,type,paths,state}  │
│        ▼                                                  │    │    → config_sync_connections.secret_stores    │
│   customer vault: Vault · AWS SM · GCP SM · Azure KV · K8s │◄───┼─────────────────────────────┘                  │
└───────────────────────────────────────────────────────────┘    └───────────────────────────────────────────────┘
```

1. **Stores are configured where they run.** The customer's platform team
   declares each store in the Helm values of the hybrid data plane. The chart
   renders them into `SECRET_STORES_FILE`, mounts any Kubernetes Secret the
   store needs, and puts the cloud identity on the data plane's ServiceAccount.
2. **The data plane reports its stores.** Each config-sync heartbeat carries
   name, type, allowed paths and health. The admin persists it on
   `config_sync_connections`. The console lists it and validates references
   against it.
3. **The control plane carries references only.** An admin stores
   `secret://store/path#field` in the credential field, and the compiler copies
   it into the scoped snapshot verbatim.
4. **The data plane resolves.** The `Materializer` swaps references for cached
   values where the gateway's runtime model is built. Downstream code is
   unchanged: provider clients, plugins, MCP dialer and exporters.
5. **Tests run on the data plane.** The console calls
   `/__diagnostics/gateways/:gateway_id/secret-stores/:name/test`, just as it
   already calls the hybrid test-connection and model-listing routes.

## Decisions

| # | Decision | Rejected | Rationale |
|---|---|---|---|
| D1 | **Hybrid first.** Phases 1–2 support references only on gateways whose `Entitlements.DataPlane` is `hybrid`. For any other gateway the admin answers 422 `secret_references_not_supported`. Hosted and dedicated come in Phase 3, after a design review of keyless federation (§9). | Ship hosted, dedicated and hybrid together with API-managed stores. | Only a hybrid data plane can reach a private vault and use the customer's own workload identity, so only there does a reference remove every credential from NeuralTrust (G3). On hosted, NeuralTrust would still hold a credential that reads the vault: the "secret zero" problem. Dedicated planes are run by NeuralTrust (`pkg/domain/gateway/entitlements.go:40-48`), so the same applies. |
| D2 | **Store configuration lives only on the data plane** (Helm values → `SECRET_STORES_FILE`). The control plane never stores a store's address, auth or credentials. The console only generates a snippet. | Configure stores through the Admin API and ship them in the snapshot. | This is what makes G3 hold. It also closes the attack where a console admin aims the pod's identity at a host they control: only whoever deploys the pod chooses where its identity is presented. |
| D3 | **Discovery, not declaration.** The data plane reports its stores in `Heartbeat.secret_stores`. The admin persists the report per connection and serves the union across a gateway's live connections. | Ask admins to also declare each store in the console. | Declaring a store twice lets the console and the Helm values drift apart. The heartbeat already identifies the connection and its scope (`config_sync_connections`, keyed by scope and instance), and a scoped data plane's scope is its gateway. |
| D4 | **The reference is a string with a URI grammar,** `secret://store/path?version=v#field`. It is recognised only at declared secret locations (`secretref.Locations`). | A structured `{"secret_ref":{…}}` object in every DTO. | Every secret field is already a string, whether typed or inside plugin `map[string]any`. A string needs no change to any DTO, snapshot JSON or masking helper, and it matches Kong and LiteLLM. Restricting where references are recognised stops one from being planted in a prompt template or a non-secret header. |
| D5 | **Only the data plane resolves.** In Phases 1–2 the control plane never contacts a vault. Admin features that need the credential already run on the hybrid data plane: the console calls `/__diagnostics/…/registries/test-connection` and `/__diagnostics/…/models` (`pkg/server/router/proxy_router.go:25-32`). The admin's model-listing fallback cannot resolve, so it lists the whole catalog, which is the degradation it already applies when the data plane does not answer. | Let the admin resolve too. | The admin could not reach a private vault, and it has no identity there anyway. |
| D6 | **Materialize in the runtime finders:** `consumer.DataFinder.load` and `registry.Finder`. Other runtime readers (§6) call the materializer explicitly. The admin read path never materializes. | Resolve at every call site. Decorate the repositories. | About 10 call sites span providers, plugins, MCP and telemetry, and missing one is the LiteLLM #35239 class of bug. The finders sit above both the Postgres and the snapshot repositories. A repository decorator would also materialize admin reads. |
| D7 | **The cache is in-process and per replica.** Key: (store, path, version). TTL 5 min. Refresh-ahead from 80 % of the TTL, with ±10 % jitter. Stale-on-error up to `max_stale` (24 h). Negative TTL 30 s. Singleflight. Fetch timeout 2 s. An entry unused for 1 h is evicted. A pinned version never refreshes. | Share the cache in Redis. Persist values in the LKG. Use LiteLLM's 24 h TTL with no refresher. | Redis or the LKG would put plaintext at rest, which breaks G3. The fetch rate is one per secret per replica per TTL. Refresh-ahead keeps requests on cache hits. |
| D8 | **An unresolved reference becomes an empty value and the entity is marked `CredentialUnavailable`.** The invoker fails with 503 `secret_unavailable` before dialing. Registry failover applies. | Send the reference string on. Fail the whole gateway load. | LiteLLM #26151 sent the literal reference upstream. Failing the whole load would let one bad reference take down every route of the gateway. |
| D9 | **A changed value invalidates only the gateways that use it.** Refresh compares a SHA-256 of the payload. When it differs, the materializer's reverse index (reference → gateway ids) drops those gateways from the `DataFinder` and `registry.Finder` caches. | Clear every TTL map. Wait for the 1 h `consumer_data` TTL. | This reuses the existing invalidation hooks, and only the affected gateways rebuild. |
| D10 | **Nothing in the snapshot lists references.** `secretref.Collector` walks the gateway's entities over the declared locations. The usages API, prewarm and health reporting all use it. | A `secret_refs` snapshot field. | One function serves every caller, and there is no second source of truth that could drift. |
| D11 | **On an upstream 401 or 403, force a refresh.** It applies when the credential came from a reference, at most once per reference per 30 s. If the value changed, invalidate and retry the request once on the same registry, provided it is not streaming or nothing has been sent yet. Otherwise fall through to failover. | Wait for the TTL. | Rotation is picked up immediately (G5). The rate limit protects the vault. |
| D12 | **Backend clients.** Vault/OpenBao and GCP Secret Manager use REST on TrustGate's HTTP client; GCP reuses the `gcpauth` token cache. AWS uses `service/secretsmanager`; Azure uses `azsecrets`. | `hashicorp/vault/api`, `cloud.google.com/go/secretmanager`. | Each needs only a small part of the API. The GCP SDK pulls in the full gRPC client stack. The AWS and Azure modules are small and reuse dependencies already in `go.mod`. |
| D13 | **Three independent guards keep local stores off NeuralTrust-run planes.** **(a)** The admin accepts references only on hybrid gateways (D1). **(b)** A data plane uses local stores only to resolve references of gateways stamped `data_plane=hybrid`, which travel only in scoped snapshots and never in the shared one (`exploration.md` §1.2). **(c)** A plane with `INSTANCE_DEPLOYMENT_TYPE=saas` refuses to start when `SECRET_STORES_FILE` is set; hosted and dedicated overlays set `saas` (`k8s/overlays/*/config.env`). | A single feature flag. | A local store's identity, environment and files belong to whoever runs the pod. On a NeuralTrust plane they are ours, so a single mistake must not expose them. |
| D14 | **Write-time validation uses what the data planes report.** When at least one data plane of the gateway is live (a heartbeat within 3× the interval), the admin checks three things: some live connection reports the store; the path is within that store's reported `allowed_paths`; every live connection is at least the minimum version. When none is live, the admin accepts the reference, so config-as-code can run before the data plane is deployed, and the console shows the store as *not reported*. | Always require a live report. Never validate. | Strict when it can be, permissive only when it cannot know. |
| D15 | **References are not secrets.** The API returns them verbatim, and `secret.Mask` / `MaskSettings` pass them through. **Writing** a reference, or changing a destination (`CredentialDestinations`) on an entity whose credential is a reference, needs `secret_stores:read` on the gateway in addition to the entity scope. | Mask references. Let anyone with entity write add one. | The console must be able to show and edit references. Using a reference sends that secret somewhere, so the scope check keeps parity with today's rule that only a caller who has seen a credential may aim it elsewhere. |
| D16 | **No literal secret in the store file.** A store's static credentials (Vault token, AppRole `secret_id`, JWT) are only accepted as `*_file` paths. The chart fills them from mounted Kubernetes Secrets. The loader refuses inline `token`, `secret_id` and `jwt` keys, and refuses unknown keys. | Allow inline credentials. | The file is a ConfigMap, and a secret in a ConfigMap leaks. Refusing unknown keys turns typos into errors instead of silent defaults. |
| D17 | **Field selection.** `#field` picks a top-level key: a KV key in Vault, or a JSON key elsewhere. With no field, the whole payload is used; Vault KV requires exactly one key in that case. Non-string values are refused. The GCP service-account field accepts a whole JSON payload. | Allow JSON pointers or nested paths. | This covers the common one-secret-many-keys layout. Nested paths can come later in a backward-compatible way. |
| D18 | **Rollout is behind `SECRET_STORES_ENABLED`, default off, with version gating.** An old data plane reports no stores, so D14 already refuses its references. A mixed fleet is refused with `data_plane_too_old`. | Rely on documentation. | An old data plane ignores references and would send empty credentials. |
| D19 | **Prewarm without gating readiness, by default.** After a snapshot apply or a store-file reload, the data plane resolves every reference of its gateways in the background. `SECRET_STORES_READINESS_GATE=true` makes readiness wait for it, which an operator may want so a broken store fails the rollout. | Always gate readiness. | A pod that cannot start while the vault is briefly down is worse than serving the routes that do resolve. Operators can opt in. |

## 1. Reference grammar

```
reference = "secret://" store "/" path [ "?" "version=" version ] [ "#" field ]
store     = [a-z0-9] *62( [a-z0-9_-] )          ; store name, case-insensitive
path      = segment *( "/" segment )             ; percent-encoded, non-empty, no "." / ".." segments
field     = 1*( unreserved / pct-encoded )
version   = 1*( unreserved / pct-encoded )
```

- `Parse` is built on `net/url`.
- A value without the `secret://` scheme is **not a reference** and stays a
  literal.
- A value that has the scheme but does not match the grammar is refused with
  400 `invalid_secret_reference`. It is never stored as a literal, so a typo
  cannot be sent upstream as a key.
- Maximum length is 1 KiB.

| Store type | `path` means | `#field` | `?version=` | Default |
|---|---|---|---|---|
| `hashicorp_vault` (KV v2) | path under the mount → `GET /v1/<mount>/data/<path>` | key in `data.data` (required unless the secret has exactly one key) | KV version | latest |
| `hashicorp_vault` (KV v1) | path under the mount → `GET /v1/<mount>/<path>` | key in `data` | refused | — |
| `aws_secrets_manager` | secret name or ARN | top-level JSON key of `SecretString` | `VersionId` or staging label | `AWSCURRENT` |
| `gcp_secret_manager` | secret id (project from the store) or `projects/<p>/secrets/<s>` | top-level JSON key | version or alias | `latest` |
| `azure_key_vault` | secret name | top-level JSON key | version id | current |
| `file` | `<k8s-secret-name>/<key>` under the store root (as the chart mounts it) | top-level JSON key | refused | — |
| `env` | variable name; must start with the store's `prefix` | top-level JSON key | refused | — |

`allowed_paths` are prefixes of `path` as written in the reference, after
normalisation. `*` must be given explicitly.

### Where a reference is accepted (`secretref.Locations`)

| Entity | Paths | Phase |
|---|---|---|
| Registry (LLM) `auth` | `api_key.api_key`, `api_key.header_value`, `api_key.param_value`, `aws.access_key_id`, `aws.secret_access_key`, `aws.session_token`, `azure.api_key`, `azure.client_secret`, `oauth2.client_secret`, `oauth2.refresh_token`, `oauth2.password`, `gcp_service_account` | 1 |
| Registry `provider_options` | `headers.*` | 1 |
| Registry `mcp_target` | `auth.value`, `auth.client_secret`, `headers.*` | 1 |
| Registry `health_checks` | `headers.*` | 2 |
| Auth (inbound IdP) `config` | `oauth2.client_secret`, `oauth2.exchange_client_secret` | 2 |
| Policy `settings` | the plugin's `CredentialPaths()` | 2 |
| Consumer `lb_config` | `embedding.auth.*` secret fields | 2 |
| Gateway `telemetry` | `exporters[*].settings.headers.*`, `exporters[*].settings.dsn` | 2 |

Write-time checks that assume a literal skip references:
- `gcpkey.Validate` does not run on a reference;
- the AWS "static keys or a role" check counts a reference as present.

A reference that resolves to an invalid payload counts as unresolved
(`invalid_payload`).

## 2. Local stores

### 2.1 Data-plane file (`SECRET_STORES_FILE`)

```yaml
version: 1
stores:
  - name: corp-vault
    type: hashicorp_vault
    allowed_paths: ["ai-gateway/"]
    cache: { ttl: 5m, max_stale: 24h, negative_ttl: 30s }     # optional
    hashicorp_vault:
      address: https://vault.internal:8200
      namespace: admin/ai                  # optional (Vault Enterprise / HCP)
      mount: kv
      kv_version: 2
      ca_cert_file: /etc/trustgate/secret-stores/corp-vault/ca.crt   # optional
      auth:
        method: kubernetes                 # kubernetes | jwt | approle | token
        role: trustgate
        mount: kubernetes                  # auth mount, default per method
        # approle: role_id + secret_id_file · token: token_file · jwt: role + jwt_file
  - name: aws
    type: aws_secrets_manager
    allowed_paths: ["prod/llm/"]
    aws_secrets_manager:
      region: eu-west-1
      endpoint: ""                         # optional VPC endpoint (https, *.amazonaws.com)
      assume_role_arn: ""                  # optional, on top of the default chain
  - name: gcp                              # Phase 2
    type: gcp_secret_manager
    allowed_paths: ["llm-"]
    gcp_secret_manager: { project_id: acme-ai }
  - name: azure                            # Phase 2
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

**Loader rules** (`pkg/infra/secretstore/localfile`):
- Strict decode. Unknown keys and inline `token` / `secret_id` / `jwt` are
  refused (D16).
- Names are unique and match the store-name grammar. `allowed_paths` is
  required.
- The loader refuses the file when `INSTANCE_DEPLOYMENT_TYPE=saas` (D13c).
- The file is watched with `fsnotify`.
  - A valid change swaps the stores atomically and marks their entries for
    refresh.
  - An invalid change keeps the previous stores, logs the error and reports
    `config_error` in the heartbeat.

**Auth per type.** All are keyless except Vault AppRole and token.

| Type | Methods |
|---|---|
| Vault/OpenBao | **kubernetes:** the pod's projected ServiceAccount token, sent to `auth/<mount>/login`. **jwt:** a token from `jwt_file`. **approle:** `role_id` + `secret_id_file`. **token:** `token_file`. The resolver renews the client token at 2/3 of its lease, and logs in again when renewal fails or Vault answers 403. |
| AWS Secrets Manager | The SDK default chain: IRSA, EKS Pod Identity, instance profile or env. Optionally `sts:AssumeRole` into `assume_role_arn`. |
| GCP Secret Manager | ADC: GKE Workload Identity or a mounted key. Tokens come from the `gcpauth` cache. |
| Azure Key Vault | `azidentity`: workload identity (with `client_id` when the pod has several), else managed identity. |
| `file` | None. The root is a mounted volume: a Kubernetes Secret, the CSI driver or ESO. Paths are confined to `root` after `filepath.Clean` and `EvalSymlinks`. |
| `env` | None. Only variables starting with `prefix` are readable. |

### 2.2 Helm chart values

The neuraltrust-platform chart is outside these repos. **These key names are a
proposal to agree with the chart owners.**

```yaml
agentgateway:
  secretStores:
    enabled: true                     # sets SECRET_STORES_ENABLED + SECRET_STORES_FILE
    readinessGate: false
    stores:
      - name: corp-vault
        type: hashicorp_vault
        allowedPaths: ["ai-gateway/"]
        hashicorpVault:
          address: https://vault.internal:8200
          mount: kv
          kvVersion: 2
          caCert: { secretName: vault-ca, key: ca.crt }          # mounted, becomes ca_cert_file
          auth: { method: kubernetes, role: trustgate }
      - name: k8s
        type: file
        allowedPaths: ["*"]
        file:
          secrets: [llm-provider-keys, mcp-tokens]               # each mounted at <root>/<secret>/<key>
  serviceAccount:
    annotations:
      eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/trustgate-secrets   # IRSA
      # iam.gke.io/gcp-service-account: trustgate@acme-ai.iam.gserviceaccount.com   # GKE WI
      # azure.workload.identity/client-id: 00000000-0000-0000-0000-000000000000      # AKS WI
```

The chart renders `stores` into a ConfigMap mounted at
`/etc/trustgate/secret-stores.yaml`. It mounts every Secret named under
`caCert`, `secretIdSecret`, `tokenSecret` and `file.secrets`, and rewrites each
of them into the matching `*_file` path.

For Docker Compose (`downloads/docker-compose.yml`), the operator mounts the
YAML and the files and sets the two environment variables.

### 2.3 Discovery

Additive fields in `configsync.proto`:

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
  string state = 4;        // ok | auth_failed | unavailable | config_error | not_allowed
  string error_class = 5;  // last failure class, empty when ok
  string checked_at = 6;   // RFC3339
}
message SecretRefHealth {
  uint32 total = 1;
  uint32 unresolved = 2;
  repeated SecretRefFailure failing = 3;          // capped at 50
}
message SecretRefFailure {
  string gateway_id = 1;
  string store = 2;
  string path = 3;
  string field = 4;
  string error_class = 5;
}
```

**How state is computed.** Every 60 s, and on every fetch, the data plane runs
a credential-level probe that needs no secret-level permission:
- Vault: `auth/token/lookup-self` after login;
- AWS: `sts:GetCallerIdentity`;
- GCP and Azure: acquiring a token;
- `file` and `env`: root and prefix readable.

The probe result is combined with the outcome of the last real fetch.

**Persistence.** `config_sync_connections` gains `secret_stores JSONB` and
`secret_refs JSONB` (additive migration). `configsyncconn.Repository.MarkHeartbeat`
writes them (`pkg/infra/repository/configsyncconn/repository.go:115`).

**Values never travel.** Neither the heartbeat nor the persisted row carries
addresses, credentials or values. Store names, types, allowed-path prefixes
and error classes are the only store data the control plane learns.

## 3. Data flows

### 3.1 Write a reference (admin)

```
PUT /v1/gateways/G/registries/R   { auth: { type: api_key, api_key: { api_key: "secret://corp-vault/ai-gateway/openai#api_key" } } }
  registry.Updater → secretref.Validator
    ├─ SECRET_STORES_ENABLED                              else 422 secret_references_disabled
    ├─ declared location?                                 else literal (D4)
    ├─ Parse                                              else 400 invalid_secret_reference
    ├─ G.Entitlements.DataPlane == hybrid                 else 422 secret_references_not_supported
    ├─ caller holds secret_stores:read                    else 403 missing scope
    └─ live connections of G (heartbeat ≤ 3× interval)?
         yes ─┬─ some reports store "corp-vault"           else 422 unknown_secret_store
              ├─ path within its allowed_paths             else 422 secret_path_not_allowed
              └─ every live connection ≥ min version       else 422 data_plane_too_old
         no  ─► accept (store shown as "not reported" in the console)
  repository: seal/encrypt as today; outbox marker for G
  log "secret_reference_set" {gateway, entity, field, store, path, actor}
```

### 3.2 Distribution

The compiler reads the reference string back through the decrypting
repositories and copies it into the scoped snapshot unchanged. The snapshot
proto does not change. `codec_secret_test.go` gains a case asserting that a
reference survives the round trip as a reference.

### 3.3 Serve (data plane)

```
request ─► AuthMiddleware ─► DataFinder.FindByGateway(G)
             cache hit ─► *Data (already materialized)                 ◄── normal path
             miss ─► load(G) raw ─► Materializer.Gateway(ctx, G, raw)
                       for each reference at a declared location:
                         G is hybrid? store loaded? path allowed?     else unresolved (not_allowed / store_missing / path_not_allowed)
                         Resolver.Resolve(store, path, version) ─► cache | singleflight fetch (≤ 2 s)
                         ok  → substitute; reverse index ref → G
                         err → "" + CredentialUnavailable{field, class}
                       registry.SecretRefs = refs used (runtime only, json:"-")
             ─► forwarder ─► provider.prepare
                  CredentialUnavailable? ─► 503 secret_unavailable (failover may pick another registry)
                  else CredentialsFromTargetAuth(materialized) ─► upstream
```

### 3.4 Rotation

| Trigger | Behaviour |
|---|---|
| Refresher tick (15 s) | Fetches entries with `age ≥ 0.8·ttl ± jitter` that were used in the last hour. Same hash → bump `fetched_at`. New hash → replace the entry and drop the dependent gateways from the caches (D9). |
| Upstream 401/403 on a registry with `SecretRefs` | `ForceRefresh`, at most once per reference per 30 s. If the value changed: invalidate and retry once (D11). |
| `SECRET_STORES_FILE` changed | Swap the stores, rebuild the backend clients of the stores that changed, mark their entries for refresh. |
| Pinned `?version=` | Never refreshed. Rotating means writing a new reference. |

To make rotation effective in cached clients:
- the Bedrock pool key includes a hash of the secret key and session token
  (`pkg/infra/providers/bedrock/client.go:386`);
- the MCP dial revision includes a hash of the materialized credential
  (`pkg/app/mcp/target.go:123`).

### 3.5 Cache entry states

```
  (miss) ─ok─► FRESH ─age ≥ 0.8·ttl─► REFRESHING ─ok─► FRESH
     │                                    │ error
     │ error                              ▼
     ▼                                STALE (age < ttl + max_stale): serve, count stale_served
  NEGATIVE (neg_ttl): fail fast       DEAD  (age ≥ ttl + max_stale): secret_unavailable
```

Errors are classified once, for every backend:

| Class | Retry and stale behaviour |
|---|---|
| `not_found` | Negative cache. Stale is served only for an entry that already resolved before. |
| `access_denied` | Negative cache. Stale is served only for an entry that already resolved before. |
| `field_not_found` | Negative cache. Stale is served only for an entry that already resolved before. |
| `invalid_payload` | Negative cache. Stale is served only for an entry that already resolved before. |
| `unavailable` (timeout, 5xx, DNS, TLS) | Retried with backoff (5 s → ttl). Stale is served. |
| `auth_failed` | Retried after a re-login. Stale is served. |
| `store_missing` (data-plane–side condition) | Unresolved; no fetch is attempted. |
| `not_allowed` (data-plane–side condition) | Unresolved; no fetch is attempted. |
| `path_not_allowed` (data-plane–side condition) | Unresolved; no fetch is attempted. |

## 4. Security model

| Threat | Control |
|---|---|
| A tenant uses NeuralTrust's pod identity, env or files. | D13: three independent guards. |
| A console admin aims the pod identity at their own host. | Store addresses and auth exist only in the customer's Helm values (D2). |
| An editor exfiltrates a vault secret by referencing it from a registry or policy that points at their own host. | `allowed_paths`, enforced on the data plane; `secret_stores:read` to write or retarget a reference (D15); the `secret_reference_set` event; the generator emits least-privilege policies for the allowed paths only; references are recognised only at declared locations (D4). |
| A secret value at rest or in transit through NeuralTrust. | Never in Postgres, Redis, the snapshot, the LKG file, the heartbeat, logs or responses. It lives only in data-plane process memory (D7). |
| A secret value in diagnostics output. | The diagnostics test returns metadata only: auth, read, class, version, latency. |
| Path traversal or env-var harvesting. | `file` stores are confined to `root`; `env` stores require a `prefix`; allowed paths apply to both. |
| Diagnostics route abuse. | The existing control-plane diagnostics token, minted per gateway and per user by the console. The route enforces `allowed_paths` and only answers for the gateway named in the token. |

## 5. Interfaces / contracts

```go
// pkg/domain/secretref
type Ref struct{ Store, Path, Field, Version string }

func Parse(s string) (Ref, bool, error) // ok=false: literal
func IsRef(s string) bool
func (r Ref) String() string
func (r Ref) PayloadKey() string        // store|path|version: the cache key

var Locations []Location               // §1 table; read by validator, materializer, collector

// pkg/domain/secretstore
type Type string // hashicorp_vault | aws_secrets_manager | gcp_secret_manager | azure_key_vault | file | env

type Store struct {
    Name         string
    Type         Type
    AllowedPaths []string
    Cache        CachePolicy
    Config       any // typed per Type
}

type CachePolicy struct{ TTL, MaxStale, NegativeTTL time.Duration }

type Secret struct {
    Payload []byte
    Fields  map[string]string
    Version string
}

type Status struct {
    Name, State, ErrorClass string
    Type                    Type
    AllowedPaths            []string
    CheckedAt               time.Time
}

//go:generate mockery --name=Backend --dir=. --output=./mocks --filename=secretstore_backend_mock.go --case=underscore --with-expecter
type Backend interface {
    Fetch(ctx context.Context, path, version string) (Secret, error)
    Probe(ctx context.Context) error
}

//go:generate mockery --name=Catalog ...
type Catalog interface { // the loaded local stores
    Get(name string) (*Store, Backend, bool)
    Statuses() []Status
}

var ( // error classes
    ErrNotFound, ErrAccessDenied, ErrAuthFailed, ErrUnavailable,
    ErrFieldNotFound, ErrInvalidPayload, ErrStoreMissing, ErrNotAllowed, ErrPathNotAllowed error
)

// pkg/app/secretref
type Resolver interface {
    Resolve(ctx context.Context, ref secretref.Ref) (string, error)
    ForceRefresh(ctx context.Context, refs []secretref.Ref) (changed bool, err error)
    OnChange(fn func(refs []secretref.Ref))
}

type Materializer interface {
    Gateway(ctx context.Context, gw *gateway.Gateway, d *consumer.Data) (*consumer.Data, []Unresolved)
    Registry(ctx context.Context, gw *gateway.Gateway, r *registry.Registry) (*registry.Registry, []Unresolved)
}

type Collector interface {
    Collect(ctx context.Context, gatewayID ids.GatewayID) ([]Use, error)
}

type Validator interface { // admin side
    Validate(ctx context.Context, gatewayID ids.GatewayID, caller Caller, uses []Use) error
}

// pkg/domain/dataplane
type Heartbeat struct {
    // … existing fields …
    SecretStores []secretstore.Status
    SecretRefs   *SecretRefHealth
}

// pkg/app/secretstore (admin)
type Lister interface { // union over live connections of the gateway
    List(ctx context.Context, gatewayID ids.GatewayID) ([]ReportedStore, error)
}

type UsagesFinder interface {
    Usages(ctx context.Context, gatewayID ids.GatewayID, store string) ([]secretref.Use, error)
}
```

The materializer never mutates its input. It returns copies, so the snapshot
store and the repositories keep the references.

## 6. Runtime readers that must materialize (data plane)

| Reader | Location | Change |
|---|---|---|
| `consumer.DataFinder.load` | `pkg/app/consumer/data_finder.go` | Materialize registries, auths and policies per gateway (D6). |
| `registry.Finder` | `pkg/app/registry/finder.go:48-62` | Materialize before caching. |
| Diagnostics test-connection / model listing | `pkg/api/handler/http/diagnostics/*` | Already read through the finders. Report `secret_unavailable` with its class. |
| MCP static target / credential resolver | `pkg/app/mcp/target.go`, `credentials.go` | Fed by materialized registries; add the revision hash. |
| Traffic-label classifier (`worker` plane) | `pkg/infra/labelllm/classifier.go:117` | Read through `registry.Finder`. |
| Telemetry exporters, consumer embedding | `pkg/infra/telemetry`, `pkg/domain/consumer/lb_config.go` | Phase 2. |

A test in `pkg/app/secretref` keeps this table honest. It wires the runtime
modules with a reference and a fake catalog, and asserts that no provider
client, plugin or exporter ever receives a `secret://` string.

## 7. API

### Admin (control plane)

Read-only in Phases 1–2. Guarded by `RequireGatewayAccess(ResourceSecretStores)`,
which gives the scope `secret_stores:read`.

| Route | Response |
|---|---|
| `GET /v1/gateways/:gateway_id/secret-stores` | `[{ name, type, allowed_paths, status: ok\|degraded\|down\|not_reported, consistent, instances: [{instance_id, version, state, error_class, checked_at}], usages }]`. It is the union over live connections. `consistent=false` when instances disagree on the type or the paths. Stores referenced but not reported appear with `not_reported`. |
| `GET /v1/gateways/:gateway_id/secret-stores/:name/usages` | `[{ entity, id, name, field, reference }]`, built by the collector. |

### Data plane (diagnostics)

The route is registered before the transport, like the existing diagnostics
routes, and takes the same token header.

| Route | Request | Response |
|---|---|---|
| `POST /__diagnostics/gateways/:gateway_id/secret-stores/:name/test` | `{ path?, field?, version? }` | `{ auth: ok\|failed, read: ok\|skipped\|<class>, version, latency_ms }`. **Never the value.** |

### Error codes

| Code | Status | Where |
|---|---|---|
| `invalid_secret_reference` | 400 | admin |
| `secret_references_disabled` | 422 | admin |
| `secret_references_not_supported` | 422 | admin |
| `unknown_secret_store` | 422 | admin |
| `secret_path_not_allowed` | 422 | admin |
| `data_plane_too_old` | 422 | admin |
| `secret_unavailable` | 503 | data plane; the body names neither path nor store, logs carry both |

## 8. Console (`NeuralTrust/app`)

### 8.1 Settings → Gateway → "Secret stores" tab

- **Placement.** The tab sits next to General, Credentials, Machine identity
  and Deployment, in `app/[locale]/v2/features/settings/components/gateway/`.
  It is shown only for `deploymentType === 'hybrid'`.
- **Header.** "Vaults your data plane can read. They are configured in your Helm
  values; NeuralTrust never sees their credentials."
- **Table:**
  - *Name*
  - *Type* (icon)
  - *Allowed paths*
  - *Status*, aggregated across instances, e.g. "3/3 instances OK"; a warning
    when instances are inconsistent or not reported
  - *Used by (n)*
  - *Last checked*
- **Row detail (side panel):**
  - status per instance and the last error class, each with a human hint
    (e.g. `access_denied` → "check the vault policy for this path");
  - the usages list, linking to each registry or MCP server;
  - **"Test a secret"** (path, field and version), which runs on the data plane.
- **Empty state.** "Your data plane has not reported any secret store", with an
  **"Add a secret store"** button and a docs link.

### 8.2 "Add a secret store" generator

The generator saves nothing in NeuralTrust.

1. **Type.** HashiCorp Vault / OpenBao, AWS Secrets Manager, GCP Secret
   Manager (Phase 2), Azure Key Vault (Phase 2), Kubernetes Secrets, or
   Environment variables.
2. **Form.** The common fields are *Name*, *Allowed paths* (with a type-specific
   default suggestion) and, under *Advanced*, cache TTL and max stale. The type
   adds the fields below. **No field accepts a secret value.**

   | Type | Connection | Auth (default first) | Generated prerequisites |
   |---|---|---|---|
   | HashiCorp Vault / OpenBao | Address\*, Namespace, KV mount\* (`secret`), KV version (2), CA certificate: Secret name/key | **Kubernetes**: role\*, auth mount (`kubernetes`) · JWT: role\* · AppRole: role ID\*, Secret holding `secret_id`\* · Token: Secret holding the token\* | Vault policy HCL (`read` on `<mount>/data/<allowed>*`) and `vault write auth/kubernetes/role/<role> bound_service_account_names=<sa> bound_service_account_namespaces=<ns> policies=<policy>` |
   | AWS Secrets Manager | Region\*, VPC endpoint, Role to assume | **IRSA / EKS Pod Identity**: IAM role ARN\*, which goes to the ServiceAccount annotation | IAM policy JSON: `secretsmanager:GetSecretValue` on `arn:aws:secretsmanager:<region>:<account>:secret:<allowed>*`, plus `kms:Decrypt` when a CMK is used |
   | GCP Secret Manager | Project ID\* | **GKE Workload Identity**: GSA email\* | `gcloud secrets add-iam-policy-binding … --role roles/secretmanager.secretAccessor` per allowed secret, or on the project |
   | Azure Key Vault | Vault URL\* | **AKS Workload Identity**: client ID\* | `az role assignment create --role "Key Vault Secrets User" --assignee <client-id> --scope <vault-id>` |
   | Kubernetes Secrets | Secret names\* | — | — (the chart mounts them) |
   | Environment variables | Prefix\* (`TG_SECRET_`) | — | — |

3. **Output.**
   - The `agentgateway.secretStores` values snippet (D2), plus the
     ServiceAccount annotation when the type needs one.
   - The prerequisites, as copyable blocks.
   - The `helm upgrade` command (reusing the Deployment tab's helpers in
     `privateDeployValues.ts`).
   - A live **"Waiting for your data plane to report `<name>`…"** indicator. It
     polls the admin listing and turns green when the store is reported with
     state `ok`, or shows the reported error class.

### 8.3 `SecretInput`

`SecretInput` replaces the password input of every field with `secret: true`:
- `RegistrySchemaFieldRenderer` (LLM providers) and `GcpServiceAccountField`;
- `McpServerConfigPanel` (static secret headers, OAuth client secret);
- policy credential fields and telemetry headers (Phase 2).

```
API key   ( Value | From secret store )
  Store    [corp-vault ▾]  ● ok            ← stores reported for this gateway; status dot
  Path     ai-gateway/openai               ← hint: allowed "ai-gateway/"; inline check
  Key      api_key                          ← optional: "leave empty if the secret holds a single value"
  Version  latest                ▸ advanced ← type-aware placeholder (7 · AWSCURRENT · latest)
  [Test]   ✓ Resolved on your data plane · version 7 · 84 ms
  secret://corp-vault/ai-gateway/openai#api_key   [copy]
```

- **Visibility.** The toggle appears only on hybrid gateways with the feature
  enabled.
- **Default mode.** *Value*, so existing flows are unchanged. The *From secret
  store* mode is preselected when the gateway reports stores and the field is
  empty.
- **Edit.** The API returns references verbatim, so a stored reference opens in
  *From secret store* mode, parsed client-side.
- **Test.** It calls the data-plane diagnostics route through a server action,
  like `testRegistryConnectionAction`. Results map error classes to messages;
  the value is never shown.
- **Store missing from the list** (no data plane live): a free-text store name
  is allowed, with a warning (D14).
- **Cards.** Registry and MCP cards show a key badge "from corp-vault". From
  Phase 2, a warning appears when the data plane reports the reference as
  failing.
- **Audit.** Server actions log `secret_reference.set` through
  `logV2AuditEvent`.

## 9. Phase 3 outline: hosted and dedicated (not in this change)

On NeuralTrust-run planes there is no customer workload identity. Two options,
to be decided in a dedicated design review:

1. **Keyless federation (preferred).**
   - TrustGate becomes an OIDC issuer: a discovery document plus JWKS, on a
     dedicated signing key; the STS signer and `/.well-known/jwks.json` are
     reusable building blocks.
   - It mints short-lived tokens with `sub=gateway:<id>`.
   - The customer trusts that subject from AWS IAM (`AssumeRoleWithWebIdentity`
     with a `sub` condition), GCP Workload Identity Federation (attribute
     condition), Azure federated credentials or Vault JWT auth (`bound_subject`).
   - No credential is stored.
   - A per-gateway subject avoids the confused deputy that a shared NeuralTrust
     identity would create; that is why Model Armor refuses ambient identity on
     shared planes.
2. **API-managed stores with sealed credentials**, only if federation is not
   enough.
   - Credentials sealed with `FieldSealer` under purpose `secret-stores/v1`.
   - Masked in responses; re-entry required when the destination changes.
   - Shipped in the snapshot.
   - Vault addresses dialed through `netguard`; Azure URL suffix allowlist; no
     custom AWS endpoint.

Everything else in this design (grammar, locations, resolver, materializer,
console `SecretInput`) carries over unchanged.

## 10. Configuration (`pkg/config`, `.env.example`)

| Variable | Default | Plane | Meaning |
|---|---|---|---|
| `SECRET_STORES_ENABLED` | `false` | all | Master switch. Off: the admin refuses references; data planes neither load stores nor resolve references. |
| `SECRET_STORES_FILE` | — | data | Local store file (§2.1). Refused when `INSTANCE_DEPLOYMENT_TYPE=saas`. |
| `SECRET_STORES_FETCH_TIMEOUT` | `2s` | data | Per-fetch timeout. |
| `SECRET_STORES_REFRESH_INTERVAL` | `15s` | data | Refresher tick. |
| `SECRET_STORES_PROBE_INTERVAL` | `60s` | data | Store health probe. |
| `SECRET_STORES_READINESS_GATE` | `false` | data | Gate readiness on prewarm (D19). |
| `SECRET_STORES_MIN_DATA_PLANE_VERSION` | first release with the feature | admin | Version gating (D18). |

## 11. File changes (TrustGate)

| File | Change |
|---|---|
| `pkg/domain/secretref/{ref.go,locations.go}` (+ tests, fuzz) | grammar, location table |
| `pkg/domain/secretstore/{store.go,config.go,backend.go,catalog.go,errors.go}` + `mocks/` | store model, ports, error classes |
| `pkg/app/secretref/{resolver.go,cache.go,refresher.go,materializer.go,collector.go,validator.go}` + `mocks/` | resolution core, admin validation |
| `pkg/app/secretstore/{lister.go,usages.go}` + `mocks/` | admin listing and usages |
| `pkg/infra/secretstore/{hashicorp,awssm,gcpsm,azurekv,filestore,envstore}/` | backends |
| `pkg/infra/secretstore/localfile/{loader.go,watch.go}` | file loader, strict decode, fsnotify reload, `saas` guard |
| `pkg/infra/configsnapshot/proto/configsync.proto` (+ generated), `pkg/infra/configsync/grpc/{heartbeat.go,hub.go}`, `pkg/domain/dataplane/heartbeat.go` | heartbeat fields |
| `pkg/infra/database/migrations/<ts>_config_sync_connections_secret_stores.go`, `pkg/infra/repository/configsyncconn/repository.go` | persist reports |
| `pkg/app/consumer/data_finder.go`, `pkg/app/registry/finder.go`, readers in §6 | materializer + invalidation |
| `pkg/app/proxy/provider.go`, `pkg/app/mcp/*`, `pkg/infra/providers/bedrock/client.go` | `CredentialUnavailable`, forced refresh + retry, cache keys |
| `pkg/common/secret/{secret.go,settings.go}` | references pass through `Mask` and `MaskSettings` |
| `pkg/domain/registry/{target.go,mcp_target.go}`, `pkg/app/registry`, `pkg/app/policy/updater.go` | validator calls, literal-only checks skipped for references |
| `pkg/api/handler/http/secretstore/{list,usages}_handler.go` + `response/…` | admin routes |
| `pkg/api/handler/http/diagnostics/secret_store_test_handler.go` | data-plane test route |
| `pkg/api/middleware/admin_scopes.go`, `pkg/server/router/{admin,proxy}_router.go` | `ResourceSecretStores`, routes |
| `pkg/container/modules/secretstore.go` | DI: catalog, resolver, refresher, probe loop (data planes); lister, validator (admin) |
| `pkg/config/config.go`, `.env.example` | variables in §10 |
| `docs/secret-stores.md`, `docs/openapi.json` / `swagger.*`, `downloads/docker-compose.yml` | user docs, API, compose example |

## 12. Testing strategy

- **Grammar.** Table tests and `FuzzParse`: round trip, `..`, encoding, ARNs,
  length.
- **Validator.** Every location accepts a reference, and non-locations stay
  literal. Non-hybrid gateways are refused. Live versus no live connection.
  Unknown store, path outside `allowed_paths`, version too old, missing scope.
- **Masking.** References pass through, masked literals still keep their value,
  and retargeting without the scope is refused.
- **Loader.**
  - Strict decode: unknown keys and inline secrets are refused.
  - Duplicates are refused.
  - The `saas` guard.
  - Reload: a valid change swaps the stores; an invalid change keeps the old
    ones and reports `config_error`.
- **Resolver.** Uses a fake clock and backend:
  - fresh → refresh with the same hash publishes no change;
  - a new hash invalidates the dependent gateways;
  - stale serving until `max_stale`, then `secret_unavailable`;
  - negative cache;
  - singleflight: 100 concurrent misses make one fetch;
  - forced-refresh rate limit;
  - pinned versions never refresh;
  - eviction;
  - `-race`.
- **Materializer.**
  - Every location is covered.
  - Unresolved references become empty plus `CredentialUnavailable`.
  - The input is not mutated.
  - The non-hybrid guard (D13b).
- **Backends.**
  - Vault KV v1/v2 with Kubernetes, AppRole and token login and renew, and the
    namespace header, against `httptest`.
  - AWS through an injected HTTP client.
  - `file` traversal and symlink escape.
  - `env` prefix.
  - Optional integration tag with a Vault dev container and LocalStack.
- **Discovery.** Heartbeat encode and decode. `MarkHeartbeat` persists the
  report. The lister union handles live versus stale connections and
  `consistent=false`.
- **Diagnostics.** The token is required. The response never contains the
  value: a test asserts the fake secret string is absent from the body.
  `allowed_paths` is enforced.
- **End to end.** A hybrid data plane with the store file, a fake Vault and an
  `httptest` upstream:
  - the upstream sees the key;
  - after a rotation it sees the new key within one refresher tick;
  - after a 401 it sees the new key on the retry;
  - with the vault down it keeps serving until `max_stale`;
  - captured logs and the snapshot bytes never contain the value.

## 13. Rollout

1. Merge the TrustGate slices with `SECRET_STORES_ENABLED=false`. The
   migration and the proto fields are additive.
2. Release a hybrid data-plane image, then the chart with
   `agentgateway.secretStores`.
3. Enable the feature on the dev admin. Validate with an internal hybrid
   gateway on EKS (IRSA) and on GKE (Vault with Kubernetes auth).
4. Enable the console tab and `SecretInput`, behind a console feature flag, for
   selected tenants.
5. Publish `docs/secret-stores.md`. It covers each backend with keyless setup,
   least-privilege policies, migrating from literal values with the usages
   list, troubleshooting by error class, and a pointer to CSI/ESO for platform
   secrets.

**Rollback:** turn the flag off. Gateways that use references need literal
values again; the usages endpoint lists them.

## Rejected alternatives

- **R1. Resolve in the compiler and ship values** (central, LiteLLM-like). The
  value stays in our snapshot, the admin cannot reach private vaults, and
  rotation depends on recompiles (D5).
- **R2. API-managed stores as the primary model.** NeuralTrust would hold
  vault credentials, and a console admin could aim the pod identity at their
  own host (D2). It is kept as a Phase 3 fallback for hosted gateways (§9).
- **R3. Declaring local stores in the console as well.** Double entry that can
  drift (D3).
- **R4. A structured reference object in the DTOs.** See D4.
- **R5. Resolving at each call site.** See D6.
- **R6. A shared Redis cache of resolved values.** It puts plaintext at rest
  (D7).
- **R7. Only documenting sidecars** (Vault Agent, ESO, CSI). That needs one file
  or env var per secret and restarts on change. It is still supported through
  the `file` and `env` stores, which read those mounts with no restart.
- **R8. LiteLLM-style `os.environ/NAME`.** It carries no store, field or
  version, and it is ambiguous between an env var and a secret id. An `env`
  store covers that use.

## Open questions

- **OQ1. Default `max_stale`.** 24 h (availability first) versus 1 h
  (revocation first). It is configurable per store; only the default needs a
  product call.
- **OQ2. Opt-in LKG persistence.** Should hybrid operators be able to opt into
  persisting resolved values in the encrypted LKG, so the plane survives a
  restart while the vault is down? Off by default (G3).
- **OQ3. Chart keys.** Exact `agentgateway.secretStores` keys and Secret-mount
  conventions, to agree with the neuraltrust-platform chart owners.
- **OQ4. Packaging.** LiteLLM, Kong and Portkey gate this as Enterprise. Do we
  gate it behind a plan entitlement (`tenant_entitlements`)? Product decision.
- **OQ5. Phase 3.** Federation issuer design (key, discovery, trust-policy
  templates), and whether API-managed stores are needed at all.
