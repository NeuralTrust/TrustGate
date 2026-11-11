# Design: External secret stores (vault references)

## Linked artifacts

- Proposal (binding): [`proposal.md`](./proposal.md), goals G1–G7.
- Research: [`exploration.md`](./exploration.md). It covers the TrustGate
  secret inventory E1–E11, LiteLLM, Kong and Portkey.
- Specs: [`specs/secret-references`](./specs/secret-references/spec.md),
  [`specs/secret-stores`](./specs/secret-stores/spec.md),
  [`specs/secret-resolution`](./specs/secret-resolution/spec.md).
- Linear: _pending_.
- Conventions: `.agents/AGENTS.md`.
  - Hexagonal layers.
  - One use case per file.
  - DI in `pkg/container/modules`.
  - One DTO per file.
  - mockery mocks.
  - Environment variables only through `pkg/config`.

## Technical approach

```
                 CONTROL PLANE (admin)                                    DATA PLANE (proxy / mcp)
 ┌───────────────────────────────────────────────┐        ┌─────────────────────────────────────────────────────────┐
 │ Admin API                                     │        │ snapshot store  (references only, never values)         │
 │  /secret-stores  CRUD · test · usages         │        │        │                                                │
 │  registries / policies / auths / gateways     │        │        ▼                                                │
 │    └─ validate secret:// at declared paths    │        │ runtime finders  (DataFinder.load, registry.Finder)     │
 │                                               │ gRPC   │        │  Materializer: secret:// ─► value               │
 │ Postgres: secret_stores (auth sealed)         │ config │        ▼                                                │
 │           registries.auth = "secret://…"      ├──sync─►│ Resolver ── cache (TTL · refresh-ahead · stale · neg)    │
 │                                               │        │        │            ▲ change ─► invalidate gateway data │
 │ Compiler: copies references verbatim,         │        │        ▼            │                                   │
 │           adds secret_stores to the snapshot  │◄─hb────┤ Backends: hashicorp · awssm · gcpsm · azurekv · env · file│
 └───────────────────────────────────────────────┘        │        │  (managed: creds from snapshot;                │
                                                          │        │   local: ambient identity / YAML on the plane) │
                                                          └────────┼────────────────────────────────────────────────┘
                                                                   ▼
                                                     customer secret manager
```

1. **References instead of values.** A credential field can hold
   `secret://<store>/<path>[?version=<v>][#<field>]`. The admin API validates
   it, the repositories store it in place of the value, and the compiler copies
   it into the snapshot unchanged.
2. **Stores are configuration.**
   - A **managed** store is created through the API. Its credentials are sealed
     in Postgres and shipped in the snapshot like registry credentials are
     today.
   - A **local** store is declared by name in the API and configured on the
     data plane in YAML. Its credentials never leave the customer's network.
3. **Each plane resolves its own references.** The `Materializer` runs where a
   gateway's runtime model is built. It swaps each reference for the cached
   value. Code that consumes credentials (provider clients, plugins, MCP
   dialer, exporters) does not change.
4. **Rotation flows through the existing invalidation.** When a resolved value
   changes, the resolver drops the cached gateway data that used it. The next
   request rebuilds that data with the new value.

## Decisions

| # | Decision | Rejected | Rationale |
|---|---|---|---|
| D1 | **Resolution happens on the data plane.** The control plane stores and distributes references only. Admin features that use a credential keep running on the plane that runs them today. **Hybrid:** the console already calls the data plane's `/__diagnostics/...` routes for test-connection and model listing (`app/server/lib/gateway/registryModelCatalog.ts`, `testRegistryConnectionAction.ts`), so they resolve there. **Hosted and dedicated:** the admin runs them (`POST …/registries/test-connection`, `GET /v1/models-catalog`) and resolves **managed** stores through the same port. The traffic-label classifier runs on the `worker` plane and resolves like a data plane. | Resolve once in the compiler and ship values in the snapshot (the LiteLLM model). | With compile-time resolution the value is still in our snapshot, a SaaS control plane cannot reach a private vault, and rotation needs polling plus a recompile. G3 rules it out. |
| D2 | **The reference is a string with a URI grammar,** `secret://store/path?version=v#field`. It is recognised **only at declared secret locations**; anywhere else it is inert text. | A structured `{"secret_ref":{…}}` object in every DTO. | Every secret field is already a string, whether typed or inside plugin `map[string]any`. A string needs no change to any DTO, snapshot JSON or masking helper, and it matches Kong and LiteLLM. Restricting where references are recognised stops a reference planted in a prompt template or a non-secret header from pulling a secret out. |
| D3 | **Two locations, `managed` and `local`.** Local stores are declared in the API with a name and type only. Their address, auth and allowed paths live in `SECRET_STORES_FILE` on the data plane. Ambient identity, `env` and `file` are local-only. A plane honours local stores only when `SECRET_STORES_ALLOW_LOCAL=true`, and the admin API accepts them only for gateways whose `Entitlements.DataPlane` is hybrid. Dedicated planes are run by NeuralTrust, so their pod identity, env and files are ours: they get managed stores only, like hosted. | Let the API configure ambient identity, as `MODEL_ARMOR_ALLOW_AMBIENT_IDENTITY` does. Discover local stores from Heartbeat with no declaration. | Whoever can use the pod identity must be whoever runs the pod. Otherwise a console admin could aim the pod's Kubernetes SA token or IMDS credentials at their own host, or read NeuralTrust's environment on a shared plane. Declaring the name keeps admin-time validation deterministic. |
| D4 | **A store belongs to exactly one gateway.** Its name is a unique slug within the gateway. `allowed_paths` is **required**, and `*` must be written explicitly. | Tenant-wide stores shared across gateways. Empty means allow all. | Gateways are the isolation unit for config, snapshots and authorization. Requiring a prefix makes the blast radius a conscious choice. Sharing across gateways can be added later as a grant without breaking this model. |
| D5 | **Materialize in the runtime finders:** `consumer.DataFinder.load` and `registry.Finder`. Runtime readers outside those finders (§9) call the materializer explicitly. The admin read path never materializes. | Resolve at every call site, e.g. `CredentialsFromTargetAuth(ctx, resolver, …)`. Use a decorator on the repositories. | About 10 call sites span providers, plugins, MCP and telemetry, and missing one is the LiteLLM #35239 class of bug. The finders sit above both the Postgres and the snapshot repositories, so a single change covers every plane. A repository decorator would also materialize admin reads and return values where references belong. |
| D6 | **The cache is in-process and per replica.** Key: (store, path, version). TTL 5 min. Refresh-ahead from 80 % of the TTL, with ±10 % jitter. Stale-on-error up to `max_stale` (24 h). Negative TTL 30 s. Singleflight. Fetch timeout 2 s. An entry unused for 1 h is evicted. A pinned `version` is immutable, so it never refreshes. | Share the cache in Redis. Persist resolved values in the LKG. Use LiteLLM's 24 h TTL with no refresher. | Redis or the LKG would put plaintext into shared or persistent storage, which breaks G3. The per-replica fetch rate is low: one fetch per secret per TTL. Refresh-ahead keeps the request path on cache hits. |
| D7 | **An unresolved reference becomes an empty value and the entity is marked `CredentialUnavailable`.** The invoker fails with `secret_unavailable` **before dialing**. Registry failover applies as for any unavailable registry. | Send the reference string on. Fail the whole gateway load. | LiteLLM #26151 sent the literal reference upstream. Failing the whole load would let one bad reference take down every route of the gateway. |
| D8 | **A changed value invalidates only the gateways that use it.** On refresh, the resolver compares a SHA-256 of the payload. When it differs, it publishes a change. The materializer keeps a reverse index from reference to gateway ids and drops those entries from the `DataFinder` and `registry.Finder` caches. | Clear every TTL map. Keep stale data until the 1 h `consumer_data` TTL expires. | This reuses the existing invalidation path, and only the affected gateways rebuild. |
| D9 | **Nothing in the snapshot lists references.** `secretref.Collector` walks a gateway's entities over the declared locations. The usages API, delete protection, prewarm and health reporting all use it. | A `secret_refs` snapshot field maintained by the compiler. | One function serves both planes, and there is no second source of truth that could drift. |
| D10 | **On an upstream 401 or 403, force a refresh.** It applies when the credential came from a reference, at most once per reference per 30 s. If the value changed, invalidate and retry the request once on the same registry. Otherwise fall through to the normal failover. | Wait for the TTL. | Rotation is picked up immediately (G4). The rate limit stops a misconfigured upstream from hammering the vault. |
| D11 | **Backend clients:** Vault/OpenBao and GCP Secret Manager use REST on TrustGate's HTTP client, so `netguard` applies and GCP reuses the `gcpauth` token cache. AWS uses `service/secretsmanager` and Azure uses `azsecrets`. | `hashicorp/vault/api`, `cloud.google.com/go/secretmanager`. | Our clients need only a small part of each API: KV read, auth login and token renew for Vault, `versions/*:access` for GCP. The GCP SDK pulls in the full gRPC client stack. The AWS and Azure modules are small and reuse dependencies already in `go.mod`. |
| D12 | **Managed store credentials are sealed** with `FieldSealer`, purpose `secret-stores/v1`, AAD = `field\|store_id`. They are masked in responses and kept on omit. Changing `address`, `vault_url`, `region`/`endpoint` or the auth method **requires re-entering** them, the same destination rule as `CredentialDestinations`. | Reuse the legacy `crypto.Cipher` used by `registries.auth`. | Same model as E2, E4 and E5. Without the binding, a caller who cannot read a credential could point it at a host they control. |
| D13 | **References are not secrets.** The API returns them verbatim, and `secret.Mask` / `MaskSettings` pass them through. **Writing** a reference, or changing a destination on an entity whose credential is a reference, needs `secret_stores:read` on the gateway in addition to the entity scope. | Mask references too. Allow anyone with entity write to add one. | The console must be able to show and edit references. Knowing a reference does not reveal its value, but using one sends that secret somewhere, so the scope check keeps parity with today's rule that only a caller who has seen a credential may aim it elsewhere. |
| D14 | **Hosted planes harden outbound calls.** Vault: HTTPS only, through `netguard`. Azure: `vault_url` must match the Key Vault DNS suffixes (public and sovereign clouds). AWS: a custom `endpoint` is allowed only on local stores. Ambient identity is never used. | Trust the tenant-supplied URLs. | These tenant-supplied URLs are SSRF and credential-replay vectors. The netguard and ambient-identity precedents are in `exploration.md` §1.5. |
| D15 | **Field selection.** `#field` picks a top-level key: a KV key in Vault, or a JSON key in AWS, GCP, Azure, `env` or `file`. With no field, the whole payload is used; Vault KV requires exactly one key in that case. Non-string field values are refused. The GCP service-account field accepts a whole JSON payload. | Allow JSON pointers or nested paths. | This covers the common one-secret-many-keys layout, and one level keeps the grammar simple. Nested paths can come later in a backward-compatible way. |
| D16 | **Rollout is behind `SECRET_STORES_ENABLED`, default off, with version gating.** The admin API refuses references on a hybrid or dedicated gateway whose connected data planes report, in `Heartbeat.version`, a version older than the first one that resolves them. | Rely on documentation. | An old data plane ignores the new snapshot field and would serve with empty credentials. |
| D17 | **Prewarm without gating readiness.** After a snapshot apply, the worker asks the materializer to warm every gateway the plane serves, in the background and with bounded concurrency. Readiness is not gated on it, except on single-gateway planes that set `SECRET_STORES_READINESS_GATE=true`. | Block readiness until every reference resolves. | On a shared plane one tenant's broken vault must not keep the pod NotReady. On a hybrid plane, an operator may prefer to fail the rollout. |

## 1. Reference grammar

```
reference = "secret://" store "/" path [ "?" "version=" version ] [ "#" field ]
store     = [a-z0-9] *62( [a-z0-9_-] )          ; store name, case-insensitive
path      = segment *( "/" segment )             ; percent-encoded, non-empty, no "." / ".." segments
field     = 1*( unreserved / pct-encoded )
version   = 1*( unreserved / pct-encoded )
```

- `Parse` is built on `net/url`. A value without the `secret://` scheme is
  **not a reference**, and the caller treats it as a literal.
- A value that has the scheme but does not match the grammar is
  `ErrInvalidReference` (400 `invalid_secret_reference`). The admin API refuses
  it rather than storing it as a literal, so a typo can never be sent upstream
  as a key.
- Maximum length is 1 KiB.

### Backend mapping

| Store type | `path` means | `#field` | `?version=` | Default version |
|---|---|---|---|---|
| `hashicorp_vault` (KV v2) | path under the store's mount → `GET /v1/<mount>/data/<path>` | key in `data.data` (required unless the secret has exactly one key) | KV version number | latest |
| `hashicorp_vault` (KV v1) | path under the mount → `GET /v1/<mount>/<path>` | key in `data` | refused | — |
| `aws_secrets_manager` | secret name or full ARN | top-level key of the JSON `SecretString` | `VersionId`, or a staging label (`AWSCURRENT`, `AWSPREVIOUS`) | `AWSCURRENT` |
| `gcp_secret_manager` | secret id (project from the store) or `projects/<p>/secrets/<s>` | top-level JSON key | version number or alias | `latest` |
| `azure_key_vault` | secret name | top-level JSON key | version id | current |
| `env` (local) | environment variable name; must start with the store's `prefix` | top-level JSON key | refused | — |
| `file` (local) | path relative to the store's `root`; must be under `root` after `filepath.Clean` and symlink evaluation | top-level JSON key | refused | — |

Examples:

```
secret://corp-vault/ai-gateway/openai#api_key
secret://aws-prod/prod/llm/anthropic?version=AWSPREVIOUS#key
secret://gcp/projects/acme-ai/secrets/vertex-sa                 # whole SA JSON → gcp_service_account
secret://k8s/openai/api-key                                      # file store: /var/run/tg-secrets/openai/api-key
```

### Where a reference is accepted

| Entity | Paths (dot notation) | Phase |
|---|---|---|
| Registry (LLM) `auth` | `api_key.api_key`, `api_key.header_value`, `api_key.param_value`, `aws.access_key_id`, `aws.secret_access_key`, `aws.session_token`, `azure.api_key`, `azure.client_secret`, `oauth2.client_secret`, `oauth2.refresh_token`, `oauth2.password`, `gcp_service_account` | 1 |
| Registry `provider_options` | `headers.*` | 1 |
| Registry `mcp_target` | `auth.value`, `auth.client_secret`, `headers.*` | 1 |
| Registry `health_checks` | `headers.*` | 3 |
| Auth (inbound IdP) `config` | `oauth2.client_secret`, `oauth2.exchange_client_secret` | 3 |
| Policy `settings` | the plugin's `CredentialPaths()` | 3 |
| Consumer `lb_config` | `embedding.auth.*` secret fields | 3 |
| Gateway `telemetry` | `exporters[*].settings.headers.*` (OTLP), `exporters[*].settings.dsn` (Postgres) | 3 |

`secretref.Locations` holds this table as code. The validator, the
materializer and the collector all read it from there.

Write-time validation that assumes a literal changes for reference values:
- `gcpkey.Validate` is skipped for a reference. The SA JSON is checked when the
  reference resolves; a parse failure counts as unresolved.
- The AWS check "static keys or a role" counts a reference as present.

## 2. Store model

```go
// pkg/domain/secretstore
type Location string // "managed" | "local"
type Type string     // "hashicorp_vault" | "aws_secrets_manager" | "gcp_secret_manager" | "azure_key_vault" | "env" | "file"

type Store struct {
    ID           ids.SecretStoreID
    GatewayID    ids.GatewayID
    Name         string   // slug, unique per gateway
    Type         Type
    Location     Location
    HashiCorp    *HashiCorpVaultConfig    // managed only; nil for local
    AWS          *AWSSecretsManagerConfig
    GCP          *GCPSecretManagerConfig
    Azure        *AzureKeyVaultConfig
    AllowedPaths []string // managed; for local the YAML owns it
    Cache        CachePolicy
    CreatedAt    time.Time
    UpdatedAt    time.Time
}

type CachePolicy struct {
    TTL         time.Duration // default 5m, min 30s, max 24h
    MaxStale    time.Duration // default 24h, 0 = never serve stale
    NegativeTTL time.Duration // default 30s
}
```

### Managed auth methods

Phases 1–2. Phase 4 adds federation.

| Type | Methods (secret fields **bold**, sealed) |
|---|---|
| `hashicorp_vault` | `token` (**token**); `approle` (role_id, **secret_id**, mount). The connection takes `address`, `namespace`, `mount`, `kv_version` (1\|2) and `ca_cert_pem`. |
| `aws_secrets_manager` | `access_keys` (access_key_id, **secret_access_key**), with an optional `assume_role` (role_arn, external_id). The connection takes `region`. |
| `gcp_secret_manager` | `service_account_json` (**json**). The connection takes `project_id`. |
| `azure_key_vault` | `client_secret` (tenant_id, client_id, **client_secret**). The connection takes `vault_url`. |

**Vault token lifecycle.** The resolver logs in lazily. It renews the token at
2/3 of its lease and logs in again when renewal fails or Vault answers 403. It
never logs a token. A token created by `token` auth is used as is; when it
expires, the store's health becomes `auth_failed`.

### Local store file

Hybrid and self-hosted planes only. Dedicated planes are run by NeuralTrust, so they get managed stores only.

```yaml
# SECRET_STORES_FILE=/etc/trustgate/secret-stores.yaml   (and SECRET_STORES_ALLOW_LOCAL=true)
stores:
  - name: corp-vault
    type: hashicorp_vault
    allowed_paths: ["ai-gateway/"]
    cache: { ttl: 5m, max_stale: 24h }
    hashicorp_vault:
      address: https://vault.internal:8200     # private addresses allowed on local stores
      namespace: admin/ai
      mount: kv
      kv_version: 2
      auth:
        method: kubernetes                     # kubernetes | approle | token | jwt
        role: trustgate
        # token_file / secret_id_file / jwt_file: credentials only by file or env reference
  - name: aws
    type: aws_secrets_manager
    allowed_paths: ["prod/llm/"]
    aws_secrets_manager: { region: eu-west-1, auth: { method: default_chain } }   # IRSA / instance profile
  - name: k8s
    type: file
    allowed_paths: ["*"]
    file: { root: /var/run/tg-secrets }        # a K8s Secret, CSI driver or ESO-managed volume
  - name: env
    type: env
    allowed_paths: ["*"]
    env: { prefix: TG_SECRET_ }
```

- **Declaration.** The admin API declares the same `name` with
  `"location": "local"` and the `type`. A data plane that serves a reference to
  a local store that is missing from its YAML reports it as `store_missing`.
- **Names.** A gateway has one name space for all its stores. When a data
  plane's YAML holds a store with the same name as a **managed** store of the
  gateway, the plane refuses to resolve that name and reports `name_conflict`.
  It never silently prefers one of the two.

## 3. Data flows

### 3.1 Write: registry with a reference

```
PUT /v1/gateways/G/registries/R   { auth: { type: api_key, api_key: { api_key: "secret://corp-vault/ai-gateway/openai#api_key" } } }
  handler → registry.Updater
    secretref.Validator (domain + app)
      ├─ SECRET_STORES_ENABLED?                          else 422 secret_references_disabled
      ├─ declared location?                              else literal (D2)
      ├─ Parse                                           else 400 invalid_secret_reference
      ├─ caller holds secret_stores:read                 else 403 missing scope
      ├─ store "corp-vault" exists in G                  else 422 unknown_secret_store
      ├─ managed: path within allowed_paths              else 422 secret_path_not_allowed
      ├─ local: G is hybrid                              else 422 secret_store_local_not_allowed
      └─ hybrid/dedicated: connected data planes ≥ min version   else 422 data_plane_too_old (D16)
    TargetAuth.ResolveSecretsFrom(prev)                  unchanged: a reference is just a new value
  repository: seal/encrypt as today; outbox marker for G
  log event "secret_reference_set" {gateway, entity, field, store, path}   (no value: there is none)
```

### 3.2 Compile and distribution

- The compiler reads registries as today, through the decrypting repository,
  and gets the reference string back. Registry JSON carries it unchanged.
- New snapshot field: `repeated SecretStore secret_stores = <next free tag>`,
  holding `bytes json` per store, the same pattern as `Registry`. A managed
  store carries its opened auth material, as registries do today. A local store
  carries only name, type and location.
- Scoped snapshots for hybrid and dedicated gateways carry only their own
  gateway's stores.

### 3.3 Data plane: load, resolve, serve

```
request ─► AuthMiddleware ─► DataFinder.FindByGateway(G)
             cache hit ─► *Data (already materialized)            ◄── the normal path
             cache miss ─► load(G): consumers, registries, auths, policies (raw, with references)
                            └─ Materializer.Gateway(ctx, G, raw)
                                 for each declared location holding a reference:
                                   Resolver.Resolve(G, ref)  ─► cache hit | singleflight fetch (≤ 2 s)
                                   ok  → substitute the value; record ref → G in the reverse index
                                   err → "" + entity.CredentialUnavailable = {field, reason}
                                 registry.SecretRefs = refs used   (runtime only, json:"-")
             ─► forwarder ─► provider.prepare
                  registry.CredentialUnavailable? ─► 503 secret_unavailable (failover may pick another registry)
                  else CredentialsFromTargetAuth(materialized auth) ─► upstream
```

### 3.4 Rotation

| Trigger | Behaviour |
|---|---|
| Background refresher, every 15 s | Finds entries with `age ≥ 0.8·ttl ± jitter` that were used in the last hour and fetches them. Same hash → only `fetched_at` is bumped. New hash → the entry is replaced and a `Change{ref}` is published. |
| `Change{ref}` | The reverse index gives the gateways that used `ref`. The plane drops `DataFinder` key G and the matching `registry.Finder` entries, then drops G from the index. The next request reloads and re-materializes. |
| Upstream 401/403 on a registry with `SecretRefs` | `Resolver.ForceRefresh(refs)`, rate-limited to once per reference per 30 s. If the value changed, the plane invalidates and **retries once** on the same registry when the request can be replayed (not streaming, or no bytes sent yet). Otherwise the existing failover runs. |
| Store edited (managed) | The new snapshot carries a new store `UpdatedAt`. The backend client for that store is rebuilt and its entries are marked for refresh. |
| Pinned `?version=` | Never refreshed. Rotation means writing a new reference. |

The Bedrock client pool key starts to include a hash of the secret key and
session token (`pkg/infra/providers/bedrock/client.go:386`). The MCP dial
revision includes a hash of the materialized credential
(`pkg/app/mcp/target.go:123`). Without these two changes, a rotated value
could keep using a cached client.

### 3.5 Cache state per entry

```
            fetch ok                           age ≥ 0.8·ttl (refresher)
  (miss) ───────────► FRESH ───────────────────────────────► REFRESHING ──ok──► FRESH
     │                  ▲                                         │ error
     │ error            └───────────── ok ──────────────┐         ▼
     ▼                                                  │   STALE (age < ttl + max_stale): serve, count stale_served
  NEGATIVE (neg_ttl): fail fast                         └── retry with backoff (min 5 s, max ttl)
                                                            DEAD (age ≥ ttl + max_stale): error secret_unavailable
```

Errors are classified once, for every backend:

| Class | Retry and stale behaviour |
|---|---|
| `not_found` | Negative cache. Stale is served only for an entry that already resolved before. |
| `access_denied` | Negative cache. Stale is served only for an entry that already resolved before. |
| `field_not_found` | Negative cache. Stale is served only for an entry that already resolved before. |
| `invalid_payload` | Negative cache. Stale is served only for an entry that already resolved before. |
| `unavailable` (timeout, 5xx, DNS, TLS) | Retried. Stale is served. |
| `auth_failed` | Retried after a re-login. Stale is served. |

## 4. Security model

| Threat | Control |
|---|---|
| A tenant reads NeuralTrust's own secrets through pod identity, env or files on a shared plane. | Local, ambient, `env` and `file` stores cannot be configured through the API (D3). Shared planes never set `SECRET_STORES_ALLOW_LOCAL`, and a local store found in a hosted snapshot is ignored and reported. |
| An editor exfiltrates a vault secret by referencing it from a registry or policy that points at their own host. | `allowed_paths` (D4); the `secret_stores:read` requirement and the destination rule (D13); a structured `secret_reference_set` event; docs recommend a least-privilege policy on the vault side. Recognising references only at declared locations (D2) stops them from being planted in non-secret fields. |
| SSRF or credential replay through a store address. | D14. A managed Vault address goes through `netguard` (private ranges blocked unless `OUTBOUND_ALLOW_PRIVATE_NETWORKS`, which hosted planes never set). Azure URL suffix allowlist. AWS endpoint override is local-only. Store credentials are bound to their destination (D12). |
| A secret value at rest in TrustGate. | Never written to Postgres, Redis, the snapshot, the LKG file or logs. It lives only in process memory (resolver cache and materialized `*Data`), as decrypted credentials do today. |
| A secret value in responses or logs. | The resolver API returns values only to the materializer. `test` and `usages` responses carry metadata (ok, version, latency), never values. Error messages name store, path and class only. |
| Cross-gateway access. | Stores are resolved by (gateway, name). The materializer passes the entity's gateway, so a reference cannot name another gateway's store. On a hosted plane the cache key includes the store id, which embeds the gateway. |
| Store credentials leaked by an admin read. | Sealed at rest, masked in responses, merge-on-omit on update, re-entry required when the destination changes (D12). |
| Path traversal in a `file` store. | `filepath.Clean` + `EvalSymlinks` + `root` prefix check. Refused when the result leaves `root`. |
| An `env` store reads platform variables (`SERVER_SECRET_KEY`). | The `prefix` is mandatory, and a variable without that prefix is never readable. |

## 5. Interfaces / contracts

```go
// pkg/domain/secretref
type Ref struct{ Store, Path, Field, Version string }

var (
    ErrInvalidReference = fmt.Errorf("secretref: invalid reference: %w", commonerrors.ErrValidation)
)

func Parse(s string) (Ref, bool, error) // ok=false: not a reference (literal)
func IsRef(s string) bool
func (r Ref) String() string
func (r Ref) PayloadKey() string        // store|path|version: the cache key, shared by every field of one secret

type Location struct {
    Entity string // "registry.auth", "registry.mcp_target", "policy.settings", …
    Path   string // dot path; "*" segment = every map key
}

// pkg/domain/secretstore
type Secret struct {
    Payload []byte            // raw string payload
    Fields  map[string]string // KV map (Vault) or decoded top-level JSON object
    Version string
}

//go:generate mockery --name=Backend --dir=. --output=./mocks --filename=secretstore_backend_mock.go --case=underscore --with-expecter
type Backend interface {
    Fetch(ctx context.Context, path, version string) (Secret, error)
}

//go:generate mockery --name=BackendFactory ...
type BackendFactory interface {
    Open(ctx context.Context, s *Store) (Backend, error)
}

var (
    ErrNotFound       = fmt.Errorf("secretstore: secret not found: %w", commonerrors.ErrNotFound)
    ErrAccessDenied   = errors.New("secretstore: access denied")
    ErrAuthFailed     = errors.New("secretstore: authentication failed")
    ErrUnavailable    = errors.New("secretstore: backend unavailable")
    ErrFieldNotFound  = errors.New("secretstore: field not found in secret")
    ErrInvalidPayload = errors.New("secretstore: secret payload is not usable")
    ErrPathNotAllowed = fmt.Errorf("secretstore: path not allowed by store: %w", commonerrors.ErrValidation)
    ErrStoreInUse     = fmt.Errorf("secretstore: store is referenced: %w", commonerrors.ErrConflict)
)

//go:generate mockery --name=Repository ...
type Repository interface {
    Create(ctx context.Context, s *Store) error
    Update(ctx context.Context, s *Store) error
    Delete(ctx context.Context, gatewayID ids.GatewayID, id ids.SecretStoreID) error
    FindByID(ctx context.Context, gatewayID ids.GatewayID, id ids.SecretStoreID) (*Store, error)
    FindByName(ctx context.Context, gatewayID ids.GatewayID, name string) (*Store, error)
    ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*Store, error)
}

// pkg/app/secretref/resolver.go
type Resolver interface {
    Resolve(ctx context.Context, gatewayID ids.GatewayID, ref secretref.Ref) (string, error)
    ForceRefresh(ctx context.Context, gatewayID ids.GatewayID, refs []secretref.Ref) (changed bool, err error)
    OnChange(fn func(gatewayIDs []ids.GatewayID))
}

// pkg/app/secretref/materializer.go
type Unresolved struct {
    Field string
    Ref   secretref.Ref
    Class string
}

type Materializer interface {
    Registry(ctx context.Context, r *registry.Registry) (*registry.Registry, []Unresolved)
    Auth(ctx context.Context, a *auth.Auth) (*auth.Auth, []Unresolved)
    PolicySettings(ctx context.Context, gatewayID ids.GatewayID, slug string, settings map[string]any) (map[string]any, []Unresolved)
    Telemetry(ctx context.Context, gatewayID ids.GatewayID, t *telemetry.Telemetry) (*telemetry.Telemetry, []Unresolved)
}

// pkg/app/secretref/collector.go
type Use struct {
    EntityKind, EntityID, EntityName, Field string
    Ref                                     secretref.Ref
}

type Collector interface {
    Collect(ctx context.Context, gatewayID ids.GatewayID) ([]Use, error)
}
```

- `ids` gains `SecretStoreKind` / `SecretStoreID`.
- The materializer never mutates its input. It returns a copy, so the
  snapshot store and the repositories keep the references.

## 6. Admin API

All routes are under `/v1/gateways/:gateway_id/secret-stores` and guarded by
`RequireGatewayAccess(ResourceSecretStores)`, which gives the scopes
`secret_stores:read` and `secret_stores:write`.

| Method & path | Purpose |
|---|---|
| `POST /` | Create a managed or local store. |
| `GET /`, `GET /:id` | List / get. Secret fields are masked. Local stores include their health from the latest heartbeat of each connected data plane. |
| `PUT /:id` | Update. Merge-on-omit for secret fields. D12 applies when the destination changes. |
| `DELETE /:id` | 409 `secret_store_in_use` with the usages when the store is still referenced. |
| `POST /:id/test` | Managed stores only. Logs in, and when `{path, field?, version?}` is given, also fetches. Returns `{auth, read, version, latency_ms}` and **never** the value. For local stores it returns 409 `test_runs_on_data_plane`. The console instead calls the data plane's diagnostics route `POST /__diagnostics/gateways/:gateway_id/secret-stores/:name/test`, with the same diagnostics token as registry test-connection. Background health comes from the heartbeat. |
| `GET /:id/usages` | `[{entity, id, name, field, reference}]`, built by the collector. |

Example create (managed HashiCorp Vault):

```json
{
  "name": "corp-vault",
  "type": "hashicorp_vault",
  "location": "managed",
  "hashicorp_vault": {
    "address": "https://vault.example.com:8200",
    "namespace": "admin/ai",
    "mount": "kv",
    "kv_version": 2,
    "auth": { "method": "approle", "role_id": "3f1c…", "secret_id": "s.…", "mount": "approle" }
  },
  "allowed_paths": ["ai-gateway/"],
  "cache": { "ttl": "5m", "max_stale": "24h" }
}
```

Error codes. They are registered in the shared error mapper and documented in
Swagger.

| Code | Status | Raised by |
|---|---|---|
| `invalid_secret_reference` | 400 | admin API |
| `secret_references_disabled` | 422 | admin API |
| `unknown_secret_store` | 422 | admin API |
| `secret_path_not_allowed` | 422 | admin API |
| `secret_store_local_not_allowed` | 422 | admin API |
| `data_plane_too_old` | 422 | admin API |
| `secret_store_in_use` | 409 | admin API |
| `test_runs_on_data_plane` | 409 | admin API |
| `secret_unavailable` | 503 | proxy and MCP, at runtime. The body names neither path nor store; logs carry both. |

## 7. Config sync and health

- **Snapshot:** the new `secret_stores` field (§3.2).
- **Heartbeat** gains, as additive fields:
  - `repeated LocalSecretStoreStatus local_secret_stores`, with `name`,
    `type` and `state` (`ok | auth_failed | unavailable | store_missing | name_conflict | not_allowed`);
  - from Phase 3, `SecretRefHealth secret_refs` with a total, an unresolved
    count, and up to 50 failing `{gateway, store, path, field, class}`.
- The control plane keeps the latest status per connection with the existing
  config-sync connection record. The store and entity responses expose it.

## 8. Configuration (`pkg/config`, `.env.example`)

| Variable | Default | Plane | Meaning |
|---|---|---|---|
| `SECRET_STORES_ENABLED` | `false` | all | Master switch. Off: admin refuses references; planes do not resolve them. |
| `SECRET_STORES_ALLOW_LOCAL` | `false` | data | Honour local stores, ambient identity, `env` and `file`. Never set on shared planes. |
| `SECRET_STORES_FILE` | — | data | YAML of local stores (§2). |
| `SECRET_STORES_FETCH_TIMEOUT` | `2s` | all | Per-fetch timeout. |
| `SECRET_STORES_REFRESH_INTERVAL` | `15s` | all | Refresher tick. |
| `SECRET_STORES_READINESS_GATE` | `false` | data | Gate readiness on prewarm (single-gateway planes) (D17). |

## 9. Runtime readers that must materialize

| Reader | Today | Change |
|---|---|---|
| `consumer.DataFinder.load` | `pkg/app/consumer/data_finder.go` | Materialize registries, auths and policies per gateway (D5). |
| `registry.Finder` | `pkg/app/registry/finder.go:48-62` | Materialize the registry before caching. |
| Catalog live availability / Bedrock lister | `pkg/container/modules/catalog.go:139,187`. Admin `GET /v1/models-catalog` serves hosted and dedicated gateways, plus the hybrid fallback. Data plane `GET /__diagnostics/gateways/:id/registries/:rid/models` serves hybrid. | Read through `registry.Finder`, or call `Materializer.Registry`, on both planes. A local reference cannot resolve on the admin, so the hybrid fallback lists the whole catalog: the degradation it already applies when the data plane does not answer. |
| Traffic-label classifier | `pkg/infra/labelllm/classifier.go:117` | Same. |
| Test connection (by `registry_id`) | `pkg/app/registry` test use case. Admin route for hosted and dedicated; data-plane `/__diagnostics/.../test-connection` for hybrid. | Materialize on whichever plane runs it; on a failure, report `secret_unavailable` with the class. |
| MCP static target / credential resolver | `pkg/app/mcp/target.go`, `credentials.go` | Fed by materialized registries; add the dial-revision hash. |
| Telemetry exporter construction | `pkg/infra/telemetry` | Phase 3: `Materializer.Telemetry`. |
| Consumer embedding (semantic LB) | `pkg/domain/consumer/lb_config.go` | Phase 3. |

A test in `pkg/app/secretref` keeps this table honest. It builds every runtime
module with a registry holding a reference and a fake resolver, and asserts
that no provider client, plugin or exporter ever sees the `secret://` string.

## 10. Console (`NeuralTrust/app`)

**Settings → Gateway → "Secret stores" tab.** It sits next to Credentials and
Machine identity, in `app/[locale]/v2/features/settings/components/gateway/`.
- **Table:** name, type, location badge (*Managed* / *Local on your data
  plane*), health, usages count and last update.
- **"Add store" side panel:**
  - type picker;
  - location picker, where *Local* is offered only for hybrid gateways;
  - for managed stores, a type-specific form, allowed paths and cache
    settings, plus *Test connection* with an optional path;
  - for local stores, name and type only, plus a copyable YAML snippet for the
    data plane.
- **Delete:** when the store is in use, the dialog shows the usages and offers
  links to them.

**`SecretInput` component.** It replaces the password input for every field
with `secret: true`: the registry schema renderer, the MCP config panel and the
policy credential fields.
- A segmented control switches between **Value** and **Secret store**.
- In *Secret store* mode the user picks a store and enters a path (with the
  allowed-path hint), an optional field and an optional version (advanced). The
  resulting `secret://…` string is shown read-only and can be copied. *Test*
  calls `POST /secret-stores/:id/test`.
- On edit, the API returns a reference verbatim, so the field opens in
  *Secret store* mode already filled in.
- **Badges:** cards show "from corp-vault". A warning appears when a data plane
  reports the reference as unresolved.
- **Audit:** console server actions log `secret_store.*` and
  `secret_reference.set` through `logV2AuditEvent`.

## 11. File changes (TrustGate)

| File | Change |
|---|---|
| `pkg/domain/ids/ids.go` | `SecretStoreKind`, `SecretStoreID` |
| `pkg/domain/secretref/{ref.go,locations.go}` (+ tests, fuzz) | grammar and the location table |
| `pkg/domain/secretstore/{store.go,config.go,auth.go,backend.go,repository.go,errors.go}` + `mocks/` | entity and ports |
| `pkg/app/secretstore/{creator,updater,deleter,finder,lister,tester,usages}.go` + `mocks/` | use cases |
| `pkg/app/secretref/{resolver.go,cache.go,refresher.go,materializer.go,collector.go,validator.go}` | resolution core |
| `pkg/infra/secretstore/{hashicorp,awssm,gcpsm,azurekv,envstore,filestore}/` | backends + factory |
| `pkg/infra/secretstore/localfile/loader.go` | `SECRET_STORES_FILE` loader + validation |
| `pkg/infra/repository/secretstore/repository.go` | Postgres + `FieldSealer` |
| `pkg/infra/database/migrations/<ts>_create_secret_stores.go` | table `secret_stores(id, gateway_id, name, type, location, config JSONB, auth TEXT sealed, allowed_paths TEXT[], cache JSONB, created_at, updated_at, UNIQUE(gateway_id, lower(name)))` |
| `pkg/infra/configsnapshot/proto/{snapshot,configsync}.proto`, `codec.go`, compiler | `secret_stores` field, heartbeat fields |
| `pkg/runtimeconfig/snapshot/adapters/secret_store_repository.go` | snapshot adapter |
| `pkg/app/consumer/data_finder.go`, `pkg/app/registry/finder.go`, readers in §9 | materializer wiring + invalidation |
| `pkg/app/proxy/provider.go`, `pkg/app/mcp/*` | `CredentialUnavailable`, forced refresh + retry, revision hash |
| `pkg/infra/providers/bedrock/client.go` | pool key includes a secret hash |
| `pkg/common/secret/{secret.go,settings.go}` | references pass through `Mask` and `MaskSettings` |
| `pkg/domain/registry/{target.go,mcp_target.go}`, `pkg/app/policy/updater.go`, auth and gateway updaters | write-time reference validation |
| `pkg/api/handler/http/secretstore/{request,response}/…`, handlers | API (one DTO per file) |
| `pkg/api/middleware/admin_scopes.go` | `ResourceSecretStores` |
| `pkg/server/router/admin_router.go` | routes |
| `pkg/container/modules/secretstore.go` | DI: backends, resolver (singleton per plane), refresher lifecycle |
| `pkg/config/config.go`, `.env.example` | variables in §8 |
| `docs/secret-stores.md`, `docs/openapi.json`/`swagger.*` | user docs, API |
| `downloads/docker-compose.yml`, `k8s/` examples | local store example for hybrid |

## 12. Testing strategy

- **Grammar.** Table tests and `FuzzParse`. The fuzz target asserts that
  `String(Parse(x)) == canonical(x)` and that no panic occurs. Edge cases:
  percent-encoding, `..`, an empty field, length limits, ARN paths.
- **Validator.** Every location in `secretref.Locations` accepts a reference.
  The same string at a non-declared location stays literal. Scope, store and
  path errors map to the right codes.
- **Masking.** `Mask`, `MaskSettings` and `ResolveSettings` return a reference
  unchanged. A masked echo still keeps a literal. A destination change with a
  reference and without `secret_stores:read` is refused.
- **Resolver.** Uses a fake clock and a fake backend:
  - fresh → refresh → same hash, no change event;
  - a new hash publishes one change;
  - stale serving up to `max_stale`, then `secret_unavailable`;
  - negative cache;
  - singleflight: 100 concurrent misses make one fetch;
  - forced-refresh rate limit;
  - pinned version never refreshes;
  - idle eviction;
  - `-race`.
- **Materializer.**
  - Every location is covered.
  - An unresolved reference gives an empty value plus `CredentialUnavailable`.
  - The input is not mutated.
  - The reverse index drives invalidation of `DataFinder`.
- **Backends.**
  - Vault KV v1/v2, AppRole login and renew, and namespace headers, against an
    `httptest` server.
  - The GCP REST client against `httptest`.
  - AWS and Azure through injected HTTP clients with recorded responses.
  - Optional integration tag with a Vault dev container and LocalStack.
- **Hardening.**
  - netguard blocks a private Vault address on hosted.
  - The Azure URL suffix allowlist.
  - The `file` store refuses `../` and symlink escapes.
  - An `env` store without its prefix cannot read the variable.
  - A local store in a hosted snapshot is ignored.
- **Snapshot.** The codec test asserts that registry JSON in the snapshot holds
  the reference and never the value. This complements `codec_secret_test.go`.
- **End to end.** A DB-less proxy fed a snapshot with a reference and a fake
  vault:
  - the upstream `httptest` sees the resolved key;
  - after a rotation it sees the new key within one refresher tick;
  - after a forced 401 it sees the new key on the retry;
  - with the vault down it keeps serving until `max_stale`.

## 13. Migration and rollout

1. Ship Phase 1 with `SECRET_STORES_ENABLED=false` everywhere. The migration is
   additive; the proto fields are additive.
2. Deploy the data planes first: hosted, then the hybrid images. Then enable
   the flag on dev data planes, then on the dev admin.
3. Dogfood: move one internal gateway's provider keys to GCP Secret Manager
   (Phase 2) or Vault.
4. Enable it in prod for selected tenants. Hybrid customers need data-plane
   images at or above the minimum version. The admin enforces this through
   D16.
5. Documentation:
   - `docs/secret-stores.md`, covering backends, the least-privilege vault
     policies, the local YAML and a migration guide from literal values;
   - a "platform secrets" section pointing to CSI and ESO for
     `SERVER_SECRET_KEY` and friends.

Rollback: turn the flag off. Gateways that use references then need literal
values again; the usages endpoint lists them.

## Rejected alternatives

- **R1. Resolve in the compiler and ship values** (central, LiteLLM-like). See
  D1: it fails G3, cannot reach private vaults, and makes rotation depend on
  polling and recompiles.
- **R2. A structured reference object in the DTOs.** See D2.
- **R3. Resolve at each call site.** See D5.
- **R4. One global secret manager per deployment, configured from the
  environment** (the LiteLLM model). That model cannot work on a multi-tenant
  SaaS plane, and it couples every gateway to one credential.
- **R5. A shared Redis cache of resolved values.** It puts plaintext in a shared
  store. The fetch volume does not justify it.
- **R6. Only document sidecars** (Vault Agent, ESO, CSI). That needs a file or
  env var per secret, restarts on change, and does nothing for hosted gateways.
  It is still supported, through the local `file` and `env` stores, which serve
  the same mounts without restarts.
- **R7. LiteLLM-style `os.environ/NAME`.** It is ambiguous: an env var and a
  secret id share one string. It carries no store, field or version. A
  `secret://env/NAME` local store covers the same use.

## Open questions

- **OQ1. Default `max_stale`.** 24 h (availability first) versus 1 h (revocation
  first). It is configurable per store; only the default needs a product call.
- **OQ2.** Should hybrid planes be allowed to opt into persisting resolved
  values in the encrypted LKG, so they survive a restart while the vault is
  down? The default stays off (G3). This would be an explicit operator flag if
  customers ask for it.
- **OQ3 (resolved). On-demand test of local stores.** Reuse the data-plane
  diagnostics routes that the console already calls for hybrid test-connection
  and model listing, through a new `POST /__diagnostics/gateways/:gateway_id/secret-stores/:name/test`.
  No config-sync message is needed.
- **OQ4. Packaging.** LiteLLM, Kong and Portkey gate this as Enterprise. Do we
  gate managed cloud backends behind a plan entitlement (`tenant_entitlements`),
  and keep `env`/`file` open? Product decision, independent of the design.
- **OQ5. Federation issuer for Phase 4.** Reuse the STS signer on a dedicated
  key with its own purpose, or use a separate issuer? Needs its own design,
  including how ExternalId is generated for AWS and the trust policy templates.
