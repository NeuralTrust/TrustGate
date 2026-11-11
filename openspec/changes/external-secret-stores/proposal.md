# Proposal: External secret stores (vault references)

## Intent

Customers want to keep upstream credentials in their own secret manager
(HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault)
instead of pasting them into TrustGate. LiteLLM, Kong and Portkey all offer
this.

Today every credential an admin configures is stored in TrustGate's database.
That covers LLM provider keys, MCP server tokens, plugin API keys and exporter
headers. Some are encrypted, some are plaintext (`exploration.md` §1.1). They
are then compiled in plaintext into the config snapshot. For **hybrid**
gateways the snapshot is sent to the customer's own data plane. A
credential that never needed to leave the customer's network therefore goes
through NeuralTrust's SaaS and database.

This change lets any credential field hold a **reference** such as
`secret://corp-vault/ai/openai#api_key`, which the data plane resolves itself.
The value is cached, refreshed in the background and survives a vault outage.
Rotating a secret in the vault needs no TrustGate write.

Linear: _pending (no issue yet)_. Research: `exploration.md`.

## Goals

- **G1. Any declared credential field can hold a reference instead of a value.**
  The same grammar works everywhere: typed fields (registry auth, MCP auth) and
  untyped plugin settings (`CredentialPaths()`).
- **G2. Backends.** HashiCorp Vault and OpenBao (KV v1/v2), AWS Secrets
  Manager, GCP Secret Manager and Azure Key Vault. Hybrid and self-hosted
  planes also get local `env` and `file` stores.
- **G3. Data-plane resolution.** For a gateway whose stores are local to its
  data plane, the secret value and the store's credentials never reach the
  control plane, its database, the snapshot or the LKG file.
- **G4. Rotation without a TrustGate write.**
  - Background refresh-ahead within the store TTL (default 5 min).
  - Immediate re-fetch when the upstream rejects a referenced credential (401/403).
- **G5. Fail static, fail loud.**
  - A vault outage keeps serving the last good value up to `max_stale`.
  - An unresolved reference is never sent upstream.
  - The failure shows up in metrics, error codes and the console.
- **G6. Multi-tenant safe.**
  - Shared (hosted) planes never use ambient pod identity, `env` or `file`.
  - Tenant-supplied addresses go through `netguard`.
  - A store can be used only by its own gateway, and only within its allowed
    path prefixes.
- **G7. Manageable.**
  - Admin API and console UI to create, test and delete stores.
  - Every secret input can switch between a value and a reference.
  - Deleting a store that is still referenced is refused, with the list of
    places that use it.

## Scope

### In scope

**Phase 1: core and managed stores (hosted and hybrid)**
- Domain:
  - `secretref.Ref` (grammar, parse, validate);
  - `secretstore.Store` (entity, typed config, sealed auth, allowed paths,
    cache policy);
  - `Repository` and `Backend` ports.
- Backends:
  - HashiCorp Vault KV v1/v2 with token or AppRole auth;
  - AWS Secrets Manager with static keys and an optional assume-role.
- Admin API: `/v1/gateways/:gateway_id/secret-stores` CRUD, `POST /:id/test`,
  `GET /:id/usages`; scope `secret_stores:read|write`.
- Postgres table `secret_stores`. Auth material is sealed with `FieldSealer`
  under purpose `secret-stores/v1`.
- The snapshot gains a `secret_stores` field (JSON per store, like `Registry`)
  and a snapshot adapter.
- Resolver with an in-process cache:
  - singleflight;
  - refresh-ahead;
  - stale-on-error up to `max_stale`;
  - negative cache;
  - forced refresh on upstream 401/403.
- Materializer: substitutes references in the runtime read model
  (`consumer.DataFinder`, `registry.Finder`). Every plane gets it at once.
- First reference sites: registry `TargetAuth` (E1), `provider_options.headers`
  (E2) and MCP target auth and headers (E4). The control-plane readers of E1
  (test-connection, catalog live availability, Bedrock lister, label
  classifier) go through the materializer too.
- Metrics and structured errors (`secret_unavailable`). Resolved values never
  appear in logs.
- All of this behind `SECRET_STORES_ENABLED` (default `false`).

**Phase 2: local stores and the other cloud backends**
- Local stores, declared on the data plane in `SECRET_STORES_FILE` (YAML).
  Allowed only on hybrid and self-hosted planes (`SECRET_STORES_ALLOW_LOCAL=true`).
  Dedicated planes are run by NeuralTrust, so they behave like hosted.
  They can use:
  - ambient identity: AWS default chain or IRSA, GCP ADC or Workload Identity,
    Azure managed or workload identity, Vault Kubernetes auth;
  - `env` and `file` stores.
- `Heartbeat` reports local store names, types and health.
- GCP Secret Manager (SA JSON, impersonation on local stores) and Azure Key
  Vault (client secret; managed identity on local stores).

**Phase 3: the remaining reference sites**
- Inbound IdP client secrets (E5), plugin `CredentialPaths()` (E6), consumer
  embedding key (E7), telemetry exporter headers and DSN (E8), health-check
  headers (E3).
- Per-reference health: the data plane reports failing references, and the
  console shows them on the entity.

**Phase 4: keyless federation for hosted gateways (separate design review)**
- TrustGate becomes an OIDC issuer with a per-gateway subject (`gateway:<id>`).
  Customers trust it from Vault JWT auth, AWS `AssumeRoleWithWebIdentity`, GCP
  Workload Identity Federation and Azure federated credentials. Hosted gateways
  then need no long-lived store credential.

**Console (`NeuralTrust/app`), alongside phases 1–3**
- Gateway Settings: a new "Secret stores" tab with list, type-specific create
  form, test connection and usages.
- A shared `SecretInput` with two modes, "Value" and "From secret store", used
  by every field with `secret: true`. The second mode picks a store, path,
  field and optional version, and has a "Test" action.

### Out of scope

- Mirroring consumer API keys into a vault, as LiteLLM's `store_virtual_keys`
  does. They are hashed, so there is nothing to store.
- Per-user MCP OAuth tokens (`pkg/domain/vault`). They are written at runtime per
  principal; moving that store to an external backend is a separate change.
- Platform secrets (`SERVER_SECRET_KEY`, `DB_PASSWORD`, …). Operators already
  inject them through env, `/etc/secrets/*`, CSI or ESO. We will document the
  pattern but add no code.
- Write-through ("TrustGate writes a pasted secret into your store"), Vault
  dynamic secrets and leases, KMS envelope encryption of `SERVER_SECRET_KEY`.
  These are follow-ups.
- CyberArk, Infisical, 1Password, Doppler. The `Backend` port keeps them cheap
  to add later.

## Capabilities

### New
- `secret-references`: the grammar, the locations where a reference is
  accepted, admin validation, and response semantics.
- `secret-stores`: the managed store lifecycle (API, sealing, scoping, delete
  protection, test) and local stores.
- `secret-resolution`: resolver semantics on every plane (cache, refresh,
  stale, negative cache, forced refresh, failure behaviour, metrics).

### Modified
- `config-snapshot`: gains the `secret_stores` field. References are carried
  verbatim and are never resolved by the compiler.
- `config-sync heartbeat`: gains local store and reference health (Phase 2–3).
- Credential masking (`pkg/common/secret`): a reference is returned verbatim
  rather than masked, because it is not a secret.

## Approach (summary; see design.md)

1. **One grammar.** `secret://<store>/<path>[?version=<v>][#<field>]` is
   recognised only at declared secret locations. Anywhere else it is plain
   text.
2. **The control plane stores and ships references, never their values.** The
   compiler copies them into the snapshot unchanged.
3. **Each plane resolves its own references.** The `Materializer` runs where a
   gateway's runtime model is loaded (`DataFinder.load`) and substitutes
   values from the resolver's cache. Downstream code (provider clients,
   plugins, MCP dialer) is unchanged.
4. **When a resolved value changes, the plane invalidates its own copy.**
   Refresh or forced refresh drops the affected gateway's cached data and
   registry entries with the existing invalidation hooks. The next request
   rebuilds them.
5. **Who may use what depends on who declared the store.**
   - Managed stores (API, sealed credentials) work everywhere.
   - Local stores (data-plane YAML, ambient identity, `env`/`file`) work only
     on planes that are not shared.

## Affected areas

| Area | Change |
|---|---|
| `pkg/domain/secretref` (new) | `Ref`, `Parse`, `IsRef`, `Location` |
| `pkg/domain/secretstore` (new) | `Store`, typed config/auth, `Repository`, `Backend`, `BackendFactory`, errors |
| `pkg/app/secretstore` (new) | creator, updater, deleter, finder, tester, usages |
| `pkg/app/secretref` (new) | `Resolver` (cache), `Materializer`, `Collector` (walks references) |
| `pkg/infra/secretstore/{hashicorp,awssm,gcpsm,azurekv,env,file}` (new) | backends |
| `pkg/infra/repository/secretstore` (new) + migration | Postgres table, sealing |
| `pkg/runtimeconfig/snapshot/adapters` | secret-store snapshot adapter |
| `pkg/infra/configsnapshot` (proto + codec + compiler) | `secret_stores` field |
| `pkg/app/consumer/data_finder.go`, `pkg/app/registry/finder.go` | call the materializer |
| `pkg/app/proxy/provider.go`, `pkg/app/mcp` | forced refresh on 401/403 |
| `pkg/common/secret` | `Mask` / `Resolve` / `MaskSettings` leave references untouched |
| `pkg/domain/registry`, `pkg/domain/auth`, `pkg/app/policy` | write-time reference validation |
| `pkg/api/handler/http/secretstore` (new), `pkg/server/router/admin_router.go`, `pkg/api/middleware/admin_scopes.go` | API, scopes |
| `pkg/config` | `SECRET_STORES_ENABLED`, `SECRET_STORES_ALLOW_LOCAL`, `SECRET_STORES_FILE` |
| `NeuralTrust/app` | Secret stores settings tab, `SecretInput`, server actions, i18n |

## Risks

| Risk | Mitigation |
|---|---|
| **Exfiltration through references.** An admin who can edit a registry can reference any path the store can read and point the registry's `base_url` at their own host. | `allowed_paths` on every store (required); a reference written by a caller needs `secret_stores:read` on that gateway; audit of every reference added; docs recommend a least-privilege policy on the vault side. |
| **Confused deputy on shared planes.** A tenant names a store that uses NeuralTrust's own pod identity, or `env`/`file`, and reads NeuralTrust secrets. | Local and ambient stores cannot be created through the API. They exist only in data-plane YAML and are refused unless `SECRET_STORES_ALLOW_LOCAL=true`, which hosted planes never set. |
| **SSRF or credential replay to a tenant-supplied address.** | Hosted planes dial Vault addresses through `netguard`. HTTPS is required. The Azure vault URL must match the Key Vault DNS suffixes. A custom AWS endpoint is allowed on local stores only. |
| **Vault outage takes traffic down.** | Refresh-ahead; stale-on-error up to `max_stale` (default 24 h); registry failover already routes around a registry whose credential is unavailable. |
| **Hot-path latency.** | Fetches happen only on a cold cache. Refresh-ahead keeps the request path at cache hits. Singleflight and a bounded timeout (default 2 s). |
| **Vault rate limits from many replicas.** | One fetch per (store, path, version) per replica per TTL, plus jitter. The negative cache stops retries on missing secrets. |
| **A reference string sent upstream (LiteLLM #26151).** | The materializer replaces an unresolved reference with an empty value and marks the entity `CredentialUnavailable`. The invoker fails with `secret_unavailable` before dialing. |
| **Snapshot compatibility.** | A new proto field. Data planes that predate it ignore it. They also cannot resolve references, so a gateway that uses references needs data planes on the new version. The console reports the version from `Heartbeat`, and the admin API warns. |

## Rollback plan

- Set `SECRET_STORES_ENABLED=false`. Then:
  - the admin API refuses new references and new stores;
  - existing references stay stored;
  - the compiler keeps sending stores, but data planes with the flag off do not
    resolve them, and traffic that depends on them fails with
    `secret_unavailable`.
- Real rollback for a gateway means replacing its references with literal
  values. A `GET /secret-stores/:id/usages` listing makes that mechanical.
- The migration is additive (a new table); the proto change is additive.

## Dependencies

- New Go modules:
  - `github.com/aws/aws-sdk-go-v2/service/secretsmanager`;
  - `github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets`.
- Vault and GCP Secret Manager go through their REST APIs on TrustGate's own
  HTTP client, which keeps `netguard` in control. Their SDKs would add heavy
  transitive dependencies; see D11.
- Console work in `NeuralTrust/app`.
- Phase 4 needs a public OIDC discovery document and JWKS for the federation
  issuer.

## Success criteria

- [ ] A registry with `api_key: secret://corp/ai/openai#key` serves traffic on
  a hosted plane (managed store) and on a hybrid plane (local store). Its value
  is never in Postgres, the snapshot, the LKG file, logs or API responses.
- [ ] A secret rotated in the vault is picked up:
  - within the TTL with no TrustGate write;
  - immediately after an upstream 401.
- [ ] With the vault unreachable, traffic keeps flowing on the last good value
  until `max_stale`, and an alert-worthy metric fires.
- [ ] An unresolved reference fails the request with `secret_unavailable`. The
  reference string is never sent upstream.
- [ ] A hosted gateway cannot use an ambient, `env` or `file` store. A
  reference outside `allowed_paths` is refused at write time.
- [ ] A store that is still referenced cannot be deleted; the response lists
  where it is used.
