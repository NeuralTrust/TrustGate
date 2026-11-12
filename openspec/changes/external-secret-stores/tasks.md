# Tasks: External secret stores for customer-operated deployments

Linear: _pending_. Base: `origin/develop`.

Chain strategy:
- TrustGate slices are stacked PRs to `develop`, one branch per slice
  (`feat/<issue>-sN-<slug>`). Every slice stays inert until
  `SECRET_STORES_ENABLED=true`.
- Chart (`NeuralTrust/neuraltrust-platform`), console (`NeuralTrust/app`) and
  docs (`NeuralTrust/docs`) each get their own PRs once the TrustGate contracts
  they depend on are merged to `develop`.

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~5,600 total, tests included: TrustGate Phase 1 ~3,100, Phase 2 ~950; chart ~300; console ~1,100; docs ~150 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | S1 → S2 → S3 → S4 → S5 → S5b → S6 → S6b → S7 (Phase 1) → S8 → S9 → S10 (Phase 2); H1 after S3; A1–A3 after S5/S6; DOC1 with H1; A4 after S10 |
| Delivery strategy | ask-on-risk |
| Chain strategy | stacked PRs to `develop` |

**Decision needed before apply: Yes.** Before work starts, settle the following:
- **Scope:** approve the customer-operated scope (D1).
- **Chart keys (OQ3):** agree the chart keys with the chart owners.
- **`max_stale` (OQ1):** decide the default.
- **Packaging (OQ4):** decide how the feature is packaged.
- **GCP/Azure in Phase 1 (OQ6):** decide whether GCP and Azure ship in Phase 1.

## Phase 1: hybrid, self-hosted and central

| Unit | Goal | Lines | Depends on |
|------|------|-------|------------|
| S1 | **Domain.** `secretref` (grammar, `Locations`, `FuzzParse`); `secretstore` (model, typed config, `Backend`/`Catalog` ports, `Eligible`, `Store.Allows`, error classes); variables in `pkg/config` + `.env.example` | ~450 | — |
| S2 | **Resolver core.** Cache (TTL, refresh-ahead, stale, negative, singleflight, eviction), refresher and probe loops, forced refresh, metrics. Fake clock and backend tests, run with `-race`. | ~550 | S1 |
| S3 | **Store file + backends.** `localfile` loader (strict, no inline secrets, `saas` guard, `gateways` allowlist, fsnotify reload). Backends: Vault/OpenBao (Kubernetes, JWT, AppRole, token; KV v1/v2; renew) over our HTTP client; AWS Secrets Manager (default chain, assume-role, VPC endpoint); `file`; `env`. | ~700 | S1, S2 |
| S4 | **Materialization (compatibility first).** Zero-cost fast path when no value starts with `secret://`; golden tests showing identical `DataFinder` output, Bedrock keys and MCP revisions for literal credentials; reference-shaped values never forwarded, flag on or off. Then: `Materializer` + `Collector`. Integration into `DataFinder.load` and `registry.Finder` on any plane with a catalog, with reverse-index invalidation. Guard D13b (eligibility + allowlist). Readers listed in §7 of the design. `CredentialUnavailable` → `secret_unavailable`. Forced refresh plus one retry on 401/403. Bedrock pool key (`ref:<registry>:<hash>`, previous entry deleted on change) and MCP revision hash, both only for reference-derived credentials. Codec test. | ~650 | S2 |
| S5 | **Store source + admin.** `SourceResolver` (heartbeat union vs. admin catalog, `supported`). Heartbeat `secret_stores`: proto, client, hub, migration on `config_sync_connections`, `MarkHeartbeat`. `ResourceSecretStores`. `GET /secret-stores` and `/:name/usages`. Write-time validator (eligibility, scope, store, allowlist, paths, version; strict when nothing is connected, with the `allow_unverified_secret_refs` opt-in), wired into the registry and MCP target writes. `too_old` instance state plus a `secret_refs_on_old_data_plane` log and metric. Masking pass-through. `secret_reference_set` event. Swagger. | ~700 | S1, S3, S4 |
| S6 | **Tests on both planes.** Admin `POST /:name/test` (catalog only). Data-plane `POST /__diagnostics/…/secret-stores/:name/test`. Admin test-connection and `/v1/models-catalog` resolve through `registry.Finder` when a catalog exists. | ~350 | S4, S5 |
| S5b | **Gated serving.** `accepts_secret_refs` in `Hello`, `GetSnapshotRequest` and `GetManifestRequest` (client always sets it); per-scope and per-version `HasSecretRefs` in the compiler and Holder (and manifests); hub suppresses notices; `FailedPrecondition` `secret_refs_unsupported`; `too_old` on the connection, log and metric; tests with a fake old client (LKG kept, fresh pod not ready, scopes without references unaffected) | ~300 | S4, S5 |
| S6b | **Pre-deploy scan.** `./trustgate secret-refs-scan` subcommand: reads Postgres, prints gateway, entity and field of credential values starting with `secret://`, never the values themselves. Chart pre-upgrade Job when `secretStores.enabled` flips on. | ~150 | S4 |
| S7 | **Prewarm, e2e, compose.** Prewarm and `SECRET_STORES_READINESS_GATE`. e2e for hybrid (DB-less plane, fake Vault, `httptest` upstream: serve, rotate, 401 retry, outage, no value in logs or the snapshot) and for external (`run` with a catalog: validate, test-connection, serve). Compose example. | ~450 | S5, S6 |

## Phase 2: complete coverage

| Unit | Goal | Lines | Depends on |
|------|------|-------|------------|
| S8 | GCP Secret Manager (REST + `gcpauth`, ADC/Workload Identity) and Azure Key Vault (`azsecrets`, workload or managed identity). Can move into Phase 1 (OQ6). | ~400 | S3 |
| S9 | Remaining locations: E3 (health-check headers), E5 (IdP secrets), E6 (plugin `CredentialPaths()` with the destination rule), E7 (consumer embedding) and E8 (telemetry exporters) | ~450 | S4, S5 |
| S10 | Per-reference health: heartbeat `secret_refs`, an admin-catalog report, persistence and exposure on entity responses | ~300 | S5 |

## Chart: `NeuralTrust/neuraltrust-platform`

| Unit | Goal | Lines | Depends on |
|------|------|-------|------------|
| H1 | `agentgateway.secretStores`: <ul><li>ConfigMap from `stores`;</li><li>mounted on proxy + MCP (hybrid) and on admin + proxy + MCP (external, saas-central);</li><li>Secret mounts (`caCert`, `secretIdSecret`, `tokenSecret`, `file.secrets`) rewritten to `*_file`;</li><li>`SECRET_STORES_ENABLED`, `SECRET_STORES_FILE`, readiness gate;</li><li>`SECRET_STORES_GATEWAYS` defaulted per `global.deploymentMode`;</li><li>a render test showing that `secretStores.enabled=false` produces manifests identical to the previous chart version;</li><li>the pre-upgrade scan Job;</li><li>reuse of `serviceAccount.annotations` and `global.gcpIdentity`;</li><li>render tests per mode;</li><li>`VALUES_SCENARIOS.md` and `SECRETS.md`.</li></ul> | ~300 | S3 (file format frozen) |

## Console: `NeuralTrust/app`

| Unit | Goal | Lines | Depends on |
|------|------|-------|------------|
| A1 | **"Secret stores" tab** (shown when `supported`; a 404 from an older admin reads as unsupported). <ul><li>`too_old` warning with the downgrade checklist.</li><li>Header by `source`.</li><li>List and row detail with per-instance state and error-class hints.</li><li>Usages.</li><li>"Test a secret", routed by gateway type: data-plane diagnostics through `mintDiagnosticsToken` for hybrid, the admin route otherwise.</li><li>i18n.</li></ul> | ~400 | S5, S6 |
| A2 | **"Add a secret store" generator.** <ul><li>Type forms with no secret inputs.</li><li>*Gateways* prefilled.</li><li>Values snippet, with the target file chosen by `source`.</li><li>Least-privilege prerequisites (Vault policy and role, IAM policy, `gcloud`, `az`).</li><li>`helm upgrade` command.</li><li>Poller that waits for the store to be reported.</li></ul> | ~400 | S5, H1 keys |
| A3 | **`SecretInput`.** <ul><li>Value / From secret store; store selector, path check, key, version, preview, Test.</li><li>Round-trip parse of stored references.</li><li>Used in `RegistrySchemaFieldRenderer`, `GcpServiceAccountField` and `McpServerConfigPanel`.</li><li>Badges.</li><li>`logV2AuditEvent`.</li><li>Confirmation dialog before sending `allow_unverified_secret_refs`.</li><li>Add `secret_stores:read` to `GATEWAY_CREDENTIAL_SCOPES` (opt-in, not in the defaults).</li></ul> | ~380 | S5, S6 |
| A4 | Failing-reference warnings on cards. `SecretInput` in the policy and telemetry forms. | ~150 | S9, S10 |

## Public docs: `NeuralTrust/docs`

| Unit | Goal | Lines | Depends on |
|------|------|-------|------------|
| DOC1 | <ul><li>`neuraltrust/deployment/secrets.mdx`: new section "Provider credentials from your secret manager".</li><li>`configuration.mdx`: `agentgateway.secretStores` reference.</li><li>Hybrid and Self-hosted pages: one example each.</li><li>A "Secret stores" guide per backend: keyless setup, least-privilege policy, migration from literal values, troubleshooting by error class.</li></ul> | ~150 (prose) | H1, S7 |

## Common verification (every TrustGate slice)

```bash
go build ./...
go vet ./...
go test -race ./pkg/domain/secretref/... ./pkg/domain/secretstore/... ./pkg/app/secretref/... ./pkg/app/secretstore/... ./pkg/infra/secretstore/...
go test -race ./pkg/app/consumer/... ./pkg/app/registry/... ./pkg/infra/configsnapshot/... ./pkg/infra/configsync/... ./pkg/runtimeconfig/...
go generate ./pkg/domain/secretstore/... ./pkg/app/secretref/... ./pkg/app/secretstore/...   # mocks up to date (no diff)
golangci-lint run ./...
```

Console slices run `npm run lint` and `npm run test:unit`, plus
`npm run build:local` before pushing. Chart slices run the render-test scripts
under `scripts/helm-render-tests/`.

## Definition of done (Phase 1)

- [ ] The e2e tests cover the proposal's success criteria for hybrid
  (Vault Kubernetes auth, AWS default chain, `file`) and for external
  (admin catalog: validate, test-connection, serve).
- [ ] No resolved value appears in a snapshot, LKG, heartbeat, log, admin
  response or diagnostics response. Tests assert this.
- [ ] A `saas` plane refuses `SECRET_STORES_FILE`. Ineligible gateways cannot
  hold or resolve references. The `gateways` allowlist is enforced on the admin
  and on the planes.
- [ ] With the flag off: golden tests prove existing gateways are unaffected,
  the disabled chart renders identically, and `secret-refs-scan` reports zero
  in dev and prod.
- [ ] Chart render tests pass for `hybrid`, `external` and `saas` (central).
  The docs pages are published.
