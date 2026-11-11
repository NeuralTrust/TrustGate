# Tasks: External secret stores for hybrid gateways

Linear: _pending_. Base: `origin/develop`.

Chain strategy:
- TrustGate slices are stacked PRs to `develop`, one branch per slice
  (`feat/<issue>-sN-<slug>`).
- Every TrustGate slice is inert until `SECRET_STORES_ENABLED=true`.
- The chart change (H1) goes to the neuraltrust-platform chart repo once the
  key names are agreed (OQ3).
- Console slices go to `develop` in `NeuralTrust/app`, behind a console feature
  flag, once the API slices they need are deployed to dev.

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~4,800 total, tests included: TrustGate Phase 1 ~2,700, Phase 2 ~900; chart ~150; console ~1,100 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | S1 → S2 → S3 → S4 → S5 → S6 (Phase 1) → S7 → S8 → S9 (Phase 2); H1 after S3; A1/A2 after S5 and S6; A3 after S5; A4 after S9 |
| Delivery strategy | ask-on-risk |
| Chain strategy | stacked PRs to `develop` |

Decision needed before apply: **Yes**.
- Approve hybrid-first scope (D1).
- Agree chart keys (OQ3).
- Decide default `max_stale` (OQ1) and packaging (OQ4).

## Phase 1: hybrid MVP

| Unit | Goal | Lines | Depends on |
|------|------|-------|------------|
| S1 | **Domain.** `secretref` (grammar, `Locations`, `FuzzParse`); `secretstore` (store model, typed config, `Backend`/`Catalog` ports, error classes); config variables in `pkg/config` + `.env.example` | ~400 | — |
| S2 | **Resolver core.** Cache (TTL, refresh-ahead, stale, negative, singleflight, eviction), refresher and probe loops in DI, forced-refresh API, metrics. Tests with a fake clock and fake backend, `-race`. | ~550 | S1 |
| S3 | **Local stores + backends.** `localfile` loader (strict decode, no inline secrets, `saas` guard, fsnotify reload); Vault/OpenBao (Kubernetes, JWT, AppRole, token; KV v1/v2; renew) over our HTTP client; AWS Secrets Manager (default chain, assume-role, VPC endpoint); `file` (confined root); `env` (prefix) | ~700 | S1, S2 |
| S4 | **Materialization.** `Materializer` + `Collector`; `DataFinder.load` / `registry.Finder` integration + reverse-index invalidation; hybrid-only guard (D13b); §6 readers; `CredentialUnavailable` → `secret_unavailable`; forced refresh + one retry on 401/403; Bedrock pool key + MCP revision hash; codec test that the reference survives | ~600 | S2 |
| S5 | **Discovery + admin.** Heartbeat `secret_stores` (proto, client, hub); migration `config_sync_connections.secret_stores`; `MarkHeartbeat`; `ResourceSecretStores`; `GET /secret-stores` + `/:name/usages`; write-time validator (hybrid only, reported store, allowed paths, version, scope) wired into the registry create/update and MCP target paths; masking pass-through in `pkg/common/secret`; `secret_reference_set` event; Swagger | ~650 | S1, S4 |
| S6 | **Diagnostics + e2e + docs.** `POST /__diagnostics/gateways/:gateway_id/secret-stores/:name/test`; prewarm + `SECRET_STORES_READINESS_GATE`; e2e (hybrid plane + fake Vault + `httptest` upstream: serve, rotate, 401 retry, outage, no value in logs or snapshot); `docs/secret-stores.md`; compose example | ~500 | S3, S4, S5 |

## Phase 2: complete hybrid coverage

| Unit | Goal | Lines | Depends on |
|------|------|-------|------------|
| S7 | GCP Secret Manager (REST + `gcpauth`, ADC/Workload Identity) and Azure Key Vault (`azsecrets`, workload or managed identity); generator entries in the console | ~400 | S3 |
| S8 | Remaining locations: health-check headers (E3), IdP secrets (E5), plugin `CredentialPaths()` with the destination rule (E6), consumer embedding (E7), telemetry exporters (E8) | ~450 | S4, S5 |
| S9 | Per-reference health: heartbeat `secret_refs`, persistence, exposure on entity responses | ~250 | S5 |

## Chart (neuraltrust-platform, outside these repos)

| Unit | Goal | Lines | Depends on |
|------|------|-------|------------|
| H1 | `agentgateway.secretStores` values: render the store file into a ConfigMap; mount the referenced Secrets (`caCert`, `secretIdSecret`, `tokenSecret`, `file.secrets`) and rewrite them into `*_file` paths; set `SECRET_STORES_ENABLED`, `SECRET_STORES_FILE`, readiness gate; `serviceAccount.annotations` passthrough | ~150 | S3 (file format frozen) |

## Console (`NeuralTrust/app`)

| Unit | Goal | Lines | Depends on |
|------|------|-------|------------|
| A1 | **"Secret stores" tab** in `app/[locale]/v2/features/settings/components/gateway/` (hybrid only): list, row detail with per-instance state and error-class hints, usages, "Test a secret" through a server action calling the data-plane diagnostics route (`mintDiagnosticsToken`, like `testRegistryConnectionAction`); i18n | ~400 | S5, S6 |
| A2 | **"Add a secret store" generator:** type-specific forms (no secret inputs), values snippet (reusing `privateDeployValues.ts` helpers), least-privilege prerequisite templates (Vault policy and role, IAM policy, `gcloud`, `az`), `helm upgrade` command, "waiting for report" poller | ~400 | S5, H1 keys |
| A3 | **`SecretInput`:** Value / From secret store; store selector with status, path with allowed-prefix check, key, version, preview, Test; round-trip parse of stored references; integrated in `RegistrySchemaFieldRenderer`, `GcpServiceAccountField` and `McpServerConfigPanel`; "from `<store>`" badges; audit through `logV2AuditEvent` | ~350 | S5, S6 |
| A4 | Failing-reference warnings on cards; `SecretInput` in policy and telemetry forms | ~150 | S8, S9 |

## Common verification (every TrustGate slice)

```bash
go build ./...
go vet ./...
go test -race ./pkg/domain/secretref/... ./pkg/domain/secretstore/... ./pkg/app/secretref/... ./pkg/app/secretstore/... ./pkg/infra/secretstore/...
go test -race ./pkg/app/consumer/... ./pkg/app/registry/... ./pkg/infra/configsnapshot/... ./pkg/infra/configsync/... ./pkg/runtimeconfig/...
go generate ./pkg/domain/secretstore/... ./pkg/app/secretref/... ./pkg/app/secretstore/...   # mocks up to date (no diff)
golangci-lint run ./...
```

Console slices: `npm run lint`, `npm run test:unit`, and `npm run build:local`
before pushing.

## Definition of done (Phase 1)

- [ ] The e2e test covers the proposal's success criteria for Vault (Kubernetes
  auth), AWS (default chain) and `file`.
- [ ] The snapshot, the LKG file, the heartbeat, the logs and the diagnostics
  responses never contain a resolved value. Tests assert this.
- [ ] A `saas` plane refuses `SECRET_STORES_FILE`, and non-hybrid gateways
  cannot hold or resolve references.
- [ ] `docs/secret-stores.md` covers keyless setup per backend,
  least-privilege policies, migration from literal values, and troubleshooting
  by error class.
