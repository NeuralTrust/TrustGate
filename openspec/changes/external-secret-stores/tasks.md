# Tasks: External secret stores (vault references)

Linear: _pending_. Base: `origin/develop`.

Chain strategy:
- Stacked PRs to `develop`, one branch per slice (`feat/<issue>-sN-<slug>`).
- Every TrustGate slice is inert until `SECRET_STORES_ENABLED=true`.
- Console slices (`NeuralTrust/app`) go to `develop` in that repo once the API
  slices they depend on are deployed to dev.

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~5,000 total (tests included): TrustGate Phase 1 ~2,600, Phase 2 ~1,000, Phase 3 ~800; console ~1,300 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | S1 → S2 → S3 → S4 → S5 (Phase 1) → S6 → S7 (Phase 2) → S8 → S9 (Phase 3); A1 after S2, A2 after S4, A3 after S6 |
| Delivery strategy | ask-on-risk |
| Chain strategy | stacked PRs to `develop` |

Decision needed before apply: **Yes**. Approve the scope and the open
questions (OQ1 default `max_stale`, OQ4 packaging) first.

## Work units

| Unit | Goal | Lines | Depends on |
|------|------|-------|------------|
| S1 | Domain: `secretref` (grammar, `Locations`, fuzz), `secretstore` (entity, typed config/auth, ports, errors), `ids.SecretStoreID`, config flags in `pkg/config` + `.env.example` | ~450 | — |
| S2 | Persistence + Admin API: migration `secret_stores`, Postgres repository with `FieldSealer` (`secret-stores/v1`), use cases (create/update/delete/get/list), DTOs, `ResourceSecretStores` scope, routes, Swagger | ~650 (split S2a repo / S2b API if asked) | S1 |
| S3 | Resolver core + first backends: cache (TTL, refresh-ahead, stale, negative, singleflight, eviction), refresher lifecycle in DI, error classes, metrics; HashiCorp Vault (KV v1/v2, token, AppRole, renew) over our HTTP client + netguard; AWS Secrets Manager (static keys, assume-role) | ~700 | S1 |
| S4 | Wiring Phase 1: snapshot `secret_stores` field + codec + compiler + snapshot adapter; `Materializer` + `Collector`; `DataFinder.load` / `registry.Finder` integration + reverse-index invalidation; §9 readers; masking pass-through in `pkg/common/secret`; write-time validation for E1/E2/E4; `CredentialUnavailable` → `secret_unavailable`; Bedrock pool key + MCP revision hash | ~700 | S2, S3 |
| S5 | Operations: forced refresh on 401/403 with one retry; `POST /:id/test`; `GET /:id/usages`; delete protection; `data_plane_too_old` gate; e2e test (DB-less proxy + fake vault + httptest upstream); `docs/secret-stores.md` | ~500 | S4 |
| S6 | Local stores: `SECRET_STORES_FILE` loader (+ reload on change), `SECRET_STORES_ALLOW_LOCAL`, `env` and `file` backends, Vault Kubernetes/JWT auth, AWS default chain; data-plane diagnostics route `POST /__diagnostics/gateways/:gateway_id/secret-stores/:name/test`; `location: local` in the API (hybrid/dedicated only); heartbeat `local_secret_stores`; name-conflict handling; compose/k8s examples | ~650 | S5 |
| S7 | GCP Secret Manager (REST + `gcpauth`: SA JSON; ADC/impersonation on local stores) and Azure Key Vault (`azsecrets`: client secret; managed/workload identity on local stores; URL suffix allowlist) | ~450 | S3 (S6 for local identities) |
| S8 | Remaining reference sites: inbound IdP secrets (E5), plugin `CredentialPaths()` incl. destination rule (E6), consumer embedding auth (E7), telemetry exporters (E8), health-check headers (E3) | ~550 | S4 |
| S9 | Per-reference health: heartbeat `secret_refs`, persistence with the connection record, exposure on entity/store responses; `SECRET_STORES_READINESS_GATE` | ~300 | S6 |
| A1 | Console: Gateway Settings → "Secret stores" tab (list, type-specific create/edit, local YAML snippet, test, usages, delete with usages), server actions + audit, i18n | ~600 | S2 (S5 for test/usages) |
| A2 | Console: `SecretInput` (Value / Secret store) in `RegistrySchemaFieldRenderer`, MCP config panel, policy credential fields; "from <store>" badges | ~500 | S4 |
| A3 | Console: health surfacing (store health, unresolved reference warnings on cards) | ~200 | S6 / S9 |

Phase 4 (keyless federation for hosted gateways: OIDC issuer, AWS
`AssumeRoleWithWebIdentity`, GCP WIF, Azure FIC, Vault JWT) is a **separate
change**, with its own design review (OQ5).

## Common verification (every TrustGate slice)

```bash
go build ./...
go vet ./...
go test -race ./pkg/domain/secretref/... ./pkg/domain/secretstore/... ./pkg/app/secretref/... ./pkg/app/secretstore/... ./pkg/infra/secretstore/...
go test -race ./pkg/app/consumer/... ./pkg/app/registry/... ./pkg/infra/configsnapshot/... ./pkg/runtimeconfig/...
go generate ./pkg/domain/secretstore/... ./pkg/app/secretstore/...   # mocks are up to date (no diff)
golangci-lint run ./...
```

Console slices: `npm run lint`, `npm run test:unit`, and `npm run build:local`
before pushing.

## Definition of done (Phase 1)

- [ ] The success criteria in `proposal.md` that apply to managed stores pass
  in the e2e test.
- [ ] The codec test proves the snapshot holds references, not values.
- [ ] No log line or metric label contains a resolved value. A grep-based test
  over captured logs in the e2e checks this.
- [ ] `docs/secret-stores.md` covers backends, least-privilege vault policies
  and migration from literal values.
