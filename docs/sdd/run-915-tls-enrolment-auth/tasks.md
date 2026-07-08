# Tasks: RUN-915 TLS Enrolment Auth

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | 1,000-1,500 across four repos |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | DataBridge code -> DataBridge deploy; DataAgent code -> DataAgent deploy; DataCore docs; TrustGate docs |
| Delivery strategy | explicit user decision in tasks phase |
| Chain strategy | stacked-to-main |

Decision needed before apply: No
Chained PRs recommended: Yes
Chain strategy: stacked-to-main
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | DataBridge token auth and TLS tests | DataBridge PR 1 | Base default branch; merge before deploy flip. |
| 2 | DataBridge env/k8s deploy defaults | DataBridge PR 2 | Depends on Unit 1; still keep mTLS opt-in. |
| 3 | DataAgent TLS mode and token credentials | DataAgent PR 1 | Can merge with compatibility preserved. |
| 4 | DataAgent env/k8s deploy defaults | DataAgent PR 2 | Depends on Unit 3 and coordinated with DataBridge PR 2. |
| 5 | DataCore docs-only update | DataCore PR | Independent docs PR. |
| 6 | TrustGate coordination docs | TrustGate PR | Restores/updates SDD and GSM guidance. |

## Phase 1: DataBridge Auth And TLS

- [ ] 1.1 Modify `DataBridge/internal/auth/auth.go` and `internal/auth/auth_test.go`: add `AUTH_MODE=token` authenticator for singular `ENROLMENT_TOKEN`, constant-time compare, missing/invalid rejection, and token-safe errors.
- [ ] 1.2 Modify `DataBridge/internal/config/config.go`, `internal/config/config_test.go`, and `internal/container/modules/bridge.go`: parse token mode, require token config outside dev, and wire the provider without changing proto or `INSTANCE_ID`.
- [ ] 1.3 Modify/create `DataBridge/internal/container/modules/servers_test.go` around `servers.go`: prove non-dev server TLS starts without client CA and fails closed without cert/key; preserve explicit `SOUTHBOUND_CLIENT_CA_FILE` mTLS compatibility.
- [ ] 1.4 Modify `DataBridge/internal/southbound/connect_test.go` and `internal/e2e/e2e_test.go`: cover TLS-only valid token, missing/invalid token, no registry registration on auth failure, and execute round trip after auth.
- [ ] 1.5 Validate DataBridge PR 1 with `gofmt`, `go vet ./...`, `golangci-lint run`, `make test`, and focused `go test -race ./...`.

## Phase 2: DataBridge Deployment Defaults

- [ ] 2.1 Modify `DataBridge/.env.example`, `README.md`, `k8s/base/secrets.env.example`, `k8s/base/deployment.yaml`, `k8s/overlays/dev/config.env`, `k8s/overlays/prod/config.env`, `k8s/overlays/prod/kustomization.yaml`, and `k8s/overlays/prod/patches/southbound-tls-patch.yaml`: add token secret and server TLS mount/env, leave client CA unset by default.
- [ ] 2.2 Validate DataBridge PR 2 with repo manifest rendering if available plus the Phase 1 Go gates.

## Phase 3: DataAgent TLS Credentials

- [ ] 3.1 Modify `DataAgent/internal/config/config.go` and `internal/config/config_test.go`: make `TLS_MODE=tls` default, require `DATABRIDGE_SERVER_NAME` and `ENROLMENT_TOKEN`, allow empty `TLS_CA_FILE` with system roots, and keep `mtls` explicit.
- [ ] 3.2 Modify `DataAgent/internal/transport/credentials.go` and `internal/transport/credentials_test.go`: build TLS-only transport credentials, attach `x-enrolment-token` only over secure transport, withhold it for insecure dev, and test private CA plus system roots.
- [ ] 3.3 Modify `DataAgent/internal/supervisor/connector_test.go`: prove TLS-mode dial/connect carries token metadata without client cert/key.
- [ ] 3.4 Validate DataAgent PR 1 with `gofmt`, `go vet ./...`, `golangci-lint run`, `make test`, and focused `go test -race ./...`.

## Phase 4: DataAgent Deployment Defaults

- [ ] 4.1 Modify `DataAgent/.env.example`, `README.md`, `k8s/base/secrets.env.example`, `k8s/overlays/dev/config.env`, `k8s/overlays/dev/kustomization.yaml`, `k8s/overlays/dev/client-cert.yaml`, `k8s/overlays/dev/patches/client-tls-patch.yaml`, `k8s/overlays/dev/databridge-ca.yaml`, `k8s/overlays/dev/patches/ca-bundle-patch.yaml`, and `k8s/overlays/prod/config.env`: remove default `dataagent-client-tls`, add CA-only dev trust, set `TLS_MODE=tls`, and document optional mTLS.
- [ ] 4.2 Validate DataAgent PR 2 with repo manifest rendering if available plus the Phase 3 Go gates.

## Phase 5: Docs And Coordination

- [ ] 5.1 Modify `DataCore/docs/hybrid-residency-deploy-secrets-checklist.md`: remove default DataAgent client cert/key rotation and describe server TLS, optional CA, `DATABRIDGE_SERVER_NAME`, and `ENROLMENT_TOKEN`.
- [ ] 5.2 Create/modify `TrustGate/docs/hybrid-residency-gsm-secrets.md` and keep `TrustGate/docs/sdd/run-915-tls-enrolment-auth/design.md` aligned: remove default client mTLS guidance and note token lifecycle follow-up.
- [ ] 5.3 Validate docs by searching for stale default `dataagent-client-tls`, `TLS_MODE=mtls`, `TLS_CLIENT_CERT_FILE`, and customer DataAgent cert rotation guidance.

## Dependencies

DataBridge auth must land before default deploy flips. DataAgent TLS credentials must land before removing client cert mounts. DataBridge and DataAgent deployment PRs should be released together; DataCore and TrustGate docs can merge after the contract is final.
