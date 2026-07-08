# Proposal: RUN-915 TLS Enrolment Auth

## Problem Statement

Hybrid deployments still require DataAgent client mTLS material by default, creating customer-side certificate rotation and secret-mount burden. RUN-915 switches the southbound DataAgent -> DataBridge path to DataBridge server TLS plus application-level enrolment auth, while preserving server identity validation and rejection of unauthenticated agents.

## Goals

- DataAgent connects with server-side TLS and `ENROLMENT_TOKEN`, without default client cert/key mounts.
- DataBridge rejects missing or invalid enrolment-token auth.
- Deployed DataBridge still serves TLS; DataAgent validates `DATABRIDGE_SERVER_NAME`.
- Dev/prod manifests and docs remove default `dataagent-client-tls` requirements.
- Tests cover TLS-only success plus missing/invalid token rejection.

## Non-Goals

- No one-time token exchange or per-agent credential lifecycle in this PR.
- No residency proto change for customer-configured `INSTANCE_ID`.
- No DataCore product-code change; DataCore impact is docs only.
- Optional mTLS compatibility may remain explicit, but not default.

## Capabilities

### New Capabilities

- `southbound-enrolment-auth`: DataBridge validates the configured singular enrolment token for DataAgent streams.

### Modified Capabilities

- `hybrid-residency-deployment`: Default hybrid deployment uses server TLS plus enrolment token instead of client mTLS.

## Chosen Approach

Implement the phased RUN-915 approach: add/finish a configured token authenticator in DataBridge that validates a non-logged singular `ENROLMENT_TOKEN` and rejects the stream before registry registration. This assumes an isolated 1:1 tenant/DataAgent deployment; shared multi-tenant DataBridge deployments need tenant-bound credential storage first. Add DataAgent TLS-only credentials that require `DATABRIDGE_SERVER_NAME`, use `TLS_CA_FILE` when provided or system roots otherwise, and send `ENROLMENT_TOKEN` only on secure transport. Remove client cert/key env vars and secret mounts from default manifests/docs; keep `TLS_MODE=mtls` / `SOUTHBOUND_CLIENT_CA_FILE` only as explicit compatibility if low churn.

## Alternatives Considered

| Alternative | Decision | Reason |
|---|---|---|
| Keep mTLS default | Rejected | Fails RUN-915 customer secret-rotation goal. |
| Static shared token only | Rejected | Too weak unless tenant-bound, validated, tested, and documented as transitional. |
| One-time bootstrap exchange now | Deferred | Requires a DataBridge credential store/lifecycle not present today. |
| Add `INSTANCE_ID` to proto | Deferred | Current contract omits it; server-generated instance id remains registry/audit identity. |

## Cross-Repo Impact

| Repo | Impact |
|---|---|
| DataBridge | Auth config/provider, southbound TLS tests, k8s/env/docs defaults. |
| DataAgent | Config validation, TLS-only credentials, token metadata, k8s/env/docs defaults. |
| DataCore | Update deployment secrets checklist only. |
| TrustGate | Restore/add `docs/hybrid-residency-gsm-secrets.md` if required and remove default DataAgent client mTLS guidance. |

## Risks And Mitigations

| Risk | Mitigation |
|---|---|
| Long-lived bearer token leakage | Never log tokens; support rotation via configured secret; document residual risk and follow-up credential lifecycle. |
| TLS misconfiguration weakens identity checks | Require `DATABRIDGE_SERVER_NAME`; use private CA when configured or system roots otherwise. |
| Breaking mTLS users | Keep explicit compatibility mode if feasible, outside default docs/manifests. |
| Prod DataBridge TLS incomplete | Ensure cert/key env and `databridge-southbound-tls` mount are present in deployed overlays. |

## Rollout And Testing

Roll out by updating DataBridge and DataAgent configs/manifests together, rotating in `ENROLMENT_TOKEN`, and removing `dataagent-client-tls` only after TLS server cert material is deployed. Rollback is to restore prior `TLS_MODE=mtls`, client cert/key mounts, and `SOUTHBOUND_CLIENT_CA_FILE` requirements.

Verify with table-driven Go tests for token validator success/failure, DataAgent TLS config with private CA and system roots, TLS-only e2e happy path, and missing/invalid token rejection before registration. Run `gofmt`, `go vet`, `golangci-lint`, unit tests, and race tests for stream/supervisor paths.
