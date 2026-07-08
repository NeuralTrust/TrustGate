# Exploration: RUN-915 TLS + enrolment auth

## Current State

DataAgent already has an `ENROLMENT_TOKEN` config field and sends it as gRPC per-RPC metadata key `x-enrolment-token`, but only when running the current `mtls` credential provider. `TLS_MODE` currently supports only `insecure` and `mtls`, defaults to `mtls`, and validation requires `TLS_CLIENT_CERT_FILE`, `TLS_CLIENT_KEY_FILE`, `TLS_CA_FILE`, and `DATABRIDGE_SERVER_NAME` for the default production path.

DataBridge already reads `x-enrolment-token` from the incoming stream context before accepting the first `Hello`, but the only implemented authenticator is `DevAuthenticator`, which accepts any non-empty token plus the tenant claimed in `Hello`. Production auth is not implemented: `provideAuthenticator` fails unless `AUTH_MODE=dev`, with a placeholder pointing at the older production cert-to-tenant binding work.

DataBridge southbound transport TLS already supports server-side TLS without client cert verification when `SOUTHBOUND_TLS_CERT_FILE` and `SOUTHBOUND_TLS_KEY_FILE` are set and `SOUTHBOUND_CLIENT_CA_FILE` is unset. If `SOUTHBOUND_CLIENT_CA_FILE` is set, the server requires and verifies a client certificate. Outside `AUTH_MODE=dev`, server TLS is required.

Kubernetes and docs still describe the default hybrid path as mTLS. DataBridge dev config sets `SOUTHBOUND_CLIENT_CA_FILE`; DataAgent dev/prod config sets `TLS_MODE=mtls` plus client cert/key paths; DataAgent dev creates and mounts `dataagent-client-tls`. DataBridge prod currently does not set southbound TLS cert/key paths or mount `databridge-southbound-tls`, so prod deployment config is incomplete for the current non-dev server TLS requirement.

DataCore is not part of the DataAgent southbound auth path. Its hybrid adapter calls DataBridge northbound with a separate `DATABRIDGE_TLS` boolean and no DataAgent credential coupling. The requested DataCore impact is documentation only.

The primary TrustGate RUN worktree does not currently contain `docs/hybrid-residency-gsm-secrets.md`, though that document exists in the main TrustGate checkout and still states that DataBridge verifies DataAgent client certs and that DataAgent requires client mTLS material.

## Affected Areas

- `DataBridge/internal/config/config.go` - `SouthboundConfig.ClientCAFile` remains useful for optional mTLS compatibility, but default deployed flow should not depend on it. Production auth config for enrolment tokens is missing.
- `DataBridge/internal/container/modules/servers.go` - southbound TLS behavior is already close to target: cert/key required outside dev, client verification only when client CA is configured. Needs tests locking the TLS-only default and optional mTLS compatibility.
- `DataBridge/internal/container/modules/bridge.go` - production boot is currently blocked without `AUTH_MODE=dev`. This is the main auth implementation gap for RUN-915.
- `DataBridge/internal/auth/auth.go` and `internal/auth/auth_test.go` - only permissive dev auth exists. Need a production authenticator that validates the singular enrolment token for the isolated 1:1 tenant/DataAgent deployment and leaves room for one-time bootstrap/per-agent credentials.
- `DataBridge/internal/southbound/connect.go` and `internal/southbound/connect_test.go` - authentication happens before registry registration and missing-token rejection is tested. Need invalid-token rejection and credential identity/tenant binding tests.
- `DataBridge/internal/e2e/e2e_test.go` - in-process flow uses insecure transport plus dev token. Add TLS-only plus valid/invalid enrolment coverage where feasible.
- `DataBridge/.env.example`, `README.md`, `k8s/base/secrets.env.example`, `k8s/overlays/dev/config.env`, `k8s/overlays/dev/southbound-cert.yaml`, `k8s/overlays/prod/config.env`, prod deployment patches - update default docs/config to server TLS plus application auth; keep client CA only for optional compatibility.
- `DataAgent/internal/config/config.go` and `internal/config/config_test.go` - add a server-TLS mode or rename the default mode so production no longer requires client cert/key. Require `ENROLMENT_TOKEN` outside insecure dev and continue requiring server identity validation.
- `DataAgent/internal/transport/credentials.go` and `internal/transport/credentials_test.go` - add TLS-only credentials using CA/system roots policy, always attach token over secure transport, and keep the "never send token over insecure transport" invariant.
- `DataAgent/internal/supervisor/connector.go` and tests - connection setup can stay mostly unchanged, but tests should prove token metadata reaches DataBridge under TLS-only. Current `INSTANCE_ID` is logged locally but not sent in `Hello`; DataBridge generates a new instance id server-side.
- `DataAgent/.env.example`, `README.md`, `k8s/base/secrets.env.example`, `k8s/base/kustomization.yaml`, `k8s/overlays/dev/config.env`, `k8s/overlays/dev/kustomization.yaml`, `k8s/overlays/dev/client-cert.yaml`, `k8s/overlays/dev/patches/client-tls-patch.yaml`, `k8s/overlays/prod/config.env` - remove default `dataagent-client-tls` requirements and document `ENROLMENT_TOKEN`, optional `DATABASE_URL`, and server validation material.
- `DataCore/docs/hybrid-residency-deploy-secrets-checklist.md` - update required secrets and rotation guidance to remove customer-side DataAgent client cert lifecycle from default production.
- `TrustGate/docs/hybrid-residency-gsm-secrets.md` - update the coordination doc in the primary worktree or restore it if missing from this branch, then remove default DataAgent client mTLS guidance.

## Approaches

| Approach | Pros | Cons | Effort |
|---|---|---|---|
| Minimal shared enrolment token | Smallest code change; matches current `x-enrolment-token` metadata plumbing; easy to test valid/missing/invalid token. | Long-lived bearer token risk; weak revocation/audit identity; does not meet security note preference by itself. | Low |
| Bootstrap token exchanged for agent credential | Aligns with issue security notes; enrolment token can be one-time/short-lived; later connections use per-agent credential with revocation and audit identity. | Needs credential persistence/lookup design in DataBridge; may require schema/store or external service not present in current code. | High |
| Phased RUN-915 default: configured token validator now, credential lifecycle follow-up | Removes client mTLS immediately; enforces real token equality/hash and tenant binding; keeps optional mTLS compatibility; creates clear follow-up for one-time exchange/rotation if no store is available now. | Enrolment token may remain longer-lived for one release unless follow-up is prioritized; requires explicit documentation of residual risk. | Medium |

## Recommendation

Use the phased approach for RUN-915. Implement server-side TLS as the default transport, add DataAgent `tls` credentials that validate the DataBridge server and send `ENROLMENT_TOKEN`, and replace DataBridge's production-auth placeholder with a real configured token authenticator that rejects missing/invalid tokens and binds the credential to the claimed tenant. Keep `SOUTHBOUND_CLIENT_CA_FILE` and DataAgent mTLS mode as an explicit compatibility mode only, not the default deployment path.

For the security notes, avoid treating the current token as an unbounded anonymous bearer. If the current repos do not have a durable credential store ready, scope RUN-915 to a hashed/configured bootstrap token with tenant binding, audit-safe credential id logging, and rate-limit hooks/tests where local structure allows. Track the stronger "bootstrap exchange to per-agent credential" as a follow-up if it needs storage or control-plane APIs outside this issue.

## Risks

- A simple static enrolment token is weaker than mTLS and can become a long-lived bearer unless the implementation scopes, hashes, rotates, and audits it.
- DataBridge currently has no production authenticator, so this issue is not only deployment cleanup; it must add auth behavior before removing mTLS defaults.
- Current event flow does not transmit DataAgent `INSTANCE_ID` to DataBridge; DataBridge generates an instance id per connection. Preserving audit fields may require a proto/schema change or a deliberate server-generated-id decision.
- Prod DataBridge deployment config appears incomplete for server TLS today because prod config does not set cert/key paths or mount `databridge-southbound-tls`.
- TrustGate hybrid docs are missing from the primary RUN worktree even though the issue names them; later phases should restore/update them in that worktree or confirm they intentionally moved.

## Open Questions

- Should RUN-915 implement one-time bootstrap exchange to a per-agent credential now, or is a configured tenant-bound token acceptable for this PR with a follow-up? Code investigation cannot fully answer this because there is no existing DataBridge credential store.
- Should DataAgent server validation require a private CA file in production or allow system roots when `DATABRIDGE_SERVER_NAME` is set? Code can support either; product/security policy must choose.
- Should `INSTANCE_ID` become part of the `Hello` contract so DataBridge can audit the customer-configured agent instance id? Code investigation shows it is not currently sent.
- Should optional mTLS compatibility remain in the same `TLS_MODE=mtls` path? The current code already supports it and keeping it is low risk, but product can decide whether to document it.

## Ready for Proposal

Yes. Proposal should define the production token validation source and TLS server validation policy, then split implementation across DataBridge auth/TLS tests, DataAgent TLS-only credentials/config, k8s overlays, and docs.
