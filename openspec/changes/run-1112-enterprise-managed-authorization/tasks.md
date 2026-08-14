# Tasks: Enterprise-Managed Authorization (RUN-1112)

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | 860–1150 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1 (200–280) → PR 2 (340–450) → PR 3 (320–420) |
| Delivery strategy | ask-on-risk |
| Chain strategy | pending |

Decision needed before apply: No — single PR `size:exception` onto RUN-1103 (same as RUN-1106)
Chained PRs recommended: Yes
Chain strategy: pending
400-line budget risk: High

May prefer one PR (`size:exception`). Else **feature-branch-chain** onto RUN-1103 tip until #400, then `develop`. Never `main`. Split PR 2 if >400.

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | `northbound_mode` + EMA metadata | PR 1 | Base 1103 tip |
| 2 | ID-JAG + jti + jwt-bearer mint | PR 2 | Base PR 1; impl; overflow risk |
| 3 | Spec tests + docs + slog | PR 3 | Base PR 2 |

### Locks
- Approach 1; no `TypeEMA`; configured JWKS only; jti/JWKS fail-closed.
- Failed jwt-bearer → `invalid_grant`; no OIDC downgrade.
- Email linking only; id `iss`+`sub`; no `act`/`Principal.Actor`.
- Advertise iff any oauth2 is `ema`|`both`.
- Leave `Callback`, omit-iss, vault, southbound untouched.

## Phase 1: Config + metadata (PR 1)

- [x] 1.1 `pkg/domain/auth/config.go`: `NorthboundMode`; empty=`oidc`; validate `oidc`|`ema`|`both`; `ema`|`both` need https JWKS or issuer. No `TypeEMA`.
- [x] 1.2 `pkg/domain/auth/config_test.go`: mode + https tables.
- [x] 1.3 `pkg/app/oauth/metadata.go`: jwt-bearer + EMA extension iff any oauth2 is `ema`|`both`. DCR `grant_types` in `pkg/infra/oauth/dcr_registrar.go` when advertising.
- [x] 1.4 `pkg/app/oauth/metadata_test.go`: oidc hides EMA; ema/both advertise.
- [x] 1.5 `clean-comments`; `go test ./pkg/domain/auth ./pkg/app/oauth`.

## Phase 2: Validator + jti + grant + mint (PR 2)

- [x] 2.1 Create `pkg/app/oauth/idjag.go`: typ `oauth-id-jag+jwt`; Peek+`IssuersEqual`; `Verify` aud=`baseURL`; configured JWKS; resource/scope/`client_id`/`iat`; reject none/HMAC; slog accept/deny ids only.
- [x] 2.2 `pkg/app/oauth/proxy_types.go`: `TokenRequest.Assertion`; `FlowStore.ConsumeJTI`; `CodeGrant.Claims`.
- [x] 2.3 `pkg/infra/oauth/store.go`: `ConsumeJTI` `SET NX` `oauth:jti:{jti}` TTL=exp; exists or Redis err → deny.
- [x] 2.4 Inject existing `OIDCVerifier` via `NewAuthProxy` + `pkg/container/modules/api.go`. Add `ConsumeJTI` to both `memFlowStore` fakes.
- [x] 2.5 `pkg/api/handler/http/oauth/token_handler.go`: read form `assertion`.
- [x] 2.6 `pkg/app/oauth/proxy.go`: `oidc` jwt-bearer → `unsupported_grant_type`; `ema`|`both` validate → `ConsumeJTI` → always `mintSession`; never return ID-JAG; fail → `invalid_grant` (no OIDC fallback). `ema` Authorize → `access_denied`; keep refresh. Subject `subject_claim` or `sub` (never `oid`); email claim only; drop `act`; no `Actor`.
- [x] 2.7 Compile-green: `go test` oauth + auth + handler packages.

## Phase 3: Spec tests (PR 3)

- [x] 3.1 `pkg/app/oauth/idjag_test.go`: typ/iss/aud/resource/scope/exp/nbf/iat/jti/HMAC/`oid`/act; JWKS refresh deny.
- [x] 3.2 `pkg/app/oauth/proxy_test.go`: oidc unsupported; both no downgrade; ema reject authorize + refresh OK; mint `mcp_session`; email linking only; `act` ignored.
- [x] 3.3 `pkg/infra/oauth/store_test.go`: jti NX replay + Redis error deny.
- [x] 3.4 `pkg/api/handler/http/oauth/handlers_test.go`: form `assertion` forwarded; slog omits secrets.

## Phase 4: Docs + polish (PR 3)

- [x] 4.1 Create `docs/mcp/enterprise-managed-authorization.md`: IdP registers TG resource; Cursor unconfirmed.
- [x] 4.2 `docs/mcp/oauth-harden.md`: point EMA at this change (replace “not started”).
- [x] 4.3 `clean-comments`; `go test -race` oauth packages; `go vet ./...`.
