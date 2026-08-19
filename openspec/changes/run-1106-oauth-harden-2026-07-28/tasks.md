# Tasks: RUN-1106 OAuth harden (MCP 2026-07-28)

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | 1080–1320 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1 (280–360) → PR 2 (340–420) → PR 3 (360–450) → PR 4 (180–250) |
| Delivery strategy | ask-on-risk |
| Chain strategy | stacked onto `feat/run-1103-dual-era-northbound-protocol-boundary` (never `main`) |

Decision needed before apply: No — locked to 1103 stack (same as RUN-1109)
Chained PRs recommended: Yes
Chain strategy: stacked onto RUN-1103 branch, then retarget `develop` after #400 lands
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | AS emit `iss` + advertise + northbound type | PR 1 | Base RUN-1103 tip |
| 2 | Client mix-up + DCR bind + handlers | PR 2 | Base PR 1; exception if >400 |
| 3 | Spec scenario unit tests | PR 3 | Base PR 2 |
| 4 | CIMD-prep + Workspace omit-`iss` docs | PR 4 | Base PR 3; docs-only |

Merge into `feat/run-1103-dual-era-northbound-protocol-boundary` in order. Never target `main`.

### Locks

- One slash-trim `issuersEqual`. Reject mismatch always; missing `iss` only when advertised.
- `EnsureClient` mismatch → slog + re-register. `RefreshAuth` mismatch → `ErrNoRegisteredClient` (no DCR).
- Empty `Issuer` stamps on discover. Redis key `gateway|registry`. Southbound DCR `web`; northbound `web`/`native` from URI.
- slog `oauth.issuer_mismatch` / `oauth.invalid_metadata` — never tokens/secrets. No CIMD runtime, DCR removal, RUN-1112, or vault issuer.

## Phase 1: Foundation + AS (PR 1)

- [x] 1.1 Create `pkg/app/oauth/issuer.go`: `issuersEqual`, `validateResponseISS`, `applicationTypeForURIs` (https→web; loopback/private-use→native; mixed/`cursor://` invalid).
- [x] 1.2 `metadata.go` `AuthorizationServer`: advertise iss param; `issuer=baseURL`. Spec: Metadata advertises iss.
- [x] 1.3 `RegisterRequest.ApplicationType`; `RegisterClient` accept `web`/`native`, infer omitted, reject other/inconsistent. Spec: infers native; inconsistent rejected.
- [x] 1.4 `proxy.go`: every MCP `clientRedirect` includes `iss=baseURL`. Spec: Redirect includes iss.
- [x] 1.5 `clean-comments`; `go test ./pkg/app/oauth ./pkg/api/handler/http/oauth`; `go vet ./...`.

## Phase 2: Client mix-up + DCR bind (PR 2)

- [x] 2.1 `ports.go`: `RegisteredClient.Issuer` + advertised flag. `connect_store.go`: additive JSON; no key change.
- [x] 2.2 Park issuer+advertised on `PendingAuthorization`/`ConnectState`. `idp_transport.go`: carry both; static IdP → advertised=false.
- [x] 2.3 Last-arg `iss` on `AuthProxy.Callback` and `ConnectService.Callback`. Handlers pass `c.Query("iss")`. Existing tests pass `""`. `go generate` mocks.
- [x] 2.4 `proxy.go`/`connect.go`: `validateResponseISS` before `tokenCall`/`ExchangeCode`; mix-up → `invalid_request` + slog `oauth.issuer_mismatch` (issuers + ids only). Spec: mix-up/match/missing iss.
- [x] 2.5 `dcr_registrar.go`: RFC 8414 issuer vs fetch; mismatch → slog `oauth.invalid_metadata`, no cache. DCR `application_type=web`. `EnsureClient`: stamp empty; mismatch re-register; match reuse. Spec: metadata; cross-issuer; stamp; reuse; southbound web.
- [x] 2.6 `connect_registration.go` `RefreshAuth`: empty → stamp via `EnsureClient`; mismatch → `ErrNoRegisteredClient` (do not re-register). Vault unchanged.
- [x] 2.7 Validate-before-cache on `metadata.go` `fetchASMetadata`. `clean-comments`; compile-green tests.

## Phase 3: Tests (PR 3)

- [x] 3.1 `issuer_test.go`: slash trim; mismatch; missing+advertised; URI type pairs.
- [x] 3.2 `metadata_test.go`+`proxy_test.go`: advertise; `iss` on redirect; mix-up before token HTTP; Google omit-iss OK; DCR type reject.
- [x] 3.3 `connect_test.go`+`idp_transport_test.go`: park/validate; static advertised=false.
- [x] 3.4 `dcr_registrar_test.go`: stamp; mismatch re-register; `RefreshAuth`→`ErrNoRegisteredClient`; metadata fail-closed; southbound `web`.
- [x] 3.5 Handler tests: `iss` forwarded; register `application_type`; slog has no secrets. `go test -race` oauth packages.

## Phase 4: Docs (PR 4)

- [x] 4.1 Create `docs/mcp/oauth-harden.md`: RFC 9207, DCR bind, slog; **DCR stays; CIMD future; `/oauth/register` remains**. Spec: Docs keep DCR.
- [x] 4.2 `docs/mcp/google-workspace-oauth.md`: Workspace/manual omit-`iss` still works.
