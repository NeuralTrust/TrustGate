# Proposal: Harden OAuth for MCP 2026-07-28 (RUN-1106)

## Intent

Close RFC 9207 mix-up and cross-issuer DCR reuse on TrustGate’s two OAuth roles (northbound AS, southbound client) without breaking Google/manual IdPs that omit `iss`.

## Scope

### In Scope

- AS: always emit `iss = baseURL`; advertise `authorization_response_iss_parameter_supported`.
- Client: reject mismatch always; reject missing `iss` only when the AS advertised the parameter.
- Bind `RegisteredClient.Issuer`; stamp empty pre-1106 rows on next discover (no consent).
- Southbound DCR `application_type=web`; northbound `web`|`native` from redirect URI (reject inconsistent pairs).
- Validate discovered AS metadata `issuer` (RFC 8414).
- slog `oauth.issuer_mismatch` / `oauth.invalid_metadata` — never tokens/secrets.
- CIMD migration note + Workspace omit-`iss` docs.

### Out of Scope

- CIMD runtime; DCR removal; RUN-1112 EMA.
- Vault `Credential` / user-token issuer binding.
- New audit bus or product MCP events.
- Redis key rewrite; observe-then-enforce flag; always-require `iss`.

## Capabilities

### New Capabilities

- `mcp-oauth-harden`: RFC 9207 `iss`, issuer-bound DCR, `application_type`, metadata issuer check, slog audit, CIMD-prep docs.

### Modified Capabilities

- None (`mcp-dual-era-northbound` is protocol-era only).

## Approach

**Approach 1** (locked): in-place harden. No new package, no kill-switch. One issuer-compare helper. Keep Redis key `gateway|registry`. Mismatch → slog + re-register. Empty `Issuer` → stamp, not mismatch.

## Affected Areas

- `pkg/app/oauth/proxy*.go`, `tokens.go` — park IdP issuer; validate/emit `iss`
- `pkg/app/oauth/connect*.go` — park/validate upstream issuer
- `pkg/app/oauth/ports.go`, `pkg/infra/oauth/connect_store.go` — additive `RegisteredClient.Issuer`
- `pkg/infra/oauth/dcr_registrar.go` — `web` DCR; issuer bind; metadata check
- `pkg/app/oauth/metadata.go`, `idp_transport.go` — advertise iss param; infer type
- `pkg/api/handler/http/oauth/` — pass `iss` + `application_type`
- `docs/mcp/` — harden + CIMD-prep; Workspace omit-`iss`

## Risks

- Always-require `iss` later breaks Google → missing `iss` only when advertised
- Empty pre-1106 rows treated as mismatch → stamp-on-discover; no consent
- Issuer string drift drops refresh tokens → single compare helper
- PR > 400 lines → split tests/docs if needed
- CIMD docs read as DCR removal → “DCR stays; CIMD future”

## Rollback Plan

Revert the PR. `Issuer` is additive JSON. No Redis migration. Reconnect only if an upstream changed AS.

## Dependencies

- Stacked on RUN-1103 / RUN-1109 tip (`feat/run-1103-dual-era-northbound-protocol-boundary`).
- Blocks RUN-1112 — do not start it.

## Success Criteria

- [ ] Mix-up rejected before redeem; missing `iss` allowed for Google/manual.
- [ ] DCR creds not reused across issuers; empty rows stamp without consent.
- [ ] Southbound DCR is `web`; northbound type matches redirect URI.
- [ ] Invalid metadata `issuer` fails closed; no secrets in logs.
- [ ] CIMD documented only; `/oauth/register` remains.
- [ ] Ready for `sdd-spec` / `sdd-design`.
