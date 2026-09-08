# Enterprise-Managed Authorization (EMA)

TrustGate accepts an IdP-issued **ID-JAG** at `/oauth/token` (`urn:ietf:params:oauth:grant-type:jwt-bearer`) and always mints a TrustGate session JWT. The ID-JAG is never returned to the client.

This is MCP **enterprise-managed authorization** (ID-JAG draft-04) on the existing `oauth2` identity provider. There is no separate auth type.

## IdP registers TrustGate as the MCP resource

The identity provider issues the ID-JAG **for TrustGate**, not for the upstream LLM.

| Claim | Value |
|-------|--------|
| `typ` | `oauth-id-jag+jwt` |
| `iss` | The configured OAuth2 issuer (trailing `/` ignored; same as RUN-1106 `IssuersEqual`) |
| `aud` | TrustGate `baseURL` (the northbound AS), **not** `oauth2.audiences` |
| `resource` | The RFC 8707 MCP resource URL the client is calling |
| `client_id` | A client registered at TrustGate (`POST /oauth/register`) |
| `sub` | End-user subject (`subject_claim` if set; never a silent Entra `oid`) |
| `jti` / `exp` / `iat` | Required; `jti` is consumed until `exp` (replay → `invalid_grant`) |

Configure a **https** `jwks_url` (or a https issuer so JWKS can be discovered from **that** issuer). JWKS is never taken from the assertion host.

## `northbound_mode`

On `oauth2`:

| Mode | Default | Authorize (OIDC) | jwt-bearer | Refresh |
|------|---------|------------------|------------|---------|
| `oidc` (empty) | yes | yes | `unsupported_grant_type` | yes |
| `ema` | | `access_denied` | yes | yes |
| `both` | | yes | yes | yes |

AS metadata advertises `grant_types_supported` jwt-bearer and `io.modelcontextprotocol/enterprise-managed-authorization` **only when any oauth2 IdP is `ema` or `both`**.

A failed jwt-bearer is `invalid_grant`. There is **no** silent fall-through to the OIDC code flow.

## Session mint

On success TrustGate always mints `token_use=mcp_session` (plus `authid`, `gwid`, session `aud` from config) and a `gwrt_` refresh token. Email on the ID-JAG is a linking claim only; identity is `iss`+`sub` (or explicit `subject_claim`). `act` is dropped (delegation / `Principal.Actor` is RUN-1117).

Logs: `oauth.ema.accept` / `oauth.ema.deny` with `auth_id`, `gateway_id`, `jti` or `reason`. No grants, tokens, secrets, or identity claims.

## Client matrix

| Client | Status |
|--------|--------|
| MCP clients that can present an IdP ID-JAG at `/oauth/token` | Supported when the IdP is configured for EMA |
| Cursor | **Unconfirmed** — Cursor's ID-JAG / enterprise-managed-auth support is not verified here |
| OIDC-only clients (`authorization_code` + PKCE) | Use `oidc` or `both` |

Google omit-`iss` / Workspace southbound connect is unchanged: [Google Workspace MCP OAuth](google-workspace-oauth.md). RFC 9207 harden: [MCP OAuth harden](oauth-harden.md).
