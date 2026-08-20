# MCP OAuth harden (RFC 9207)

TrustGate emits and validates RFC 9207 `iss` on authorization responses,
binds southbound DCR clients to the issuing AS, and logs mix-up /
invalid-metadata without secrets. **DCR stays.** `/oauth/register` remains
the runtime registration path. CIMD is documentation only — not implemented.

## Quick path

1. Treat TrustGate AS metadata `issuer` as `baseURL`. Every MCP-client
   redirect includes `iss=baseURL`.
2. Keep using `/oauth/register` (DCR). Do not wait for CIMD.
3. Google Workspace and other manual IdPs that omit `iss` keep working —
   see [Google Workspace MCP OAuth](google-workspace-oauth.md).
4. On mix-up or bad AS metadata, look for slog `oauth.issuer_mismatch` or
   `oauth.invalid_metadata` (issuer URLs and ids only).

## RFC 9207 `iss`

TrustGate is both an authorization server (northbound, MCP clients) and a
client (IdP callback and southbound connect).

| Role | Rule |
|------|------|
| AS (always) | Redirect query includes `iss=baseURL`. Metadata sets `authorization_response_iss_parameter_supported` true and `issuer` to `baseURL`. |
| Client, `iss` present and matching | Redeem may proceed. |
| Client, `iss` present and different | Reject before redeem. slog `oauth.issuer_mismatch`. |
| Client, `iss` missing | Reject **only** when that AS advertised `authorization_response_iss_parameter_supported`. Otherwise redeem may proceed. |

Issuer compare trims a trailing `/` only. No scheme rewrite.

## DCR stays — CIMD is future only

| Topic | Status in this change |
|-------|------------------------|
| Dynamic Client Registration | **Current runtime.** Not removed. |
| `POST /oauth/register` | **Remains.** |
| CIMD (`client_id` as URL) | **Documentation / future only.** No CIMD routes, types, or catalog flags. |
| Enterprise Managed Auth (RUN-1112) | **This change.** See [Enterprise-Managed Authorization](enterprise-managed-authorization.md). |

Do not read this page as “CIMD is implemented” or “DCR is going away.”

## DCR client issuer bind

Southbound cached clients (`RegisteredClient`) carry `Issuer`. Cache
identity stays `gateway` + `registry` (no Redis key rewrite). Vault user
grants do **not** gain an issuer field.

| Cached `Issuer` | Discovered AS | `EnsureClient` | `RefreshAuth` |
|-----------------|---------------|----------------|---------------|
| Empty (pre-1106) | A | Stamp `Issuer=A`, reuse credentials, no new consent | Stamp via `EnsureClient` |
| A | A | Reuse | Reuse |
| A | B | slog `oauth.issuer_mismatch`, **re-register** (no credential reuse) | slog + `ErrNoRegisteredClient` — **no DCR**; user consents again |

## `application_type`

| Direction | Behavior |
|-----------|----------|
| Southbound DCR (TrustGate → upstream AS) | Body always includes `application_type=web` (TrustGate callback is HTTPS). |
| Northbound DCR (MCP client → TrustGate) | Accepts `web` or `native`. Omits are inferred: `https` → `web`; loopback / private-use → `native`. Other values and inconsistent pairs (e.g. `web` + `cursor://`) are rejected. |

## Discovered AS metadata

Fetched AS metadata `issuer` must equal the fetch identifier (RFC 8414).
Mismatch fails closed: no DCR, no redeem, slog `oauth.invalid_metadata`.
Invalid metadata is not cached.

## slog (not an audit bus)

| Event | When | Allowed attrs |
|-------|------|----------------|
| `oauth.issuer_mismatch` | Wrong callback `iss`, or cached DCR client bound to a different AS | `expected_issuer`, `got_issuer`, `gateway_id`, `provider` / `key` |
| `oauth.invalid_metadata` | Discovered document `issuer` ≠ fetch identifier | `expected_issuer`, `metadata_issuer`, `gateway_id`, `provider` / `key` |

Never log tokens, codes, client secrets, or raw DCR bodies. This change
does **not** add a product MCP event or a new audit bus.

## Not in this change

- CIMD runtime (routes, types, catalog flags)
- Removal of DCR or `/oauth/register`
- Vault `Credential` issuer field
- Redis key migration
- Feature-flag / observe-then-enforce mode

## Checklist

- [ ] AS discovery shows `authorization_response_iss_parameter_supported` and `issuer=baseURL`
- [ ] MCP-client redirects include `iss=baseURL`
- [ ] Google Workspace / manual omit-`iss` connect still completes
- [ ] `/oauth/register` still registers clients
- [ ] Mix-up and metadata-mismatch logs have issuer URLs and ids only — no secrets

## Next step

Workspace and other omit-`iss` IdPs: [Google Workspace MCP OAuth](google-workspace-oauth.md).
Enterprise-managed authorization (jwt-bearer / ID-JAG): [Enterprise-Managed Authorization](enterprise-managed-authorization.md).
Exercise the plane: [MCP testing guide](testing-guide.md).
