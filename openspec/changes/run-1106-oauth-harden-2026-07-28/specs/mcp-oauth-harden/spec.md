# MCP OAuth Harden Specification

## Purpose

RFC 9207 mix-up protection, issuer-bound DCR, and `application_type`. Omit-`iss` IdPs keep working. CIMD is docs only.

## Requirements

### Requirement: AS authorization `iss`

As AS, every authorization redirect to an MCP client MUST include `iss` equal to metadata `issuer` (`baseURL`). AS metadata MUST set `authorization_response_iss_parameter_supported` true.

#### Scenario: Redirect includes iss
- GIVEN completed northbound authorization
- WHEN redirecting the MCP client with a code
- THEN query `iss` equals `baseURL`

#### Scenario: Metadata advertises iss
- GIVEN AS discovery
- WHEN returning `/.well-known/oauth-authorization-server`
- THEN `authorization_response_iss_parameter_supported` is true and `issuer` is `baseURL`

### Requirement: Client mix-up protection

As client (IdP and connect callbacks), TrustGate MUST validate `iss` before redeem. Present matching `iss` MUST be accepted; present mismatch MUST reject redeem and MUST emit slog `oauth.issuer_mismatch` (issuer URLs and ids). Missing `iss` MUST be rejected only when that AS advertised `authorization_response_iss_parameter_supported`. MUST NOT log tokens, codes, secrets, or registration bodies.

#### Scenario: Mix-up rejected
- GIVEN expected issuer A and callback `iss` B
- WHEN processing the callback
- THEN redeem is skipped and `oauth.issuer_mismatch` is emitted

#### Scenario: Matching iss accepted
- GIVEN expected issuer A and callback `iss` A
- WHEN processing the callback
- THEN redeem MAY proceed

#### Scenario: Missing iss allowed when not advertised
- GIVEN AS did not advertise `authorization_response_iss_parameter_supported`
- WHEN callback omits `iss`
- THEN redeem MAY proceed

#### Scenario: Missing iss rejected when advertised
- GIVEN AS advertised `authorization_response_iss_parameter_supported`
- WHEN callback omits `iss`
- THEN redeem is skipped

### Requirement: DCR credential issuer binding

Southbound cached clients MUST carry `Issuer`. Cache identity (`gateway` + `registry`) MUST stay. Non-empty `Issuer` that differs from discovered MUST re-register (no credential reuse) and MUST emit `oauth.issuer_mismatch`. Empty pre-1106 `Issuer` MUST stamp the discovered issuer without consent. Vault user grants MUST NOT gain an issuer field.

#### Scenario: Cross-issuer reuse rejected
- GIVEN cached client bound to A and discovery of B
- WHEN ensuring the client
- THEN credentials are not reused, registration is new, and `oauth.issuer_mismatch` is emitted

#### Scenario: Pre-1106 empty issuer stamped
- GIVEN cached client with empty `Issuer` and discovery of A
- WHEN ensuring the client
- THEN `Issuer` is A and credentials are reused without consent

#### Scenario: Matching issuer reused
- GIVEN cached client bound to A and discovery of A
- WHEN ensuring the client
- THEN existing credentials are reused

### Requirement: application_type

Southbound DCR MUST send `application_type=web`. Northbound MUST accept `web`|`native`, MUST reject other values, MUST infer omitted type (`web` from https, `native` from loopback/private-use), and MUST reject inconsistent pairs.

#### Scenario: Southbound DCR is web
- GIVEN auto registration toward an upstream AS
- WHEN sending DCR
- THEN body includes `application_type=web`

#### Scenario: Northbound infers native
- GIVEN loopback or private-use redirect URI and no `application_type`
- WHEN processing DCR
- THEN client is `native`

#### Scenario: Inconsistent pair rejected
- GIVEN `application_type=web` and a private-use redirect URI
- WHEN processing DCR
- THEN registration fails

### Requirement: Discovered AS metadata issuer

Fetched AS metadata `issuer` MUST equal the fetch identifier (RFC 8414). Mismatch MUST fail closed (no DCR, no redeem) and MUST emit `oauth.invalid_metadata`. MUST NOT add an audit bus or product MCP events.

#### Scenario: Matching metadata proceeds
- GIVEN metadata `issuer` equals fetch identifier
- WHEN discovery completes
- THEN registration or callback MAY continue

#### Scenario: Mismatched metadata fails closed
- GIVEN metadata `issuer` differs from fetch identifier
- WHEN discovery completes
- THEN fail closed and `oauth.invalid_metadata` is emitted

### Requirement: CIMD documentation only

Docs MUST cover RFC 9207 `iss`, Workspace/manual omit-`iss`, and CIMD as future client_id-as-URL with DCR remaining runtime. MUST NOT add CIMD routes or types or remove `/oauth/register`.

#### Scenario: Docs keep DCR
- GIVEN MCP OAuth harden docs
- WHEN reading CIMD guidance
- THEN DCR is current runtime, CIMD is future-only, and `/oauth/register` remains
