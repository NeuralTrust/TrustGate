# MCP Enterprise-Managed Authorization Specification

## Purpose

Clients exchange an IdP ID-JAG at `/oauth/token` for the TG session JWT. EMA is a jwt-bearer grant on `oauth2` Auth (draft-04).

## Requirements

### Requirement: Northbound mode

`OAuth2Config` MUST accept `northbound_mode` `oidc` (default if empty), `ema`, or `both`. MUST NOT add `TypeEMA`. `oidc` MUST reject jwt-bearer with `unsupported_grant_type`. `ema` MUST reject `/oauth/authorize` and MUST keep `refresh_token`. `both` MUST accept jwt-bearer and OIDC.

#### Scenario: Default oidc rejects jwt-bearer
- GIVEN empty or omitted `northbound_mode`
- WHEN a client POSTs jwt-bearer
- THEN the response is `unsupported_grant_type`

#### Scenario: ema rejects authorize keeps refresh
- GIVEN `northbound_mode=ema` and a minted session
- WHEN a client starts `/oauth/authorize`
- THEN authorize is rejected and `refresh_token` still succeeds

#### Scenario: both accepts either grant
- GIVEN `northbound_mode=both`
- WHEN the client uses `authorization_code` or valid jwt-bearer
- THEN the chosen grant proceeds

### Requirement: EMA metadata advertisement

AS metadata MUST advertise jwt-bearer and `io.modelcontextprotocol/enterprise-managed-authorization` iff mode is `ema` or `both`.

#### Scenario: oidc hides EMA
- GIVEN `northbound_mode=oidc`
- WHEN fetching AS metadata
- THEN jwt-bearer and the EMA extension are absent

#### Scenario: ema and both advertise
- GIVEN mode `ema` or `both`
- WHEN fetching AS metadata
- THEN jwt-bearer and the EMA extension are present

### Requirement: ID-JAG validation

In `ema`|`both`, `/oauth/token` MUST accept jwt-bearer `assertion`. Draft-04 MUST hold: `typ=oauth-id-jag+jwt`; `iss` via `IssuersEqual`; `aud`=`baseURL` (not session audiences); matching `resource`; scopes ⊆ allowed; valid `exp`/`nbf`/`iat`; registered `client_id` (no secret). MUST reject `none`/HMAC. MUST use only configured https JWKS. JWKS refresh errors MUST deny, not cache as success. Failure MUST be `invalid_grant` with no OIDC fallback.

#### Scenario: Valid ID-JAG accepted
- GIVEN `ema` or `both` and a passing draft-04 ID-JAG
- WHEN the client POSTs jwt-bearer
- THEN the grant succeeds

#### Scenario: Invalid claim rejected
- GIVEN `both` and wrong typ, iss, aud, resource, scope, time, client_id, or alg
- WHEN the client POSTs jwt-bearer
- THEN the response is `invalid_grant` and no OIDC fallback starts

#### Scenario: JWKS refresh failure denies
- GIVEN JWKS refresh fails
- WHEN the client POSTs jwt-bearer
- THEN the grant is denied and not cached as success

### Requirement: jti replay protection

Accepted ID-JAG MUST include `jti`, consumed until `exp`. Reuse or store-down MUST deny (`invalid_grant` on reuse).

#### Scenario: Replay rejected
- GIVEN a consumed `jti` still before `exp`
- WHEN it is replayed
- THEN the response is `invalid_grant`

#### Scenario: Store down denies
- GIVEN the jti store is unavailable
- WHEN a client POSTs jwt-bearer
- THEN the grant is denied

### Requirement: Session mint and identity

A valid jwt-bearer MUST `mintSession` (`token_use=mcp_session`, `authid`, `gwid`, session `aud`) and MUST NOT return or propagate the ID-JAG. Primary id MUST be `iss`+`sub` or explicit `subject_claim` (no silent Entra `oid`). Email MAY link; failed link MUST still accept. MUST NOT set `Principal.Subject` from email, map `act`, or add `Principal.Actor`. RoleScoper MUST still evaluate session claims.

#### Scenario: Session minted
- GIVEN a valid ID-JAG
- WHEN jwt-bearer succeeds
- THEN a session JWT (`token_use=mcp_session`) is returned, not the ID-JAG

#### Scenario: Email is linking only
- GIVEN a valid ID-JAG with unmatched email
- WHEN jwt-bearer succeeds
- THEN id is `iss`+`sub` (or `subject_claim`), not email

#### Scenario: act ignored
- GIVEN a valid ID-JAG that includes `act`
- WHEN jwt-bearer succeeds
- THEN `Principal.Actor` is absent and `act` is not mapped

### Requirement: Audit and docs

Accept and deny MUST emit slog without grants, tokens, secrets, claims, or email. Docs MUST cover IdP registration of TG as MCP resource and a Cursor-unconfirmed client matrix.

#### Scenario: Logs omit secrets
- GIVEN accept or deny of jwt-bearer
- WHEN slog is emitted
- THEN no grant, token, secret, claim, or email values appear

#### Scenario: Docs mark Cursor unconfirmed
- GIVEN the EMA docs
- WHEN reading the client matrix
- THEN Cursor is unconfirmed
