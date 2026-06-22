# MCP OAuth Session Token Specification

## Purpose

The gateway mints, validates locally, and refreshes its own MCP session token,
decoupled from the upstream IdP token format. Behavior is opt-in per OAuth2 auth;
OFF preserves today's IdP pass-through. RFC 2119 keywords apply.

## Requirements

### Requirement: Opt-in gateway session mode

The system MUST gate gateway-minted session tokens behind a per-auth opt-in flag
on the OAuth2 auth config. When the flag is OFF (default), the gateway MUST hand
the upstream IdP token to the MCP client unchanged. When ON, the gateway MUST
return its own minted session token instead.

#### Scenario: Default is pass-through
- GIVEN an OAuth2 auth with session mode unset
- WHEN a client completes the token exchange
- THEN the gateway MUST return the upstream IdP token unchanged

#### Scenario: Opt-in mints a gateway token
- GIVEN an OAuth2 auth with session mode ON
- WHEN a client completes the token exchange
- THEN the gateway MUST return a gateway-issued session token, not the IdP token

### Requirement: Opaque-IdP MCP OAuth flow

With session mode ON, a gateway whose IdP issues opaque (non-JWT) tokens MUST
complete the full MCP OAuth flow: login, consent detour to link a downstream
provider, and subsequent authenticated MCP requests.

#### Scenario: GitHub end-to-end flow
- GIVEN a session-mode gateway brokering an opaque-token IdP (GitHub)
- WHEN a user logs in, links a downstream provider (Linear) via the consent detour, then issues an MCP request
- THEN login MUST return a gateway session token
- AND the consent detour MUST link the downstream provider
- AND the authenticated MCP request MUST succeed

### Requirement: Subject capture and precedence

At callback the gateway MUST capture the user subject exactly once, preferring the
`id_token` claim when an id_token is present, otherwise calling the configured
userinfo endpoint. The subject value MUST be read from a configurable subject
claim (default `sub`). If no subject can be resolved, the flow MUST fail rather
than silently skip consent.

#### Scenario: Subject from id_token
- GIVEN a callback whose token response includes an id_token
- WHEN the subject is captured
- THEN it MUST come from the configured claim of the id_token

#### Scenario: Subject from userinfo
- GIVEN a callback with no id_token and a configured userinfo endpoint and subject claim (e.g. GitHub `id`)
- WHEN the subject is captured
- THEN exactly one userinfo call MUST occur and the subject MUST be read from the configured claim

#### Scenario: Unresolvable subject fails the flow
- GIVEN session mode ON and no id_token and no resolvable subject claim
- WHEN the callback runs
- THEN the flow MUST fail and MUST NOT complete login

### Requirement: Subject parity between consent and request

The subject captured at callback MUST be identical to the subject used for the
consent vault write and the subject embedded in the minted session token (vault
read). A credential linked during consent MUST therefore be found on later MCP
requests for the same user.

#### Scenario: Consent credential found on later request
- GIVEN a user who linked a downstream provider during the consent detour
- WHEN that same user later issues an authenticated MCP request
- THEN the vault credential written at consent MUST be found using the request principal's subject

#### Scenario: Distinct users do not share credentials
- GIVEN two users with distinct captured subjects
- WHEN one user issues an MCP request
- THEN it MUST NOT resolve the other user's vault credential

### Requirement: Local validation with no IdP hot-path call

On each MCP request the gateway MUST validate its own session token in-process,
recognizing it by the gateway STS issuer, and MUST NOT call the IdP userinfo or
introspection endpoint on the request path. A token whose issuer is the upstream
IdP MUST NOT be matched as a gateway session token. An invalid signature or
expired token MUST be rejected as unauthenticated.

#### Scenario: Gateway token validated locally
- GIVEN a valid gateway session token presented on an MCP request
- WHEN the request is authenticated
- THEN validation MUST succeed in-process with no IdP network call
- AND the resolved principal subject MUST equal the captured subject

#### Scenario: Invalid or expired token rejected
- GIVEN a gateway session token with a bad signature or past expiry
- WHEN it is presented on an MCP request
- THEN the request MUST be rejected as unauthenticated

### Requirement: Session token lifecycle and refresh

The session token MUST carry a bounded TTL. The gateway MUST issue its own
refresh_token that re-mints a fresh session token from the stored session,
without re-contacting the IdP. Refresh MUST preserve the original subject and
scopes.

#### Scenario: Expired session token requires refresh
- GIVEN a session token past its TTL
- WHEN it is presented on an MCP request
- THEN it MUST be rejected as unauthenticated

#### Scenario: Refresh re-mints without IdP
- GIVEN a valid gateway refresh_token
- WHEN the client exchanges it
- THEN the gateway MUST issue a new valid session token with the same subject and scopes
- AND no IdP call MUST occur

### Requirement: Okta JWT no-regression

With session mode OFF, JWT-issuing IdP gateways (Okta) MUST behave exactly as
before: the IdP JWT is passed through, validated per request via JWKS or
introspection keyed by the IdP issuer, and the principal subject derives from the
IdP token.

#### Scenario: Okta pass-through unchanged
- GIVEN an Okta gateway with session mode OFF
- WHEN a user logs in and issues an MCP request
- THEN the IdP JWT MUST be returned at exchange and validated against the IdP issuer
- AND the principal subject MUST derive from the IdP token as it does today
