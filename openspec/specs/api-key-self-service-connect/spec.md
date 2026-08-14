# API-Key Self-Service Connect Specification

## Purpose

Define a browser flow that exchanges an MCP consumer API key for a connect ticket without exposing the key or changing existing authentication flows.

## Requirements

### Requirement: Connect form target validation

`GET /:slug/connect` MUST resolve the gateway from `Host` and MUST require an active MCP consumer matching the route slug.

#### Scenario: Valid target
- GIVEN a resolvable Host and an active MCP consumer for the slug
- WHEN the client requests `GET /:slug/connect`
- THEN the system returns the API-key connect form

#### Scenario: Invalid target
- GIVEN the Host is invalid or the slug has no active MCP consumer
- WHEN the client requests the form
- THEN the system returns the same generic `404` response

### Requirement: Secure form and caching

The form MUST use a blank password input with `autocomplete="off"`, MUST NOT render a key value, and every endpoint response MUST include `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.

#### Scenario: Form rendering
- GIVEN a valid target
- WHEN the form is rendered
- THEN it contains a blank password field with autocomplete disabled
- AND the response includes both required policies

#### Scenario: Response policy across outcomes
- GIVEN any success or error outcome
- WHEN the endpoint responds
- THEN both required policies are present

### Requirement: Body-only form submission

`POST /:slug/connect` MUST accept the API key only from an `application/x-www-form-urlencoded` body and MUST NOT use query or header values as fallback credentials.

#### Scenario: Supported submission
- GIVEN a correctly encoded form containing the API-key field
- WHEN the client submits it
- THEN the system evaluates that body credential

#### Scenario: Unsupported media type
- GIVEN a POST with any other media type
- WHEN the client submits it
- THEN the system returns `415`

#### Scenario: Malformed form
- GIVEN an invalid form body
- WHEN the client submits it
- THEN the system returns `400`

### Requirement: Target-first API-key authorization

The system MUST resolve the Host gateway and active MCP consumer before key lookup. It MUST authorize only an enabled API-key auth belonging to that gateway whose AuthID is attached to that consumer.

#### Scenario: Authorized key
- GIVEN the target is valid and the enabled API-key auth matches its gateway and consumer
- WHEN the form is submitted
- THEN authorization succeeds with `principalSub` equal to the auth name exactly

#### Scenario: Expected authorization miss
- GIVEN any expected Host, gateway, consumer, key, auth-type, enabled-state, gateway-membership, or AuthID-membership check fails
- WHEN the form is submitted
- THEN the system returns the same generic `401` status and body

#### Scenario: Invalid target avoids key lookup
- GIVEN the submitted target cannot be resolved
- WHEN the form is submitted
- THEN the system returns generic `401` without looking up the key

### Requirement: Ticket creation and redirect

After authorization, the system MUST persist a reusable fifteen-minute ticket for the resolved gateway, exact auth name, consumer path, consumer ID, AuthID, and a stable, deduplicated snapshot of the exact forwarded `MCPAuth.Provider` IDs authorized for that consumer, then MUST redirect with `303` to `/{slug}/mcp/connect?ticket={ticket}`. The provider snapshot MUST NOT contain registry names or credentials. This change MUST NOT alter the existing ticket TTL.

#### Scenario: Successful exchange
- GIVEN an authorized API key
- WHEN persistence succeeds
- THEN the exact identity fields and sorted provider-ID snapshot persist with a fifteen-minute TTL
- AND the redirect contains only the opaque ticket

#### Scenario: Internal failure
- GIVEN unexpected non-limiter failure
- WHEN processed
- THEN generic `500` is returned

### Requirement: Secret non-disclosure

The API key or hash MUST NOT appear in URLs, bucket keys, logs, audit events, metric attributes, redirects, response bodies, or response headers.

#### Scenario: No leakage across outcomes
- GIVEN a sentinel key
- WHEN processing ends in success, `401`, `429`, `500`, or `503`
- THEN the key and hash are absent from every listed surface

### Requirement: Routing and compatibility

The new GET and POST routes MUST take precedence over `/+/connect`. Existing OAuth connect routes, MCP `X-AG-API-Key` runtime authentication, and forwarded vault-principal behavior MUST remain unchanged.

#### Scenario: Real route dispatch
- GIVEN the complete MCP Fiber router
- WHEN GET or POST is dispatched to `/:slug/connect`
- THEN the self-service handler receives the request rather than `/+/connect`

#### Scenario: Existing flows
- GIVEN an existing OAuth connect or authenticated MCP request
- WHEN it follows its existing route
- THEN its routing and principal behavior remain unchanged

### Requirement: Existing security boundaries

The endpoint MUST NOT require Origin validation or add a gateway-status gate. It MUST apply the source limit before target resolution, preserve target-before-key lookup, and apply the consumer limit after target resolution but before key lookup. Expected authorization misses below limits MUST remain uniform.

#### Scenario: Uniform authorization miss
- GIVEN any nonexistent, disabled, wrong-type, wrong-gateway, or cross-consumer key below limits
- WHEN submitted
- THEN the same generic `401` status/body is returned

#### Scenario: Invalid target avoids key lookup
- GIVEN the target cannot be resolved
- WHEN submitted below the source limit
- THEN generic `401` is returned without key lookup

#### Scenario: Valid request without Origin
- GIVEN an otherwise valid request without an Origin header
- WHEN processed
- THEN absence of Origin does not cause rejection
