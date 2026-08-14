# Delta for API-Key Self-Service Connect

## MODIFIED Requirements

### Requirement: Secure form and caching
The form MUST use a blank password input with `autocomplete="off"`, MUST NOT render a key value, and every endpoint response MUST include `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
(Previously: only `Cache-Control: no-store` was normative.)

#### Scenario: Form rendering
- GIVEN a valid target
- WHEN the form is rendered
- THEN it contains a blank password field with autocomplete disabled
- AND the response includes both required policies

#### Scenario: Response policy across outcomes
- GIVEN any success or error outcome
- WHEN the endpoint responds
- THEN both required policies are present

### Requirement: Ticket creation and redirect
After authorization, the system MUST persist a reusable fifteen-minute ticket for the resolved gateway, exact auth name, consumer path, consumer ID, and AuthID, then MUST redirect with `303` to `/{slug}/mcp/connect?ticket={ticket}`. This change MUST NOT alter the existing ticket TTL.
(Previously: consumer ID, AuthID, reusability, and TTL were not normative.)

#### Scenario: Successful exchange
- GIVEN an authorized API key
- WHEN persistence succeeds
- THEN the exact identity fields persist with a fifteen-minute TTL
- AND the redirect contains only the opaque ticket

#### Scenario: Internal failure
- GIVEN unexpected non-limiter failure
- WHEN processed
- THEN generic `500` is returned

### Requirement: Secret non-disclosure
The API key or hash MUST NOT appear in URLs, bucket keys, logs, audit events, metric attributes, redirects, response bodies, or response headers.
(Previously: buckets, audit, metrics, and new errors were not explicit.)

#### Scenario: No leakage across outcomes
- GIVEN a sentinel key
- WHEN processing ends in success, `401`, `429`, `500`, or `503`
- THEN the key and hash are absent from every listed surface

### Requirement: Existing security boundaries
The endpoint MUST NOT require Origin validation or add a gateway-status gate. It MUST apply the source limit before target resolution, preserve target-before-key lookup, and apply the consumer limit after target resolution but before key lookup. Expected authorization misses below limits MUST remain uniform.
(Previously: dedicated limiting was optional.)

#### Scenario: Uniform authorization miss
- GIVEN any nonexistent, disabled, wrong-type, wrong-gateway, or cross-consumer key below limits
- WHEN submitted
- THEN the same generic `401` status/body is returned

#### Scenario: Invalid target avoids key lookup
- GIVEN the target cannot be resolved
- WHEN submitted below the source limit
- THEN generic `401` is returned without key lookup

#### Scenario: Valid request without Origin
- GIVEN an otherwise valid request without Origin
- WHEN processed
- THEN absence of Origin does not cause rejection
