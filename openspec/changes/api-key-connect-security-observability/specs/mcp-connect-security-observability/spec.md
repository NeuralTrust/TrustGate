# MCP Connect Security and Observability Specification

## Purpose
Bound public API-key connect attempts, audit successful lifecycle mutations, and preserve OAuth compatibility without exposing credentials or unbounded identifiers.

## Requirements

### Requirement: Attempt limits
The dedicated fixed-window limiter MUST default on at 10 attempts per source and 100 per resolved consumer per minute, counting successes and failures independently. Limits and window MUST be positive. An exceeded bucket MUST return generic `429` with `Retry-After`; limiter failure MUST fail closed with generic `503` before credential lookup or ticket creation.

#### Scenario: Source boundary
- GIVEN nine source attempts
- WHEN attempts ten and eleven occur
- THEN ten proceeds and eleven returns `429` with positive `Retry-After`

#### Scenario: Consumer boundary
- GIVEN 99 consumer attempts across sources
- WHEN attempts 100 and 101 occur
- THEN 100 proceeds and 101 returns the same generic `429` with `Retry-After`

#### Scenario: Limiter outage
- GIVEN either limiter check fails
- WHEN a POST is processed
- THEN generic `503` is returned before credential or ticket work

#### Scenario: Invalid configuration
- GIVEN an enabled limit or window is non-positive
- WHEN configuration is validated
- THEN startup MUST fail

### Requirement: Proxy trust
Source MUST default to the canonical socket peer. Canonicalization MUST remove ports and unmap IPv4-mapped IPv6. `X-Forwarded-For` MAY apply only when that peer is in a configured trusted CIDR; addresses MUST be walked right-to-left past trusted hops to the first untrusted canonical IP. Invalid or missing data MUST fall back to the peer. Other forwarding headers MUST NOT apply, and invalid CIDRs MUST fail startup.

#### Scenario: Untrusted proxy
- GIVEN an untrusted peer supplies forwarding headers
- WHEN bucketing
- THEN the canonical peer is used

#### Scenario: Trusted proxy chain
- GIVEN a trusted peer and valid XFF chain
- WHEN bucketing
- THEN the first untrusted address found right-to-left is canonicalized and used

#### Scenario: Invalid forwarding data
- GIVEN trusted peer XFF is missing or invalid
- WHEN bucketing
- THEN the canonical peer is used

#### Scenario: Canonical address
- GIVEN equivalent port-bearing or IPv4-mapped peer forms
- WHEN bucketing
- THEN they resolve to the same normalized source

### Requirement: Opaque buckets
Bucket keys MUST be `gt:mcp:connect:rl:v1:{source|consumer}:<digest>`, where digest is lowercase HMAC-SHA-256 under `SERVER_SECRET_KEY` over `source\x00<canonical-ip>` or `consumer\x00<consumer-uuid>`. Raw source, target, consumer, or credential values MUST NOT appear in keys or telemetry.

#### Scenario: Bucket observation
- GIVEN source and consumer checks
- WHEN keys and telemetry are observed
- THEN only domain-separated digests and bounded labels exist

### Requirement: Lifecycle audit
Each successful identity-complete API-key-origin ticket, provider upsert, or provider delete MUST emit exactly one JSON `slog` INFO `"security audit"` event after persistence. Event values MUST be `mcp_connect_ticket_created`, `mcp_provider_linked`, or `mcp_provider_unlinked`. Only `event`, `gateway_id`, `consumer_id`, `auth_id`, and link/unlink `provider_id` MAY appear; provider MUST equal `MCPAuth.Provider`. Other-origin, incomplete, and failed operations MUST emit none.

#### Scenario: Successful lifecycle audit
- GIVEN an identity-complete API-key ticket
- WHEN ticket, provider link, or provider unlink persistence succeeds
- THEN exactly one corresponding allowlisted event is emitted afterward

#### Scenario: Failed or ineligible audit
- GIVEN persistence fails or ticket identity/origin is ineligible
- WHEN processing ends
- THEN no lifecycle event is emitted

### Requirement: Bounded metrics
`/:slug/connect`, paths ending `/mcp/connect`, and existing OAuth shapes MUST classify as MCP OAuth using bounded enums. Slugs and paths MUST NOT become labels; unrelated connect-looking paths MUST remain outside that class.

#### Scenario: Route classification
- GIVEN `/tools/connect`, `/tools/mcp/connect`, OAuth, and unrelated paths
- WHEN classified
- THEN only defined shapes use the bounded MCP OAuth class

#### Scenario: Metric cardinality
- GIVEN arbitrary slugs
- WHEN metrics are emitted
- THEN no slug or raw path appears in attributes

### Requirement: Bearer challenge
Self-service forms MUST NOT emit Bearer challenges. Known runtime MCP `401` responses MUST challenge only when an enabled OAuth2 auth or usable default IdP applies. Known API-key-only paths MUST suppress it; unknown or failed eligibility MUST preserve existing behavior.

#### Scenario: Form and API-key-only responses
- GIVEN form or known API-key-only `401`
- WHEN returned
- THEN no Bearer challenge is present

#### Scenario: Usable OAuth response
- GIVEN a known runtime `401` with usable OAuth
- WHEN returned
- THEN the existing Bearer challenge is present

#### Scenario: Unknown eligibility
- GIVEN path eligibility is unknown or lookup failed
- WHEN a runtime `401` is returned
- THEN existing challenge behavior is preserved

### Requirement: TTL and state
Connect tickets MUST retain their fifteen-minute TTL and remain reusable. OAuth states MUST retain their ten-minute TTL and remain atomically single-use through `GETDEL`. This change MUST NOT alter either existing TTL constant.

#### Scenario: Reusable ticket
- GIVEN a fresh ticket
- WHEN read repeatedly within fifteen minutes
- THEN each read succeeds

#### Scenario: Preserved TTL boundaries
- GIVEN a newly persisted ticket and OAuth state
- WHEN their expiry is inspected
- THEN the ticket expires after fifteen minutes and the state after ten minutes

#### Scenario: One-time state
- GIVEN a fresh state
- WHEN consumed twice within ten minutes
- THEN the first succeeds and the second fails

### Requirement: Stacked base
Work MUST remain on `fix/api-key-connect-security-observability` from `feat/api-key-self-service-connect-endpoint@fd8782b5`; the isolated child PR MUST target that branch, never `develop`.

#### Scenario: PR validation
- GIVEN the child PR
- WHEN base/diff are inspected
- THEN they match the chain without unrelated slices
