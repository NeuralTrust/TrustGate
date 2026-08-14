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

### Requirement: Provider authorization and identity freshness
A ticket MUST be classified as API-key-origin when `providers` is present or either ConsumerID or AuthID is non-empty. Every API-key-origin ticket MUST have a provider snapshot and both identity IDs; partial identity and identity-complete tickets without a snapshot MUST fail with `ErrTicketNotFound` before state, provider exchange, vault mutation, or audit. Only a ticket with absent `providers` and both IDs empty is legacy.

API-key-origin tickets MUST authorize page visibility, start, callback, and disconnect only for exact provider IDs captured in their ticket snapshot. Page MUST list and query vault status only for snapshot providers that remain in current effective registries, so providers added after mint expose neither provider/registry metadata nor credential status. Disconnect MUST retain authorization if the captured provider's registry is later removed or renamed. Start and callback MUST still require the provider in current effective registries, and MUST reject a provider added after mint. Legacy tickets MUST list and authorize providers against current effective registries. API-key tickets MUST fail safely when the current consumer ID differs or the captured API-key AuthID is no longer attached, enabled, and applicable.

#### Scenario: Cross-consumer provider
- GIVEN an API-key ticket whose provider snapshot excludes a provider configured for another consumer
- WHEN disconnect requests that other provider
- THEN it fails before vault deletion or audit

#### Scenario: Provider configuration changes after mint
- GIVEN an API-key ticket whose snapshot includes a provider
- WHEN that provider's registry is later removed or renamed and disconnect requests the captured provider
- THEN the canonical provider credential is deleted and audited

#### Scenario: Legacy ticket fallback
- GIVEN a ticket without a provider snapshot
- WHEN disconnect requests a provider
- THEN only an exact provider in the consumer's current effective registries is accepted

#### Scenario: Stale API-key identity
- GIVEN an identity-complete API-key ticket
- WHEN its path resolves to another consumer or its AuthID is detached, disabled, or otherwise no longer applicable
- THEN the operation fails before vault mutation or audit

#### Scenario: Partial API-key identity
- GIVEN a ticket with any API-key marker but a missing provider snapshot, ConsumerID, or AuthID
- WHEN any lifecycle operation resolves it
- THEN it fails with `ErrTicketNotFound` before state, exchange, vault mutation, or audit

#### Scenario: Provider added after mint
- GIVEN an API-key ticket whose snapshot excludes a provider added later to current registries
- WHEN page, start, or callback processes that provider
- THEN page omits its metadata and does not query its credential
- AND start/callback fail before state creation, exchange, vault upsert, or audit

#### Scenario: Page provider visibility
- GIVEN a valid API-key ticket
- WHEN its connect page is built
- THEN only currently configured providers in its authorization-time snapshot are listed and queried
- AND a fully legacy ticket continues to list and query current effective providers

#### Scenario: Callback ticket tampering
- GIVEN callback state whose embedded ticket metadata or provider authorization was changed
- WHEN callback revalidates the ticket and snapshot
- THEN it fails before exchange, vault upsert, or audit

### Requirement: Atomic credential deletion
Vault credential deletion MUST atomically verify and delete the exact stored tuple and MUST return `ErrNotFound` when no key is deleted. Concurrent disconnects MUST therefore emit exactly one unlink audit, from the call that deleted the credential.

#### Scenario: Concurrent disconnect
- GIVEN two concurrent disconnects for the same credential
- WHEN both reach vault deletion
- THEN exactly one succeeds and emits the unlink audit
- AND the other returns `ErrNotFound` without an audit

#### Scenario: Corrupt stored credential
- GIVEN the Redis key contains malformed JSON
- WHEN deletion attempts to decode and compare it
- THEN the key remains untouched
- AND deletion returns `ErrNotFound` without a script error or audit

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
