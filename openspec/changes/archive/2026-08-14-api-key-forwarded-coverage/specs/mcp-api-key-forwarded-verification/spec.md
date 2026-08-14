# MCP API-Key Forwarded Verification Specification

## Purpose

Define what the functional suite MUST prove about the existing API-key self-service connect and forwarded credential injection behavior, and under which conditions.

This capability adds no product behavior. Every requirement below is a verification obligation over behavior already specified in `api-key-self-service-connect` and `mcp-connect-security-observability`; where a scenario proves an existing normative requirement it references that requirement rather than restating it. Archiving this capability MUST NOT modify either canonical spec.

## Requirements

### Requirement: End-to-end self-service connect proof

The functional suite MUST prove, through the running three-process harness rather than mocks, that an MCP consumer with an attached API-key auth and a `forwarded` registry completes the self-service connect flow against a fake external OAuth provider, exercising the real provider client over HTTP. It MUST NOT re-assert route dispatch or form markup, already covered by `api-key-self-service-connect`.

#### Scenario: Connect page reachable
- GIVEN a seeded gateway, active MCP consumer, API-key auth and forwarded registry
- WHEN the suite requests the consumer's connect page on the running MCP plane
- THEN the page is served (Requirement: Connect form target validation)

#### Scenario: Key exchanged for a ticket
- GIVEN the plaintext API key of that consumer
- WHEN it is submitted as a form-encoded body
- THEN the response is `303` and its `Location` carries an opaque ticket (Requirement: Ticket creation and redirect)

#### Scenario: Consent completed against the fake provider
- GIVEN that ticket
- WHEN the suite drives authorize and callback against the provider stub
- THEN the callback completes without an error outcome

### Requirement: Forwarded injection proves principal identity

The suite MUST prove that the principal derived at connect time equals the principal derived at runtime, by asserting the upstream MCP server receives exactly the bearer minted by the provider stub. Persistence MUST be proven behaviorally; the suite MUST NOT assert against the `vault_credentials` table.

#### Scenario: Stored token injected upstream
- GIVEN a completed connect for the consumer's forwarded provider
- WHEN a tool is called with `X-AG-API-Key`
- THEN the upstream receives an `Authorization` bearer equal to the token the stub minted
- AND no refresh exchange is needed to obtain it

### Requirement: Shared-key grant reuse asserted explicitly

Shared-key behavior MUST be a deliberate, named assertion, not an incidental side effect of another scenario.

#### Scenario: Second client, same key, same grant
- GIVEN a completed connect for one API key
- WHEN a second client calls a tool with that same key and performs no connect of its own
- THEN the upstream receives the same bearer

### Requirement: Principal and consumer isolation

The suite MUST prove that grants never cross API-key principals, and MUST prove the connect endpoint's consumer boundary end to end with a single assertion rather than a dedicated test.

#### Scenario: Different principal does not inherit the grant
- GIVEN a second MCP consumer with its own API key and the same forwarded provider
- WHEN it calls a tool without connecting
- THEN it does not receive the first principal's grant and consent is required

#### Scenario: Cross-consumer key rejected
- GIVEN the second consumer's API key
- WHEN it is submitted to the first consumer's connect endpoint
- THEN the generic `401` is returned (Requirement: Target-first API-key authorization)

### Requirement: OAuth2 per-user regression without new tests

Unchanged inbound OAuth2 per-user behavior MUST be covered by regression rather than new test code; this change MUST NOT add an inbound IdP stub for that purpose.

#### Scenario: Existing OAuth2 coverage still passes
- GIVEN this change
- WHEN the functional suite runs
- THEN `TestMCPOAuth_SharedHostScopesChallengeAndResolvesConsumerIdP` and `TestMCPServer_RoleBasedConsumer*` pass unmodified

### Requirement: Secret hygiene in verification

No API-key, connect-ticket or OAuth token value MAY appear in test logs, assertion messages, failure output or golden files. Secrets MUST be asserted by equality or shape only.

#### Scenario: Failing assertion discloses nothing
- GIVEN any assertion over a key, ticket or token
- WHEN it fails
- THEN the rendered output contains no secret value

### Requirement: Deterministic execution conditions

New tests MUST live behind the `functional` build tag in package `functional_test` and MUST carry no comments. The connect attempt limiter MUST be disabled for the suite through `.env.functional.example` so a shared source bucket cannot produce order-dependent `429`s; limiter behavior stays covered by unit tests and a functional `429` proof is out of scope. The suite MUST pass under `-race`, `go vet` and lint within the existing local package timeout.

#### Scenario: Suite is order-independent
- GIVEN the whole functional package runs in one window from a single source address
- WHEN connect attempts accumulate across tests
- THEN no test fails with `429`

#### Scenario: Verification changes no production behavior
- GIVEN the change's diff
- WHEN it is reviewed
- THEN it contains no production code change
- AND any behavior the tests cannot satisfy is escalated as a defect rather than accommodated
