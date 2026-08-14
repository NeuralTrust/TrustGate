# Delta for MCP Dual-Era Northbound

## MODIFIED Requirements

### Requirement: Modern statuses and errors

Unsupported versions MUST return HTTP 400 `-32022` with exact `data.requested` and newest-first `data.supported`: `[2026-07-28, 2025-06-18, 2025-03-26, 2024-11-05]`. Unknown modern methods MUST return HTTP 404 `-32601`. Valid modern notifications, including `notifications/cancelled`, MUST return HTTP 202 without a body.
(Previously: cancelled was not an accepted modern notification.)

#### Scenario: Unsupported version
- GIVEN an unknown non-legacy version
- WHEN validated
- THEN the exact `-32022` payload is returned

#### Scenario: Unknown method or notification
- GIVEN a validated modern request
- WHEN its method is unknown or it is a notification
- THEN HTTP 404 `-32601` or HTTP 202 is returned, respectively

#### Scenario: Cancelled notification
- GIVEN a validated modern `notifications/cancelled`
- WHEN handled
- THEN HTTP 202 with no body and no continuation store mutation

### Requirement: Role-scoped discovery

`server/discover` MUST use only the role-scoped configured view and MUST NOT probe upstreams. It SHALL advertise supported versions, server identity, and capabilities; denied kinds MUST be omitted. Allowed kinds MUST map to `{}` except when MRTR is end-to-end: then `tools` MUST be `{"inputRequests":{}}`. End-to-end means modern northbound, ticket secret set, and at least one bound registry is not `protocol_mode=legacy`. MUST NOT advertise if all registries are `legacy` or the secret is missing. MUST NOT advertise on legacy `initialize`.
(Previously: allowed kinds always mapped to `{}`.)

#### Scenario: Different role grants
- GIVEN two principals have different visible primitive kinds
- WHEN each calls `server/discover`
- THEN each sees only their configured kinds

#### Scenario: Local discovery
- GIVEN a valid discover request
- WHEN it completes
- THEN local telemetry is recorded without upstream, plugin, rate-limit, consent, or composer effects

#### Scenario: E2E advertises MRTR
- GIVEN modern discover, secret set, and a non-legacy registry
- WHEN discover completes
- THEN `tools` is `{"inputRequests":{}}`

#### Scenario: No e2e hides MRTR
- GIVEN all registries are `legacy` or the secret is missing
- WHEN modern discover completes
- THEN `tools` is `{}`

#### Scenario: Legacy initialize never advertises
- GIVEN a legacy `initialize`
- WHEN handled
- THEN no `inputRequests` advertisement is present

### Requirement: Modern response and caching

Every modern success MUST preserve existing fields and add `io.modelcontextprotocol/serverInfo`. Modern `tools/call` MUST set `resultType` to `"input_required"` when the mediated upstream result is `input_required`; otherwise `"complete"`. All other modern methods MUST set `resultType: "complete"` and MUST strip MRTR fields. Discover/list results MUST use `ttlMs: 300000`; `resources/read` MUST use `ttlMs: 0`; all MUST use `cacheScope: "private"`.
(Previously: every modern success forced `resultType: "complete"`.)

#### Scenario: Cacheable result
- GIVEN a successful modern discover, list, or resource read
- WHEN serialized
- THEN identity and method-specific private cache hints are present

#### Scenario: Legacy result
- GIVEN a legacy success
- WHEN serialized
- THEN no modern result or cache fields are added

#### Scenario: tools/call input_required preserved
- GIVEN a modern `tools/call` whose mediated upstream returns `input_required`
- WHEN serialized
- THEN `resultType` is `input_required` and ticket-wrapped `requestState` is present

#### Scenario: Non-tools stay complete
- GIVEN a modern `prompts/get` or `resources/read` with upstream MRTR fields
- WHEN serialized
- THEN `resultType` is `complete` and MRTR fields are absent
