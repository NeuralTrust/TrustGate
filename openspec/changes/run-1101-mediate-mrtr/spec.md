# Spec: run-1101-mediate-mrtr

## Domain: mcp-mrtr-mediation

# MCP MRTR Mediation Specification

## Purpose

Stateless HMAC-ticket mediation of modern `tools/call` MRTR. One POST equals one policy pass. No session store.

## Requirements

### Requirement: HMAC ticket bind

The system MUST HMAC-wrap `requestState` with `MCP_MRTR_TICKET_SECRET` and MUST NOT use JWT. The ticket MUST bind `{consumer, registry, exposed tool, upstream tool, method, round, exp}` plus the upstream blob. A ticket MUST be minted even if upstream omitted `requestState`. Unset secret MUST fail closed: no `input_required`, no advertise.

#### Scenario: Secret missing fails closed
- GIVEN secret unset and upstream `input_required`
- WHEN `tools/call` serializes or `server/discover` runs
- THEN `resultType` is `complete` and discover `tools` is `{}`

#### Scenario: Ticket minted without upstream state
- GIVEN `input_required` with no `requestState`
- WHEN serialized
- THEN a bound ticket is present

### Requirement: Continuation and policy

Modern `tools/call` MUST forward opaque `inputResponses` and the ticket. Composer MUST re-resolve by exposed name. Every round MUST re-run authn, authz, toolkit, rate limits, and plugins. Mismatch or expiry MUST return `-32023` with no upstream. `prompts/get` and `resources/read` MUST stay `complete` and MUST strip MRTR fields.

#### Scenario: Retry reaches original tool
- GIVEN a valid ticket and matching exposed name
- WHEN the client retries with `inputResponses`
- THEN the original authorized upstream receives unwrapped state and opaque responses after a full policy pass

#### Scenario: Cross-tenant replay rejected
- GIVEN a ticket replayed for a different consumer, registry, or tool
- WHEN dispatched
- THEN HTTP 400 `-32023` and no upstream

#### Scenario: One-round tools unchanged
- GIVEN a modern `tools/call` that completes in one round
- WHEN serialized
- THEN `resultType` is `complete`

#### Scenario: Policy deny on retry
- GIVEN a valid continuation denied by policy this round
- WHEN processed
- THEN the call is denied and outcome is `policy_denied`

### Requirement: Caps, kinds, and plugins

Southbound MUST forward declared client caps and populate SDK continuation fields; empty `{}` MUST NOT be sent on MRTR-capable calls. Declared `inputRequests` kinds MUST pass through; undeclared kinds MUST be stripped. Plugins MUST scan `inputResponses` and MUST ignore name rewrites. MUST NOT log user input or plaintext `requestState`. MUST NOT originate sampling or roots.

#### Scenario: Caps forwarded and undeclared kinds stripped
- GIVEN declared caps and an undeclared `inputRequests` kind
- WHEN southbound call and northbound serialize run
- THEN caps and continuation are forwarded and the undeclared kind is absent

#### Scenario: Plugin scan without logging user input
- GIVEN a retry with `inputResponses`
- WHEN PreRequest and logs run
- THEN plugins receive `inputResponses` and logs omit user input

### Requirement: Limits and error codes

Defaults MUST be 8 rounds, 5-minute TTL, and 256 KiB continuation. Round overflow MUST return `-32024`. Size or shape errors MUST return `-32602`. Replay, expiry, or mismatch MUST return `-32023`. MUST NOT use `-32021` for MRTR. In-flight deadline expiry MUST surface as timeout.

#### Scenario: Round limit
- GIVEN the next round would exceed 8
- WHEN validated
- THEN `-32024` and no upstream

#### Scenario: Oversized continuation
- GIVEN continuation over 256 KiB
- WHEN validated
- THEN `-32602`

#### Scenario: Timeout
- GIVEN the round's context deadline fires
- WHEN `tools/call` is in flight
- THEN the client sees timeout and outcome is `timeout`

### Requirement: MRTR telemetry

When ops metrics are enabled, the system MUST increment `mcp.northbound.mrtr.outcome_total{outcome,era}` with `round` ∈ {`1`,`2`,`3+`}. `outcome` MUST be one of `input_required`, `complete`, `cancelled`, `policy_denied`, `timeout`, `round_limit`, `replay_rejected`.

#### Scenario: Enumerated outcome
- GIVEN `input_required` on round 2
- WHEN ops metrics emit
- THEN `outcome=input_required`, `round=2`, `era=modern`

#### Scenario: Cancelled notification metered
- GIVEN a validated modern `notifications/cancelled`
- WHEN accepted
- THEN HTTP 202 and `outcome=cancelled`

## Domain: mcp-dual-era-northbound

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
