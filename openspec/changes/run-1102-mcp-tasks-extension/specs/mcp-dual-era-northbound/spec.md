# Delta for MCP Dual-Era Northbound

## MODIFIED Requirements

### Requirement: Modern request validation

A modern request MUST contain JSON-RPC 2.0, object `params._meta`, matching `MCP-Protocol-Version` and `io.modelcontextprotocol/protocolVersion`, object `io.modelcontextprotocol/clientCapabilities`, and matching `Mcp-Method`. `tools/call`, `resources/read`, and `prompts/get` MUST match `Mcp-Name` after exact Base64-sentinel UTF-8 decoding. `tasks/get`, `tasks/update`, and `tasks/cancel` MUST match `Mcp-Name` against `params.taskId`, which MUST be a task handle of at most `MCP_TASK_HANDLE_MAX_BYTES`. Any `Mcp-Param-*` MUST be rejected. Header names are case-insensitive; values are case-sensitive.
(Previously: `Mcp-Name` was enforced only for `tools/call`, `resources/read`, and `prompts/get`.)

#### Scenario: Valid modern request
- GIVEN all metadata and mirrored headers match
- WHEN validation runs
- THEN execution MAY continue

#### Scenario: Invalid modern request
- GIVEN malformed metadata, a mismatch, invalid Base64, or `Mcp-Param-*`
- WHEN validation runs
- THEN HTTP 400 returns `-32602` for body shape or `-32020` for header validation

#### Scenario: tasks/* name binding
- GIVEN a modern `tasks/get` whose `Mcp-Name` differs from `params.taskId`
- WHEN validation runs
- THEN the request is rejected at the boundary with no policy effect

### Requirement: Modern statuses and errors

Unsupported versions MUST return HTTP 400 `-32022` with exact `data.requested` and newest-first `data.supported`: `[2026-07-28, 2025-06-18, 2025-03-26, 2024-11-05]`. `tasks/get`, `tasks/update`, and `tasks/cancel` are supported modern methods and MUST NOT return `-32601`; when the client did not declare `io.modelcontextprotocol/tasks` on that request they MUST return `-32025` with `data.requiredCapabilities: ["io.modelcontextprotocol/tasks"]`, and a rejected task handle MUST return `-32602` with one constant message and no `data`. Unknown modern methods MUST return HTTP 404 `-32601`. Valid modern notifications, including `notifications/cancelled`, MUST return HTTP 202 without a body; `notifications/cancelled` MUST NOT cancel a task.
(Previously: `tasks/*` were unknown modern methods returning `-32601`.)

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
- THEN HTTP 202 with no body, no continuation store mutation, and no task cancellation

#### Scenario: tasks/* dispatched, not 404
- GIVEN a declaring modern client posts `tasks/get` with a valid handle
- WHEN dispatched
- THEN the request is handled by the tasks mediation path and never returns `-32601`

### Requirement: Role-scoped discovery

`server/discover` MUST use only the role-scoped configured view and MUST NOT probe upstreams. It SHALL advertise supported versions, server identity, and capabilities; denied kinds MUST be omitted. Allowed kinds MUST map to `{}` except when MRTR is end-to-end: then `tools` MUST be `{"inputRequests":{}}`. End-to-end means modern northbound, ticket secret set, and at least one bound registry is not `protocol_mode=legacy`. MUST NOT advertise if all registries are `legacy` or the secret is missing. MUST NOT advertise on legacy `initialize`. `capabilities.extensions["io.modelcontextprotocol/tasks"]` MUST be advertised as `{}` under the same local-only test applied to `MCP_TASK_HANDLE_SECRET`, and the `extensions` key MUST be absent otherwise.
(Previously: capabilities carried no `extensions` key.)

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
- THEN no `inputRequests` and no `extensions` advertisement is present

#### Scenario: Tasks extension advertised or hidden
- GIVEN modern discover with the task handle secret set and a non-legacy registry
- WHEN discover completes
- THEN `capabilities.extensions` contains `io.modelcontextprotocol/tasks`, and the key is absent when the secret is unset or every registry is `legacy`

### Requirement: Modern response and caching

Every modern success MUST preserve existing fields and add `io.modelcontextprotocol/serverInfo`. Modern `tools/call` MUST set `resultType` to `"input_required"` when the mediated upstream result is `input_required`, MUST preserve `resultType: "task"` verbatim when the mediated upstream returned a `CreateTaskResult` for a declaring client, and otherwise MUST set `"complete"`. A `resultType: "task"` result MUST NOT be rewritten to `"complete"` and MUST NOT be emitted to a non-declaring client. All other modern methods, including `tasks/get|update|cancel`, MUST set `resultType: "complete"` and MUST strip MRTR fields. Discover/list results MUST use `ttlMs: 300000`; `resources/read` and `tasks/*` MUST use `ttlMs: 0`; all MUST use `cacheScope: "private"`.
(Previously: any non-`input_required` result was forced to `resultType: "complete"`, corrupting a `CreateTaskResult`.)

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

#### Scenario: tools/call task preserved
- GIVEN a declaring modern client whose mediated upstream returns `resultType: "task"`
- WHEN serialized
- THEN `resultType` stays `task`, `taskId` is the signed handle, and no MRTR field is injected
