# Delta for MCP Dual-Era Northbound

## ADDED Requirements

### Requirement: Era classification

After authentication, the server MUST parse each POST independently before consumer lookup. `initialize` or a known legacy header MUST select legacy despite modern metadata. Any `2026-07-28` header or metadata signal MUST select modern; an unknown version header MUST produce `-32022`; no modern signal MUST select legacy.

#### Scenario: Legacy precedence
- GIVEN `initialize` or a known legacy header with modern metadata
- WHEN the request is classified
- THEN legacy semantics apply

#### Scenario: Modern intent
- GIVEN one or both modern signals
- WHEN the request is classified
- THEN modern validation runs and missing counterparts fail closed

### Requirement: Modern request validation

A modern request MUST contain JSON-RPC 2.0, object `params._meta`, matching `MCP-Protocol-Version` and `io.modelcontextprotocol/protocolVersion`, object `io.modelcontextprotocol/clientCapabilities`, and matching `Mcp-Method`. `tools/call`, `resources/read`, and `prompts/get` MUST match `Mcp-Name` after exact Base64-sentinel UTF-8 decoding. `tasks/get`, `tasks/update`, and `tasks/cancel` MUST match `Mcp-Name` against `params.taskId`, which MUST be a task handle of at most `MCP_TASK_HANDLE_MAX_BYTES`. `subscriptions/listen` MUST NOT carry `Mcp-Name`, and its `Accept` MUST contain both `text/event-stream` and `application/json`; a violation of either MUST return `-32020` at the boundary. Any `Mcp-Param-*` MUST be rejected. Header names are case-insensitive; values are case-sensitive.

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

#### Scenario: listen Accept and Mcp-Name binding
- GIVEN a modern `subscriptions/listen` whose `Accept` omits `text/event-stream` or `application/json`, or which carries `Mcp-Name`
- WHEN validation runs
- THEN `-32020` is returned at the boundary with no policy effect

### Requirement: Modern statuses and errors

Unsupported versions MUST return HTTP 400 `-32022` with exact `data.requested` and newest-first `data.supported`: `[2026-07-28, 2025-06-18, 2025-03-26, 2024-11-05]`. `tasks/get`, `tasks/update`, and `tasks/cancel` are supported modern methods and MUST NOT return `-32601`; when the client did not declare `io.modelcontextprotocol/tasks` on that request they MUST return `-32025` with `data.requiredCapabilities: ["io.modelcontextprotocol/tasks"]`, and a rejected task handle MUST return `-32602` with one constant message and no `data`. `subscriptions/listen` is a supported modern method while `MCP_SUBSCRIPTIONS_ENABLED` is true and MUST NOT return `-32601`; a capacity refusal MUST return `-32026` with one constant message and no `data`, and a missing or malformed `params.notifications` MUST return `-32602`. When the feature is disabled `subscriptions/listen` MUST remain unlisted and return `-32601`. Unknown modern methods MUST return HTTP 404 `-32601`. Valid modern notifications, including `notifications/cancelled`, MUST return HTTP 202 without a body; `notifications/cancelled` MUST NOT cancel a task.

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

#### Scenario: listen dispatched when enabled, 404 when disabled
- GIVEN a modern `subscriptions/listen` with a valid `Accept`
- WHEN the feature is enabled and, separately, disabled
- THEN the first is handled by the subscriptions path and never returns `-32601`, and the second returns HTTP 404 `-32601`

#### Scenario: Capacity refusal is opaque
- GIVEN any subscription capacity cap is reached
- WHEN a further listen is dispatched
- THEN `-32026` is returned with one constant message and no `data`

### Requirement: Role-scoped discovery

`server/discover` MUST use only the role-scoped configured view and MUST NOT probe upstreams. It SHALL advertise supported versions, server identity, and capabilities; denied kinds MUST be omitted. Allowed kinds MUST map to `{}` except when MRTR is end-to-end: then `tools` MUST be `{"inputRequests":{}}`. End-to-end means modern northbound, ticket secret set, and at least one bound registry is not `protocol_mode=legacy`. MUST NOT advertise if all registries are `legacy` or the secret is missing. MUST NOT advertise on legacy `initialize`. `capabilities.extensions["io.modelcontextprotocol/tasks"]` MUST be advertised as `{}` under the same local-only test applied to `MCP_TASK_HANDLE_SECRET`, and the `extensions` key MUST be absent otherwise. Allowed `tools`, `prompts`, and `resources` MUST additionally carry `listChanged: true` when subscriptions are end-to-end — the feature enabled and at least one bound registry not `protocol_mode=legacy`, decided locally without dialling — merged with MRTR's `inputRequests` rather than replacing it. `resources.subscribe` MUST NEVER be advertised.

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
- THEN no `inputRequests`, no `extensions`, and no `listChanged` advertisement is present

#### Scenario: Tasks extension advertised or hidden
- GIVEN modern discover with the task handle secret set and a non-legacy registry
- WHEN discover completes
- THEN `capabilities.extensions` contains `io.modelcontextprotocol/tasks`, and the key is absent when the secret is unset or every registry is `legacy`

#### Scenario: listChanged advertised or hidden, subscribe never
- GIVEN modern discover with subscriptions enabled and a non-legacy registry, and separately with subscriptions disabled
- WHEN discover completes
- THEN allowed kinds carry `listChanged: true` in the first case and omit it in the second, `tools` retains `inputRequests` when MRTR is end-to-end, and `resources.subscribe` is absent in both

### Requirement: Modern response and caching

Every modern success MUST preserve existing fields and add `io.modelcontextprotocol/serverInfo`. Modern `tools/call` MUST set `resultType` to `"input_required"` when the mediated upstream result is `input_required`, MUST preserve `resultType: "task"` verbatim when the mediated upstream returned a `CreateTaskResult` for a declaring client, and otherwise MUST set `"complete"`. A `resultType: "task"` result MUST NOT be rewritten to `"complete"` and MUST NOT be emitted to a non-declaring client. All other modern methods, including `tasks/get|update|cancel`, MUST set `resultType: "complete"` and MUST strip MRTR fields. Discover/list results MUST use `ttlMs: 300000`; `resources/read` and `tasks/*` MUST use `ttlMs: 0`; all MUST use `cacheScope: "private"`. A modern response MAY be `text/event-stream`: an honoured `subscriptions/listen` MUST stream frames instead of a buffered body. Frames carrying notifications are not results and MUST NOT be given `resultType`, `ttlMs`, or `cacheScope`; the terminal `SubscriptionsListenResult` MUST be normalized as a result with `ttlMs: 0` and `cacheScope: "private"`.

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

#### Scenario: Notification frames are not results
- GIVEN an honoured listen emitting the acknowledged notification and a `list_changed`
- WHEN each frame is serialized
- THEN neither carries `resultType`, `ttlMs`, or `cacheScope`, while the terminal result carries `ttlMs: 0` and `cacheScope: "private"`

### Requirement: Northbound schema sanitization

Modern `tools/list` output MUST recursively omit every `x-mcp-header` key and MUST preserve all other schema fields. Sanitization MUST NOT mutate cached or southbound payloads.

#### Scenario: Concurrent sanitization
- GIVEN a shared tool schema contains nested `x-mcp-header` keys
- WHEN concurrent modern and legacy responses serialize it
- THEN modern omits only those keys while cached, legacy, and southbound views remain unchanged

### Requirement: Validation isolation

Modern parsing and validation MUST finish before consumer lookup, role scoping, routing, rate limiting, plugins, composer, or upstream discovery. Failures MUST create no composer span and MUST mark operation metrics skipped.

#### Scenario: Boundary rejection
- GIVEN any modern parse or validation failure
- WHEN the handler rejects it
- THEN none of the downstream collaborators or policy effects occur

### Requirement: Transport and legacy compatibility

The endpoint MUST remain `POST /{consumer_slug}/mcp`; validated non-discover requests SHALL use the existing gateway/composer. Modern handling MUST ignore and never emit `Mcp-Session-Id`, including on a streamed `subscriptions/listen` response. GET and DELETE MUST return 405 with `Allow: POST`, and no subscription transport MUST add a route, a standalone SSE channel, or any other method to the endpoint. A legacy-era `subscriptions/listen` MUST follow existing unknown-legacy-method behaviour. All existing legacy initialization, methods, errors, policies, filtering, consent, and telemetry MUST remain unchanged.

#### Scenario: Stateless modern transport
- GIVEN a modern request carries a session ID
- WHEN handled
- THEN the ID has no effect and no response session header is emitted

#### Scenario: Legacy regression
- GIVEN an existing legacy request or unsupported HTTP method
- WHEN handled
- THEN prior legacy behavior or HTTP 405 with `Allow: POST` is preserved

#### Scenario: Streaming adds no transport surface
- GIVEN subscriptions are enabled
- WHEN `GET` and `DELETE` are issued on the endpoint and a listen is streamed
- THEN both non-POST methods still return 405 with `Allow: POST`, no standalone SSE channel exists, and the stream emits no `Mcp-Session-Id`

#### Scenario: Legacy client cannot reach the listen path
- GIVEN a legacy-era request whose method is `subscriptions/listen`
- WHEN classified and handled
- THEN legacy unknown-method behaviour applies and no stream is opened
