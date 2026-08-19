# Spec: run-1104-bounded-mcp-subscriptions

**Change**: `run-1104-bounded-mcp-subscriptions` · **Linear**: [RUN-1104](https://linear.app/neuraltrust/issue/RUN-1104) — epic [RUN-1100](https://linear.app/neuraltrust/issue/RUN-1100)
**Contract**: SEP-2575 "Stateless MCP", protocol `2026-07-28`, `subscriptions/listen`. Revision pinned in the domain spec.

## Domain: mcp-subscriptions (new)

# MCP Subscriptions Specification

## Purpose

Bounded `subscriptions/listen` streaming for MCP `2026-07-28` (SEP-2575, revision <https://modelcontextprotocol.io/specification/2026-07-28>). A stream is not a session: it is a periodically re-authorized lease over a policy decision, hard-capped below `SERVER_WRITE_TIMEOUT`, on which every emitted notification is the product of a fresh full authorization pass. TrustGate persists no subscription state and holds no session handle.

## Requirements

### Requirement: Modern-only listen transport

`subscriptions/listen` MUST be a supported modern method only while `MCP_SUBSCRIPTIONS_ENABLED` is true; when disabled it MUST stay unlisted and answer HTTP 404 `-32601` byte-identically to before this change. It MUST be reachable only on the unchanged `POST /{consumer_slug}/mcp` endpoint and only after the unchanged policy prologue (auth, era, modern validation, consumer resolve, protocol acceptance, role scope, rate limit, plugins). `Accept` MUST contain both `text/event-stream` and `application/json`; a missing member, or the presence of `Mcp-Name` or any `Mcp-Param-*` on listen, MUST be refused at the boundary with `-32020` before any policy effect. An accepted listen MUST respond `200 text/event-stream` with `Cache-Control: no-cache, no-transform` and `X-Accel-Buffering: no`, MUST deliver frames incrementally rather than buffered until close, and MUST NOT emit `Mcp-Session-Id`. Legacy behaviour MUST be unaffected: a legacy-era `subscriptions/listen` MUST fall out as an unknown legacy method, legacy `initialize` capabilities MUST be byte-identical, and `GET`/`DELETE` MUST still return 405 with `Allow: POST`.

#### Scenario: Disabled restores prior behaviour
- GIVEN `MCP_SUBSCRIPTIONS_ENABLED=false`
- WHEN a modern client posts `subscriptions/listen`
- THEN HTTP 404 `-32601` is returned, no capability is advertised, and no stream is opened

#### Scenario: Accept and header negotiation refused at the boundary
- GIVEN a listen whose `Accept` omits `text/event-stream` or `application/json`, or which carries `Mcp-Name` or `Mcp-Param-*`
- WHEN validation runs
- THEN `-32020` is returned and no consumer lookup, rate limit, plugin, or composer effect occurs

#### Scenario: Frames arrive incrementally
- GIVEN an honoured listen with the metrics middleware enabled
- WHEN the ack and a keepalive are written
- THEN the client observes them chunk by chunk before close, not as one burst

#### Scenario: Legacy era and non-POST unchanged
- GIVEN a legacy-era `subscriptions/listen`, and separately a `GET` and a `DELETE` on the endpoint
- WHEN each is handled
- THEN the legacy request follows existing unknown-legacy-method behaviour and both non-POST methods return 405 with `Allow: POST`

### Requirement: Explicit notification-type negotiation

`params.notifications` MUST be present; a missing object MUST return `-32602`. The honoured subset MUST be the intersection of the types the client requested with the types TrustGate advertises for that request's role-scoped surface, and MUST NOT contain a type the client did not request or a primitive kind the principal cannot see. Only `toolsListChanged`, `promptsListChanged`, and `resourcesListChanged` MAY be honoured. `params.resourceSubscriptions` MUST be parsed and bounded to `MCP_SUBSCRIPTIONS_MAX_URIS` entries (default `32`) — over-cardinality or a malformed entry MUST return `-32602` — and MUST NEVER be honoured; `resources.subscribe` MUST NEVER be advertised and `notifications/resources/updated` MUST NEVER be emitted. `notifications/subscriptions/acknowledged`, carrying exactly the honoured subset, MUST be the first frame on the stream. Every frame, including the ack and the terminal result, MUST carry `_meta["io.modelcontextprotocol/subscriptionId"]` equal to the listen call's JSON-RPC id. An empty honoured subset MUST ack, send the terminal result, and close immediately.

#### Scenario: Ack is the first frame and carries only the honoured subset
- GIVEN a modern client requests all four types on a tools-and-prompts surface
- WHEN the stream opens
- THEN the first frame is the acknowledged notification honouring `toolsListChanged` and `promptsListChanged` only, stamped with the subscription id

#### Scenario: resourceSubscriptions bounded, refused, never advertised
- GIVEN a client requests `resourceSubscriptions` with 32 URIs, and separately with 33
- WHEN each listen is handled
- THEN the first is acked with `resourceSubscriptions` excluded from the honoured subset, the second returns `-32602`, and `resources.subscribe` is absent from every advertisement

#### Scenario: Role scope narrows the honoured subset
- GIVEN two principals on one consumer, one scoped to prompts only
- WHEN both request `toolsListChanged` and `promptsListChanged`
- THEN the prompts-only principal is honoured `promptsListChanged` alone

#### Scenario: Missing notifications rejected
- GIVEN a listen whose `params` omits `notifications`
- WHEN validation runs
- THEN `-32602` is returned and no stream is opened

#### Scenario: Empty honoured subset terminates at once
- GIVEN a client requests only unsupported types
- WHEN the stream opens
- THEN the ack carries an empty subset, the terminal result follows immediately, and the response closes

### Requirement: Every emission is a fresh authorization decision

On each `MCP_SUBSCRIPTIONS_REAUTH_INTERVAL` tick (default `30s`, floored) the stream MUST re-run the full authorization pass — re-resolve consumer `Data`, re-apply role scope, re-compose the surface — and MUST compare a per-kind surface fingerprint against the previous pass. A `list_changed` MUST be emitted only for an honoured kind whose fingerprint changed on the most recent successful pass; no other notification MUST ever be emitted. A re-authorization refusal — role revoked, registry detached, toolkit no longer exposing the kind, consumer switched to `protocol_acceptance=legacy_only`, or the feature disabled — MUST terminate the stream and MUST NOT silently narrow the honoured subset.

#### Scenario: Surface change emits exactly one notification
- GIVEN an honoured `toolsListChanged` stream and an edit to the consumer's toolkit
- WHEN the next re-auth tick runs
- THEN exactly one `notifications/tools/list_changed` is emitted within one interval

#### Scenario: Unchanged surface emits nothing
- GIVEN an honoured stream whose surface is unchanged across several ticks
- WHEN the ticks run
- THEN no notification is emitted and only keepalive frames appear

#### Scenario: Revocation terminates rather than narrows
- GIVEN a live stream whose principal loses its role grant, or whose registry is detached
- WHEN the next re-auth tick runs
- THEN the stream sends the terminal result and closes, and no narrowed subset is served

#### Scenario: Non-honoured kinds are never emitted
- GIVEN a stream honouring `promptsListChanged` only
- WHEN the tools surface changes
- THEN no `notifications/tools/list_changed` is emitted

### Requirement: Bounded lease lifetime and uniform termination

Maximum stream lifetime MUST come from `MCP_SUBSCRIPTIONS_MAX_LIFETIME`; when unset it MUST derive as `SERVER_WRITE_TIMEOUT` minus a fixed `10s` margin, clamped to a `30m` ceiling, so a stream can never outlive the server write deadline (which a flush does not reset). The effective deadline MUST be jittered by `−rand[0, 10%]` so a fleet does not re-open in lockstep. At the deadline the stream MUST write the terminal `SubscriptionsListenResult` and close cleanly; the client MUST NOT observe a transport error, and it is expected to re-issue `subscriptions/listen`. Client disconnect, `notifications/cancelled` for the listen id, deadline, re-authorization refusal, capacity reclaim, and server shutdown MUST all terminate the same way and MUST be indistinguishable on the wire — same terminal frame, no cause-specific error, message, or `data`. Keepalive comment frames MUST be written every `MCP_SUBSCRIPTIONS_KEEPALIVE` (default `15s`). A live stream MUST NOT hold a rate-limit token-bucket slot; rate limiting is checked once at open.

#### Scenario: Deadline closes cleanly, never mid-frame
- GIVEN `SERVER_WRITE_TIMEOUT` set below production and a derived lifetime
- WHEN a stream reaches its jittered deadline
- THEN the terminal result is delivered and the connection closes without `unexpected EOF`

#### Scenario: Every termination cause looks identical
- GIVEN streams ended by disconnect, `notifications/cancelled`, deadline, re-auth refusal, capacity reclaim, and shutdown
- WHEN each wire trace is compared
- THEN all end with the same terminal frame and carry no discriminator

#### Scenario: Deadlines are jittered
- GIVEN many streams opened at the same instant with one configured lifetime
- WHEN they reach their deadlines
- THEN the close times are spread below the configured lifetime, not identical

#### Scenario: Keepalive keeps an idle stream alive
- GIVEN an honoured stream with no surface change
- WHEN the keepalive interval elapses
- THEN a comment frame is written and the stream stays open until its deadline

### Requirement: Fail-fast lifetime configuration

Configuration validation MUST refuse to boot with `ErrInvalidConfig` when subscriptions are enabled and the effective maximum lifetime plus the fixed `10s` margin exceeds `SERVER_WRITE_TIMEOUT`, and the error MUST name both configured values and both environment variables. The margin MUST NOT be configurable. Validation MUST be skipped when the feature is disabled, so the default build is unaffected. A lifetime that would exceed the write timeout MUST be a boot failure, never a runtime truncation.

#### Scenario: Boot refused with both values named
- GIVEN `MCP_SUBSCRIPTIONS_ENABLED=true` and `MCP_SUBSCRIPTIONS_MAX_LIFETIME` within `10s` of `SERVER_WRITE_TIMEOUT` or above it
- WHEN configuration loads
- THEN startup fails with `ErrInvalidConfig` naming `MCP_SUBSCRIPTIONS_MAX_LIFETIME` and `SERVER_WRITE_TIMEOUT` and their values

#### Scenario: Disabled feature skips validation
- GIVEN `MCP_SUBSCRIPTIONS_ENABLED=false` and a lifetime above the write timeout
- WHEN configuration loads
- THEN startup succeeds and no subscription validation is applied

#### Scenario: Derived default always boots
- GIVEN `MCP_SUBSCRIPTIONS_ENABLED=true` and no explicit lifetime
- WHEN configuration loads
- THEN the lifetime derives to `SERVER_WRITE_TIMEOUT − 10s` clamped to `30m` and startup succeeds

### Requirement: Stream isolation

A stream MUST be accounted and evaluated under the key `{gatewayID, consumerID, principalFingerprint, roleScopeFingerprint}`, and no event MUST reach any stream other than the one whose own authorization pass produced it. No notification MUST cross a consumer, a principal, a role scope, or a registry boundary, including when two registries expose the same resource URI or share a discovery cache entry.

#### Scenario: Disjoint role scopes do not observe each other
- GIVEN two principals on one consumer with disjoint role-scoped surfaces
- WHEN one principal's surface changes
- THEN only that principal's stream emits a notification

#### Scenario: Consumer boundary holds
- GIVEN two consumers on one gateway, each with a live stream
- WHEN one consumer's toolkit changes
- THEN the other consumer's stream emits nothing

#### Scenario: Registry boundary holds
- GIVEN a registry attached to consumer A and not to consumer B
- WHEN that registry's surface changes
- THEN only A's stream emits a notification, even when both consumers see the same resource URI

### Requirement: Capacity bounds and non-probeable refusal

Live streams MUST be capped process-wide by `MCP_SUBSCRIPTIONS_MAX_STREAMS` (default `1024`), per consumer by `MCP_SUBSCRIPTIONS_MAX_PER_CONSUMER` (default `16`), and per principal by `MCP_SUBSCRIPTIONS_MAX_PER_PRINCIPAL` (default `4`). Reaching any cap MUST refuse the new listen with `-32026` (`CodeSubscriptionRefused`) carrying one constant message and no `data`, byte-identical across which cap was reached, so caps cannot be used as an occupancy oracle. A refusal MUST take effect before any stream is opened and MUST NOT disturb existing streams. No frame MUST exceed `MCP_SUBSCRIPTIONS_MAX_EVENT_BYTES` (default `8192`): a frame that would exceed it MUST NOT be emitted and MUST terminate the stream. Memory MUST be bounded — no unbounded per-stream buffer — and a consumer that stops reading MUST NOT cause unbounded growth.

#### Scenario: Refusals are indistinguishable across caps
- GIVEN the process cap reached, and separately the per-consumer and per-principal caps
- WHEN a further listen is attempted in each case
- THEN each returns `-32026` with a byte-identical message and no `data`

#### Scenario: Refusal does not disturb live streams
- GIVEN the per-consumer cap is reached
- WHEN another listen is refused
- THEN every existing stream for that consumer continues to its own deadline

#### Scenario: A consumer that never reads is bounded
- GIVEN a client that opens a listen and never reads from the socket
- WHEN the stream runs
- THEN memory attributed to it stays bounded and it is terminated no later than its deadline

#### Scenario: Oversize frame terminates rather than truncates
- GIVEN a frame that would exceed the maximum event size
- WHEN it is about to be written
- THEN it is not emitted and the stream terminates with the terminal result

### Requirement: Deterministic shutdown drain

Server shutdown MUST drain every live stream — terminal result then close — so the HTTP router's shutdown cannot block on a stream parked on its request context. Shutdown MUST complete within its budget with the process cap of streams open. Every goroutine started on behalf of a stream MUST be joined on the same termination path, and goroutine count MUST return to baseline after client disconnect, deadline, re-authorization refusal, capacity reclaim, and shutdown, verified under `-race`.

#### Scenario: Shutdown completes with live streams
- GIVEN N live streams parked awaiting their next tick
- WHEN the server shuts down
- THEN each receives the terminal result and shutdown completes within its budget rather than hanging

#### Scenario: No goroutine leak on any termination path
- GIVEN streams ended by disconnect, deadline, re-auth refusal, capacity reclaim, and shutdown
- WHEN each path completes
- THEN goroutine count returns to baseline with the race detector enabled

### Requirement: Bounded subscription telemetry

Subscription telemetry MUST use bounded label sets only — notification kind, outcome, and era drawn from fixed enumerations — plus an up/down counter of live streams. A stream MUST report its true duration at close rather than the near-zero latency observed when the handler chain unwinds, and the metrics middleware MUST NOT read the response body of a live stream. No metric, span, or log MUST contain a resource URI, a notification payload, a subscription id, a JSON-RPC id, a principal identifier, a token or credential, a consumer slug, or any tenant-identifying free text.

#### Scenario: Bounded labels with no content
- GIVEN an emitted `list_changed`, a capacity refusal, and a deadline close
- WHEN telemetry emits
- THEN every label comes from the fixed kind/outcome/era enumerations and no identifier, URI, or payload appears

#### Scenario: True duration recorded at close
- GIVEN a stream that lives for its full lifetime
- WHEN it closes
- THEN MCP-plane latency reflects the stream's real duration, not the handler unwind time

#### Scenario: Middleware never drains a live stream
- GIVEN a live stream with ops and MCP metrics enabled
- WHEN the middleware builds its response context
- THEN the streamed body is not read into memory and incremental delivery is preserved

## Domain: mcp-dual-era-northbound (delta)

# Delta for MCP Dual-Era Northbound

## MODIFIED Requirements

### Requirement: Modern request validation

A modern request MUST contain JSON-RPC 2.0, object `params._meta`, matching `MCP-Protocol-Version` and `io.modelcontextprotocol/protocolVersion`, object `io.modelcontextprotocol/clientCapabilities`, and matching `Mcp-Method`. `tools/call`, `resources/read`, and `prompts/get` MUST match `Mcp-Name` after exact Base64-sentinel UTF-8 decoding. `tasks/get`, `tasks/update`, and `tasks/cancel` MUST match `Mcp-Name` against `params.taskId`, which MUST be a task handle of at most `MCP_TASK_HANDLE_MAX_BYTES`. `subscriptions/listen` MUST NOT carry `Mcp-Name`, and its `Accept` MUST contain both `text/event-stream` and `application/json`; a violation of either MUST return `-32020` at the boundary. Any `Mcp-Param-*` MUST be rejected. Header names are case-insensitive; values are case-sensitive.
(Previously: `Accept` took no part in validation and `Mcp-Name` was unconstrained on `subscriptions/listen`.)

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
(Previously: `subscriptions/listen` was an unknown modern method returning `-32601`, and `-32026` was unassigned.)

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
(Previously: capability objects carried no `listChanged` sub-capability.)

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
(Previously: every modern response was a buffered JSON body and every emitted frame went through result normalization.)

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

### Requirement: Transport and legacy compatibility

The endpoint MUST remain `POST /{consumer_slug}/mcp`; validated non-discover requests SHALL use the existing gateway/composer. Modern handling MUST ignore and never emit `Mcp-Session-Id`, including on a streamed `subscriptions/listen` response. GET and DELETE MUST return 405 with `Allow: POST`, and no subscription transport MUST add a route, a standalone SSE channel, or any other method to the endpoint. A legacy-era `subscriptions/listen` MUST follow existing unknown-legacy-method behaviour. All existing legacy initialization, methods, errors, policies, filtering, consent, and telemetry MUST remain unchanged.
(Previously: no modern response was streamed, so the transport surface was asserted only for buffered responses.)

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
