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
