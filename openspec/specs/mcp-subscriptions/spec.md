# MCP Subscriptions Specification

## Purpose

Bounded `subscriptions/listen` streaming for MCP `2026-07-28` (SEP-2575, revision <https://modelcontextprotocol.io/specification/2026-07-28>). A stream is not a session: it is a periodically re-authorized lease over a policy decision, hard-capped below `SERVER_WRITE_TIMEOUT`, on which every emitted notification is the product of a fresh full authorization pass. TrustGate MAY multiplex equivalent modern southbound listeners, but persists no subscription state, holds no legacy session handle, and never treats transport sharing as authorization.

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

`params.notifications` MUST be present; a missing object MUST return `-32602`. The honoured subset MUST be the intersection of the types the client requested with the types TrustGate advertises for that request's role-scoped surface, and MUST NOT contain a type the client did not request or a primitive kind the principal cannot see. When `MCP_SUBSCRIPTIONS_UPSTREAM_ENABLED=true`, the intersection MUST additionally contain only kinds explicitly negotiated from at least one eligible modern bound registry. Legacy and unsupported registries MUST contribute no honoured kind. Only `toolsListChanged`, `promptsListChanged`, and `resourcesListChanged` MAY be honoured. `params.resourceSubscriptions` MUST be parsed and bounded to `MCP_SUBSCRIPTIONS_MAX_URIS` entries (default `32`) — over-cardinality or a malformed entry MUST return `-32602` — and MUST NEVER be honoured; `resources.subscribe` MUST NEVER be advertised and `notifications/resources/updated` and task notifications MUST NEVER be emitted. `notifications/subscriptions/acknowledged`, carrying exactly the honoured subset, MUST be the first frame on the stream. Every frame, including the ack and the terminal result, MUST carry `_meta["io.modelcontextprotocol/subscriptionId"]` equal to the listen call's JSON-RPC id. An empty honoured subset MUST ack, send the terminal result, and close immediately.

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

#### Scenario: Southbound capabilities narrow the honoured subset
- GIVEN upstream multiplexing is enabled, the client requests all three list-changed kinds, and its eligible modern registries explicitly negotiate tools and resources only
- WHEN the stream opens
- THEN the ack honours tools and resources only, and prompts notifications can never be emitted on that lease

### Requirement: Every emission is a fresh authorization decision

On each `MCP_SUBSCRIPTIONS_REAUTH_INTERVAL` tick (default `30s`, floored) the stream MUST re-run the full authorization pass — re-resolve consumer `Data`, re-apply role scope, re-compose the surface, and verify AuthID, registry and source bindings. With `MCP_SUBSCRIPTIONS_UPSTREAM_ENABLED=false`, a `list_changed` MUST be emitted only for an honoured kind whose surface fingerprint changed on the most recent successful pass. With upstream multiplexing enabled, a `list_changed` MUST be emitted only after an allowed southbound event and a successful fresh authorization decision; the periodic pass is a watchdog and MUST NOT emit polling-derived duplicates. A re-authorization refusal or binding drift — role revoked, AuthID changed, registry detached, toolkit no longer exposing the kind, credentials or negotiated capabilities changed, consumer switched to `protocol_acceptance=legacy_only`, or either required feature disabled — MUST terminate the whole northbound lease and MUST NOT silently narrow or migrate it.

#### Scenario: Surface change emits exactly one notification
- GIVEN upstream multiplexing is disabled, an honoured `toolsListChanged` stream and an edit to the consumer's toolkit
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

#### Scenario: Upstream event requires a fresh authorization
- GIVEN upstream multiplexing is enabled and a shared listener receives `notifications/tools/list_changed`
- WHEN one attached subscriber has lost its tools role and another remains authorized
- THEN the first lease terminates, the second receives one tools notification, and the event crosses neither role scope nor registry boundary

#### Scenario: Watchdog does not duplicate upstream events
- GIVEN upstream multiplexing is enabled and the role-scoped surface fingerprint changes without a southbound event
- WHEN the re-authorization tick runs
- THEN the lease either remains valid or terminates for binding drift, but no polling-derived list-changed notification is emitted

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

A stream MUST be accounted and evaluated under the identity `{gatewayID, consumerID, principalFingerprint, AuthID, registryID, roleScopeFingerprint}`, and no event MUST reach a stream without a fresh authorization decision for that complete identity. Physical southbound listener sharing MUST NOT weaken this identity. No notification MUST cross a gateway, consumer, principal, AuthID, role scope, or registry boundary, including when registries share an origin, credential type, resource URI, or discovery cache entry.

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

#### Scenario: AuthID boundary holds on a shared source
- GIVEN two subscribers otherwise resolve to one physical source but carry different AuthIDs
- WHEN a source event arrives and one AuthID no longer resolves to the bound authorization
- THEN that lease terminates and the other lease alone receives the event

### Requirement: Capacity bounds and non-probeable refusal

Live streams MUST be capped process-wide by `MCP_SUBSCRIPTIONS_MAX_STREAMS` (default `128`), per consumer by `MCP_SUBSCRIPTIONS_MAX_PER_CONSUMER` (default `16`), and per principal by `MCP_SUBSCRIPTIONS_MAX_PER_PRINCIPAL` (default `4`). Physical southbound listeners MUST additionally be capped process-wide by `MCP_SUBSCRIPTIONS_MAX_UPSTREAM_LISTENERS` (default `256`) and per canonical origin by `MCP_SUBSCRIPTIONS_MAX_UPSTREAM_PER_ORIGIN` (default `16`). Reuse of an existing equivalent listener MUST remain allowed when listener caps are full; only creation consumes a listener slot. Reaching any stream or required-listener cap MUST refuse the new listen with `-32026` (`CodeSubscriptionRefused`) carrying one constant message and no `data`, byte-identical across which cap was reached, so caps cannot be used as an occupancy oracle. A multi-registry attach MUST be atomic: refusal MUST leave no binding or listener from the failed attach and MUST NOT disturb existing streams. Each northbound stream MUST have a fixed queue of `MCP_SUBSCRIPTIONS_STREAM_QUEUE` entries (default `16`). A full queue MUST terminate that slow stream and MUST NOT drop, replace or coalesce the event or block the shared listener. No southbound SSE event or northbound frame MUST exceed `MCP_SUBSCRIPTIONS_MAX_EVENT_BYTES` (default `8192`); oversize input MUST be rejected before JSON decoding and MUST terminate the listener and its attached leases without truncation. Memory MUST remain bounded.

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

#### Scenario: Equivalent listener reuse is allowed at capacity
- GIVEN the global listener cap is full and a new stream resolves only to an existing complete source key
- WHEN it attaches
- THEN no listener slot is consumed and the stream attaches successfully

#### Scenario: Per-origin cap refuses atomically
- GIVEN one origin has reached its listener cap and a multi-registry stream would require a new listener for that origin
- WHEN attach is attempted
- THEN `-32026` is returned and no partial binding or listener remains

#### Scenario: Slow consumer terminates without loss to healthy consumers
- GIVEN two streams share a listener, one queue is full and the other has capacity
- WHEN another allowed event arrives
- THEN the slow stream terminates, the healthy stream receives the event, the listener never blocks, and no event is silently dropped

### Requirement: Modern-only southbound listen

When `MCP_SUBSCRIPTIONS_UPSTREAM_ENABLED=true`, TrustGate MUST open southbound `subscriptions/listen` only to a registry that negotiates modern protocol `2026-07-28`, supports the listen operation, and explicitly advertises at least one of `tools.listChanged`, `prompts.listChanged`, or `resources.listChanged`. It MUST use the registry's existing credential resolution and modern stateless POST transport and MUST NOT use a legacy cached session, standalone GET SSE, or `Mcp-Session-Id`. A legacy registry, unsupported modern version, absent listen support, or empty trio MUST fail closed and contribute no honoured notification kind. Only the negotiated list-changed trio MAY enter fan-out. `notifications/resources/updated`, task notifications and unknown methods MUST be rejected as protocol failures.

#### Scenario: Legacy fails closed
- GIVEN a role-scoped registry negotiates legacy
- WHEN a northbound subscription is prepared
- THEN no southbound listener is opened through the legacy session and that registry contributes no honoured kind

#### Scenario: Explicit listChanged required
- GIVEN a modern registry advertises tools but omits `tools.listChanged`
- WHEN a client requests `toolsListChanged`
- THEN the registry contributes no tools capability and no tools event from it can be forwarded

#### Scenario: URI and task notifications are rejected
- GIVEN a modern listener emits `notifications/resources/updated`, a task notification, or an unknown method
- WHEN the adapter decodes it
- THEN no northbound event is emitted and the listener terminates as a protocol failure

### Requirement: Complete-key listener pooling

A physical southbound listener MUST be pooled only by equality of canonical registry target and origin, `Target.PinKey`, the fingerprint of final credentialed request headers, negotiated protocol version, and exact list-changed capability set. A difference in any component MUST prevent sharing. The fingerprint MUST be stable for equality but MUST NOT expose raw credentials. Northbound subscriber identity MUST NOT be used to weaken or replace the source key. The last subscriber detaching MUST cancel and join the listener and release its global and per-origin slots; a zero-subscriber listener MUST NOT be retained by an idle TTL.

#### Scenario: Equal complete source identities share
- GIVEN two authorized subscribers resolve to equal target, origin, pin, credential fingerprint, protocol and capability set
- WHEN both attach
- THEN exactly one physical listener exists and each subscriber retains an independent queue and authorization binding

#### Scenario: Credentials are never shared
- GIVEN two targets have the same URL and capabilities but different credential pins or final-header fingerprints
- WHEN both attach
- THEN two physical listeners are opened and no event read under one credential reaches a subscriber bound to the other

#### Scenario: Capability set partitions listeners
- GIVEN the same target and credentials negotiate different list-changed capability sets at different times
- WHEN the change is observed
- THEN the old listener is not reused or mutated and its northbound leases terminate to renegotiate

#### Scenario: Last detach joins listener
- GIVEN one subscriber remains on a listener
- WHEN it disconnects
- THEN the outbound request is cancelled, its goroutine joins, and both listener slots are released

### Requirement: Bounded identity-preserving reconnect

A physical listener MAY reconnect transparently only after a transport close, clean upstream terminal, or `MCP_SUBSCRIPTIONS_UPSTREAM_IDLE_TIMEOUT` (default `60s`). It MUST use context-cancellable jittered exponential backoff between `MCP_SUBSCRIPTIONS_RECONNECT_BACKOFF_MIN` (default `250ms`) and `MCP_SUBSCRIPTIONS_RECONNECT_BACKOFF_MAX` (default `5s`) for no more than `MCP_SUBSCRIPTIONS_RECONNECT_MAX_ATTEMPTS` consecutive attempts (default `3`). Before each retry TrustGate MUST re-resolve credentials and capabilities. It MUST reconnect only when the complete source key and acknowledged trio are unchanged; authentication failure or target, credential, protocol or capability drift MUST terminate all attached northbound leases so clients renegotiate. A valid event resets the consecutive attempt count. Malformed, unknown and oversize events MUST NOT be retried. No event identifier or `Last-Event-ID` MUST be retained or sent.

#### Scenario: Equivalent transient reconnect is transparent
- GIVEN a listener closes transiently and preparation returns the identical complete source identity
- WHEN a retry succeeds within the configured attempt budget
- THEN attached northbound leases remain open and subsequent allowed events are delivered once

#### Scenario: Identity drift terminates instead of migrating
- GIVEN a reconnect preparation resolves changed credentials, protocol or capabilities
- WHEN the listener supervisor compares the source identity
- THEN it opens no replacement under the old lease and terminates all attached leases

#### Scenario: Reconnect budget is finite
- GIVEN repeated transport failures with unchanged identity
- WHEN the maximum consecutive attempts is exhausted
- THEN the listener stops, releases its slots, and all attached leases terminate

#### Scenario: Idle connection is reclaimed
- GIVEN no valid SSE frame or comment arrives before the idle timeout
- WHEN the timer expires
- THEN the request is cancelled and enters the same bounded identity-preserving reconnect path

### Requirement: Deterministic shutdown drain

Server shutdown MUST stop accepting new subscription attachments, cancel every physical southbound listener, terminate and drain every live northbound stream — terminal result then close — and join all listener and stream goroutines before the HTTP router's shutdown budget expires. The multiplexer close MUST run before the northbound drain waits, so an outbound read cannot keep Fiber open. Last detach, client disconnect, deadline, re-authorization refusal, capacity reclaim, reconnect exhaustion and shutdown MUST each use idempotent stop/join paths, and goroutine count MUST return to baseline under `-race`.

#### Scenario: Shutdown completes with live streams
- GIVEN N live streams parked awaiting their next tick
- WHEN the server shuts down
- THEN each receives the terminal result and shutdown completes within its budget rather than hanging

#### Scenario: No goroutine leak on any termination path
- GIVEN streams ended by disconnect, deadline, re-auth refusal, capacity reclaim, and shutdown
- WHEN each path completes
- THEN goroutine count returns to baseline with the race detector enabled

#### Scenario: Shared listeners stop before Fiber drain
- GIVEN live northbound streams are attached to blocked southbound reads
- WHEN server shutdown starts
- THEN every outbound read is cancelled and joined before the router waits for the northbound streams

### Requirement: Bounded subscription telemetry

Subscription telemetry MUST use bounded label sets only — the three notification kinds and fixed lifecycle (`unsupported`, `open_failed`, `opened`, `reused`, `joined`), fan-out (`authorized`, `denied`, `revoked`, `transient`, `rejected`), reconnect (`attempted`, `succeeded`, `failed`, `exhausted`, `source_changed`, `cancelled`, `terminal`), queue (`enqueued`, `full`) and listener-terminal (`last_detach`, `shutdown`, `reconnect_exhausted`, `source_changed`, `authentication`, `protocol_failure`, `transport_failure`) outcomes — plus up/down counters for live northbound streams and physical southbound listeners. Physical listener live accounting MUST increment only when the supervisor starts and decrement when it joins; unsupported preparation and failed open MUST never increment it. A stream MUST report its true duration at close rather than the near-zero latency observed when the handler chain unwinds, and the metrics middleware MUST NOT read the response body of a live stream. No metric, span, or log MUST contain a resource URI, notification payload, event/request/subscription id, gateway/consumer/principal/AuthID/registry identifier, token, credential, pin/fingerprint, target, origin, pool key, consumer slug, or tenant-identifying free text.

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

#### Scenario: Source metrics reveal no pool identity
- GIVEN listeners are reused, partitioned by credentials, reconnected and terminated
- WHEN source telemetry and logs are inspected
- THEN values contain only fixed outcomes, counts and durations and reveal no target, origin, credential fingerprint or subscriber identifier

#### Scenario: Physical listener gauge follows join ownership
- GIVEN unsupported preparation, failed open, last detach, reconnect exhaustion and shutdown
- WHEN each path completes
- THEN unsupported preparation and failed open never increment the physical-listener gauge, and every started supervisor decrements it exactly once on join so the gauge returns to zero
