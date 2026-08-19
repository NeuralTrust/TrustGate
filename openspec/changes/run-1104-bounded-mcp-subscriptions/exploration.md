# Exploration: RUN-1104 add bounded MCP subscriptions

**Change**: `run-1104-bounded-mcp-subscriptions`
**Linear**: [RUN-1104](https://linear.app/neuraltrust/issue/RUN-1104) — epic [RUN-1100](https://linear.app/neuraltrust/issue/RUN-1100) "TrustGate MCP 2026-07-28 dual-era"
**Workspace**: `/Users/edu/Neuraltrust/TrustGate-run-1104-upstream`
**Slice 1 branch**: `feat/run-1104-bounded-mcp-subscriptions` / PR #464
**Slice 2 branch**: `feat/run-1104-upstream-subscription-multiplex`
**Slice 2 base**: `feat/run-1104-bounded-mcp-subscriptions`
**Depends on**: RUN-1103 (dual-era boundary), RUN-1102 (tasks — landed on this base), RUN-1108 (upstream negotiation), RUN-1109 (telemetry)

## Contract (source of truth)

SEP-2575 "Stateless MCP", protocol version `2026-07-28`. Read from the vendored SDK's own
normative summary: `go-sdk@v1.7.0/docs/protocol.md` §"Subscriptions (`subscriptions/listen`)"
and `internal/docs/protocol.src.md:104-118`.

| Item | Contract |
|---|---|
| Purpose | `subscriptions/listen` **replaces** both the legacy `resources/subscribe` RPC and the standalone GET SSE endpoint with one long-lived request that multiplexes every server→client change notification the client opted in to |
| Transport shape | One JSON-RPC **call** (has an `id`) over `POST`. The response is **always** `text/event-stream`, never buffered `application/json` — the SDK forces SSE for this method precisely because there is no synchronous result to wait for (`mcp/streamable.go:1650-1655`: `useSSE := !c.jsonResponse \|\| isSubscriptionsListen`). Client `Accept` must contain **both** `application/json` and `text/event-stream` (`mcp/streamable.go:393-396`) |
| Negotiation (request) | `params.notifications` is **required** and is an explicit opt-in per type: `toolsListChanged`, `promptsListChanged`, `resourcesListChanged`, `resourceSubscriptions: []string` (resource URIs). A missing `notifications` object is `ErrInvalidParams` / `-32602` (`mcp/server.go:1193-1195`) |
| Negotiation (server) | The server honours only the **subset** its own advertised capabilities allow (`Tools.ListChanged`, `Prompts.ListChanged`, `Resources.ListChanged`, `Resources.Subscribe` — `allowedSubscriptions`, `mcp/server.go:1254-1270`) and MUST NOT push a type the client did not request |
| First message | `notifications/subscriptions/acknowledged` carrying the honoured subset, sent **before** anything else on the stream (`mcp/server.go:1241`) |
| Multiplexing | Every notification carries `_meta["io.modelcontextprotocol/subscriptionId"]` = the listen call's JSON-RPC request id, so a client with several concurrent listens can demultiplex (`injectMetaSubscriptionID`, `mcp/server.go:790`) |
| Notification set | `notifications/tools/list_changed`, `notifications/prompts/list_changed`, `notifications/resources/list_changed`, `notifications/resources/updated` |
| Termination | Graceful teardown sends the `SubscriptionsListenResult` (the JSON-RPC response for the listen id) as the **last** frame, itself carrying the subscription id. An abrupt transport close carries no response. Client-side cancellation is `notifications/cancelled` referencing the listen id, or simply dropping the connection |
| Lifetime | If nothing was honoured the server returns immediately; otherwise it blocks on `<-ctx.Done()` (`mcp/server.go:1246-1249`). The HTTP request's lifetime **is** the cancellation signal — the SDK sets `shouldPropagateCancellation: info.usesNewProtocol && info.isSubscriptionsListen` unconditionally for listen (`mcp/streamable.go:431`) |
| Statelessness | Modern-era streamable HTTP requires `Stateless: true` in the SDK server; `Mcp-Session-Id` is not used. GET and DELETE are 405 |

**Deprecated and explicitly out of scope:** the standalone HTTP+SSE transport and the
GET SSE channel. TrustGate already answers `405` with `Allow: POST` on `GET`/`DELETE`
(`pkg/server/router/mcp_router.go:104-105`) and that must not change.

## go-sdk v1.7.0: what exists vs what we must hand-roll

Unlike RUN-1102 (where the SDK shipped **no** Tasks types at all), v1.7.0 has a complete
`subscriptions/listen` implementation — but almost all of the useful surface is **unexported**
and reachable only through the SDK's own `mcp.Server` + `mcp.StreamableHTTPHandler`, which
TrustGate does not use northbound.

**Exported and directly reusable (wire types only):**

| Symbol | File | Shape |
|---|---|---|
| `mcp.SubscriptionsListenParams` | `mcp/protocol.go:2086` | `{Meta, Notifications *NotificationSubscriptions}` |
| `mcp.NotificationSubscriptions` | `mcp/protocol.go:2071` | `ToolsListChanged`, `PromptsListChanged`, `ResourcesListChanged bool`; `ResourceSubscriptions []string` |
| `mcp.SubscriptionsAcknowledgedParams` | `mcp/protocol.go:2102` | `{Meta, Notifications NotificationSubscriptions}` |
| `mcp.SubscriptionsListenResult` | `mcp/protocol.go:2115` | `{completeResultWithType, Meta}` — note the embedded `resultType` |
| `mcp.MetaKeySubscriptionID` | `mcp/protocol.go:2379` | `"io.modelcontextprotocol/subscriptionId"` |
| `mcp.ResourceUpdatedNotificationParams` | `mcp/protocol.go` | `{Meta, URI}` |
| `mcp.DefaultMaxRequestBodyBytes` | `mcp/streamable.go:225` | `4 << 20` — already TrustGate's southbound body cap (`modern_upstream.go:41`) |

**Unexported — must be hand-rolled:**

| Missing | SDK location | Consequence |
|---|---|---|
| `methodSubscriptionsListen = "subscriptions/listen"` | `mcp/protocol.go:2350` | TrustGate needs its own method constants (as it already does in `pkg/app/mcp/tasks.go`) |
| `notificationSubscriptionsAck` (`:2353`) and the four `notifications/*/list_changed` / `resources/updated` constants | `mcp/protocol.go:2340-2355` | same |
| `(*Server).subscriptionsListen`, `allowedSubscriptions`, `notifySubscribedSessions`, `injectMetaSubscriptionID` | `mcp/server.go:1187`, `:1254`, `:768`, `:790` | the entire server-side hub is private to `mcp.Server`, keyed on its own `map[*ServerSession]jsonrpc.ID` subscription maps |
| `stream.isListen`, the forced-SSE branch, `propagateCancellation` | `mcp/streamable.go:997`, `:1643-1655`, `:934` | the northbound SSE framing has to be written on Fiber |
| `(*ClientSession).subscriptionsListen`, `callSubscriptionsListen` | `mcp/client.go:1451`, `mcp/transport.go:260` | southbound: only `Subscribe`/`Unsubscribe` are exported (`client.go:1375`, `:1415`) and they cover **only** `resourceSubscriptions`, one URI per background goroutine. There is **no** exported way to open a listen for `toolsListChanged`/`promptsListChanged`/`resourcesListChanged` |

**Consequence.** Northbound we hand-roll the transport and the fan-out on Fiber, reusing the
SDK's exported params/result/ack types so the wire shape is not re-invented. Southbound, if we
listen at all, we hand-roll too: `modernUpstream` never touches `mcp.ClientSession` — it
hand-builds JSON-RPC over `sdk.StreamableClientTransport` (`modern_upstream.go:554-594`).

## Current State

TrustGate is a **stateless, POST-only** MCP gateway. One `POST /{consumer_slug}/mcp` equals one
complete policy pass, and nothing survives between POSTs:

```
auth middleware (mcp_auth.go)     → gateway + consumer Data + Principal on ctx
classifyEra (protocol_era.go)     → legacy | modern(2026-07-28)
validateModernRequest             → _meta, header mirroring, Mcp-Name binding
resolveMCPConsumer + MatchPath    → RoutableConsumer
denyModernIfLegacyOnly            → protocol_acceptance gate
scopeByRoles (role_scope.go)      → role-scoped registry/toolkit view
RPCGateway.Dispatch               → rate limit → plugins PreRequest
composer.compose                  → per-registry discovery (TTL cache + singleflight)
                                  → toolkit/allowlist filter, name collision resolution
credentials.target + creds.Apply  → per-request credential resolution
dialer.Connect                    → legacy (cached session, 30m idle TTL) | modern (stateless)
                                  → plugins PreResponse → normalizeModernResult
```

`subscriptions/listen` is **not** in `isSupportedModernMethod` (`mcp_handler.go:619-639`), so today
a modern client gets HTTP 404 `-32601`. `configuredCapabilities` (`server_discover.go:53-84`) emits
`tools`/`prompts`/`resources` as `{}` (or `{"inputRequests":{}}` for MRTR) with **no** `listChanged`
and **no** `subscribe` sub-capability — so a spec-compliant client would correctly conclude that
nothing is subscribable, and the SDK's `allowedSubscriptions` gate would honour an empty subset.

### What is missing

| Layer | Today | Subscriptions gap |
|---|---|---|
| `mcp_router.go:108` | `app.Post("/*", h.Handle)` — one handler, one buffered JSON response | needs a streaming response path; `GET`/`DELETE` 405 registered **before** `authTransport` must stay untouched |
| `mcp_handler.go` `Handle` | always ends in `writeJSON`/`writeRPCResult` (buffered `c.Status(...).JSON(...)`) | a listen must take a `SetBodyStreamWriter` branch that never returns a buffered body |
| `mcp_handler.go` `isSupportedModernMethod` | 11 methods, no `subscriptions/listen` | 404 `-32601` today |
| `modern_validation.go` | no `Accept` inspection; `Mcp-Name` bound for `tools/call`/`prompts/get`/`resources/read`/`tasks/*` | must require `Accept: text/event-stream` (+`application/json`), reject `Mcp-Name` on listen, and validate/bound `params.notifications` |
| `modern_response.go` `normalizeModernResult` | stamps `_meta.serverInfo`, `resultType`, `ttlMs`, `cacheScope` on a `map[string]any` | the ack notification and each streamed notification are **not** results; the terminal `SubscriptionsListenResult` is. Needs a separate framing path — reusing `normalizeModernResult` would inject `ttlMs`/`cacheScope` into a notification |
| `server_discover.go` `configuredCapabilities` | `tools: {}`, `prompts: {}`, `resources: {}` | needs `listChanged: true` / `subscribe: true` sub-capabilities, gated end-to-end exactly like `mrtrEndToEnd`/`tasksEndToEnd` (`server_discover.go:86-98`) |
| `rpc_dispatcher.go` `Dispatch`/`dispatch` | returns `(any, error)` — a single value | a stream is not a value; either a new entry point or a channel/iterator-returning port |
| `mcp_metrics.go` `buildResponseContext` | `Body: c.Response().Body()`, `Streaming: false` hardcoded | reading `Body()` on a stream forces fasthttp to drain it into memory (the exact trap `access_log.go:44-52` documents). The proxy plane solved this with `infracontext.StreamMetricsFinalizer` (`metrics.go:70,86-100`; consumed in `proxy_handler.go:152-204`) — the MCP metrics middleware has no equivalent |
| `ops_metrics.go` | `Duration: time.Since(start)` measured after `c.Next()` | with `SetBodyStreamWriter` the handler chain unwinds immediately, so a 30-minute stream records ~0 ms latency |
| `pkg/app/mcp/composer.go` `Composer` | 11 synchronous use cases | no subscription use case, no notification port |
| `pkg/app/mcp/protocol.go` `Upstream` / `TaskUpstream` | request/response only | no `SubscriptionUpstream` port |
| `pkg/app/mcp/mrtr_caps.go` | allowlists `elicitation`, `sampling`, `roots`, `extensions{tasks}` | if subscriptions are negotiated through client capabilities they must join the bounded allowlist |
| `pkg/infra/mcp/client/modern_upstream.go` | `exchange` returns on the **first** `*jsonrpc.Response` (`:615-622`); `maxModernResponseMessages = 100`; `boundedModernResponseBody` caps cumulative bytes at 4 MiB (`:41,152-189`); `MaxRetries: -1` disables SDK reconnect | none of this can carry a long-lived stream; a southbound listen needs its own read loop with its own bounds |
| `pkg/infra/mcp/client/probe.go:495-499` | decodes `capabilities` from `server/discover` and **throws it away** | TrustGate has no persisted knowledge of a modern upstream's `listChanged`/`subscribe` capabilities |
| `pkg/infra/mcp/client/negotiating_dialer.go:203` | `auto` mode returns `guardedUpstream`, which does **not** implement `TaskUpstream` | the same wrapper will silently swallow any new `SubscriptionUpstream` port unless it forwards it — this is a live latent gap for tasks today |
| `pkg/infra/mcp/client/cached_dialer.go:35` | legacy sessions cached per pin key, 30 min idle TTL, `evictIdleLocked` closes on the next `lookup` | a legacy-era subscription would sit on a session that can be evicted underneath it |
| `pkg/infra/trace/span.go:128-157` | bounded `TaskOperation`/`TaskOutcome` enums | no subscription enums |
| `protocol_metrics.go` | `NewProtocolValidationRecorder`, `NewMRTRRecorder`, `NewTasksRecorder` | no subscription recorder |
| `pkg/config/config.go:240-246` | `MCPTasksConfig` (secret, TTL, poll floor, max bytes) | no `MCPSubscriptionsConfig` |
| `pkg/server/server.go:46-48` | Fiber `WriteTimeout` / `IdleTimeout` from `SERVER_WRITE_TIMEOUT` (default **60 s**) / `SERVER_IDLE_TIMEOUT` (120 s) | a long-lived response must survive these, or the feature is capped at 60 s |

## Affected areas

**Northbound transport (`pkg/api/handler/http/mcp/`)**

- `subscriptions_listen.go` *(new)* — the streaming handler: `SetBodyStreamWriter`, SSE frame writer, ack-first ordering, keepalive, terminal `SubscriptionsListenResult`, per-connection accounting
- `subscription_validation.go` *(new)* — `Accept` negotiation, `params.notifications` shape + cardinality bounds (max `resourceSubscriptions` entries, max URI length), reject `Mcp-Name`/`Mcp-Param-*`
- `mcp_handler.go` — `isSupportedModernMethod` gains `subscriptions/listen`; `Handle` branches to the streaming path **after** the full policy prologue; `SubscriptionsSupport` struct + constructor mirroring `TasksSupport` (`:71-81`)
- `modern_validation.go` — `Accept` header plumbed into `modernRequestHeaders`; listen excluded from the `Mcp-Name` source-field switch (`:106-131`)
- `modern_response.go` — a notification/ack framing path that does **not** go through `normalizeModernResult`; the terminal result does
- `server_discover.go` — `listChanged`/`subscribe` sub-capabilities under a `subscriptionsEndToEnd(...)` gate
- `rpc_dispatcher.go` — a `DispatchSubscription` entry point returning a notification stream + cleanup, with its own span
- `protocol_metrics.go` — `SubscriptionsRecorder` (bounded), and a gauge/updown-counter for live streams

**Application core (`pkg/app/mcp/`)**

- `subscriptions.go` *(new)* — domain vocabulary: `NotificationKind`, prepared source identity,
  complete subscriber identity and handle contracts
- `subscription_multiplexer.go` *(slice 2)* — complete-key physical-listener pool, independent
  per-stream queues, terminate-on-overflow fan-out and explicit start/stop/join lifecycle
- `subscription_policy.go` *(new)* — periodic and per-event re-authorization, including AuthID,
  registry and stable source-binding checks
- `subscription_targets.go` *(slice 2)* — resolve role-scoped registries through existing target and
  credential paths
- `composer.go` — `Composer` gains the subscription use case; regenerate `mocks/mcp_composer_mock.go` (`//go:generate mockery`, `:33`)
- `protocol.go` — dedicated `SubscriptionConnector` port; the request/response `Upstream` remains unchanged
- `mrtr_caps.go` — extend the bounded allowlist if subscriptions are declared as a client capability
- `errors.go` — subscription sentinels + codes; `-32003`/`-32021`/`-32025` are taken (`:40-54`), so pick fresh

**Southbound (`pkg/infra/mcp/client/`)**

- `modern_subscriptions.go` *(slice 2)* — modern-only prepare/listen adapter with independent byte,
  idle and reconnect classification, separate from `exchange` and `boundedModernResponseBody`
- `modern_subscription_sse.go` *(slice 2)* — incremental bounded SSE parser and trio allowlist
- `probe.go` — retain typed explicit `listChanged` capabilities currently discarded (`:495-499`)
- `negotiating_dialer.go` — prepare subscriptions only after modern negotiation; legacy fails closed
- legacy `Session` — unchanged; it never implements the connector port

**Cross-cutting**

- `pkg/server/router/mcp_router.go` — no new route (still `POST /*`), but the streaming branch must be reachable and the `GET`/`DELETE` 405 registrations must be provably unchanged
- `pkg/api/middleware/mcp_metrics.go` — a `StreamMetricsFinalizer` equivalent so `buildResponseContext` never drains a live stream
- `pkg/api/middleware/ops_metrics.go` — decide how a stream reports latency, or exclude it
- `pkg/infra/trace/span.go` — bounded `SubscriptionKind` / `SubscriptionOutcome` labels
- `pkg/config/config.go` + `pkg/container/modules/mcp.go` + `server_mcp.go` — `MCPSubscriptionsConfig`, hub provider, recorder wiring, graceful-shutdown hook
- `openspec/changes/run-1104-.../specs/mcp-dual-era-northbound/spec.md` *(delta)* and `.../mcp-subscriptions/spec.md` *(new domain)*
- `docs/mcp/subscriptions.md` *(new)*, `docs/operational-metrics.md`, `docs/mcp/dual-era-rollout.md`

**Unchanged by design:** legacy `initialize` capabilities, MRTR ticket and task handle wire formats,
registry `protocol_mode` semantics, `GET`/`DELETE` → 405, standalone SSE (stays disabled).

## The hard problem: a long-lived stream inside a per-request policy model

Every authorization input TrustGate uses is bound to the **request**, not to a session:

| Input | Where it lives | Lifetime today |
|---|---|---|
| Principal (issuer/subject, raw token) | `identitydomain.WithPrincipal` set in `mcp_auth.go:88-90` | one request |
| Consumer `Data` snapshot (registries, toolkit, fail mode, protocol acceptance) | `dataFinder.FindByGateway` per request (`mcp_auth.go:71`) | one request |
| Role scope | `roleScoper.Scope(ctx, rc, data)` per request (`mcp_handler.go:741`) | one request |
| Rate limit budget | `limiter.Check(ctx, GatewayID)` once per dispatch (`rpc_dispatcher.go:183-207`) | one request |
| Plugin verdicts | `PreRequest`/`PreResponse` per payload | one payload |
| Upstream credentials | `c.target(...)` → `creds.Apply()` per dial (`credentials.go`) | one dial |
| Composed surface | `compose()` behind a TTL cache + singleflight (`discovery.go:179-217`) | cache TTL |

A `subscriptions/listen` stream that lives for minutes or hours therefore has **no** natural
re-evaluation point. Concretely:

1. **Authentication.** The bearer token was verified once, at stream open. If it expires mid-stream
   nothing notices. A stream must carry its own **authorization deadline** — at minimum the
   principal's token expiry — and terminate at it, forcing the client to re-open with a fresh token.
2. **Authorization / surface.** Emitting `tools/list_changed` is nearly harmless (it says "re-list"),
   but `resources/updated` for URI *X* asserts *this principal may know that X changed*. That is a
   live authorization decision and must be re-taken **on every emission**, not at open: re-`compose()`
   (cheap — TTL cache + singleflight already absorb bursts) and confirm the URI is still allowed by
   `toolkit.AllowsResource(reg.ID, uri)` and that the registry is still attached via `mcpRegistries(rc)`.
   This is the same assertion `composer_tasks.go:228-252` (`boundBinding`) already makes per task poll.
3. **Authorization change mid-stream.** Toolkit edited, registry detached, role revoked, consumer
   switched to `protocol_acceptance=legacy_only`, or the principal's grant withdrawn. The
   fail-closed answer is to **terminate the stream**, not to silently narrow it: a client that keeps
   receiving *some* notifications cannot distinguish "nothing changed" from "you lost access". Send
   the terminal `SubscriptionsListenResult` (graceful) and let the client re-open, where the normal
   prologue will refuse it. Termination must be indistinguishable across causes, exactly like
   `TaskHandleRejectedMessage` (`errors.go:56-59`).
4. **Rate limits.** One `Check` at open buys an unbounded number of pushes. Notifications are
   generated by config/upstream change, not by the client, so metering the *client* is the wrong
   axis; metering **concurrent streams** per consumer/principal and the **emission rate** per stream
   is the right one. A stream must also not hold a token bucket slot open for its whole life.
5. **Plugins.** `notifications/*/list_changed` carry no payload — nothing to scan. `resources/updated`
   carries a `uri`, which is upstream-controlled free text. Either bound and validate it against the
   composed surface (recommended) or run it through the request stage; letting an arbitrary upstream
   string reach the client unchecked is the same class of hole that the existing upstream-value scrubs
   close — `normalizeModernResult` refuses to let an upstream own `resultType`/`ttlMs`
   (`modern_response.go:57-101`) and `echoHandle` replaces any upstream-returned task handle with
   TrustGate's own (`composer_tasks.go:150-163`).
6. **Graceful shutdown.** `httpServer.Shutdown()` calls Fiber's `Router.Shutdown()`
   (`pkg/server/http_server.go:50-56`), which waits for in-flight requests. A stream blocked on
   `ctx.Done()` is in-flight **forever** — shutdown would hang. The hub
   needs an explicit close hook that drains every stream (terminal result, then close) before the
   Fiber shutdown is allowed to complete.

**The design consequence:** a stream is not a session. It is a *bounded, periodically re-authorized
lease* over a policy decision that was taken at open, with a hard ceiling on its own lifetime.

## Isolation analysis

An event must never cross a consumer, a principal, or a registry. The identities are all already
carried in the request; the work is keying on all of them.

| Dimension | Where it exists today | Why it must be in the key |
|---|---|---|
| Gateway | `identity.GatewayID` (`mcp_auth.go:81`), `rc.Consumer.GatewayID` | multi-tenant boundary; the task handle already binds it (`TaskHandleClaims.GID`) |
| Consumer | `rc.Consumer.ID`, resolved by `data.MatchPath(c.Path())` (`mcp_handler.go:760`) | two consumers on the same gateway expose different surfaces |
| Principal | `sha256(issuer\|subject)` via `principalFingerprint(ctx)` (`task_handle.go:153-160`) | role scoping and per-principal credentials differ; `discoveryKey` already partitions the discovery cache by the truncated digest (`discovery.go:265-277`) |
| Registry | `reg.ID` from `mcpRegistries(rc)` | a notification from registry A must not be delivered to a consumer that does not bind A |
| Role scope | applied by `roleScoper.Scope` before dispatch | two principals on one consumer can see disjoint primitive kinds (`server_discover_test.go` covers this for discover) |
| Subscription instance | the listen call's JSON-RPC id → `_meta[MetaKeySubscriptionID]` | a single client may hold several concurrent listens; the SDK stamps this and the client demultiplexes on it |

So the isolation key is `{gatewayID, consumerID, principalFingerprint, roleScopeFingerprint}` for the
**subscriber**, and `{registryID, notificationKind, uri?}` for the **event**, with delivery gated by a
fresh `compose()` at emission time. Note the existing `surfaceFingerprint(rc)` helper
(`mcp_handler.go:503-528`) already digests registries + toolkit into a bounded hex string — it is the
natural building block for "did this consumer's surface change", both for role-scope keying and for
*detecting* a `list_changed` condition.

**Two concrete leak traps found in the current code:**

- **Resource URIs are not namespaced.** Tool names get collision-resolved with a registry prefix
  (`resolveExposedNames` + `registryPrefix`, `naming.go:43-85`), but `ListResources` passes upstream
  URIs through verbatim (`composer_resources.go:27-46`) and `ReadResource` searches registries in order
  for the first match (`:63-111`). Two registries can therefore expose the **same** URI. A
  `resources/updated` for that URI
  is ambiguous about its origin, and delivering it tells the client that *some* registry changed —
  potentially one it is not the origin of. Either namespace subscribed URIs per registry or restrict
  `resourceSubscriptions` to URIs that resolve to exactly one attached registry.
- **The discovery cache is shared per registry** unless the registry uses per-principal auth
  (`discoveryKey` returns a principal-free key when `!perPrincipalAuth(reg)`, `discovery.go:265-277`).
  That is correct for *reads* — the toolkit filter runs after — but a fan-out hub keyed on the cache
  key rather than on the subscriber identity would inherit the sharing and leak across principals.

## Approaches

1. **Per-request stream tied to the HTTP request lifecycle, gateway-side notifications only (chosen for PR #464)**
   The listen handler runs the normal policy prologue, then takes a `SetBodyStreamWriter` branch. A
   single goroutine per stream — the fasthttp body-stream writer itself — owns the whole lifecycle:
   write the ack, then loop on `select { ctx.Done() | ticker | notification }`. Notifications are
   **derived by TrustGate from its own composed surface** (re-`compose()` on a tick, compare
   `surfaceFingerprint`), not relayed from upstream listens. Scope: `toolsListChanged`,
   `promptsListChanged`, `resourcesListChanged`. `resourceSubscriptions` is **not honoured** in this
   slice — advertised as not supported, and refused in the ack per the spec's "honoured subset" rule.
   - Pros: zero new long-lived southbound connections, so no interaction at all with the 4 MiB
     `boundedModernResponseBody`, `maxModernResponseMessages`, the legacy 30-minute session cache, or
     the `guardedUpstream` port gap. Goroutine count is exactly one per HTTP connection, which the
     web server already bounds (`Concurrency: 16384`, `MaxConnsPerIP: 1024`). Cancellation is
     structurally correct — the writer returns when the socket dies. Re-authorization is a natural
     tick, reusing `compose()` + the TTL cache + singleflight. Nothing is buffered, so backpressure
     is the socket's, and a slow consumer stalls only its own `w.Flush()`. Reuses the proxy plane's
     proven `SetBodyStreamWriter` + `StreamMetricsFinalizer` pattern (`proxy_handler.go:152-204`).
     Fully testable with `httptest`/Fiber `app.Test` plus `-race` and a goroutine-leak assertion.
   - Cons: notifications are polling-derived, so latency is the tick interval, not upstream-real-time.
     No `resources/updated`. Duplicated re-composition work across concurrent streams of the same
     consumer (mitigated by the singleflight, but the tick multiplies cache reads).
   - Effort: Medium

2. **Gateway-side fan-out hub with bounded modern southbound listens (chosen for slice 2 after refinement)**
   A hub in `pkg/app/mcp` keyed by the isolation key. Each `(registry, principal-class)` gets a
   southbound `subscriptions/listen` goroutine; the hub multiplexes upstream events to northbound
   subscribers through bounded per-subscriber channels.
   - Pros: real-time list-changed events; one upstream connection amortised across
     subscribers; the natural end state.
   - Cons: this is where every risk in the ticket concentrates. Goroutine count becomes
     `O(streams + registries × principal-classes)` with two independent lifecycles to join. Requires
     a new southbound long-lived read loop that bypasses `exchange`'s single-response contract,
     `boundedModernResponseBody`'s 4 MiB cap, and `MaxRetries: -1`; needs its own reconnect with
     backoff, its own idle timeout, and its own credential-refresh story (per-principal auth modes
     need a live token that may expire mid-listen). Fan-out is exactly where a keying mistake leaks
     across principals. `guardedUpstream` must be taught the new port or `auto`-mode registries
     silently never subscribe — the same latent bug tasks already has. Legacy registries with cached
     30-minute sessions add a third lifecycle.
   - Effort: High
3. **Delegate multiplexing to the SDK server (`mcp.Server` + `mcp.StreamableHTTPHandler{Stateless:true}`)**
   Stand up an SDK `Server` per consumer surface and let `subscriptionsListen`, `allowedSubscriptions`,
   `notifySubscribedSessions`, and `injectMetaSubscriptionID` do the work.
   - Pros: the spec-conformant implementation for free, including ack ordering, `subscriptionId`
     stamping, capability gating, and teardown; maintained upstream.
   - Cons: architecturally unshippable here. TrustGate's northbound is a Fiber/fasthttp handler with a
     hand-rolled dual-era boundary; the SDK handler is `net/http` and owns request parsing, era
     detection, error codes, and the `_meta` contract that RUN-1103 deliberately implemented itself.
     Adopting it means either mounting `net/http` inside Fiber (losing the middleware chain that
     supplies auth, consumer resolution, trace, and ops metrics) or reimplementing the boundary twice.
     The SDK `Server` is also a *feature registry* (`s.tools`, `s.resources`) — TrustGate's surface is
     computed per request from the consumer's toolkit and federated registries, and there is no
     per-request hook to swap it. The pieces we would want are all unexported, so we cannot borrow the
     hub without the server. Blast radius: the entire northbound.
   - Effort: Very High, and rejected

4. **Accept `subscriptions/listen`, honour nothing (empty ack, immediate result)**
   Implement the transport, advertise no subscribable capability, always ack an empty subset and return
   at once — which is precisely what the spec prescribes when nothing is honoured
   (`mcp/server.go:1245-1249`).
   - Pros: tiny; strictly conformant; removes the 404 that makes conformance suites fail; zero
     long-lived state, zero leak surface.
   - Cons: delivers no value against the ticket's scope (no negotiation to speak of, no multiplexing,
     no backpressure story to test). Useful only as **slice 1** of a chain, not as the change.
   - Effort: Low

| | 1. Request-lifetime stream | 2. Fan-out hub + southbound | 3. SDK server | 4. Empty-ack only |
|---|---|---|---|---|
| Complexity | Medium | High | Very High | Low |
| Blast radius | northbound handler + metrics middleware | + whole southbound client + dialer | entire northbound | northbound handler |
| Leak risk | Low — one stream, one identity, re-checked per emit | **High** — shared upstream listens, cross-principal fan-out | Medium — SDK keys on its own sessions, not ours | None |
| Resource bounds | inherited from the HTTP server + explicit caps | must be invented at 3 levels (northbound, hub, southbound) | SDK's, not ours to tune | trivial |
| Goroutine lifecycle | 1 per connection, dies with the socket | 2 independent trees to join | SDK-owned | none |
| Testability | High (`app.Test` + `-race` + leak check) | Low — needs fake upstreams, timing, reconnect matrices | Low — hard to reach through Fiber | High |
| Real-time `resources/updated` | No | Yes | Yes | No |

## Slice 1 recommendation

**Approach 1, structured so Approach 2 remains reachable later without a wire break.** This is the
foundation implemented by PR #464, not the final RUN-1104 scope.

The reasoning is the ticket's own security framing. Every item on the QA checklist — cancellation,
race/leak coverage, isolation, bounded memory, disabled SSE, unadvertised types — is *cheap* when a
stream is one goroutine bound to one HTTP request carrying one identity, and *expensive* when it is a
shared hub. And the ticket explicitly permits it: *"Supporting notification types that TrustGate cannot
safely mediate"* is out of scope, and `resources/updated` sourced from a shared upstream listen is,
today, exactly that — the resource URI namespace is not registry-namespaced
(`composer_resources.go:27-46`), the discovery cache is principal-shared for non-per-principal
registries (`discovery.go:265-277`), and `guardedUpstream` would silently drop the port
(`negotiating_dialer.go:203`). Advertising it would be promising mediation we cannot yet prove.

Concretely:

1. **Method and transport.** Add `subscriptions/listen` to `isSupportedModernMethod`. Require
   `Accept` to contain both `text/event-stream` and `application/json`, matching what the SDK client
   sends and the SDK server enforces; refuse otherwise at the boundary with `-32020`, before any
   policy effect (RUN-1103's `Validation isolation` requirement). Reject `Mcp-Name` and `Mcp-Param-*`.
   The response is `text/event-stream` + `Cache-Control: no-cache, no-transform` + `X-Accel-Buffering: no`,
   written through `SetBodyStreamWriter` exactly as `proxy_handler.go:164` does. Never emit
   `Mcp-Session-Id`.
2. **Negotiation, honoured-subset semantics.** Parse `params.notifications` into
   `sdk.NotificationSubscriptions`; a missing object is `-32602`. Intersect with what TrustGate
   advertises **for this consumer's role-scoped surface**: a prompts-only consumer never gets
   `toolsListChanged` — the same reasoning `addTasksExtension` already applies
   (`server_discover.go:37-51`). Emit `notifications/subscriptions/acknowledged` with the honoured
   subset as the **first** frame, stamping `_meta["io.modelcontextprotocol/subscriptionId"]` with the
   listen id. If the honoured subset is empty, ack and return the terminal result immediately.
3. **Discovery.** Add `listChanged: true` to the advertised `tools`/`prompts`/`resources` capability
   objects (preserving MRTR's `inputRequests` merge) under a `subscriptionsEndToEnd(rc)` gate — the
   feature flag plus a bound MCP registry, decided locally, never dialling. `resources.subscribe`
   stays **absent**, which is how "unsupported types are not advertised" is satisfied by construction.
   Legacy `initialize` capabilities stay byte-identical.
4. **Change detection.** On a tick, re-run the full authorization pass (re-resolve `Data`,
   role-scope, `compose()`) and compare a per-kind fingerprint derived the way
   `surfaceFingerprint` already derives one (`mcp_handler.go:503-528`). A changed fingerprint emits
   the corresponding `list_changed`; nothing else is ever emitted. This makes every notification the
   product of a fresh authorization decision, which is the whole point.
5. **Termination, one shape for every cause.** Cancellation (`ctx.Done()` from client disconnect or
   `notifications/cancelled`), the configured idle/max-lifetime ceiling, the principal's token expiry,
   a re-authorization refusal, and server shutdown all end the same way: terminal
   `SubscriptionsListenResult`, then close. No cause is distinguishable from the wire, and no partial
   narrowing is ever served.
6. **Shutdown.** Register the hub's drain with the MCP server's shutdown path so
   `Router.Shutdown()` cannot block on streams parked in `ctx.Done()`.
7. **Metrics middleware.** Give the MCP plane the proxy plane's `StreamMetricsFinalizer` treatment so
   `buildResponseContext` never calls `Response().Body()` on a live stream, and decide explicitly how
   `ops_metrics` reports a stream's latency (own route class, or excluded).
8. **Telemetry.** Bounded `mcp.northbound.subscriptions.outcome_total{kind, outcome, era}` plus a live-stream
   up/down counter. Never record a URI, a notification payload, a subscription id, a principal, or a
   tenant name.
9. **Forward compatibility.** Keep the northbound notification type and the hub interface free of any
   assumption that events are gateway-derived, so RUN-1104's successor can plug a southbound source in
   behind the same port without changing the wire contract or the isolation key.

Reject 3 outright. Fold 4 into the northbound chain. The user subsequently chose to complete the
ticket's full scope in a second stacked slice by implementing a constrained form of Approach 2.
Resource URI namespacing is not a prerequisite because slice 2 explicitly excludes
`resourceSubscriptions` and `notifications/resources/updated`.

## Slice 2 decision: authorized complete-key multiplexing

The second slice retains PR #464 unchanged as the flag-off fallback and adds modern southbound
`subscriptions/listen` for the explicit tools/prompts/resources `listChanged` trio. It addresses the
original Approach 2 risks with narrower contracts:

1. **Dedicated app port.** A `SubscriptionConnector` prepares an immutable, non-secret source
   identity and opens a listener. It does not extend the request/response `Upstream` contract and
   cannot be implemented by legacy sessions.
2. **Complete source key.** Pool only when canonical target/origin, credential pin and final-header
   fingerprint, modern protocol version and exact capability bitset all match. Never pool across
   credentials.
3. **Independent recipient bindings.** Every northbound subscriber retains gateway, consumer,
   principal, AuthID, registry and role-scope identity and is re-authorized before fan-out.
4. **Narrow notification set.** Retain explicit upstream `listChanged` capability booleans and reject
   URI updates, task notifications and unknown methods.
5. **Three levels of bounds.** Keep PR #464 stream caps; add global/per-origin physical-listener caps,
   one fixed queue per northbound stream, the existing max-event bound and a southbound idle timeout.
6. **No silent loss.** A full queue terminates the slow northbound lease; it never drops, overwrites
   or coalesces an event and never blocks the shared listener.
7. **Identity-preserving reconnect.** Retry transient close/idle only within a finite jittered budget
   and only after preparation returns the identical source key and capabilities. Auth or capability
   drift terminates all attached leases to renegotiate.
8. **Owned lifecycle.** The composition-root multiplexer owns root cancellation and join for every
   listener. Last detach cancels and joins; server shutdown closes the multiplexer before Fiber
   drains northbound streams.

This refinement keeps Approach 2's multiplexing benefit while removing its unsafe origin-only
sharing, legacy lifecycle and resource-URI routing assumptions.

## Resource bounds

All env-only, following the `MCPTasksConfig` precedent (`config.go:240-246`, `:477-483`) — a new
`MCPSubscriptionsConfig` with an `Enabled` (or empty-value) kill switch as the rollback lever, exactly
as an unset `MCP_TASK_HANDLE_SECRET` disables task mediation.

| Bound | Env var | Suggested default | Rationale |
|---|---|---|---|
| Feature switch | `MCP_SUBSCRIPTIONS_ENABLED` | `false` | ship dark; off means `subscriptions/listen` keeps 404-ing and no capability is advertised — behaviour identical to today |
| Max concurrent streams, process-wide | `MCP_SUBSCRIPTIONS_MAX_STREAMS` | `1024` | well under Fiber's `Concurrency: 16384`; refuse past it so streams cannot starve request traffic |
| Max streams per consumer | `MCP_SUBSCRIPTIONS_MAX_PER_CONSUMER` | `16` | one noisy tenant must not consume the global budget |
| Max streams per principal | `MCP_SUBSCRIPTIONS_MAX_PER_PRINCIPAL` | `4` | the SDK client opens one listen **per subscribed URI** (`client.go:1380-1405`), so a small-but-not-1 cap is right |
| Per-stream outbound queue | `MCP_SUBSCRIPTIONS_STREAM_QUEUE` | `16` events | bounds memory at `max_streams × queue × event_size`; a full queue terminates without dropping or blocking |
| Southbound feature switch | `MCP_SUBSCRIPTIONS_UPSTREAM_ENABLED` | `false` | returns to PR #464 while northbound subscriptions remain enabled |
| Max physical listeners | `MCP_SUBSCRIPTIONS_MAX_UPSTREAM_LISTENERS` | `256` | process-wide outbound connection and goroutine budget |
| Max listeners per origin | `MCP_SUBSCRIPTIONS_MAX_UPSTREAM_PER_ORIGIN` | `16` | one origin cannot consume the process budget |
| Southbound idle timeout | `MCP_SUBSCRIPTIONS_UPSTREAM_IDLE_TIMEOUT` | `60s` | reclaims a half-open modern listener through bounded reconnect |
| Reconnect attempts | `MCP_SUBSCRIPTIONS_RECONNECT_MAX_ATTEMPTS` | `3` | prevents dead origins retaining listener slots indefinitely |
| Reconnect backoff | `MCP_SUBSCRIPTIONS_RECONNECT_BACKOFF_MIN` / `MAX` | `250ms` / `5s` | context-cancellable jittered exponential window |
| Max stream lifetime | `MCP_SUBSCRIPTIONS_MAX_LIFETIME` | `30m`, hard ceiling `4h` | the authorization-lease ceiling; forces periodic re-auth through a fresh open. Clamp like `MaxTaskHandleTTL` does (`task_handle.go:37`) |
| Re-authorization interval | `MCP_SUBSCRIPTIONS_REAUTH_INTERVAL` | `30s` | also the change-detection tick; bounded below so a client cannot make it a re-composition amplifier |
| Keepalive interval | `MCP_SUBSCRIPTIONS_KEEPALIVE` | `15s` | SSE comment frames to keep LBs and the idle timeout honest |
| Max event size | `MCP_SUBSCRIPTIONS_MAX_EVENT_BYTES` | `8192` | `list_changed` frames are tiny; the cap exists so an upstream-sourced field can never be unbounded |
| Max `resourceSubscriptions` per listen | `MCP_SUBSCRIPTIONS_MAX_URIS` | `32` (inert while unsupported) | bounds request parsing today, and the future fan-out later |

Additionally, **`SERVER_WRITE_TIMEOUT` (default 60 s) must be reconciled.** Fiber/fasthttp applies it
as a write deadline; whether a `SetBodyStreamWriter` body resets it per flush needs to be **verified
experimentally**, not assumed — the proxy plane streams under the same setting today, so the pattern
is probably safe, but the maximum stream lifetime cannot be documented until this is measured.

## Risks and unknowns

- **`SERVER_WRITE_TIMEOUT` vs long-lived streams (unknown, must verify first).** If fasthttp enforces
  the 60 s write deadline across a streamed body, every documented bound above is fiction. Verify with
  a test that holds a stream open past the timeout before design commits to a max lifetime.
- **Goroutine leaks.** The chosen shape has one goroutine per stream, owned by fasthttp, but any
  helper (ticker, re-auth, keepalive) must be joined on the same `defer`. Tests must assert goroutine
  count returns to baseline after client disconnect, after idle timeout, after re-auth refusal, and
  after shutdown — with `-race`.
- **Graceful shutdown deadlock.** `http_server.go:50-56` calls Fiber's `Router.Shutdown()`, which waits
  for in-flight requests; a stream parked on `ctx.Done()` is in-flight indefinitely. Without an explicit
  drain hook, deploys hang. This is the single highest-severity operational risk.
- **Metrics middleware drains the stream.** `mcp_metrics.go:119` calls `c.Response().Body()`
  unconditionally. On a stream this collapses chunk-by-chunk delivery into one burst at end-of-stream
  and buffers the whole thing in memory — the exact failure `access_log.go:44-52` already documents for
  the proxy plane. Must be fixed in the same slice that introduces streaming, or the feature looks
  broken and leaks memory.
- **Ops latency distortion.** `ops_metrics.go:43-65` measures after `c.Next()`, which returns before the
  stream writer runs, so a 30-minute stream records ~0 ms. Silently skews the MCP-plane latency SLO.
- **Backpressure / slow consumers.** Producer must never block on a subscriber. The first failed
  enqueue into a full bounded queue terminates that subscriber; no event is dropped or overwritten.
  A test must prove that a consumer which never reads cannot affect healthy subscribers.
- **Legacy era interaction.** Legacy sessions are cached per pin key with a 30-minute idle TTL and
  evicted lazily inside `lookup` (`cached_dialer.go:104-114,188-200`) — a legacy-era stream could be
  sitting on a session closed underneath it. Mitigation in the recommendation: subscriptions are
  modern-only and gated on a non-legacy registry, and the idle timeout is set below 30 minutes.
  `classifyEra` already routes `initialize` and legacy headers to the legacy path, so a legacy client's
  `subscriptions/listen` falls out as an unknown legacy method — this must be asserted, not assumed.
- **`guardedUpstream` swallows optional ports (pre-existing, confirmed).** `auto`-mode registries get
  `guardedUpstream` (`negotiating_dialer.go:203`), which does not implement `TaskUpstream` — so
  `resolveTask`'s type assertion (`composer_tasks.go:193-198`) fails and tasks silently only work on
  `protocol_mode=modern`. Any southbound subscription port would inherit the same trap. Worth fixing
  or at least filing regardless of which approach wins.
- **Southbound bounds are hostile to streams (confirmed).** `exchange` returns on the first
  `*jsonrpc.Response` (`modern_upstream.go:615-622`), `maxModernResponseMessages = 100`,
  `boundedModernResponseBody` caps cumulative bytes at 4 MiB (`:41,152-189`), and `MaxRetries: -1`
  disables SDK reconnect. Approach 2 needs an entirely separate southbound read path; reusing `call`
  would fail after 100 messages or 4 MiB with a misleading "unreachable".
- **Upstream capabilities are discarded (confirmed).** `probe.go:495-499` validates that
  `server/discover` returned a `capabilities` object and then throws it away, so TrustGate cannot know
  whether a modern upstream supports `listChanged`/`subscribe`. Any relay design needs this retained
  first.
- **Load balancers and proxies.** A long-lived `text/event-stream` response is at the mercy of the
  ingress: GKE/Envoy idle timeouts, response buffering, and HTTP/2 flow control. Needs
  `X-Accel-Buffering: no`, keepalive comment frames below the shortest hop timeout, and an operator
  note in `docs/mcp/`. Clients must be told a stream will be closed and re-opened periodically by
  design.
- **Reconnect storms.** A short max lifetime plus many clients means synchronised re-opens. Jitter the
  lifetime, and make the re-open path cheap (the discovery cache and singleflight already help).
- **Resource URI ambiguity (confirmed).** Upstream URIs are passed through unnamespaced and
  `ReadResource` resolves first-match across registries (`composer_resources.go:27-111`), so a
  `resources/updated` cannot be attributed to one registry. Prerequisite for ever honouring
  `resourceSubscriptions`.
- **`SubscriptionsListenResult` embeds `completeResultWithType`.** It serialises a `resultType`, which
  collides conceptually with `normalizeModernResult`'s `resultType` handling
  (`modern_response.go:113-131`). Design must decide whether the terminal frame goes through the
  normalizer at all.
- **Free error codes.** `-32003` (consent), `-32020`–`-32022` (header/acceptance/version), `-32023`/`-32024`
  (MRTR, `errors.go:41-42`), `-32025` (task capability, `:46`) are taken, and tasks deliberately reuses
  `-32602`/`-32603` for handle rejection and oversize (`:52`, `:55`). Subscription refusals need a fresh
  code or a documented reuse.
- **Conformance suites.** The SDK ships `mcp/conformance` and `conformance_test.go`; worth checking
  whether any listen scenario there can be pointed at TrustGate as an external validation.

## Size forecast

| Slice | Scope | Est. changed lines |
|---|---|---|
| 1 | Config + container + kill switch + `subscriptions/listen` accepted with an empty honoured subset (immediate ack + terminal result); `Accept`/params validation; no capability advertised | ~350 (incl. tests) |
| 2 | Streaming transport: `SetBodyStreamWriter` path, SSE framing, keepalive, cancellation, idle/lifetime ceilings, shutdown drain; MCP `StreamMetricsFinalizer`; ops-metrics decision | ~600 |
| 3 | Negotiation + change detection: `listChanged` advertisement gated end-to-end, role-scoped honoured subset, re-auth tick, `list_changed` emission, mid-stream termination | ~550 |
| 4 | Bounds + backpressure + isolation hardening: per-consumer/per-principal caps, buffer + slow-consumer policy, race/leak tests, isolation matrix tests | ~500 |
| 5 | Telemetry + specs + docs: bounded recorders, trace labels, `mcp-subscriptions` spec, dual-era delta, `docs/mcp/subscriptions.md`, `docs/operational-metrics.md` | ~450 |

**Total ≈ 2400–2500 changed lines.**

- `Decision needed before apply: Yes`
- `Chained PRs recommended: Yes`
- `400-line budget risk: High`

The epic has been shipping one PR per issue with `size:exception`, but this change is ~6× the budget
and, unlike RUN-1101/RUN-1102, it introduces a *new execution model* (long-lived goroutines, streaming
responses, shutdown coupling) rather than new message shapes. Recommend a **chained PR** chain along
the slice boundaries above: slice 1 is independently shippable and behaviour-neutral behind the kill
switch, slice 2 is the risky transport change reviewed on its own, and slices 3–5 layer policy, bounds,
and observability. If the epic insists on a single PR, it needs `size:exception` **and** the reviewer
guidance that slices 2 and 4 carry all the risk.

## Resolved decisions

1. `resourceSubscriptions`, `notifications/resources/updated` and task notifications remain out.
2. PR #464 supplies the gateway-derived northbound foundation; slice 2 adds authorized southbound
   relay for the list-changed trio.
3. PR #464's maximum lifetime and re-authorization rules remain the outer lease bounds.
4. A live stream is charged once at open and bounded by concurrency, queue and listener caps.
5. Existing northbound error and streaming-metrics decisions remain unchanged in slice 2.
6. The `TaskUpstream` wrapper gap is unrelated and MUST NOT be bundled into the subscription port.

## Ready for second-slice design

Yes. Use complete-key modern listener multiplexing behind an app port, retain per-subscriber
authorization isolation, terminate rather than drop on queue pressure, reconnect only across
equivalent source identity, and preserve PR #464 behind the independent upstream kill switch.
