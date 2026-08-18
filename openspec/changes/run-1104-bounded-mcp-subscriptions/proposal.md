# Proposal: RUN-1104 add bounded MCP subscriptions

**Change**: `run-1104-bounded-mcp-subscriptions` · **Linear**: [RUN-1104](https://linear.app/neuraltrust/issue/RUN-1104) — epic [RUN-1100](https://linear.app/neuraltrust/issue/RUN-1100)
**Branch**: `feat/run-1104-bounded-mcp-subscriptions` · **Base**: `feat/run-1103-dual-era-northbound-protocol-boundary`
**Contract**: SEP-2575 "Stateless MCP", protocol `2026-07-28`, `subscriptions/listen`. Revision pinned in the spec delta.

## Intent

A modern client that calls `subscriptions/listen` gets HTTP 404 `-32601` today, so TrustGate fails the `2026-07-28` conformance surface and a client has no way to learn that its tool/prompt/resource surface changed other than re-listing on a timer. `configuredCapabilities` correctly advertises no `listChanged` and no `subscribe`, so the gap is honest — but it is a gap.

The hard part is not the wire shape; it is that TrustGate is a **stateless, POST-only** gateway where every authorization input (principal, consumer `Data`, role scope, toolkit, rate-limit budget, credentials) is bound to one request. A long-lived stream has no natural re-evaluation point, and shipping one naively means a client keeps receiving notifications after its access is revoked.

## Scope

### In Scope

- `subscriptions/listen` as a supported modern method: `Accept` negotiation, `params.notifications` validation with cardinality bounds, honoured-subset ack, `_meta` subscription-id stamping, terminal `SubscriptionsListenResult`.
- A **streaming response path** on Fiber (`SetBodyStreamWriter`), reusing the proxy plane's proven pattern (`proxy_handler.go:152-204`).
- **Bounded maximum stream lifetime** validated against `SERVER_WRITE_TIMEOUT` at startup, fail-fast (see *Locked decisions* 2–4).
- Gateway-derived `toolsListChanged` / `promptsListChanged` / `resourcesListChanged`, emitted only as the product of a **fresh full authorization pass** on a re-auth tick.
- `listChanged: true` advertisement under a `subscriptionsEndToEnd(rc)` gate; `resources.subscribe` stays absent.
- Concurrency caps (process / consumer / principal), keepalive, jittered lifetime, one indistinguishable termination shape.
- **MCP-plane `StreamMetricsFinalizer`** so `buildResponseContext` never drains a live stream (required, not optional).
- **Shutdown drain hook** so `Router.Shutdown()` cannot block on a stream parked in `ctx.Done()` (required, not optional).
- Bounded telemetry, `MCPSubscriptionsConfig`, spec delta + new spec, operator docs.

### Out of Scope

- `resourceSubscriptions` / `notifications/resources/updated` — parsed and bounded, **never honoured, never advertised** (see decision 8).
- Any southbound `subscriptions/listen`: no `SubscriptionUpstream` port, no long-lived upstream read loop, no probe capability retention.
- Fixing the pre-existing `guardedUpstream` / `TaskUpstream` gap (`negotiating_dialer.go:203`) — separate RUN issue.
- Raising `SERVER_WRITE_TIMEOUT`. It is shared with the whole data plane and is slowloris protection.
- Legacy-era subscriptions, the standalone GET SSE transport, `Mcp-Session-Id`. `GET`/`DELETE` → 405 is unchanged and asserted.
- Per-registry resource URI namespacing (prerequisite for ever honouring `resourceSubscriptions`).

## Capabilities

### New Capabilities
- `mcp-subscriptions`: negotiation and honoured-subset semantics, bounded stream lifecycle, per-emission re-authorization, isolation, capacity bounds, termination contract, telemetry.

### Modified Capabilities
- `mcp-dual-era-northbound`: `subscriptions/listen` is a supported modern method; a modern response may be `text/event-stream`; `Accept` participates in validation; `Mcp-Name` is rejected on listen; `tools`/`prompts`/`resources` may carry `listChanged`.

## Approach

**A stream is not a session. It is a bounded, periodically re-authorized lease, hard-capped below the server write timeout.**

The listen handler runs the *unchanged* policy prologue (auth → era → validate → consumer resolve → acceptance → role scope → rate limit → plugins → compose), then takes a `SetBodyStreamWriter` branch. One goroutine — the fasthttp body-stream writer itself — owns the entire lifecycle: write the ack, then `select` on `ctx.Done()`, the keepalive ticker, the re-auth ticker, and the deadline timer. On each re-auth tick it re-runs the full authorization pass and compares a per-kind fingerprint derived the way `surfaceFingerprint` (`mcp_handler.go:503-528`) already derives one. A changed fingerprint emits the corresponding `list_changed`; nothing else is ever emitted, so **every notification is the product of a fresh authorization decision**. A refusal terminates the stream rather than silently narrowing it.

### The write-timeout ceiling (measured, first-class)

Probed on this worktree: with `WriteTimeout = 2s` and a `SetBodyStreamWriter` body flushing every 500 ms, the client received exactly 4 events and the connection was severed with `unexpected EOF` at **2.002 s**. **Flushing does not reset the write deadline** — fasthttp applies it to the whole response. `NewBaseServer` (`pkg/server/server.go:47`) builds every plane from the same `cfg.WriteTimeout`, so this binds the MCP plane. Production sets `SERVER_WRITE_TIMEOUT=300s` in all three overlays; the code default is `60s`.

This is not a bug to work around — it is the ceiling the feature is designed against, and the repo already lives by it: the proxy plane bounds a stream at `providers.StreamTimeout = 5m` and the overlays carry the comment *"Must stay above the 5m StreamTimeout"*. (Worth flagging: at `300s` vs `5m` that margin is currently **zero**.)

### Locked decisions

| # | Decision |
|---|---|
| 1 | **Approach 1 confirmed** (exploration Q2): per-request stream tied to the HTTP request lifecycle, gateway-derived `list_changed`. No southbound listen. Ports and the northbound notification type stay free of any "gateway-derived" assumption so a fan-out source can be added later without a wire break. |
| 2 | **`MCP_SUBSCRIPTIONS_MAX_LIFETIME` is the authorization lease and is hard-capped by the write timeout.** When unset it **derives** as `SERVER_WRITE_TIMEOUT − margin` (290 s in prod, 50 s on the code default), clamped to a `30m` ceiling so a large write timeout cannot buy an unbounded lease. |
| 3 | **Fail-fast startup validation.** `Config.Validate()` (called from `Load()`, `config.go:434`) refuses to boot with `ErrInvalidConfig` when subscriptions are **enabled** and `MaxLifetime + MCPSubscriptionsLifetimeMargin > Server.WriteTimeout`, naming both values and both env vars. Margin `10s`, a package constant, not configurable. Misconfiguration is a **boot failure, not a runtime truncation** — the alternative is streams that die mid-frame with `unexpected EOF` and look like a network fault. Validation is skipped when the feature is off so the default build is unaffected. |
| 4 | **Clean end-of-stream is the contract, not an error path.** At the deadline the stream writes the terminal `SubscriptionsListenResult` and closes; the client re-issues `subscriptions/listen`. Documented client-side as *streams are ephemeral by design*. Deadline is **jittered** (`−rand[0, 10%]`) so a fleet does not re-open in lockstep. |
| 5 | **One termination shape for every cause.** Client disconnect, `notifications/cancelled`, deadline, re-auth refusal, capacity reclaim, and shutdown all end with the terminal result then close. Indistinguishable on the wire, exactly like `TaskHandleRejectedMessage` (`errors.go:56-59`). No partial narrowing is ever served. |
| 6 | **The writer is the producer — there is no buffer and no slow-consumer policy.** *Deliberate divergence from the exploration*, which specified `MCP_SUBSCRIPTIONS_BUFFER=16` with drop-oldest. With a gateway-derived source the tick runs inline in the writer's `select`, so no second goroutine ever hands events across a channel. Backpressure is the socket; a consumer that never reads stalls its own `w.Flush()` and dies at the deadline. This removes an entire class of leak and one env var. |
| 7 | **`subscription_registry`, not `subscription_hub`** — again a divergence: this slice needs live-stream accounting (capacity caps + shutdown drain), not fan-out. Naming it a hub would advertise multiplexing that does not exist. The registry keys on `{gatewayID, consumerID, principalFingerprint, roleScopeFingerprint}`; no event crosses a consumer, principal, or registry by construction, because no event ever leaves the stream that produced it. |
| 8 | **`resourceSubscriptions` out** (exploration Q1). `params.resourceSubscriptions` is parsed and bounded (`MCP_SUBSCRIPTIONS_MAX_URIS`, default `32`) but never honoured and refused in the ack per the spec's honoured-subset rule; `resources.subscribe` is never advertised. Rationale unchanged: URIs are not registry-namespaced (`composer_resources.go:27-111`), so a `resources/updated` cannot be attributed to one registry. |
| 9 | **No separate idle timeout** — a third divergence. The exploration's `5m` idle timeout is dominated by a ≤ 290 s lifetime ceiling and would be dead config. Keepalive (`15s`) plus the lifetime ceiling is the whole story. |
| 10 | **No token-expiry deadline in this slice** (exploration Q3, deferred with rationale). Principal token expiry is not on the request context today, and a lease already capped under 5 minutes bounds staleness far below any realistic token TTL. Revisit only if the write-timeout ceiling is ever raised. |
| 11 | **Rate limiting**: one `Check` at open through the normal dispatch path; a live stream **holds no token-bucket slot**. Concurrency caps are the metering axis (exploration Q5). |
| 12 | **Ops metrics** (exploration Q6): the stream claims metrics ownership synchronously (`StreamMetricsOwnedKey`) exactly as `proxy_handler.go:158-161` does, gets its own bounded `o11y.Route` class, and reports its **true duration at close** via the finalizer — not the ~0 ms `ops_metrics.go` would record at handler unwind. |

### Locked error codes

Free range confirmed: `-32002/-32003` (handler), `-32020/-32021/-32022` (validation), `-32023/-32024` (MRTR), `-32025` (tasks).

| Condition | Code | Constant |
|---|---|---|
| `Accept` missing `text/event-stream` and/or `application/json`; `Mcp-Name`/`Mcp-Param-*` present on listen | `-32020` | existing header-validation code, refused at the boundary before any policy effect (RUN-1103 *Validation isolation*) |
| Missing `params.notifications`; malformed or over-cardinality `resourceSubscriptions` | `-32602` | spec-mandated `ErrInvalidParams` |
| Capacity refusal (process / consumer / principal cap reached) | **`-32026`** | `CodeSubscriptionRefused` (new) — **one constant message, no `data`**, so caps cannot be probed as an occupancy oracle |
| Feature disabled | — | method stays unlisted ⇒ `-32601`, byte-identical to today |

## Affected Areas

| Area | Impact | Description |
|---|---|---|
| `pkg/api/handler/http/mcp/subscriptions_listen.go` | New | Streaming handler: `SetBodyStreamWriter`, SSE framing, ack-first ordering, keepalive, re-auth tick, jittered deadline, terminal result |
| `pkg/api/handler/http/mcp/subscription_validation.go` | New | `Accept` negotiation, `params.notifications` shape + bounds, `Mcp-Name` rejection |
| `pkg/api/handler/http/mcp/{mcp_handler,modern_validation,modern_response,server_discover,rpc_dispatcher,protocol_metrics}.go` | Modified | Method set, `SubscriptionsSupport` (mirroring `TasksSupport`), `Accept` plumbing, notification framing that bypasses `normalizeModernResult`, gated `listChanged`, stream dispatch entry point, bounded recorder |
| `pkg/app/mcp/subscriptions.go` | New | `NotificationKind` enum, honoured-subset value type, isolation key |
| `pkg/app/mcp/subscription_registry.go` | New | Live-stream accounting, capacity caps, drain hook, explicit goroutine lifecycle |
| `pkg/app/mcp/subscription_policy.go` | New | Re-authorization pass + per-kind surface fingerprint diff |
| `pkg/app/mcp/{composer,errors}.go`, `mocks/` | Modified | Subscription use case, `CodeSubscriptionRefused`, regenerate mocks |
| `pkg/api/middleware/mcp_metrics.go` | Modified | `StreamMetricsFinalizer` equivalent; never call `Response().Body()` on a body stream |
| `pkg/api/middleware/ops_metrics.go` | Modified | Stream route class + true duration at close |
| `pkg/infra/trace/span.go` | Modified | Bounded `SubscriptionKind` / `SubscriptionOutcome` labels |
| `pkg/config/config.go`, `pkg/container/modules/mcp.go` | Modified | `MCPSubscriptionsConfig`, derived + validated lifetime, registry provider, drain wiring |
| `openspec/specs/…`, `docs/mcp/subscriptions.md`, `docs/operational-metrics.md` | New/Modified | Spec delta, new spec, operator + client docs |

Unchanged by design: router (still `POST /*`), `GET`/`DELETE` → 405, auth middleware, role scoper, registry `protocol_mode`, legacy `initialize` capabilities, MRTR and task wire formats, `SERVER_WRITE_TIMEOUT`.

## Configuration

All env-only, following `MCPTasksConfig` (`config.go:238-246`).

| Env var | Default | Note |
|---|---|---|
| `MCP_SUBSCRIPTIONS_ENABLED` | `false` | Kill switch. Off ⇒ 404 `-32601`, no capability advertised, no startup validation |
| `MCP_SUBSCRIPTIONS_MAX_LIFETIME` | derived `SERVER_WRITE_TIMEOUT − 10s`, ceiling `30m` | Validated fail-fast (decision 3) |
| `MCP_SUBSCRIPTIONS_REAUTH_INTERVAL` | `30s` | Also the change-detection tick; floored so it cannot become a re-composition amplifier |
| `MCP_SUBSCRIPTIONS_KEEPALIVE` | `15s` | SSE comment frames, below the shortest LB hop timeout |
| `MCP_SUBSCRIPTIONS_MAX_STREAMS` | `1024` | Process-wide; far under Fiber `Concurrency: 16384` |
| `MCP_SUBSCRIPTIONS_MAX_PER_CONSUMER` | `16` | One tenant cannot take the global budget |
| `MCP_SUBSCRIPTIONS_MAX_PER_PRINCIPAL` | `4` | |
| `MCP_SUBSCRIPTIONS_MAX_EVENT_BYTES` | `8192` | No frame is ever unbounded |
| `MCP_SUBSCRIPTIONS_MAX_URIS` | `32` | Bounds request parsing while `resourceSubscriptions` is unsupported |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Shutdown deadlock — `Router.Shutdown()` waits on a stream parked in `ctx.Done()` | High if unwired | Drain hook is an acceptance criterion with its own test; highest-severity operational risk |
| Metrics middleware drains a live stream into memory and collapses chunked delivery | High if unwired | `StreamMetricsFinalizer` ships in the same commit as the streaming path, mirroring `access_log.go:44-52` |
| Operator sets a lifetime above the write timeout ⇒ mid-frame `unexpected EOF` | Med | Boot refused with both values named (decision 3) |
| Goroutine leak on disconnect / deadline / refusal / shutdown | Med | One goroutine per stream, every helper joined on the same `defer`; `-race` + goroutine-count-returns-to-baseline tests for all four paths |
| Notification emitted after access is revoked | Med | Emission requires a fresh full authorization pass; refusal terminates rather than narrows |
| Reconnect storm at the lifetime ceiling | Med | 10 % jitter; re-open absorbed by the discovery TTL cache + singleflight |
| LB/ingress buffers or idles out the stream | Med | `Cache-Control: no-cache, no-transform`, `X-Accel-Buffering: no`, keepalive below the shortest hop timeout, operator note |
| Legacy client reaches the listen path | Low | Modern-only by construction; asserted, not assumed — `classifyEra` routes legacy `subscriptions/listen` to an unknown legacy method |
| PR ≫ 400 lines | High | `size:exception` + sequenced commits (see *Delivery*) |

## Rollback Plan

1. **Instant, no deploy**: `MCP_SUBSCRIPTIONS_ENABLED=false`. `subscriptions/listen` leaves the modern method set (404 `-32601`), no `listChanged` is advertised, no stream can be opened, and startup validation is skipped. Behaviour is byte-identical to today.
2. Live streams are self-terminating: the longest outlives the flag flip by at most one lifetime (≤ 290 s in prod), each closing with the normal terminal result.
3. Full revert = `git revert` the commit range. Nothing is persisted — no store, no handles, no session state — so revert has no data migration. The metrics-middleware and shutdown-drain commits are independently useful and safe to keep.

## Dependencies

- RUN-1103 dual-era boundary (base branch); RUN-1102 tasks (landed on the base); RUN-1109 telemetry conventions for the bounded recorder.
- go-sdk v1.7.0 exported wire types only (`SubscriptionsListenParams`, `NotificationSubscriptions`, `SubscriptionsAcknowledgedParams`, `SubscriptionsListenResult`, `MetaKeySubscriptionID`). **Not** upgraded, **not** forked; the server-side hub is unexported and deliberately not adopted (exploration approach 3, rejected).
- No new modules.

## Delivery

400-line budget risk: **High** (~2400 lines forecast). Per standing epic preference, ship **one PR against `feat/run-1103-dual-era-northbound-protocol-boundary` with `size:exception`**, sequenced as atomic commits on this single branch — explicitly **not** the chained PR chain the exploration suggested, since the epic tracks one PR per issue:

1. Config (incl. derived lifetime + fail-fast validation) + container + kill switch + `subscriptions/listen` accepted with an empty honoured subset; `Accept`/params validation. Behaviour-neutral behind the switch.
2. Streaming transport: `SetBodyStreamWriter`, SSE framing, keepalive, cancellation, jittered deadline, **shutdown drain**, **MCP `StreamMetricsFinalizer`**, ops-metrics route class.
3. Negotiation + change detection: gated `listChanged`, role-scoped honoured subset, re-auth tick, emission, mid-stream termination.
4. Capacity caps + isolation hardening + race/leak/isolation tests.
5. Telemetry, specs, docs.

Commits 2 and 4 carry all the risk and must be called out in the PR body as the reviewer's focus. Commit 2 must not ship without commit 1.

## Success Criteria

- [ ] A modern client with a valid `Accept` opens a listen, receives `notifications/subscriptions/acknowledged` as the **first** frame carrying only the honoured subset, and every frame is stamped with `_meta["io.modelcontextprotocol/subscriptionId"]`.
- [ ] Editing the toolkit emits exactly one `list_changed` of the right kind within one re-auth interval; a revoked role, detached registry, or `legacy_only` switch **terminates** the stream instead of narrowing it.
- [ ] A stream reaches its jittered deadline, sends the terminal `SubscriptionsListenResult`, and closes cleanly — no `unexpected EOF`, verified against a `SERVER_WRITE_TIMEOUT` shorter than production.
- [ ] Booting with `MCP_SUBSCRIPTIONS_ENABLED=true` and `MCP_SUBSCRIPTIONS_MAX_LIFETIME >= SERVER_WRITE_TIMEOUT − 10s` fails with `ErrInvalidConfig` naming both env vars.
- [ ] `Router.Shutdown()` completes within the drain budget with N live streams open; goroutine count returns to baseline after disconnect, deadline, refusal, and shutdown, under `-race`.
- [ ] Frames reach the client incrementally (chunked, not one burst at close) with the metrics middleware enabled, and MCP-plane latency reflects the stream's true duration.
- [ ] `resources.subscribe` is never advertised and a client requesting `resourceSubscriptions` receives an ack whose honoured subset excludes it.
- [ ] Two principals on one consumer with disjoint role scopes never observe each other's `list_changed`; capacity refusals are indistinguishable across caps.
- [ ] `MCP_SUBSCRIPTIONS_ENABLED=false` restores pre-change behaviour with no code change; legacy `initialize` capabilities are byte-identical and `GET`/`DELETE` still answer 405.
- [ ] No URI, notification payload, subscription id, principal, token, or tenant name appears in any metric, span, or log.
