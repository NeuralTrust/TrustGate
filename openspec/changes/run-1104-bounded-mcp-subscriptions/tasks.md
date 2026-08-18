# Tasks: RUN-1104 add bounded MCP subscriptions

**Branch**: `feat/run-1104-bounded-mcp-subscriptions` · **Base**: `feat/run-1103-dual-era-northbound-protocol-boundary` @ `805e7901`
**Inputs**: `exploration.md`, `proposal.md` (decisions 1–12 locked), `design.md` (D1–D12, file table, testing strategy), `specs/mcp-subscriptions/spec.md`, `specs/mcp-dual-era-northbound/spec.md`

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | 3900–4200 (≈ 3 520 Go incl. generated mocks, ≈ 545 spec/doc prose) |
| 400-line budget risk | High |
| Chained PRs recommended | No |
| Suggested split | One PR (`size:exception`), five sequenced commits on this branch |
| Delivery strategy | exception-ok |
| Chain strategy | size-exception |

Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: size-exception
400-line budget risk: High

### Size forecast per commit

| Commit | Non-test Go | Test Go | Spec/doc | Total | Note |
|--------|------------|---------|----------|-------|------|
| 1 — Foundation and kill switch | ~470 | ~330 | — | **~800** | Behaviour-neutral with the flag off; independently shippable |
| 2 — Streaming transport, drain, stream metrics | ~650 | ~500 | — | **~1 150** | Highest risk; **never ships without commit 1** |
| 3 — Negotiation and change detection | ~460 (+90 generated mocks) | ~450 | — | **~1 000** | Revertible |
| 4 — Isolation and adversarial verification | ~30 | ~370 | — | **~400** | Test-dominated; second reviewer-focus commit |
| 5 — Telemetry, specs, docs | ~115 | ~60 | ~545 | **~720** | Revertible; ~204 of the prose is the already-authored spec copied on archive |
| **Total** | **~1 725 (+90)** | **~1 710** | **~545** | **~4 070** | Go subtotal ≈ 3 435, within 3 % of the design's ≈ 3 350 |

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Config (derived lifetime, fail-fast validate, **5 s re-auth floor**), errors, value types, `Accept`/params validation, gated method set | commit 1 | Inert alone; flag default `false` |
| 2 | SSE framing, registry + leases, stream loop, **MCP stream-metrics finalizer**, **ops route class**, **shutdown drain hook** | commit 2 | **Never ships without unit 1** |
| 3 | `federateWithStats`, re-auth policy, **bounded pass + skip rule**, honoured-subset intersection, gated `listChanged` | commit 3 | Revertible |
| 4 | Cap matrix, race, goroutine-leak, memory thresholds, isolation, integration | commit 4 | Revertible |
| 5 | Bounded telemetry, openspec publication, operator + client docs, verify | commit 5 | Revertible |

Apply phases 1→5 sequentially in one worktree. The whole epic lands as **one PR per issue with `size:exception`** against
`feat/run-1103-dual-era-northbound-protocol-boundary` — explicitly **not** a chained-PR chain. Name commits **2 and 4** as the
reviewer's focus in the PR body (design *Push-backs*).

### Locked decisions (override design Open Questions)

1. `resourcesListChanged` **folds `ListResourceTemplates` into its digest**. A template edit is a resource-surface change and has no
   separate notification; a false positive costs one client re-list, a false negative loses the change permanently.
2. `IsolationKey.RoleScope` **keeps `SurfaceConfigFingerprint`** (registry `UpdatedAt` + toolkit entries). Correct-but-conservative:
   a config edit unrelated to roles terminates the stream. That is a documented operator-visible behaviour (task 5.5), not a defect,
   and hashing only the resolved role set would make toolkit narrowing invisible to the lease identity.
3. `ReauthBudget`'s `[1s, 8s]` clamp **stays local to `pkg/app/mcp`**; the margin is not exported from `pkg/config`. The relation
   (`budget ceiling < lifetime margin`) is asserted by a named test in `config_test.go` (task 1.2) rather than by a shared constant,
   so `pkg/app/mcp` gains no dependency on `pkg/config`.
4. **`subscription_registry.go` lands whole in commit 2**, including cap accounting — a deviation from the proposal's "caps in
   commit 4". `Claim` checks and increments all three counters in one mutex block, and commit 2's drain hook needs live-lease
   tracking, so splitting the file would ship a half-written mutex. Commit 4 keeps the proposal's *content*: cap verification under
   `-race`, refusal uniformity, isolation, leak and memory assertions.

## Phase 1: Foundation and kill switch (commit 1)

- [x] 1.1 Modify `pkg/config/config.go`: `MCPSubscriptionsConfig` (nine fields) following `MCPTasksConfig`; nine env vars with the
      design's defaults; derivation inside `getServerConfig` off the locally computed `writeTimeout` so the two can never disagree;
      package constants `mcpSubscriptionsLifetimeMargin = 10s` and `mcpSubscriptionsLifetimeCeiling = 30m`. Clamps: `MaxLifetime`
      unset or `≤ 0` ⇒ `min(writeTimeout − 10s, 30m)`; **`ReauthInterval` floor `5s`**, ceiling `MaxLifetime`; `Keepalive` floor `1s`,
      ceiling `MaxLifetime`; four caps must be `> 0`.
      **Accept**: `config_test.go` (`t.Setenv`, no sleeps) proves each default, the derived lifetime, and that
      `MCP_SUBSCRIPTIONS_REAUTH_INTERVAL=1s` resolves to `5s` — the floor that stops the interval becoming a re-composition
      amplifier (design *Re-authorization Cost*, required change 1). Spec: *Fail-fast lifetime configuration* → "Derived default
      always boots".
- [x] 1.2 Modify `pkg/config/config.go` `(*Config).Validate()`: add the subscriptions branch reached from `LoadConfig`. Refuse with
      `errors.ErrInvalidConfig` when enabled and `MaxLifetime <= 0 || MaxLifetime + margin > Server.WriteTimeout`, the message naming
      **both env vars and both values**. Skip the whole branch when disabled.
      **Accept**: `config_test.go` covers boot refused with both names present in the error string; `MCP_SUBSCRIPTIONS_ENABLED=false`
      with an over-long lifetime boots; `SERVER_WRITE_TIMEOUT=10s` refuses (derived lifetime non-positive); plus the named
      budget-vs-margin relation test from locked decision 3. Spec: *Fail-fast lifetime configuration* → all three scenarios.
- [x] 1.3 Modify `pkg/app/mcp/errors.go`: `CodeSubscriptionRefused int64 = -32026`, `SubscriptionRefusedMessage` constant,
      `ErrSubscriptionRefused` / `ErrSubscriptionRevoked` sentinels, `SubscriptionRefusedRPCError()`.
      **Accept**: the constructed RPC error has `Data == nil` and one constant message regardless of call site, mirroring
      `TaskHandleRejectedMessage`. Spec: *Capacity bounds and non-probeable refusal* → "Refusals are indistinguishable across caps".
- [x] 1.4 Create `pkg/app/mcp/subscriptions.go` and modify `pkg/api/handler/http/mcp/mcp_handler.go`: `NotificationKind` +
      `BoundNotificationKind` + `Method()`; `HonouredSet` with deterministic `Kinds()` order (tools, prompts, resources), `Has`,
      `Empty`; `IsolationKey` + `NewIsolationKey` (gateway, consumer, full `principalFingerprint`, role scope);
      `SurfaceConfigFingerprint` lifted verbatim from the handler, with `surfaceFingerprint` reduced to a one-line delegation.
      Tests in `subscriptions_test.go`: kind binding rejects unknown strings, honoured-subset algebra, isolation-key derivation, and
      **fingerprint parity** with the pre-lift algorithm.
      **Accept**: `mcp_handler_test.go` and `mrtr_advertise_test.go` pass **unedited** — that is the behaviour-preservation gate.
      Spec: *Stream isolation* (key definition).
- [x] 1.5 Create `pkg/api/handler/http/mcp/subscription_validation.go` + `subscription_validation_test.go`: `Accept` must contain both
      `text/event-stream` and `application/json`; `Mcp-Name` or any `Mcp-Param-*` on listen ⇒ `-32020` **at the boundary**;
      `params.notifications` missing ⇒ `-32602`; `params.resourceSubscriptions` parsed, bounded to `MaxURIs`, malformed or
      over-cardinality ⇒ `-32602`, otherwise discarded. The honoured-subset intersection helper is introduced here and returns the
      **empty set** in this commit (real narrowing wired in 3.7).
      **Accept**: table test covers the `-32020`/`-32602` matrix and 32-vs-33 URIs, and asserts no consumer lookup, rate limit,
      plugin, or composer effect occurs on a boundary refusal. Spec: *Modern-only listen transport* → "Accept and header negotiation
      refused at the boundary"; *Explicit notification-type negotiation* → "Missing notifications rejected",
      "resourceSubscriptions bounded, refused, never advertised".
- [x] 1.6 Modify `pkg/api/handler/http/mcp/modern_validation.go`: add `Accept` to `modernRequestHeaders`; `subscriptions/listen` must
      not carry `Mcp-Name` (the inverse of the `tasks/*` binding).
      **Accept**: dual-era delta *Modern request validation* → "listen Accept and Mcp-Name binding"; every existing
      `modern_validation_test.go` case stays green.
- [x] 1.7 Modify `pkg/api/handler/http/mcp/mcp_handler.go` + `rpc_dispatcher.go`: `SubscriptionsSupport` struct with
      `Enabled() bool` (`On && Registry != nil && Policy != nil`) mirroring `TasksSupport`; `subscriptions/listen` joins
      `isSupportedModernMethod` **only** when `subs.Enabled()`; dispatch branch, listen span, and **one** rate-limit `Check` at open.
      In this commit the branch validates and writes the terminal `SubscriptionsListenResult` as an ordinary buffered result —
      commit 2 replaces that write with the stream.
      **Accept**: with the flag off, `subscriptions/listen` returns HTTP 404 `-32601` byte-identical to today and no capability is
      advertised; with the flag on it never returns `-32601`; a live listen holds no token-bucket slot. Spec: *Modern-only listen
      transport* → "Disabled restores prior behaviour"; dual-era delta → "listen dispatched when enabled, 404 when disabled";
      proposal decision 11.
- [x] 1.8 Modify `pkg/container/modules/mcp.go`: build `SubscriptionsSupport` from `MCPSubscriptionsConfig` and inject it into the
      handler constructor.
      **Accept**: with `MCP_SUBSCRIPTIONS_ENABLED=false` the support value is inert (`Enabled()` false) and no registry or policy is
      constructed, so the default build boots and behaves exactly as before.

## Phase 2: Streaming transport, drain, stream metrics (commit 2 — requires Phase 1)

- [x] 2.1 Create `pkg/api/handler/http/mcp/sse_frame.go` + `sse_frame_test.go`: `frameSink` interface (`Frame`, `Comment`, `Flush`)
      and the `bufioSink` implementation over a fixed-size `*bufio.Writer`; frame is `event: message` + a **single** `data:` line;
      keepalive is `: keepalive`; `ErrFrameTooLarge` when the assembled frame exceeds `MaxEventBytes`.
      **Accept**: golden byte strings assert the exact wire bytes, that **no `id:` field is ever written** (the SDK would treat it as
      a `Last-Event-ID` resumption cursor a stateless gateway cannot honour, D-*sse_frame*), and that the size bound rejects rather
      than truncates. Spec: *Capacity bounds and non-probeable refusal* → "Oversize frame terminates rather than truncates".
- [x] 2.2 Create `pkg/app/mcp/subscription_registry.go` + first half of `subscription_registry_test.go`: `SubscriptionCaps`,
      `SubscriptionRegistry` with all three counters checked and incremented under **one** mutex, `Claim(parent, key)` returning a
      `*SubscriptionLease` whose context is cancelled by `Release` or `Drain`, `sync.Once`-guarded idempotent `Release`, `draining`
      gate flipped under the same mutex as the `sync.WaitGroup` increment, and `Drain(ctx)` cancelling every live lease and waiting
      bounded by `ctx`. Refusal returns `ErrSubscriptionRefused` (locked decision 4).
      **Accept**, under `-race`: double `Release` decrements exactly once; a lease cancelled by `Drain` and then released by its
      writer decrements exactly once; `draining` refuses every subsequent `Claim`; `Drain` with N live leases completes inside the
      budget. Spec: *Deterministic shutdown drain* → "Shutdown completes with live streams".
- [x] 2.3 Create the handler half of `pkg/api/handler/http/mcp/subscriptions_listen.go`: capture `c.UserContext()` and every `c.*`
      value the stream needs (JSON-RPC id, path, honoured subset, isolation key, auth id) into a plain `streamSpec` **before the
      handler returns** (D8 — Fiber recycles `*fiber.Ctx`); `Registry.Claim` under the isolation key; on refusal write the buffered
      `-32026` and open no stream; write `200 text/event-stream` with `Cache-Control: no-cache, no-transform` and
      `X-Accel-Buffering: no`; call `ClaimOpsStream` and read `StreamMetricsFinalizerKey`, setting `StreamMetricsOwnedKey`
      **synchronously**; then `SetBodyStreamWriter`.
      **Accept**: a refusal produces an ordinary buffered JSON-RPC error with no stream ever having existed; no `Mcp-Session-Id` is
      emitted. Spec: *Modern-only listen transport*; *Capacity bounds* → "Refusal does not disturb live streams"; dual-era delta →
      "Streaming adds no transport surface".
- [x] 2.4 Add `runSubscriptionStream(ctx, sink, spec)` to `subscriptions_listen.go`: the single-goroutine loop — ack frame first
      (`notifications/subscriptions/acknowledged` carrying exactly the honoured subset, `_meta` subscription id, flushed
      immediately), then `select` over `leaseCtx.Done()`, keepalive, re-auth tick (branch left as a no-op hook until 3.6) and the
      jittered deadline; one terminal `SubscriptionsListenResult` on **every** exit; unconditional ordered `defer` chain
      `recover()` → `timers.Stop()` → ops finalizer → metrics finalizer → `lease.Release()`, with its own `defer recover()` because
      `PanicRecoverMiddleware` does not wrap fasthttp's stream goroutine. An empty honoured subset acks, writes the terminal frame,
      and closes at once.
      **Accept**: exactly one exit point, so deadline, shutdown, oversize and disconnect are byte-identical on the wire with no
      cause-specific error, message, or `data`. Spec: *Bounded lease lifetime and uniform termination* → "Every termination cause
      looks identical"; *Explicit notification-type negotiation* → "Ack is the first frame", "Empty honoured subset terminates at
      once".
- [x] 2.5 Add `newSubscriptionTimers(lifetime, reauth, keepalive, jitter)` to `subscriptions_listen.go`: three `<-chan time.Time`
      sources plus `Remaining() time.Duration` and `Stop()`, with the jitter function injected as `func(time.Duration) time.Duration`
      over a seeded `*rand.Rand`. `Remaining()` exists now because 3.6 needs it for the skip rule.
      **Accept**: the effective deadline is drawn once at open and lies in `[0.9L, L)`; two leases with one configured `L` differ.
      Spec: *Bounded lease lifetime and uniform termination* → "Deadlines are jittered".
- [x] 2.6 Create `pkg/api/handler/http/mcp/subscriptions_listen_test.go` (loop suite): injected `chan time.Time` for all three
      timers, a fake `Remaining()`, a seeded jitter and a recording `frameSink`. Cases: ack is frame 1; keepalive comment on tick;
      deadline, shutdown via `leaseCtx`, and `ErrFrameTooLarge` each produce the identical terminal frame; empty honoured subset
      closes immediately.
      **Accept**: **zero sleeps and no Fiber app** — the whole suite is table-driven over injected channels (D1), and runs under
      `-race`.
- [x] 2.7 Modify `pkg/api/middleware/mcp_metrics.go` + `mcp_metrics_test.go`: give `MCPMetricsMiddleware.Middleware` the three edits
      `MetricsMiddleware` already has (stash a `StreamMetricsFinalizer`, a `streamed` flag, an owned check after `c.Next()`), and
      **replace the unconditional `c.Response().Body()` call in `buildResponseContext`** with an `IsBodyStream()` guard that passes a
      `nil` body and `Streaming: true` (D9). Today's unconditional call drains the body stream into a buffer and closes it, which
      would consume the entire lease inside the middleware and deliver one burst at close.
      **Accept**: a test asserts `Response().Body()` is never called on a body-stream response, that a claimed stream emits exactly
      once via the finalizer, that frames are observed incrementally, and that the unclaimed non-stream path is unchanged. Spec:
      *Bounded subscription telemetry* → "Middleware never drains a live stream"; *Modern-only listen transport* → "Frames arrive
      incrementally".
- [x] 2.8 Modify `pkg/api/middleware/ops_metrics.go`, `pkg/infra/o11y/provider.go` + `ops_metrics_test.go`: add
      `RouteMCPSubscription Route = "mcp.subscription"`; add `OpsStreamFinalizer` and `ClaimOpsStream(c, route)`, stashing the
      closure over `start`/`plane`/`boundedMethod` before `c.Next()` and skipping the inline `RecordRequest` when claimed — the same
      shape as the metrics middleware, so the codebase has one pattern rather than two. `classifyRoute` is untouched.
      **Accept**: a claimed stream records `mcp.subscription` with the stream's **true duration at close**, not the ~0 ms handler
      unwind that would otherwise poison `mcp.rpc` p50; the unclaimed path is byte-identical. Spec: *Bounded subscription telemetry*
      → "True duration recorded at close"; proposal decision 12.
- [x] 2.9 Modify `pkg/server/server.go` + `pkg/server/http_server.go` + `http_server_test.go`: `type ShutdownHook func(context.Context) error`,
      `(*BaseServer).WithShutdownHooks(hooks ...ShutdownHook)`, `const shutdownHookBudget = 5 * time.Second`, and run the hooks under
      `context.WithTimeout(context.Background(), shutdownHookBudget)` at the **top of `httpServer.Shutdown()`, before
      `s.Router.Shutdown()`** — `fiber.App.Shutdown()` waits for connections to become idle and an SSE stream never does (D12).
      `NewHTTPServer` takes `hooks ...ShutdownHook` so the admin and proxy call sites compile unchanged.
      **Accept**: a latched fake hook proves ordering (hook completes before `Router.Shutdown()` is entered), that the budget is
      honoured, and that a failing hook does not block shutdown. Spec: *Deterministic shutdown drain*.
- [x] 2.10 Modify `pkg/container/modules/mcp.go` + `pkg/container/modules/server_mcp.go`: provide the `SubscriptionRegistry` from
      `MCPSubscriptionsConfig` into `SubscriptionsSupport`, and pass `registry.Drain` as the MCP HTTP server's shutdown hook.
      **Accept**: with the feature disabled no registry is constructed and no hook is registered; with it enabled, shutdown with live
      streams completes rather than hanging (asserted end-to-end in 4.5).

## Phase 3: Negotiation and change detection (commit 3)

- [x] 3.1 Modify `pkg/app/mcp/discovery.go` + `discovery_test.go`: introduce `federateWithStats[T](...) (items []T, degraded bool, err error)`
      and reduce `federate` to a wrapper discarding `degraded`. `degraded` is set by the two fail-open `continue` branches — registry
      skipped for unavailability or pending consent.
      **Accept**: every existing `federate` caller is byte-identical (the existing discovery tests pass unedited), and a new test
      proves `degraded` is true exactly when a registry was skipped. This is the change the design flagged as *not anticipated by the
      proposal*: without it a transient upstream blip shrinks the composed surface, fires a spurious `list_changed`, then fires
      another on recovery — a client-visible re-list storm caused by nothing changing (D6).
- [x] 3.2 Create `pkg/app/mcp/subscription_policy.go`: `LeaseIdentity`, `SurfaceSnapshot` (per-kind digest + `Degraded`),
      `Evaluation`, and the `SubscriptionPolicy` interface with `//go:generate mockery`. `Evaluate` re-runs the prologue without
      Fiber, in order — `DataFinder.FindByGateway` → `data.MatchPath` → `TypeMCP` → `hasAuth` → `ProtocolAcceptance() != legacy_only`
      → `RoleScoper.Scope` → role-scope fingerprint match → per honoured kind `Composer.List*` + digest — returning
      `ErrSubscriptionRevoked` at the first refusal and treating any other error as transient. Digest is `sha256` over the
      **composed, role-scoped, exposed** surface per kind, sorted by exposed name, truncated to 12 hex chars, with
      `ListResourceTemplates` folded into the resources digest (locked decision 1). Inputs are re-resolved, never read from a frozen
      `appconsumer.DataFromContext` snapshot (D7).
      **Accept**: a degraded pass keeps `prev` and returns no changed kinds. Spec: *Every emission is a fresh authorization decision*.
- [x] 3.3 Add `ReauthBudget(reauth, keepalive) time.Duration` to `subscription_policy.go`: `min(reauth, keepalive)/2` clamped to
      `[1s, 8s]` (7.5 s with the defaults).
      **Accept**: a unit test pins both clamp ends and the default. This is the **bound the design flagged as easy to forget**:
      `discoverCached` → `askUpstream` → `c.target()` → `dialer.Connect` has no deadline of its own, `singleflight` makes concurrent
      streams wait together, and the lease context is not request-cancelled — so without the bound a dead upstream parks the loop,
      stops keepalives, and lets the fasthttp write deadline sever the connection (D2, design *Concurrency contract*).
- [x] 3.4 Create `pkg/app/mcp/subscription_policy_test.go`: revocation matrix (role loss, registry detach, toolkit drops the kind,
      `legacy_only`, auth removed, role-scope fingerprint drift); degraded pass keeps `prev` and emits nothing; digest stable across
      identical composes and changing on add / remove / rename; digest determinism over **100 repetitions of a shuffled payload map**
      (D5 — `encoding/json` sorts map keys, so the envelope is byte-stable); `ReauthBudget` clamps.
      **Accept**: mocked `DataFinder`, `RoleScoper`, `Composer`; no real clock, no sleeps; `-race`. Spec: *Every emission is a fresh
      authorization decision* → "Revocation terminates rather than narrows", "Unchanged surface emits nothing".
- [x] 3.5 Regenerate `pkg/app/mcp/mocks/` for `SubscriptionPolicy` via `go:generate mockery`.
      **Accept**: generated file only; no hand edits.
- [x] 3.6 Wire the re-auth tick into `runSubscriptionStream` (`subscriptions_listen.go`) + extend `subscriptions_listen_test.go`:
      **skip the tick entirely when `timers.Remaining() < spec.budget`**, otherwise run `Evaluate` under
      `context.WithTimeout(leaseCtx, spec.budget)`; revoked ⇒ terminate; degraded or transient ⇒ keep the previous snapshot, emit
      nothing, increment a consecutive-failure counter, terminate at three; changed kinds ⇒ one `list_changed` frame each, in the
      deterministic `HonouredSet.Kinds()` order.
      **Accept**: table tests prove emit-on-change, silence-on-unchanged, silence-on-degraded, revoke-terminates,
      three-inconclusive-terminates, and that **no pass is ever in flight when the deadline fires** — so the terminal frame always
      lands at ≤ `MaxLifetime` with the full 10 s of write budget intact (D2/D3). Spec: *Every emission is a fresh authorization
      decision* → "Surface change emits exactly one notification", "Non-honoured kinds are never emitted"; *Bounded lease lifetime*
      → "Deadline closes cleanly, never mid-frame".
- [x] 3.7 Modify `subscription_validation.go` + `subscription_validation_test.go`: replace the 1.5 stub with the real intersection —
      requested kinds ∩ the kinds `configuredCapabilities` allows for this role-scoped consumer.
      **Accept**: the honoured subset never contains a type the client did not request nor a primitive kind the principal cannot see;
      a prompts-only principal requesting tools and prompts is honoured prompts alone. Spec: *Explicit notification-type negotiation*
      → "Role scope narrows the honoured subset", "Ack is the first frame and carries only the honoured subset".
- [x] 3.8 Modify `pkg/api/handler/http/mcp/server_discover.go` + `server_discover_test.go`: rename
      `serverDiscoveryResultWithTasks` → `serverDiscoveryResultWith(rc, mrtr, tasks, listChanged bool)`; add `addListChanged`
      **mutating** each existing per-kind map after the `configuredCapabilities` loop (`addCapability` replaces the whole map per
      toolkit entry, so an in-loop write would be wiped); add
      `subscriptionsEndToEnd(subs, rc) = subs.Enabled() && appmcp.HasNonLegacyMCPRegistry(rc)`, decided locally with no dial.
      **Accept**: order is kinds → `listChanged` → `extensions`; `tools` retains `inputRequests` when MRTR is end-to-end; a denied
      kind stays absent; `resources.subscribe` is **never** present; disabled omits `listChanged`; legacy `initialize`
      (`mcp_handler.go:492-494`) stays byte-identical at `listChanged: false` and never gains `subscribe`. Dual-era delta:
      *Role-scoped discovery* → "listChanged advertised or hidden, subscribe never", "Legacy initialize never advertises".
- [x] 3.9 Modify `pkg/api/handler/http/mcp/modern_response.go`: normalize the terminal `SubscriptionsListenResult` through
      `normalizeModernResult` (`resultType: "complete"`, `ttlMs: 0`, `cacheScope: "private"`, subscription id), and make notification
      frames bypass result normalization entirely.
      **Accept**: an ack or `list_changed` frame carries no `resultType`, `ttlMs`, or `cacheScope`, while the terminal frame carries
      all three. Dual-era delta: *Modern response and caching* → "Notification frames are not results".

## Phase 4: Isolation and adversarial verification (commit 4)

- [x] 4.1 Extend `pkg/app/mcp/subscription_registry_test.go`: full cap matrix (process / consumer / principal); **256 concurrent
      claims yield exactly `MaxStreams`**; the refusal message is byte-identical whichever cap was reached and carries no `data`.
      **Accept**: `-race` with `sync.WaitGroup` fan-in; a byte comparison, not a substring match, so caps cannot be used as an
      occupancy oracle. Spec: *Capacity bounds and non-probeable refusal* → "Refusals are indistinguishable across caps".
- [x] 4.2 Add the goroutine-leak assertions across the registry, loop, and handler suites: count returns to baseline after
      **disconnect, deadline, re-authorization refusal, capacity reclaim, and shutdown**, and exactly one goroutine exists per live
      stream.
      **Accept**: `runtime.GC()` + `runtime.NumGoroutine()` with a `baseline+2` tolerance, matching
      `pkg/infra/providers/stream_test.go:131-149`, run under **`-race`**. Spec: *Deterministic shutdown drain* → "No goroutine leak
      on any termination path".
- [x] 4.3 Add the memory assertions to `subscriptions_listen_test.go`, using `runtime.ReadMemStats` after two `runtime.GC()` passes:
      **A (ceiling)** — with `N = 64` concurrent streams, `(HeapInuse_streams − HeapInuse_baseline) / N ≤ 64 KiB`;
      **B (drift, the sharp one)** — between **tick 5 and tick 20** the same per-stream quantity grows by **≤ 4 KiB**. Both are also
      asserted for a client that never reads from the socket.
      **Accept**: anything that accumulates per frame — a captured body, an unbounded emitted-kind history, a `[]Tool` retained
      across ticks — fails B long before it fails A. Ticks are driven by injected channels, not sleeps. Spec: *Capacity bounds and
      non-probeable refusal* → "A consumer that never reads is bounded".
- [x] 4.4 Add isolation tests to the MCP handler suite with a scripted composer: two principals on one consumer with disjoint role
      scopes; two consumers on one gateway; two registries sharing a resource URI and a discovery cache entry.
      **Accept**: only the principal whose own authorization pass produced the change emits; no notification crosses a consumer,
      principal, role scope, or registry boundary. Spec: *Stream isolation* → all three scenarios.
- [x] 4.5 Add the integration test to the MCP handler suite: a real Fiber app with `WriteTimeout: 12s` and explicit
      `MaxLifetime: 1s` (valid, since `1 + 10 ≤ 12`) exercising open → ack → keepalive → deadline in ~1 s, plus shutdown with N live
      streams completing inside the drain budget.
      **Accept**: **clean close with no `unexpected EOF`**, frames observed incrementally rather than as one burst at close, and no
      `Mcp-Session-Id` header. This is the **only** place a real clock is used. Spec: *Bounded lease lifetime and uniform
      termination* → "Deadline closes cleanly, never mid-frame"; *Deterministic shutdown drain* → "Shutdown completes with live
      streams".
- [x] 4.6 Regression gate — run the existing MCP suites **unedited**: `MCP_SUBSCRIPTIONS_ENABLED=false` ⇒ `-32601` byte-identical,
      legacy `initialize` capabilities byte-identical, `GET`/`DELETE` ⇒ 405 with `Allow: POST`, legacy-era `subscriptions/listen`
      falls out as an unknown legacy method.
      **Accept**: passing verbatim is the gate — no test file in the existing suites is modified. Spec: *Modern-only listen
      transport* → "Legacy era and non-POST unchanged"; dual-era delta → "Legacy client cannot reach the listen path".

## Phase 5: Telemetry, specs, docs, verify (commit 5)

- [x] 5.1 Modify `pkg/api/handler/http/mcp/protocol_metrics.go`: `SubscriptionsRecorder` + `NewSubscriptionsRecorder` mirroring
      `NewTasksRecorder` (nil-recorder when `Telemetry.OpsMetricsEnabled` is false):
      `mcp.northbound.subscriptions.outcome_total{kind, outcome, era}` and the `mcp.northbound.subscriptions.live` up/down counter.
      **Accept**: `live` returns to zero after every termination path. Spec: *Bounded subscription telemetry*.
- [x] 5.2 Modify `pkg/infra/trace/span.go`: bounded `SubscriptionKind*` / `SubscriptionOutcome*` enumerations,
      `BoundSubscriptionKind`, `BoundSubscriptionOutcome`, `SetMCPSubscription`. Outcomes are
      `opened|acked|emitted|deadline|revoked|refused|degraded|shutdown|disconnected|oversize`.
      **Accept**: no subscription id, JSON-RPC id, or resource URI field exists on the span at all.
- [x] 5.3 Add telemetry tests: an unknown kind or outcome is **dropped rather than emitted**, and no resource URI, notification
      payload, subscription id, JSON-RPC id, principal identifier, token, consumer slug, or tenant free text reaches any metric,
      span, or log — including the metrics finalizer, which passes a `nil` body (D9).
      **Accept**: spec *Bounded subscription telemetry* → "Bounded labels with no content".
- [x] 5.4 Publish the openspec deltas: apply `specs/mcp-dual-era-northbound/spec.md` onto
      `openspec/specs/mcp-dual-era-northbound/spec.md` and create `openspec/specs/mcp-subscriptions/spec.md` from
      `specs/mcp-subscriptions/spec.md`.
      **Accept**: the five modified dual-era requirements carry their `(Previously: …)` lines, every `### Requirement:` in the new
      capability has at least one `#### Scenario:`, and no requirement outside the delta is touched (diff-reviewed against the
      pre-change `openspec/specs/mcp-dual-era-northbound/spec.md`).
- [x] 5.5 Create `docs/mcp/subscriptions.md` (~180 lines) — the dual-era operator and client doc the design names, alongside
      `dual-era-rollout.md` and `tasks-extension.md`. Contents: **streams are ephemeral by design**, re-issue `subscriptions/listen`
      on the terminal result; the nine env vars and the fail-fast lifetime rule with both env-var names; LB/ingress guidance
      (`no-transform`, `X-Accel-Buffering`, keepalive below the shortest hop timeout); and the four documented limitations —
      upstream-originated changes are only visible after the 5-minute `mcp_tools` TTL so a 290 s lease may never observe one;
      disconnect detection is bounded by the keepalive interval, so a dead peer holds a slot for up to 15 s; a cancel must be a
      transport-level abort of the listen request, not a separate `notifications/cancelled` POST (D11); a client that never reads is
      severed by `SERVER_WRITE_TIMEOUT` and sees `unexpected EOF` instead of the terminal frame. Add a one-line cross-link from
      `docs/mcp/dual-era-rollout.md`.
      **Accept**: every documented limitation traces to a design *Push-back* or the *Re-authorization Cost* section; the locked
      decision 2 behaviour (a config edit terminates streams) is stated explicitly.
- [x] 5.6 Modify `docs/operational-metrics.md` (~40 lines): the two new counters and their bounded label sets, the
      `route: mcp.subscription` class and why MCP-plane latency now reflects true stream duration, and the 5 s shutdown drain budget.
      **Accept**: no label is documented that the bounded enumerations cannot produce.
- [x] 5.7 Verify: `go test ./... -race`, `go vet ./...`, `golangci-lint run`, `gofmt`; clean-comments pass over every touched Go
      file (doc comments on exported identifiers only, no narrative).
      **Accept**: all clean; success criteria in `proposal.md` re-checked against the implementation before the PR is opened.

## Delivery

**One PR** against `feat/run-1103-dual-era-northbound-protocol-boundary` with **`size:exception`** — one PR per issue for epic
RUN-1100, **not** chained PRs. Five sequenced commits on `feat/run-1104-bounded-mcp-subscriptions`, in order.

- **Commit 1 is behaviour-neutral and independently shippable**: the kill switch defaults to `false`, `subscriptions/listen` stays
  out of the modern method set, discovery omits `listChanged`, `Config.Validate()` skips the lifetime rule, and no registry or
  policy is constructed.
- **Commit 2 must not ship without commit 1.** Its metrics-middleware and shutdown-drain work is independently useful and safe to
  keep across a revert of the rest.
- **Reviewer focus: commits 2 and 4** — the streaming transport and the adversarial verification carry all the risk.
- Rollback is `MCP_SUBSCRIPTIONS_ENABLED=false` with no deploy; live streams self-terminate within one lifetime (≤ 290 s in prod),
  each with the normal terminal frame. Nothing is persisted, so a full `git revert` of the range has no data migration.

## Deferred

- Proxy-plane zero-margin `providers.StreamTimeout` vs `SERVER_WRITE_TIMEOUT=300s` in all three overlays (design Q2) — **raise as its
  own RUN issue**; explicitly not fixed here.
- Southbound `subscriptions/listen`, `SubscriptionUpstream`, any long-lived upstream read loop.
- Honouring `resourceSubscriptions` / `notifications/resources/updated` — blocked on per-registry resource URI namespacing.
- Token-expiry-derived lease deadlines (proposal decision 10); revisit only if the write-timeout ceiling is ever raised.
- `guardedUpstream` / `TaskUpstream` gap (`negotiating_dialer.go:203`) — separate RUN issue.
