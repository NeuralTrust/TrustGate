# Design: RUN-1104 add bounded MCP subscriptions

**Change**: `run-1104-bounded-mcp-subscriptions` · **Linear**: [RUN-1104](https://linear.app/neuraltrust/issue/RUN-1104) — epic [RUN-1100](https://linear.app/neuraltrust/issue/RUN-1100)
**Branch**: `feat/run-1104-bounded-mcp-subscriptions` · **Base**: `feat/run-1103-dual-era-northbound-protocol-boundary`
**Inputs**: `exploration.md`, `proposal.md` (decisions 1–12 locked), `specs/mcp-subscriptions/spec.md`, `specs/mcp-dual-era-northbound/spec.md`

## Technical Approach

A subscription is a **lease**, not a session. `subscriptions/listen` runs the unchanged policy prologue
in `Handler.Handle` and then, instead of `writeRPCResult`, takes a `SetBodyStreamWriter` branch
modelled exactly on `proxy_handler.go:152-204`. The fasthttp body-stream writer is the only goroutine:
it writes the ack, then `select`s on the lease context, a re-auth ticker, a keepalive ticker and a
jittered deadline timer, and finally writes one terminal `SubscriptionsListenResult` and returns.

Everything the loop decides is pulled out of the transport into two app-layer objects so it is testable
without Fiber: `SubscriptionRegistry` (capacity accounting, lease contexts, shutdown drain) and
`SubscriptionPolicy` (the re-authorization pass and the per-kind surface digest diff). The transport
owns SSE framing, header negotiation and the `bufio.Writer`; the app layer owns *what a tick means*.

Three cross-cutting fixes ship in the same change because the streaming path is unsafe without them:
the MCP metrics middleware must stop calling `Response().Body()` on a body stream, the ops middleware
must report the stream's true duration, and `httpServer.Shutdown()` must drain leases before
`Router.Shutdown()` waits on connections that will never go idle.

## Architecture Decisions

| # | Decision | Chosen | Rejected | Rationale |
|---|---|---|---|---|
| D1 | Where the loop lives | Pure loop `runSubscriptionStream(ctx, frameSink, streamSpec)` in `subscriptions_listen.go`, driven by injected `<-chan time.Time`; `frameSink` is an interface with a `*bufio.Writer` impl and a recording test impl | Loop inside the `SetBodyStreamWriter` closure against `*bufio.Writer` directly | Keeps the transport transport-only in spirit (framing + sockets) while making every tick-ordering, jitter and termination assertion a table-driven unit test with **no sleeps and no Fiber app** |
| D2 | Re-auth is inline, but **bounded** | The pass runs in the writer's `select` under `context.WithTimeout(leaseCtx, ReauthBudget)`, and a tick is **skipped entirely** when `timers.Remaining() < budget` | Second goroutine + result channel; unbounded inline pass | Proposal decision 6 (writer is the producer) survives only with a bound — see *Concurrency contract*. `discoverCached` → `askUpstream` → `c.target()` → `dialer.Connect` can block on a dead upstream for as long as the transport allows, and the loop holds the deadline timer. A second goroutine does not fix that; a timeout does, and doing it inline makes a leak structurally impossible |
| D3 | What the 10 s margin actually buys | Terminal frame is written at ≤ `MaxLifetime`, leaving a full 10 s of fasthttp write-deadline budget for a ~200-byte frame | Margin as a round safety number | A reader that cannot absorb 200 bytes in 10 s is indistinguishable from a dead one. This makes the margin a *provable* property (clean close, never `unexpected EOF`) rather than a guess, and it is why D2 skips a pass that cannot finish before the deadline |
| D4 | Fingerprint source | `sha256` over the **composed, role-scoped, exposed** surface per kind (`ListTools` / `ListPrompts` / `ListResources` + `ListResourceTemplates`), sorted by exposed name, truncated to 12 hex chars like `surfaceFingerprint` | Reuse `surfaceFingerprint(rc)` (config-only); hash exposed names only | `surfaceFingerprint` hashes registry `UpdatedAt` + toolkit entries, so it is blind to an upstream adding a tool and to a role-scope change. Hashing the composed surface catches config change, role change, and upstream add/remove/schema change once the 5-minute discovery TTL rolls |
| D5 | Fingerprint determinism | `Tool`/`Prompt`/`Resource` marshal a `map[string]json.RawMessage` envelope, and `encoding/json` sorts map keys, so `json.Marshal` of the sorted slice is byte-stable for identical upstream bytes | Hand-rolled canonical serializer | Zero new code, and the property is asserted directly by a round-trip test. A re-serialization difference upstream is a real byte change, and a false positive is one spurious `list_changed` — safe, unlike a false negative |
| D6 | Degraded passes must not emit | `federate` gains an internal stats variant reporting whether any registry was skipped; a pass with `Degraded=true` keeps the previous snapshot and emits nothing | Emit on whatever the partial federation returned | `federate` is fail-open by default (`discovery.go:126-131`): a transient upstream blip shrinks the composed surface, which would fire `list_changed`, then fire it again on recovery. That is a client-visible re-list storm caused by *nothing changing*. Fail-closed consumers are already covered because `federate` errors instead |
| D7 | Where the pass reads its inputs | `SubscriptionPolicy.Evaluate` re-resolves `Data` through `DataFinder.FindByGateway`, then `data.MatchPath(path)`, `hasAuth`, acceptance, `RoleScoper.Scope` | Reuse `appconsumer.DataFromContext(ctx)` | The context snapshot is frozen at request time, so reusing it would make revocation and toolkit edits permanently invisible — the exact failure the spec's "fresh authorization decision" requirement exists to prevent |
| D8 | Lease context parent | `registry.Claim(capturedUserCtx, key)` where `capturedUserCtx := c.UserContext()` is captured **before** the handler returns; every `c.*` value the stream needs (path, id, headers, honoured subset) is copied into a plain struct at the same point | Hold `*fiber.Ctx` in the writer | Fiber pools `*fiber.Ctx` and recycles it once the handler returns, but the `context.Context` it held is an immutable value that keeps the trace and principal alive. The proxy already copies `req.Body` for this reason (`proxy_handler.go:168`) |
| D9 | Metrics body for a stream | The MCP stream finalizer passes `nil` output and `Streaming: true`; no per-stream capture buffer exists | Mirror the proxy's `var captured bytes.Buffer` | The telemetry requirement forbids a notification payload or subscription id in any metric, span or log, so capturing frames would have to be scrubbed anyway. Passing nothing is both the compliant and the bounded choice, and it removes the only structure that grows with stream length |
| D10 | Ops duration | `middleware.ClaimOpsStream(c, o11y.RouteMCPSubscription)` returns a finalizer the writer calls at close; the middleware skips its own `RecordRequest` when claimed | Leave `ops_metrics.go` recording at handler unwind | Otherwise every stream reports ~0 ms and `mcp.rpc` latency is silently poisoned by a route whose real p50 is minutes (proposal decision 12) |
| D11 | `notifications/cancelled` | Stays a 202 no-op as `mcp-dual-era-northbound` mandates. A client cancelling its listen cancels the **HTTP request**, which the stream observes as disconnect at the next write | Build a JSON-RPC-id → live-stream index so a separate POST can address a stream | That index is cross-request session state, which is precisely what decision 7 keeps out of the registry. The observable outcome is identical (same terminal shape, no discriminator), so the spec requirement holds — see *Push-backs* |
| D12 | Drain hook placement | `BaseServer.WithShutdownHooks(...)`, run with a 5 s package-constant budget at the top of `httpServer.Shutdown()`, before `Router.Shutdown()` | Drain from `runServers`; `ShutdownWithTimeout` | `fiber.App.Shutdown()` waits for connections to become idle and an SSE stream never does, so the drain has to precede it. Hooks are variadic, so the admin and proxy call sites are unchanged. Not a config knob: the loop's first `select` case is `ctx.Done()` and the terminal write is one flush, so 5 s is generous by orders of magnitude |

## Resolved Open Questions

### Q1 — `listChanged` merges with `inputRequests`; order is kinds → listChanged → extensions

**Merge, in place, as a third post-pass.** `serverDiscoveryResultWithTasks` is renamed
`serverDiscoveryResultWith(rc, mrtr, tasks, listChanged bool)` and becomes:

```go
capabilities := configuredCapabilities(rc, mrtr) // 1. which kinds exist at all
addListChanged(capabilities, listChanged)        // 2. merge into each kind's map
addTasksExtension(capabilities, tasks)           // 3. top-level sibling key
```

The order is forced by the real code, not by taste. `addCapability` (`server_discover.go:78-84`)
**replaces** the whole per-kind map on every call:

```go
capabilities[kind] = map[string]any{"inputRequests": map[string]any{}} // or {}
```

and `configuredCapabilities` calls it once **per toolkit entry** (`server_discover.go:65-74`). A
`listChanged` written from inside that loop would be wiped by the next entry for the same kind. So
`addListChanged` has to run after the loop completes, and it mutates the existing map rather than
assigning a new one:

```go
func addListChanged(capabilities map[string]any, on bool) {
	if !on {
		return
	}
	for _, kind := range []string{"tools", "prompts", "resources"} {
		existing, ok := capabilities[kind].(map[string]any)
		if !ok {
			continue // denied kind stays absent
		}
		existing["listChanged"] = true
	}
}
```

`addTasksExtension` writes `capabilities["extensions"]`, a top-level sibling, so steps 2 and 3 touch
disjoint keys and commute; the fixed order is what the tests assert. Note `mrtr_caps.go` is **not**
involved in advertisement at all — it owns the northbound client-capability allowlist. The only other
`listChanged` in the codebase is legacy `initialize` (`mcp_handler.go:492-494`), which stays
byte-identical at `false` and never gains `subscribe: true`.

Result for a tools+prompts consumer with MRTR and subscriptions both end-to-end:

```json
{
  "tools":      {"inputRequests": {}, "listChanged": true},
  "prompts":    {"listChanged": true},
  "extensions": {"io.modelcontextprotocol/tasks": {}}
}
```

`subscriptionsEndToEnd(subs, rc) = subs.Enabled() && appmcp.HasNonLegacyMCPRegistry(rc)`, mirroring
`tasksEndToEnd` (`server_discover.go:96-98`) — decided locally, no dial.

### Q2 — RUN-1104 does not touch the proxy plane

**Confirmed: no proxy-plane change.** The finding is real and is being raised as a separate issue.

`providers.StreamTimeout = 5 * time.Minute` (`stream.go:30`) is applied as
`context.WithTimeout(ctx, StreamTimeout)` around the upstream read, while all three overlays set
`SERVER_WRITE_TIMEOUT=300s` under a comment that reads *"Must stay above the 5m StreamTimeout"*
(`k8s/overlays/{dev,prod,prod-us}/config.env:13-15`). 300 s is not above 5 m; the margin is **zero**.
A proxy stream that runs to its full timeout races the fasthttp write deadline, and whichever fires
first decides whether the client sees a clean end or `unexpected EOF`.

Reasons not to fix it here: the proxy plane is the highest-traffic path in the product and this change
already carries a `size:exception`; changing `StreamTimeout` or the overlays is a behaviour change on a
path this proposal explicitly lists as unchanged; and the two planes want different answers — the proxy
bounds an *upstream read* it does not control, the MCP plane bounds a *lease it issues itself*, which
is exactly why the MCP plane can afford to fail fast at boot and the proxy plane cannot.

**How an operator reads the difference.** One rule, applied twice with different confidence:

| Plane | Bound | Margin | Enforcement | If the operator gets it wrong |
|---|---|---|---|---|
| MCP subscriptions | `MCP_SUBSCRIPTIONS_MAX_LIFETIME` | 10 s, fixed | `Config.Validate()` refuses to boot | Pod never starts; the error names both env vars and both values |
| Proxy streaming | `providers.StreamTimeout` (compile-time) | 0 s today | none | A long stream may be severed mid-frame and look like a network fault |

The MCP margin is strict because TrustGate chose the number and must therefore guarantee the clean
close the spec promises. The proxy margin is zero because nobody chose it — it is an artifact of two
constants that happen to be equal. Operators who raise `SERVER_WRITE_TIMEOUT` improve both planes;
operators who lower it below `310s` will now be told at boot, which is a strict improvement even for
proxy users, because the MCP plane refuses first and loudly.

### Q3 — Bounded memory is asserted as ≤ 64 KiB steady state and ≤ 4 KiB drift over 15 ticks

Per-stream retained memory, from the actual allocations:

| Source | Bytes | Note |
|---|---|---|
| fasthttp read + write buffer | 16 KiB | `server.go:57-58`, charged to any connection, not just a stream |
| `SetBodyStreamWriter` `bufio.Writer` | ≤ 8 KiB | fixed size, never grows |
| One frame scratch buffer | ≤ 8 KiB | `MCP_SUBSCRIPTIONS_MAX_EVENT_BYTES` |
| Lease state | < 1 KiB | isolation key, 3× 12-char digest, honoured subset, 2 tickers, 1 timer |
| Capture buffer | **0** | removed by D9 |

Nominal ≈ 17 KiB excluding the shared connection buffers. Two assertions:

- **A — ceiling.** With `N = 64` concurrent streams, `(HeapInuse_streams − HeapInuse_baseline) / N ≤ 64 KiB`,
  measured after two `runtime.GC()` passes. ~3.7× headroom over nominal: loose enough not to flake,
  tight enough that any per-stream accumulator is caught.
- **B — no drift, the sharp one.** Between tick 5 and tick 20 the same quantity grows by **≤ 4 KiB per
  stream**. Anything that accumulates per frame (a captured body, an unbounded emitted-kind history,
  a `[]Tool` retained across ticks) fails B long before it fails A.

A third case, the client that never reads: the `bufio.Writer` is fixed size, so `w.Flush()` blocks on
the socket rather than buffering. Memory does not grow — A and B are asserted for that case too — and
the stream is torn down by the fasthttp write deadline at `SERVER_WRITE_TIMEOUT`, 10 s after its own
lease deadline. See *Push-backs* for what that means for the uniform-termination requirement.

## Interfaces / Contracts

### `pkg/app/mcp/subscriptions.go` (new)

```go
type NotificationKind string

const (
	NotificationKindTools     NotificationKind = "toolsListChanged"
	NotificationKindPrompts   NotificationKind = "promptsListChanged"
	NotificationKindResources NotificationKind = "resourcesListChanged"
)

// BoundNotificationKind maps a client-supplied string onto the fixed enumeration.
func BoundNotificationKind(raw string) (NotificationKind, bool)

// Method returns the JSON-RPC notification method for the kind.
func (k NotificationKind) Method() string // notifications/{tools,prompts,resources}/list_changed

// HonouredSet is the intersection of what the client asked for with what the
// role-scoped surface can actually produce.
type HonouredSet struct{ tools, prompts, resources bool }

func (h HonouredSet) Kinds() []NotificationKind // deterministic order: tools, prompts, resources
func (h HonouredSet) Has(k NotificationKind) bool
func (h HonouredSet) Empty() bool

// IsolationKey is the accounting and evaluation identity of a stream.
type IsolationKey struct {
	GatewayID  string
	ConsumerID string
	Principal  string // principalFingerprint(ctx), full digest
	RoleScope  string
}

func NewIsolationKey(ctx context.Context, rc *appconsumer.RoutableConsumer) IsolationKey

// SurfaceConfigFingerprint is the existing handler-local surfaceFingerprint,
// lifted so the role-scope component of an IsolationKey and legacy initialize
// share one algorithm.
func SurfaceConfigFingerprint(rc *appconsumer.RoutableConsumer) string
```

`mcp_handler.go`'s `surfaceFingerprint` becomes a one-line delegation to `SurfaceConfigFingerprint`;
its existing tests are the behaviour-preservation gate and are not edited.

### `pkg/app/mcp/subscription_registry.go` (new)

```go
type SubscriptionCaps struct{ MaxStreams, MaxPerConsumer, MaxPerPrincipal int }

// SubscriptionRegistry accounts live streams. It fans nothing out: no event ever
// leaves the stream that produced it.
type SubscriptionRegistry struct {
	mu           sync.Mutex
	caps         SubscriptionCaps
	total        int
	perConsumer  map[string]int
	perPrincipal map[string]int
	live         map[*SubscriptionLease]struct{}
	draining     bool
	wg           sync.WaitGroup
}

func NewSubscriptionRegistry(caps SubscriptionCaps) *SubscriptionRegistry

// Claim reserves capacity and returns a lease whose context is cancelled by
// Release or by Drain. It returns ErrSubscriptionRefused when any cap is
// reached or the registry is draining.
func (r *SubscriptionRegistry) Claim(parent context.Context, key IsolationKey) (*SubscriptionLease, error)

// Drain cancels every live lease and waits for their writers to release,
// bounded by ctx. Called before Router.Shutdown().
func (r *SubscriptionRegistry) Drain(ctx context.Context) error

func (r *SubscriptionRegistry) Live() int

type SubscriptionLease struct {
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
	// ...
}

func (l *SubscriptionLease) Context() context.Context
func (l *SubscriptionLease) Release() // idempotent
```

**Claim/release ordering.** All three counters are checked and incremented under one mutex, so two
concurrent listens can never both pass the last slot. `Claim` runs in the handler **before** any byte
is written, so a refusal is an ordinary buffered `-32026` JSON-RPC error with a 200-status stream never
having existed — satisfying *"a refusal MUST take effect before any stream is opened"*. `Release` is
`sync.Once`-guarded and called from the writer's `defer`; `Drain` may also observe the same lease, and
double release is a no-op. `draining = true` makes every subsequent `Claim` refuse, so shutdown cannot
race a new stream into the wait group.

### `pkg/app/mcp/subscription_policy.go` (new)

```go
// LeaseIdentity is everything a re-authorization pass needs, captured at open.
// It deliberately holds no *fiber.Ctx and no consumer Data snapshot.
type LeaseIdentity struct {
	Key       IsolationKey
	GatewayID ids.GatewayID
	AuthID    ids.AuthID
	Path      string
	Honoured  HonouredSet
}

// SurfaceSnapshot is one pass's per-kind digest. An unhonoured kind is "".
type SurfaceSnapshot struct {
	Tools, Prompts, Resources string
	Degraded                  bool // a registry was skipped; the pass is inconclusive
}

type Evaluation struct {
	Changed  []NotificationKind
	Snapshot SurfaceSnapshot
}

//go:generate mockery --name=SubscriptionPolicy ...
type SubscriptionPolicy interface {
	Evaluate(ctx context.Context, id LeaseIdentity, prev SurfaceSnapshot) (Evaluation, error)
}

// ReauthBudget bounds one pass so a slow upstream cannot stall the writer.
func ReauthBudget(reauth, keepalive time.Duration) time.Duration // min/2, clamped to [1s, 8s]
```

`Evaluate` re-runs the prologue without Fiber, in order, returning `ErrSubscriptionRevoked` at the
first refusal: `DataFinder.FindByGateway(gatewayID)` → `data.MatchPath(path)` → consumer is
`TypeMCP` → `hasAuth(rc, authID)` → `ProtocolAcceptance() != legacy_only` → `RoleScoper.Scope` →
`SurfaceConfigFingerprint(scoped) == id.Key.RoleScope` → per honoured kind, `Composer.List*` and a
digest. Any other error (`ErrUpstreamUnavailable`, `context.DeadlineExceeded`) is transient, not a
revocation. `MatchPath` is on the app-layer `Data` and `ProtocolAcceptance` is domain, so the policy
imports nothing from transport.

### `pkg/app/mcp/discovery.go` (modified)

`federate` is re-expressed on a stats-carrying variant so a degraded pass is detectable:

```go
func federateWithStats[T any](...) (items []T, degraded bool, err error)

func federate[T any](...) ([]T, error) {
	items, _, err := federateWithStats[T](...)
	return items, err
}
```

`degraded` is set when a registry was skipped for unavailability or pending consent — the two
`continue` branches at `discovery.go:118-131`. Existing callers are byte-identical.

### `pkg/api/handler/http/mcp/sse_frame.go` (new)

```go
// frameSink is the narrow write surface a stream needs, so the loop can be
// tested without fasthttp.
type frameSink interface {
	Frame(payload []byte) error   // event: message\ndata: <payload>\n\n
	Comment(text string) error    // : <text>\n\n
	Flush() error
}

type bufioSink struct {
	w        *bufio.Writer
	maxBytes int
}
```

The frame is `event: message` + a single `data:` line. `event: message` is emitted explicitly even
though the SDK defaults an unnamed event to `message`, because explicit is byte-checkable. **No `id:`
field** — the SDK treats an event id as a resumption cursor it may replay via `Last-Event-ID`, and a
stateless gateway cannot honour that. Keepalive is `: keepalive\n\n`, which the SDK's scanner drops as
a comment. `bufioSink.Frame` returns `ErrFrameTooLarge` when the assembled frame exceeds
`MCP_SUBSCRIPTIONS_MAX_EVENT_BYTES`, and the loop turns that into a normal termination — never a
truncated write.

### `pkg/api/handler/http/mcp/subscriptions_listen.go` (new)

```go
type SubscriptionsSupport struct {
	On             bool
	MaxLifetime    time.Duration
	ReauthInterval time.Duration
	Keepalive      time.Duration
	MaxEventBytes  int
	MaxURIs        int
	Registry       *appmcp.SubscriptionRegistry
	Policy         appmcp.SubscriptionPolicy
	Recorder       SubscriptionsRecorder
}

// Enabled reports whether the feature can serve a stream at all. The field is
// On rather than Enabled so the predicate keeps the TasksSupport name.
func (s SubscriptionsSupport) Enabled() bool { return s.On && s.Registry != nil && s.Policy != nil }

// streamSpec is everything the loop needs, captured before the handler returns.
type streamSpec struct {
	id       json.RawMessage // the listen call's JSON-RPC id, stamped on every frame
	identity appmcp.LeaseIdentity
	policy   appmcp.SubscriptionPolicy
	timers   subscriptionTimers
	budget   time.Duration
}

type subscriptionTimers struct {
	Reauth, Keepalive, Deadline <-chan time.Time
	Remaining                   func() time.Duration
	Stop                        func()
}

func newSubscriptionTimers(lifetime, reauth, keepalive time.Duration, jitter func(time.Duration) time.Duration) subscriptionTimers

func (h *Handler) handleSubscriptionsListen(c *fiber.Ctx, req rpcRequest, rc *appconsumer.RoutableConsumer) error
func runSubscriptionStream(ctx context.Context, sink frameSink, spec streamSpec) subscriptionOutcome
```

### `pkg/infra/context/stream_metrics.go` + `pkg/api/middleware/mcp_metrics.go` (modified)

No new types: the MCP plane reuses `StreamMetricsFinalizer`, `StreamMetricsFinalizerKey` and
`StreamMetricsOwnedKey`. `MCPMetricsMiddleware.Middleware` gains the same three edits
`MetricsMiddleware` already has (`metrics.go:69-88`) — stash a finalizer, a `streamed` flag, and an
owned check after `c.Next()` — plus one belt-and-braces guard in `buildResponseContext`:

```go
body := []byte(nil)
streaming := c.Response().IsBodyStream()
if !streaming {
	body = append([]byte(nil), c.Response().Body()...)
}
```

That guard matters independently of the claim protocol: `fasthttp.Response.Body()` on a body-stream
response drains the stream into a buffer and closes it, so today's unconditional call at
`mcp_metrics.go:119` would consume the entire lease inside the middleware and deliver one burst at the
end — the exact failure `access_log.go:44-52` documents for the proxy plane.

### `pkg/api/middleware/ops_metrics.go` + `pkg/infra/o11y` (modified)

```go
const RouteMCPSubscription Route = "mcp.subscription" // new bounded route class

type OpsStreamFinalizer func(outcome o11y.Outcome, statusCode int)

// ClaimOpsStream takes ownership of the ops emission for a streamed response and
// returns the finalizer the stream writer must call at close.
func ClaimOpsStream(c *fiber.Ctx, route o11y.Route) OpsStreamFinalizer
```

The middleware stashes the closure (over `start`, `plane`, `boundedMethod`) before `c.Next()` and skips
its own `RecordRequest` when the claim flag is set — the same shape as the metrics middleware, so there
is one pattern in the codebase rather than two. `classifyRoute` is untouched: the path is `/{slug}/mcp`
for every MCP method, so the route class can only come from the handler.

### `pkg/server/{server,http_server}.go` (modified)

```go
type ShutdownHook func(context.Context) error

func (s *BaseServer) WithShutdownHooks(hooks ...ShutdownHook) *BaseServer

const shutdownHookBudget = 5 * time.Second
```

`httpServer.Shutdown()` runs the hooks under `context.WithTimeout(context.Background(), shutdownHookBudget)`
before `s.Router.Shutdown()`. `NewHTTPServer` takes `hooks ...ShutdownHook`, so the admin and proxy
call sites compile unchanged; only `server_mcp.go` passes one.

### `pkg/app/mcp/errors.go` (modified)

```go
// CodeSubscriptionRefused is the single capacity refusal. Which cap was reached
// is never disclosed, so occupancy cannot be probed.
const CodeSubscriptionRefused int64 = -32026

const SubscriptionRefusedMessage = "mcp: subscription refused"

var (
	ErrSubscriptionRefused = fmt.Errorf(SubscriptionRefusedMessage)
	ErrSubscriptionRevoked = fmt.Errorf("mcp: subscription revoked")
)

func SubscriptionRefusedRPCError() *RPCError // constant message, never any data
```

`ErrSubscriptionRevoked` never reaches the wire — it selects the terminal frame, which carries no cause.

## Stream Lifecycle

```
open ── validate ── claim ── ack ─┬─▶ reauth tick ──▶ [emit list_changed]* ──┐
                                  ├─▶ keepalive tick ─────────────────────────┤
                                  ├─▶ deadline (jittered) ────────────────────┤
                                  └─▶ leaseCtx.Done() (shutdown) ─────────────┘
                                                                              │
                                                terminal SubscriptionsListenResult, close
```

1. **Open.** `Handle` runs the unchanged prologue. `subscriptions/listen` joins
   `isSupportedModernMethod` only when `subs.Enabled()` — disabled keeps the 404 `-32601` byte-identical.
2. **Negotiate.** `subscription_validation.go` enforces `Accept ⊇ {text/event-stream, application/json}`
   and absent `Mcp-Name` (→ `-32020`, at the boundary, before any policy effect), then parses
   `params.notifications` (missing → `-32602`) and `params.resourceSubscriptions` (malformed or
   `> MaxURIs` → `-32602`; otherwise parsed, bounded, and dropped). The honoured subset is the
   intersection of the requested kinds with the kinds `configuredCapabilities` allows for this
   role-scoped consumer.
3. **Claim.** `Registry.Claim` under the isolation key. Refusal → buffered `-32026`, no stream.
4. **Capture and hand off.** The handler copies id, path, honoured subset, isolation key and auth id
   into `streamSpec`, calls `ClaimOpsStream` and reads `StreamMetricsFinalizerKey`, sets
   `StreamMetricsOwnedKey` **synchronously**, writes the SSE headers, and returns from
   `SetBodyStreamWriter`.
5. **Ack.** The writer's first frame is `notifications/subscriptions/acknowledged` carrying exactly the
   honoured subset, then `Flush()`. An empty subset acks, writes the terminal frame, and closes.
6. **Re-auth tick.** Skipped when `timers.Remaining() < budget` (D2/D3). Otherwise `Evaluate` under the
   budget. Revoked → terminate. Degraded or transient error → keep the previous snapshot, emit nothing,
   increment a consecutive-failure counter; three in a row terminates. Changed kinds → one frame each.
7. **Keepalive.** `: keepalive` every `MCP_SUBSCRIPTIONS_KEEPALIVE`. This is also the disconnect
   detector: a dead peer surfaces as a write error within one keepalive interval.
8. **Deadline.** `MaxLifetime − rand[0, 10%]`, drawn once at open.
9. **Close.** One terminal `SubscriptionsListenResult`, normalized through `normalizeModernResult` so
   it carries `resultType: "complete"`, `ttlMs: 0`, `cacheScope: "private"` and the subscription id;
   then return, which ends the body stream and closes the response.

**Every termination path produces the same wire shape**, because there is exactly one exit:

| Cause | How the loop sees it | Wire |
|---|---|---|
| Deadline | `<-timers.Deadline` | terminal frame, close |
| Re-auth refusal | `ErrSubscriptionRevoked` | terminal frame, close |
| Repeated inconclusive passes | failure counter = 3 | terminal frame, close |
| Oversize frame | `ErrFrameTooLarge` from the sink | terminal frame, close (frame not emitted) |
| Shutdown / capacity reclaim | `<-leaseCtx.Done()` | terminal frame, close |
| Client disconnect (incl. SDK cancel) | write error on the next frame | connection already gone; nothing to differentiate |
| Feature disabled mid-flight | next `Evaluate` revokes | terminal frame, close |

No cause-specific error, message, or `data` exists anywhere on the path — the terminal frame is
constructed from the honoured subset alone, exactly as `TaskHandleRejectedMessage` is one constant.

## Concurrency Contract

**Goroutines per stream: one, and we do not create it.** `SetBodyStreamWriter` runs the writer func on
fasthttp's own stream goroutine. Everything — ack, ticks, emission, keepalive, terminal frame,
`Release()` — happens on it, in one `select`. There is no channel hand-off, no producer/consumer split,
and therefore no buffer and no slow-consumer policy (proposal decision 6).

**Does that survive a slow re-auth pass? Not on its own.** `Evaluate` calls `Composer.List*` →
`federate` → `discoverCached`; on a cache miss that is `c.target()` (credential resolution, possibly
network) then `dialer.Connect` then the upstream list call, and `singleflight` makes concurrent
streams on the same key *wait together* rather than fail fast. Nothing in that chain has its own
deadline, and the stream's context has none either (D8: the parent is Fiber's `UserContext`, which is
not request-cancelled). An unresponsive upstream would therefore park the loop, stop keepalives, and
let the fasthttp write deadline sever the connection — the precise failure the 10 s margin exists to
prevent. Two rules close it and keep the single-goroutine model:

- Every pass runs under `context.WithTimeout(leaseCtx, ReauthBudget)` — `min(reauth, keepalive)/2`,
  clamped to `[1s, 8s]`; 7.5 s with the defaults. Worst-case keepalive slip is one budget.
- A tick is skipped when `Remaining() < budget`, so no pass is ever in flight when the deadline fires
  and the terminal frame always lands at ≤ `MaxLifetime` with the full 10 s of write budget intact.

**Cancellation.** `leaseCtx` is cancelled by `Release()` (normal exit) and by `Drain` (shutdown). The
loop's first `select` case is `<-leaseCtx.Done()`. Client disconnect is *not* observable through the
context — fasthttp does not cancel a body-stream writer's context on peer close — so it is detected by
the write error on the next frame, bounded by the keepalive interval. That latency is stated in the
operator docs.

**Why nothing leaks.** The writer's `defer` chain is unconditional and ordered: `recover()` →
`timers.Stop()` → ops finalizer → metrics finalizer → `lease.Release()`. `Release` is `sync.Once`, so
a lease cancelled by `Drain` and then released by its writer decrements exactly once. `Drain` waits on
a `sync.WaitGroup` incremented inside `Claim` under the same mutex that flips `draining`, so no stream
can be admitted after the drain begins. The only unbounded wait in the loop is the pass, and it now has
a deadline.

**Panic safety.** `PanicRecoverMiddleware` wraps the handler, not fasthttp's stream goroutine, and
`NewStreamReader` does not recover. The writer therefore installs its own `defer recover()` that logs
without payload and falls through to the same terminal path. Without it a bug in the emission path
takes the process down.

## Data Flow

```
        northbound POST                     app layer                        sources
 ┌──────────────────────────────┐  ┌────────────────────────────┐  ┌───────────────────────┐
 │ mcp_handler   (prologue)     │  │ SubscriptionRegistry       │  │ DataFinder (TTLMap +  │
 │ subscription_validation      │─▶│  claim / release / drain   │  │  singleflight, 1h,    │
 │ subscriptions_listen (SSE)   │  │ SubscriptionPolicy         │─▶│  event-invalidated)   │
 │ sse_frame (frames, bounds)   │◀─│  re-authz + digest diff    │◀─│ RoleScoper (in-memory)│
 └──────────────────────────────┘  └────────────────────────────┘  │ Composer.List* (5m    │
        │                                                          │  discovery TTL + sf)  │
        └── StreamMetricsFinalizer / OpsStreamFinalizer            └───────────────────────┘
```

**1 · open** — `POST /{slug}/mcp`, `Mcp-Method: subscriptions/listen`, no `Mcp-Name`,
`Accept: text/event-stream, application/json`. Prologue unchanged through `scopeByRoles`. Validation
yields `HonouredSet{tools, prompts}` for a tools-and-prompts surface even if the client asked for all
four; `resourceSubscriptions` is bounded to 32 and discarded. `Claim` succeeds; the handler captures
`streamSpec`, claims both finalizers, writes `200 text/event-stream` with
`Cache-Control: no-cache, no-transform` and `X-Accel-Buffering: no`, and returns.

**2 · ack** — first frame, `notifications/subscriptions/acknowledged`, params carry the honoured subset
and `_meta["io.modelcontextprotocol/subscriptionId"] = <listen id>`. Flushed immediately, so the client
sees it before any tick.

**3 · tick** — at 30 s, `Evaluate` re-reads `Data` through `DataFinder` (cache hit unless a gateway or
registry event invalidated it), re-matches the path, re-checks auth and acceptance, re-scopes roles,
and composes tools and prompts. Digests match the previous snapshot → nothing emitted. An operator
edits the toolkit → the invalidation subscriber drops the `consumer_data` entry → the next tick loads
fresh, the tools digest changes → exactly one `notifications/tools/list_changed`.

**4 · revoke** — the principal loses its role grant. `RoleScoper.Scope` returns `ErrNoRoleAccess`, or
the recomputed role-scope fingerprint no longer matches the lease's. `Evaluate` returns
`ErrSubscriptionRevoked`; the loop writes the terminal frame and closes. The client re-issues
`subscriptions/listen` and is refused by the ordinary prologue with the ordinary 403 — the stream never
served a narrowed subset.

**5 · close** — at `MaxLifetime − jitter` the terminal `SubscriptionsListenResult` goes out, the writer
returns, `Release()` decrements all three counters, the ops finalizer records
`{route: mcp.subscription, outcome: allowed, duration: ~290s}` and the metrics finalizer emits with a
`nil` body and `Streaming: true`.

## Configuration

All env-only on `ServerConfig`, following `MCPTasksConfig` (`config.go:238-246`).

```go
type MCPSubscriptionsConfig struct {
	Enabled         bool
	MaxLifetime     time.Duration
	ReauthInterval  time.Duration
	Keepalive       time.Duration
	MaxStreams      int
	MaxPerConsumer  int
	MaxPerPrincipal int
	MaxEventBytes   int
	MaxURIs         int
}
```

| Env var | Default | Clamp |
|---|---|---|
| `MCP_SUBSCRIPTIONS_ENABLED` | `false` | — |
| `MCP_SUBSCRIPTIONS_MAX_LIFETIME` | derived | `min(SERVER_WRITE_TIMEOUT − 10s, 30m)` when unset or `≤ 0` |
| `MCP_SUBSCRIPTIONS_REAUTH_INTERVAL` | `30s` | floor `5s`, ceiling `MaxLifetime` |
| `MCP_SUBSCRIPTIONS_KEEPALIVE` | `15s` | floor `1s`, ceiling `MaxLifetime` |
| `MCP_SUBSCRIPTIONS_MAX_STREAMS` | `1024` | must be `> 0` |
| `MCP_SUBSCRIPTIONS_MAX_PER_CONSUMER` | `16` | must be `> 0` |
| `MCP_SUBSCRIPTIONS_MAX_PER_PRINCIPAL` | `4` | must be `> 0` |
| `MCP_SUBSCRIPTIONS_MAX_EVENT_BYTES` | `8192` | must be `> 0` |
| `MCP_SUBSCRIPTIONS_MAX_URIS` | `32` | must be `> 0` |

Derivation is inside `getServerConfig`, which already computes `WriteTimeout` locally, so the two never
disagree:

```go
func getServerConfig() ServerConfig {
	writeTimeout := getEnvDuration("SERVER_WRITE_TIMEOUT", defaultServerWriteTimeout)
	return ServerConfig{
		// ...
		WriteTimeout:     writeTimeout,
		MCPSubscriptions: getMCPSubscriptionsConfig(writeTimeout),
	}
}
```

The `10s` margin and the `30m` ceiling are package constants
(`mcpSubscriptionsLifetimeMargin`, `mcpSubscriptionsLifetimeCeiling`), not env vars. Fail-fast, added
to the existing `(*Config).Validate()` and therefore reached from `LoadConfig` (`config.go:434`):

```go
if s := c.Server.MCPSubscriptions; s.Enabled {
	if s.MaxLifetime <= 0 || s.MaxLifetime+mcpSubscriptionsLifetimeMargin > c.Server.WriteTimeout {
		return fmt.Errorf(
			"%w: MCP_SUBSCRIPTIONS_MAX_LIFETIME (%s) plus the fixed %s margin must not exceed SERVER_WRITE_TIMEOUT (%s)",
			errors.ErrInvalidConfig, s.MaxLifetime, mcpSubscriptionsLifetimeMargin, c.Server.WriteTimeout)
	}
	// caps > 0, keepalive < MaxLifetime, reauth < MaxLifetime
}
```

Skipped entirely when disabled, so the default build boots exactly as today. A `SERVER_WRITE_TIMEOUT`
at or below `10s` makes the derived lifetime non-positive and hits the same branch, which is the
correct answer — a 0 s lease is not a lease.

## Re-authorization Cost at Maximum Concurrency

**Verdict: cheap enough at `MAX_STREAMS=1024`, with one caveat and one required floor.**

The pass has three inputs, and the caches in the code already absorb two of them:

- **`DataFinder.FindByGateway`** — `TTLMap` named `consumer_data` with a 1-hour TTL
  (`ttlmap_manager.go:48`) plus a `singleflight.Group` (`data_finder.go:78`), and it is
  **event-invalidated** by the gateway and registry subscribers. Steady state is a map lookup. After an
  invalidation the first tick across all streams collapses into one DB load through singleflight.
- **`RoleScoper.Scope`** — `ResolveOIDCRoles` over already-loaded roles. Pure in-memory, no I/O.
- **`Composer.List*`** — `discoverCached` against the `mcp_tools` TTLMap, 5-minute TTL
  (`ttlmap_manager.go:54`), keyed by `kind:registryID:registryUpdatedAt[:principal]`
  (`discovery.go:265-277`), with `singleflight` on miss.

The dial rate does **not** scale with the tick rate — it scales with *distinct cache keys ÷ TTL*. With
`perPrincipalAuth` registries the key includes the principal fingerprint, which is the worst case:
1024 distinct principals × 3 kinds × 2 registries = 6144 keys, each dialled once per 300 s ≈ **20
dials/s**. That is the same load those principals already generate by polling `tools/list` on a timer,
which is what the feature replaces. Without per-principal auth the key set collapses to
`3 × registries` and the dial rate is negligible.

What *does* scale with the tick rate is the in-memory compose plus the digest. At the 30 s default:
1024 streams × 3 kinds ÷ 30 s ≈ 102 compose+marshal passes per second. A 100-item surface marshals in
roughly 150 µs, so ≈ 1.5 % of one core, against a 90 % discovery-cache hit rate (30 s tick over a
300 s TTL).

Required changes, both already in the design:

1. **Floor `MCP_SUBSCRIPTIONS_REAUTH_INTERVAL` at 5 s.** At 1 s the compose cost is 30× the above and
   the interval becomes a re-composition amplifier for no detection benefit — nothing upstream can
   change faster than the 5-minute discovery TTL anyway.
2. **Bound each pass** (D2), because averages do not protect a single stream from one dead upstream.

**Stated limitation, for the docs and the risk table.** Config-originated changes (toolkit edits,
registry attach/detach, role changes) are event-invalidated and therefore visible within one re-auth
interval. **Upstream-originated changes** — a remote MCP server adding a tool without any TrustGate
config change — only become visible after the 5-minute `mcp_tools` TTL expires for that key, so a
290 s lease may end without ever observing one. The gateway-derived design cannot do better without a
southbound listen, which is explicitly out of scope. This is a documentation obligation, not a defect.

## File Changes

| File | Action | Lines | Description |
|---|---|---|---|
| `pkg/api/handler/http/mcp/subscriptions_listen.go` | Create | ~300 | `SubscriptionsSupport`, `handleSubscriptionsListen`, `streamSpec`, `subscriptionTimers`, `runSubscriptionStream`, jitter, ack/notification/terminal frame builders |
| `pkg/api/handler/http/mcp/subscriptions_listen_test.go` | Create | ~320 | Loop table tests with injected channels: ack first, emit-on-change, silent-on-unchanged, revoke, degraded, oversize, deadline, shutdown; no sleeps |
| `pkg/api/handler/http/mcp/subscription_validation.go` | Create | ~140 | `Accept` negotiation, `Mcp-Name` rejection, `params.notifications` shape, `resourceSubscriptions` bound, honoured-subset intersection |
| `pkg/api/handler/http/mcp/subscription_validation_test.go` | Create | ~130 | `-32020` / `-32602` matrix, role-scope narrowing, 32-vs-33 URIs |
| `pkg/api/handler/http/mcp/sse_frame.go` | Create | ~110 | `frameSink`, `bufioSink`, frame/comment framing, `ErrFrameTooLarge` |
| `pkg/api/handler/http/mcp/sse_frame_test.go` | Create | ~90 | Exact bytes, no `id:`, single-line `data:`, size bound |
| `pkg/api/handler/http/mcp/mcp_handler.go` | Modify | ~60 | `subscriptions/listen` in `isSupportedModernMethod` gated on `subs.Enabled()`; `SubscriptionsSupport` on `Handler` + constructor; dispatch branch; `surfaceFingerprint` delegates to `appmcp.SurfaceConfigFingerprint` |
| `pkg/api/handler/http/mcp/modern_validation.go` | Modify | ~30 | `Mcp-Name` must be absent on listen; `Accept` added to `modernRequestHeaders` |
| `pkg/api/handler/http/mcp/modern_response.go` | Modify | ~20 | Terminal result normalization (`ttlMs: 0`, `cacheScope: private`); notification frames bypass `normalizeModernResult` |
| `pkg/api/handler/http/mcp/server_discover.go` | Modify | ~25 | `serverDiscoveryResultWith(..., listChanged)`, `addListChanged`, `subscriptionsEndToEnd` |
| `pkg/api/handler/http/mcp/server_discover_test.go` | Modify | ~70 | Merge order, MRTR coexistence, `subscribe` never present, disabled omits |
| `pkg/api/handler/http/mcp/rpc_dispatcher.go` | Modify | ~15 | Listen span; rate-limit `Check` once at open |
| `pkg/api/handler/http/mcp/protocol_metrics.go` | Modify | ~70 | `SubscriptionsRecorder`, `NewSubscriptionsRecorder`, outcome counter + live up/down counter |
| `pkg/app/mcp/subscriptions.go` | Create | ~150 | `NotificationKind`, `HonouredSet`, `IsolationKey`, `SurfaceConfigFingerprint` |
| `pkg/app/mcp/subscriptions_test.go` | Create | ~130 | Kind binding, honoured-subset algebra, isolation-key derivation, fingerprint parity with the old `surfaceFingerprint` |
| `pkg/app/mcp/subscription_registry.go` | Create | ~170 | Caps, claim/release under one mutex, lease contexts, `Drain`, `draining` gate |
| `pkg/app/mcp/subscription_registry_test.go` | Create | ~190 | Cap matrix, concurrent claim under `-race`, refusal uniformity, idempotent release, drain with N live leases, goroutine baseline |
| `pkg/app/mcp/subscription_policy.go` | Create | ~200 | `LeaseIdentity`, `SurfaceSnapshot`, `Evaluate`, per-kind digest, `ReauthBudget` |
| `pkg/app/mcp/subscription_policy_test.go` | Create | ~220 | Revocation matrix, degraded pass emits nothing, digest stability, budget clamps |
| `pkg/app/mcp/discovery.go` | Modify | ~25 | `federateWithStats`; `federate` becomes a wrapper |
| `pkg/app/mcp/errors.go` | Modify | ~25 | `CodeSubscriptionRefused`, constant message, sentinels, `SubscriptionRefusedRPCError` |
| `pkg/app/mcp/mocks/` | Modify | ~90 | Regenerate for `SubscriptionPolicy` (`go:generate mockery`) |
| `pkg/api/middleware/mcp_metrics.go` | Modify | ~45 | Finalizer stash, `streamed` flag, owned check, `IsBodyStream` guard in `buildResponseContext` |
| `pkg/api/middleware/mcp_metrics_test.go` | Modify | ~80 | Body never drained; finalizer emits once; incremental delivery preserved |
| `pkg/api/middleware/ops_metrics.go` | Modify | ~45 | `ClaimOpsStream`, owned check, skip inline record |
| `pkg/api/middleware/ops_metrics_test.go` | Modify | ~60 | True duration at close; unclaimed path unchanged |
| `pkg/infra/o11y/*.go` | Modify | ~5 | `RouteMCPSubscription` |
| `pkg/infra/trace/span.go` | Modify | ~45 | `SubscriptionKind*` / `SubscriptionOutcome*`, `BoundSubscriptionKind`, `BoundSubscriptionOutcome`, `SetMCPSubscription`. No id, no URI |
| `pkg/config/config.go` | Modify | ~75 | `MCPSubscriptionsConfig`, nine env vars, derivation, clamps, `Validate()` branch |
| `pkg/config/config_test.go` | Modify | ~90 | Derived default, explicit-too-large refusal naming both vars, disabled skips, clamps |
| `pkg/container/modules/mcp.go` | Modify | ~30 | Provide the registry and the policy; `SubscriptionsSupport` into the handler |
| `pkg/container/modules/server_mcp.go` | Modify | ~15 | Pass `registry.Drain` as a shutdown hook |
| `pkg/server/server.go` | Modify | ~20 | `ShutdownHook`, `WithShutdownHooks` |
| `pkg/server/http_server.go` | Modify | ~25 | Run hooks under the budget before `Router.Shutdown()` |
| `pkg/server/http_server_test.go` | Modify | ~60 | Hooks run before shutdown; budget honoured; hook error does not block shutdown |
| `openspec/specs/mcp-dual-era-northbound/spec.md` | Modify | ~120 | Apply the delta on archive |
| `openspec/specs/mcp-subscriptions/spec.md` | Create | — | New capability, applied on archive |
| `docs/mcp/subscriptions.md` | Create | ~180 | Client contract (streams are ephemeral, re-issue on terminal), nine env vars, LB guidance, upstream-change latency caveat |
| `docs/operational-metrics.md` | Modify | ~40 | New counters, route class, drain budget |

**Unchanged by design**: router (`POST /*`), `GET`/`DELETE` → 405, auth middleware, `RoleScoper`,
registry `protocol_mode` semantics, legacy `initialize` capabilities, MRTR and task wire formats,
`SERVER_WRITE_TIMEOUT`, the proxy plane (Q2), `access_log.go` (already stream-safe).

**Forecast**: ≈ 1 950 non-test lines, ≈ 3 350 including tests — above the proposal's ~2 400 estimate,
which appears to have under-counted the test files. The `size:exception` and the five-commit sequence
still hold; the delta is called out in *Push-backs*.

## Telemetry

`mcp.northbound.subscriptions.outcome_total{kind, outcome, era}` and
`mcp.northbound.subscriptions.live` (up/down), both nil-recorder when `Telemetry.OpsMetricsEnabled` is
false, mirroring `NewTasksRecorder` (`protocol_metrics.go:141-153`). `kind` ∈ the three
`NotificationKind` values plus `""`; `outcome` ∈
`opened|acked|emitted|deadline|revoked|refused|degraded|shutdown|disconnected|oversize`, both filtered
through `trace.BoundSubscriptionKind` / `BoundSubscriptionOutcome` so an unknown value is dropped
rather than emitted. Ops metrics report `route: mcp.subscription` with the stream's true duration.
No resource URI, notification payload, subscription id, JSON-RPC id, principal, token, consumer slug,
or tenant text reaches any metric, span, or log — which is also why the metrics finalizer passes a
`nil` body (D9).

## Testing Strategy

| Layer | File | What to Test | Approach |
|---|---|---|---|
| Unit — loop | `subscriptions_listen_test.go` | Ack is frame 1; emit only on change; nothing on unchanged; degraded emits nothing; revoke/oversize/deadline/shutdown all produce the identical terminal frame; three inconclusive passes terminate | Injected `chan time.Time` for all three timers, fake `Remaining()`, recording `frameSink`. **Zero sleeps, no Fiber** |
| Unit — jitter | `subscriptions_listen_test.go` | Effective deadline ∈ `[0.9L, L)`; two leases with one `L` differ | Seeded `*rand.Rand` injected |
| Unit — framing | `sse_frame_test.go` | Exact bytes; `event: message`; **no `id:`**; single-line `data:`; `: keepalive`; `ErrFrameTooLarge` at the bound | Golden byte strings |
| Unit — validation | `subscription_validation_test.go` | `Accept` matrix → `-32020`; `Mcp-Name` present → `-32020`; missing `notifications` → `-32602`; 32 vs 33 URIs; honoured subset narrowed by role scope | Table-driven |
| Unit — registry | `subscription_registry_test.go` | Three caps; 256 concurrent claims yield exactly `MaxStreams`; refusal message byte-identical across caps; idempotent release; `draining` refuses; `Drain` with N leases completes inside the budget | `-race`, `sync.WaitGroup` fan-in |
| Unit — policy | `subscription_policy_test.go` | Revoked on: role loss, registry detach, toolkit drops the kind, `legacy_only`, auth removed, role-scope fingerprint drift. Degraded pass keeps `prev`. Digest stable across identical composes and changes on add/remove/rename | Mocked `DataFinder`, `RoleScoper`, `Composer` |
| Unit — digest determinism | `subscription_policy_test.go` | `json.Marshal` of a `Tool` slice is byte-stable across runs and map iteration orders | 100 repetitions over a shuffled payload map |
| Unit — config | `config_test.go` | Derived default; explicit lifetime within 10 s of the write timeout refuses naming both env vars and values; disabled skips; clamps and floors; `SERVER_WRITE_TIMEOUT ≤ 10s` refuses | `t.Setenv`, no sleeps |
| Middleware | `mcp_metrics_test.go` | `Response().Body()` is never called on a body stream; claimed stream emits exactly once via the finalizer; unclaimed non-stream path unchanged | Existing `metrics_test.go:225-240` pattern |
| Middleware | `ops_metrics_test.go` | Claimed stream records `mcp.subscription` with the true duration; unclaimed path byte-identical | Fake `RequestRecorder` |
| Server | `http_server_test.go` | Hooks run before `Router.Shutdown()`; budget honoured; a failing hook does not block shutdown | Fake hook with a latch |
| Leak | across the three suites | Goroutine count returns to baseline after **disconnect, deadline, refusal, capacity reclaim, shutdown**; exactly one goroutine per live stream | `runtime.GC()` + `runtime.NumGoroutine()` with a `baseline+2` tolerance, matching `pkg/infra/providers/stream_test.go:131-149` |
| Memory | `subscriptions_listen_test.go` | Q3 thresholds A (≤ 64 KiB/stream) and B (≤ 4 KiB drift over 15 ticks), including a client that never reads | `runtime.ReadMemStats` after two `runtime.GC()`, N = 64 |
| Integration | MCP handler suite | Real Fiber app, `WriteTimeout: 12s`, explicit `MaxLifetime: 1s` (valid: 1 + 10 ≤ 12): full open → ack → keepalive → deadline in ~1 s, **clean close, no `unexpected EOF`**, frames observed incrementally | One ~1 s test; the only place a real clock is used |
| Isolation | MCP handler suite | Two principals, disjoint role scopes, one consumer: only the changed principal's stream emits. Two consumers: no cross-talk. Two registries sharing a URI: no cross-talk | Scripted composer |
| Regression | existing MCP suites | Disabled ⇒ `-32601` byte-identical, legacy `initialize` byte-identical, `GET`/`DELETE` 405 | **Not edited** — passing verbatim is the gate |

Everything runs with `-race`; `go vet ./...` and `golangci-lint run` clean.

## Migration / Rollout

No schema, no store, no persisted state, so no migration and no data-shaped revert risk. Inert until
`MCP_SUBSCRIPTIONS_ENABLED=true`: `subscriptions/listen` stays out of the modern method set, discovery
omits `listChanged`, `Config.Validate()` skips the lifetime rule, and no registry is consulted. Turning
the flag off is the instant rollback with no deploy; live streams self-terminate within one lifetime
(≤ 290 s in prod), each with the normal terminal frame. Delivery is the proposal's five commits on one
branch with `size:exception`; commit 2 must not ship without commit 1, and the metrics-middleware and
shutdown-drain work in commit 2 is independently useful and safe to keep across a revert.

## Push-backs

- **The spec lists `notifications/cancelled` as a termination cause; TrustGate cannot route it.** There
  is no JSON-RPC-id → live-stream index and building one is cross-request session state that decision 7
  rules out. In practice an SDK client cancelling its listen cancels the HTTP request, which the stream
  observes as disconnect, so the observable behaviour matches the requirement (same terminal shape, no
  discriminator). Recorded as D11; the spec wording can stand, but the docs must say the cancel must be
  a transport-level abort of the listen request, not a separate POST.
- **A client that never reads is torn down by the fasthttp write deadline, not by its lease**, so it
  gets `unexpected EOF` at `SERVER_WRITE_TIMEOUT` instead of the terminal frame — the one path that is
  not byte-identical. It is vacuously compliant (a client refusing to read cannot observe the shape it
  refuses to read) and it is self-inflicted, but it should be written down rather than discovered.
- **Disconnect detection is bounded by the keepalive interval, not immediate** — fasthttp does not
  cancel a body-stream writer's context on peer close. A dead peer occupies a capacity slot for up to
  15 s. Acceptable against a 4-per-principal cap; worth an operator note.
- **The line forecast is ~3 350 including tests, against the proposal's ~2 400.** The commit sequence
  and the `size:exception` still hold, but the reviewer-focus note in the PR body should name commits
  2 and 4 explicitly, and the test files are what moved.
- **The proxy plane has a zero-margin `StreamTimeout` today** (Q2). Not fixed here; raise as its own
  RUN issue against `providers.StreamTimeout` and the three overlays.
- **`federate` needed a change** (D6) that the proposal did not anticipate. It is small and
  behaviour-preserving for existing callers, but it does touch a shared composer path, so it belongs in
  commit 3 with its own test rather than being folded into the policy.

## Open Questions

- [ ] Should `resourcesListChanged` fold `ListResourceTemplates` into its digest? The design does,
  because a template change is a change to the resource surface and there is no separate notification
  for it. A false positive costs one client re-list; excluding it would make template edits invisible.
- [ ] `IsolationKey.RoleScope` reuses `SurfaceConfigFingerprint`, which hashes registry `UpdatedAt` and
  toolkit entries. It therefore changes on any config edit, which terminates streams that a pure role
  change would not have touched. Correct-but-conservative, or should the role-scope component hash only
  the resolved role set?
- [ ] `ReauthBudget`'s `[1s, 8s]` clamp is tied to the 10 s margin by comment and by a config test, not
  by a shared constant, because the margin lives in `pkg/config` and the budget in `pkg/app/mcp`.
  Acceptable, or export the margin so the relation is compiler-visible?
