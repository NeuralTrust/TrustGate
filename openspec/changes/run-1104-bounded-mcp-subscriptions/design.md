# Design: RUN-1104 authorized southbound subscription multiplexing

**Linear**: [RUN-1104](https://linear.app/neuraltrust/issue/RUN-1104/featmcp-add-bounded-mcp-subscriptions)
**Foundation**: `feat/run-1104-bounded-mcp-subscriptions` / [PR #464](https://github.com/NeuralTrust/TrustGate/pull/464)
**Second slice**: `feat/run-1104-upstream-subscription-multiplex`

## Technical approach

PR #464 remains the northbound transport and lease foundation. The second slice inserts an
application-layer `SubscriptionMultiplexer` between each northbound lease and modern upstream
`subscriptions/listen` connections. It shares a physical listener only when a prepared,
non-secret source identity proves that target, credentials, protocol and negotiated capabilities
are equal. Each northbound binding remains independently authorized and receives events through its
own bounded queue.

An application port separates pooling and fan-out policy from wire transport. The
`pkg/infra/mcp/client` adapter performs modern discovery, retains the exact negotiated
`listChanged` trio, sends the long-lived POST, validates its first acknowledgement and exposes a
bounded `Next` reader. Fiber owns neither
outbound clients nor listener goroutines; the composition root creates and closes the multiplexer,
and the existing handler only attaches a lease, drains its queue and maps typed terminal reasons to
the established northbound stream ending.

## Decisions

### Keep PR #464 as a deployable foundation

- **Choice:** Preserve gateway-derived polling when `MCP_SUBSCRIPTIONS_UPSTREAM_ENABLED=false`.
  When the flag is on, the same periodic tick re-evaluates authorization and binding identity, but
  only southbound events cause list-changed frames.
- **Rejected:** Delete polling and make northbound listen dependent on upstream support in the same
  release. That removes the rollback path and changes #464's reviewed behavior before the new
  transport is proven.
- **Rationale:** The second slice is additive, can be disabled independently, and has no database or
  wire migration.

### Separate preparation from a long-lived listen

- **Choice:** Add `SubscriptionConnector.Prepare` and `SubscriptionConnector.Open`. Preparation
  resolves modern protocol support, retained capabilities and a safe source identity before a
  listener slot is committed. `Open` sends the listen call, waits for and validates the southbound
  acknowledgement, then returns a bounded stream reader before TrustGate writes the northbound
  acknowledgement.
- **Rejected:** Extend the general `Upstream` interface with `Listen`. Existing list/call methods
  open one exchange and close it after a response; adding a lifetime-owning stream would force every
  implementation, including legacy, into a contract it cannot safely satisfy.
- **Rejected:** Have the Fiber handler instantiate the SDK streamable transport. That couples HTTP
  ingress to an outbound protocol adapter and makes listener sharing, shutdown and reconnect
  request-local.
- **Rationale:** A dedicated port expresses the different ownership model and keeps legacy failure
  explicit.

### Pool on a complete source identity

- **Choice:** Build a `SubscriptionSourceKey` from:
  1. canonical origin and canonical target URL digest,
  2. registry target identity,
  3. `Target.PinKey`,
  4. the fingerprint of the final credentialed request headers,
  5. negotiated modern protocol version, and
  6. the exact tools/prompts/resources `listChanged` capability bitset.
  The key is comparable and remains process-local. Its raw components are never logged or exported
  as metric labels.
- **Rejected:** Pool by origin or registry URL only. Different API keys, per-principal credentials
  or capability views can share an endpoint; origin-only reuse would cross an authorization
  boundary.
- **Rejected:** Pool by northbound isolation key. It is safe but prevents permitted reuse among
  independently authorized subscribers with the same source identity.
- **Rationale:** Physical transport reuse and northbound authorization are different concerns.
  The source key proves which wire connection is shareable; the binding proves who can receive an
  event from it.

### Retain and intersect only the negotiated trio

- **Choice:** Decode `server/discover.capabilities` into a typed `ListChangedCapabilities` with
  `Tools`, `Prompts` and `Resources` booleans. A subscriber's honoured set is:

  ```text
  requested ∩ role-scoped local surface ∩ union(prepared eligible upstream capabilities)
  ```

  Each binding also records the subset supplied by each registry listener. An event is queued only
  to bindings whose requested and current authorized set contains that kind.
- **Rejected:** Treat a present `tools`, `prompts` or `resources` capability object as support for
  list changes. The explicit nested `listChanged` flag is the contract.
- **Rejected:** Forward all upstream notifications. `notifications/resources/updated`, task
  notifications and extension methods have different routing and authorization semantics.
- **Rationale:** The gateway cannot safely acknowledge or forward a capability it did not
  explicitly negotiate.

### Preserve subscriber isolation during fan-out

- **Choice:** Every `SubscriptionBinding` retains gateway, consumer, principal fingerprint, AuthID,
  registry and role-scope identity. Before enqueueing an event, the multiplexer evaluates the
  current policy and confirms that the source registry is still attached and the notification kind
  remains authorized. The handler also runs the periodic binding watchdog from #464.
- **Rejected:** Authorize only when attaching to a shared listener. Long-lived streams outlive role,
  registry and credential changes.
- **Rejected:** Use source-key equality as recipient authorization. Equal credentials do not imply
  equal gateway, consumer or role scope.
- **Rationale:** A shared read loop is an optimization, not an authorization boundary.

### Use one bounded queue per northbound stream

- **Choice:** One fixed-capacity queue carries `SubscriptionEvent` values to each northbound stream.
  Fan-out uses a non-blocking send. If the queue is full, the binding is atomically detached and
  terminated with `ErrSubscriptionSlowConsumer`; the triggering event is not reported as delivered.
- **Rejected:** Block the shared listener until every subscriber accepts an event. One slow client
  would stall all subscribers and eventually the upstream.
- **Rejected:** Drop, overwrite, coalesce or sample events. The MCP notification contract does not
  give the gateway authority to hide a state transition.
- **Rejected:** One queue per physical listener. That reintroduces head-of-line blocking and does
  not identify which northbound stream exceeded its budget.
- **Rationale:** Memory is bounded, healthy streams continue, and loss is explicit.

### Bound physical listeners independently of stream leases

- **Choice:** Reserve a global and canonical-origin listener slot only when creating a new pool
  entry. Reuse is allowed at capacity. The last binding detaches, cancels the connection and joins
  the listener before releasing its slots.
- **Rejected:** Count every binding against listener caps. That double-counts multiplexed transport
  and makes safe reuse impossible at capacity.
- **Rejected:** Leave zero-subscriber listeners idle for a TTL. It adds another timer and keeps
  credentials and goroutines alive with no beneficiary.
- **Rationale:** The bound matches the scarce resource and shutdown has one deterministic owner.

### Reconnect only across equivalent identity

- **Choice:** Transport close, clean upstream terminal and idle timeout may reconnect with jittered
  exponential backoff for at most the configured consecutive attempts. Before each retry,
  `Prepare` runs again. Reconnect proceeds only if the full source key and acknowledged capability
  set equal the listener's immutable values. A valid event resets the consecutive-attempt counter.
- **Rejected:** Retry indefinitely. A dead origin could retain listener capacity forever.
- **Rejected:** Transparently update credentials or capabilities on the existing northbound lease.
  The client's acknowledgement and the sharing proof would no longer describe reality.
- **Rejected:** Resume from `Last-Event-ID`. The source contract does not guarantee resumable event
  identifiers, and event identifiers are deliberately not retained.
- **Rationale:** Transient transport failure is hidden; authorization or contract drift is not.

### Treat idle timeout as transport failure

- **Choice:** The SSE adapter resets an idle timer on every syntactically valid SSE frame or comment.
  Expiry cancels the current request and enters the bounded reconnect path.
- **Rejected:** Depend on the northbound keepalive. Northbound comments prove only that TrustGate is
  alive, not the upstream connection.
- **Rationale:** A half-open southbound connection cannot pin a listener slot forever.

### Make event-size enforcement two-sided

- **Choice:** The SSE decoder rejects an event once its accumulated `data:` bytes exceed
  `MaxEventBytes`, before JSON decoding. The existing northbound encoder applies the same configured
  bound before writing. Oversize southbound input terminates the listener and attached leases; it is
  not retried as a transport failure.
- **Rejected:** Rely on `bufio.Scanner`'s default token limit or measure after unmarshalling. Both
  permit an accidental, hidden and differently sized memory budget.
- **Rationale:** The configured byte limit has one explicit meaning at both trust boundaries.

### Use a start/stop/join lifecycle

- **Choice:** `SubscriptionMultiplexer` has one root context, one mutex-protected pool and one
  waitgroup. Each physical listener owns exactly one supervisor goroutine and at most one current
  blocking adapter read. `Close(ctx)` marks the multiplexer closed, snapshots listeners, cancels all
  of them, terminates bindings, then waits for join or returns the shutdown context error.
- **Rejected:** Fire-and-forget goroutines per event or subscriber. They cannot be bounded or joined.
- **Rejected:** Let Fiber shutdown discover and close listeners indirectly through request
  cancellation. Shared listeners can outlive any one request.
- **Rationale:** Every goroutine has one cancellation source and one join owner.

### Keep telemetry fixed-cardinality

- **Choice:** Add counters/gauges with fixed labels only: capability kind, lifecycle outcome and
  reconnect outcome. Logs contain operation, fixed reason and counts/durations. Sensitive values
  are available only as in-memory equality inputs.
- **Rejected:** Label by origin, pool key, target, registry, gateway, consumer, principal, AuthID,
  request/subscription id, resource URI or payload.
- **Rationale:** Those fields either expose identity/data or create unbounded series.

## Interfaces and contracts

The exact names may be adjusted to existing package naming, but their ownership and data boundaries
are fixed.

```go
type ListChangedCapabilities struct {
	Tools     bool
	Prompts   bool
	Resources bool
}

type SubscriptionSourceKey struct {
	TargetDigest          [32]byte
	PinDigest             [32]byte
	CredentialFingerprint [32]byte
	ProtocolVersion       string
	Capabilities          ListChangedCapabilities
}

type PreparedSubscription struct {
	Key          SubscriptionSourceKey
	OriginDigest [32]byte
	Capabilities ListChangedCapabilities
}

type SubscriptionEvent struct {
	Kind NotificationKind
}

type SubscriptionConnector interface {
	Prepare(ctx context.Context, target Target) (PreparedSubscription, error)
	Open(
		ctx context.Context,
		target Target,
		prepared PreparedSubscription,
	) (SubscriptionStream, error)
}

type SubscriptionStream interface {
	Acknowledged() ListChangedCapabilities
	Next(ctx context.Context) (SubscriptionEvent, error)
	Close() error
}
```

`Prepare` returns `ErrSubscriptionUnsupported` for legacy, modern versions other than `2026-07-28`,
an absent `subscriptions/listen` capability, or an empty list-changed trio. Authentication,
discovery and malformed-capability failures remain distinct typed errors and do not become
unsupported. `Open` MUST read the first southbound frame synchronously, require a valid
`notifications/subscriptions/acknowledged`, and require its trio to equal the prepared capability
set. The application listener supervisor owns the `Next` loop and always calls `Close`; the infra
adapter starts no unjoined fan-out goroutine.

```go
type SubscriptionIdentity struct {
	GatewayID           string
	ConsumerID          string
	PrincipalFingerprint string
	AuthID              string
	RegistryID          string
	RoleScopeFingerprint string
}

type SubscriptionRequest struct {
	Identity SubscriptionIdentity
	Target   Target
	Requested HonouredSet
}

type SubscriptionHandle interface {
	Events() <-chan SubscriptionEvent
	Done() <-chan struct{}
	Err() error
	Close()
}

type SubscriptionSource interface {
	Attach(ctx context.Context, requests []SubscriptionRequest) (SubscriptionHandle, HonouredSet, error)
	Close(ctx context.Context) error
}
```

`Attach` is atomic from the handler's perspective:

- preparation may happen before reservations;
- all required existing/new listener bindings and the stream queue are committed together;
- any failure rolls back bindings and newly created listeners;
- the returned honoured set is stable for the lease;
- an empty honoured set uses the existing terminal response rather than returning a live handle.

The implementation may attach one northbound stream to multiple registry listeners. The handle
owns one queue and one terminal state; any terminal source drift or authorization failure closes the
whole northbound lease so the client receives a single, coherent renegotiation boundary.

```go
var (
	ErrSubscriptionUnsupported       = errors.New("upstream subscriptions unsupported")
	ErrSubscriptionListenerCapacity  = errors.New("upstream listener capacity exceeded")
	ErrSubscriptionSlowConsumer      = errors.New("subscription consumer is too slow")
	ErrSubscriptionSourceChanged     = errors.New("subscription source identity changed")
	ErrSubscriptionIdle              = errors.New("upstream subscription idle timeout")
	ErrSubscriptionReconnectExhausted = errors.New("upstream reconnect exhausted")
)
```

These internal errors map to the existing bounded northbound terminal mechanism and fixed telemetry
outcomes. Their text is not forwarded as upstream detail.

## Data flow

### Open and attach

```text
Northbound client
  │ POST subscriptions/listen + negotiated trio
  ▼
Fiber handler
  │ authenticate, route consumer, authorize method, acquire #464 stream lease
  ▼
SubscriptionPolicy / target resolver
  │ role-scoped registries + final credentialed Targets
  ▼
SubscriptionMultiplexer.Attach
  │
  ├─ SubscriptionConnector.Prepare(target A)
  │    └─ discover modern version + explicit listChanged trio
  ├─ SubscriptionConnector.Prepare(target B)
  │    └─ legacy/unsupported => contributes no honoured kind
  │
  ├─ calculate requested ∩ authorized surface ∩ prepared capabilities
  ├─ reserve one bounded stream queue
  ├─ reuse or reserve global/per-origin physical listener slots
  └─ atomically bind stream to source listener(s)
       │
       ├─ existing source key => attach only
       └─ new source key => Open, validate southbound ack, start one listener supervisor
  ▼
Fiber writes definitive ack, then drains handle.Events()
```

Preparation does not expose credential values to the multiplexer. The adapter obtains final headers
through the existing target credential pipeline, fingerprints them, and retains only the request
material needed by its private prepared object. The public prepared key contains digests only.

### Southbound event fan-out

```text
Modern upstream
  │ bounded SSE: notifications/{tools|prompts|resources}/list_changed
  ▼
Infra connector read loop
  │ syntax + method allowlist + MaxEventBytes
  ▼
Physical listener supervisor
  │ immutable source key/capabilities
  ▼
snapshot matching bindings under lock
  │
  ├─ re-evaluate gateway/consumer/principal/AuthID/registry/role scope
  │    └─ denied or drifted => terminate complete northbound handle
  ├─ requested and source capability contain event kind?
  │    └─ no => do not enqueue
  └─ non-blocking enqueue to per-stream queue
       ├─ success => Fiber stream writes existing notification frame
       └─ full => detach + ErrSubscriptionSlowConsumer
```

No policy or network call runs while the pool mutex is held. Listener fan-out snapshots binding
references, releases the lock, evaluates them, and uses per-binding atomic terminal state to make
detach idempotent.

### Reconnect and drift

```text
read closes / clean terminal / idle timeout
  │
  ├─ attempts exhausted? ── yes ──> terminate attached leases
  ▼ no
jittered capped backoff (ctx-cancellable)
  ▼
Prepare(target again)
  │
  ├─ identical complete source key + capability ack
  │    └─ Listen again; valid frame resets failure count
  └─ auth failure, legacy, target/credential/protocol/capability change
       └─ terminate attached leases; client must reopen and renegotiate
```

Malformed, unknown or oversize events are protocol failures, not reconnectable transport failures.
This avoids a loop against a consistently incompatible or hostile source.

### Shutdown

```text
server shutdown
  ▼
SubscriptionMultiplexer.Close(ctx)
  ├─ reject new Attach
  ├─ cancel all listener contexts
  ├─ terminate all handles
  └─ waitgroup join
       ▼
subscriptionDrainHook / Fiber shutdown completes
```

The composition root registers the multiplexer close hook before the northbound drain hook, so
shared southbound reads stop and unblock their streams before Fiber waits for those streams.

## Exact implementation file changes

This table is the implementation boundary for slice 2. Product Go files are listed for planning
only; this design change does not modify them.

| File | Action | Exact change |
|---|---|---|
| `pkg/app/mcp/protocol.go` | Modify | Add `ListChangedCapabilities`, prepared source values and narrow connector/stream ports; do not add listen to general `Upstream` |
| `pkg/app/mcp/errors.go` | Modify | Add typed unsupported, capacity, slow-consumer, source-drift, idle and reconnect-exhausted errors |
| `pkg/app/mcp/subscriptions.go` | Modify | Extend identity to include AuthID and RegistryID; add source/binding/handle contracts and fixed lifecycle outcomes |
| `pkg/app/mcp/subscriptions_test.go` | Modify | Cover complete identity derivation and non-secret stable fingerprints |
| `pkg/app/mcp/subscription_targets.go` | Create | Resolve role-scoped registries into prepared `SubscriptionRequest` values through existing credential/target paths |
| `pkg/app/mcp/subscription_targets_test.go` | Create | Cover registry filtering, per-principal credentials, AuthID and legacy/unsupported exclusion |
| `pkg/app/mcp/subscription_multiplexer.go` | Create | Implement atomic attach, complete-key pooling, listener caps, per-stream queues, fan-out, reconnect supervision and close/join |
| `pkg/app/mcp/subscription_multiplexer_test.go` | Create | Race-safe unit tests for pooling, isolation, caps, overflow, reconnect, drift, last detach and shutdown |
| `pkg/app/mcp/subscription_policy.go` | Modify | Return current registry/source bindings and AuthID in re-evaluation; compare stable source identity |
| `pkg/app/mcp/subscription_policy_test.go` | Modify | Cover credential, capability, registry, AuthID and role-scope drift termination |
| `pkg/app/mcp/mocks/subscription_connector.go` | Create | Generated/mockery implementation of the connector port for app tests |
| `pkg/infra/mcp/client/probe.go` | Modify | Retain and strictly decode the explicit list-changed trio from modern discovery |
| `pkg/infra/mcp/client/probe_test.go` | Modify | Cover true/false/missing/malformed nested listChanged fields and empty capability sets |
| `pkg/infra/mcp/client/era.go` | Modify | Include retained list-changed capabilities in modern era entries and equality |
| `pkg/infra/mcp/client/era_test.go` | Modify | Prove capability changes invalidate prepared identity |
| `pkg/infra/mcp/client/negotiating_dialer.go` | Modify | Expose modern-only subscription preparation without permitting legacy fallback |
| `pkg/infra/mcp/client/negotiating_dialer_test.go` | Modify | Prove legacy fails closed and modern capability/protocol drift is surfaced |
| `pkg/infra/mcp/client/modern_subscriptions.go` | Create | Implement credentialed prepare and long-lived modern POST/open adapter, synchronous ack validation and typed reconnect classification |
| `pkg/infra/mcp/client/modern_subscriptions_test.go` | Create | HTTP integration tests for method, headers, ack, close, auth failure and unsupported capability |
| `pkg/infra/mcp/client/modern_subscription_sse.go` | Create | Implement bounded incremental SSE parsing, idle reset and trio method allowlist |
| `pkg/infra/mcp/client/modern_subscription_sse_test.go` | Create | Fragmentation, comments, CRLF, multiline data, oversize, unknown method, EOF and cancellation tests |
| `pkg/api/handler/http/mcp/subscriptions_listen.go` | Modify | Attach to the multiplexer when enabled, write its definitive ack, drain its queue and retain polling as the binding watchdog |
| `pkg/api/handler/http/mcp/subscriptions_listen_test.go` | Modify | Handler tests for honoured intersection, upstream event emission and typed terminal mappings |
| `pkg/api/handler/http/mcp/subscriptions_listen_isolation_test.go` | Create | Cross-gateway/consumer/principal/AuthID/registry/role-scope negative fan-out tests |
| `pkg/api/handler/http/mcp/protocol_metrics.go` | Modify | Record fixed listener, reconnect, queue and terminal outcomes without identifiers |
| `pkg/api/handler/http/mcp/protocol_metrics_test.go` | Modify | Assert the exact bounded label set and absence of identity/source values |
| `pkg/infra/o11y/trace/span.go` | Modify | Add validated fixed outcome enums used by subscription source telemetry |
| `pkg/infra/o11y/trace/span_test.go` | Modify | Reject unknown or identifier-bearing subscription outcome labels |
| `pkg/config/config.go` | Modify | Add upstream flag, listener caps, queue capacity, idle timeout and reconnect settings with cross-field validation |
| `pkg/config/config_test.go` | Modify | Defaults, disabled behavior, invalid ranges and reconnect/backoff ordering |
| `pkg/container/modules/mcp.go` | Modify | Provide the connector, target resolver and optional multiplexer through app ports |
| `pkg/container/modules/mcp_subscriptions_test.go` | Modify | Verify upstream-disabled fallback and enabled dependency graph |
| `pkg/container/modules/server_mcp.go` | Modify | Register multiplexer close/join before northbound subscription drain |
| `pkg/container/modules/server_mcp_test.go` | Create | Assert shutdown hook ordering and deadline propagation |
| `docs/configuration.md` | Modify | Document slice-2 env variables, bounds and kill switch |
| `docs/mcp-legacy-protocol-removal.md` | Modify | State that legacy upstream subscriptions fail closed and no legacy session is pooled |
| `openspec/changes/run-1104-bounded-mcp-subscriptions/proposal.md` | Modify | Expand RUN-1104 to the stacked southbound slice and remove the exclusion |
| `openspec/changes/run-1104-bounded-mcp-subscriptions/design.md` | Modify | Replace the northbound-only design with this complete two-slice architecture |
| `openspec/changes/run-1104-bounded-mcp-subscriptions/exploration.md` | Modify | Record why northbound-only was slice 1 and why complete-key multiplexing is chosen for slice 2 |
| `openspec/changes/run-1104-bounded-mcp-subscriptions/specs/mcp-subscriptions/spec.md` | Modify | Add normative pooling, isolation, bounds, reconnect, lifecycle and telemetry scenarios |
| `openspec/changes/run-1104-bounded-mcp-subscriptions/specs/mcp-dual-era-northbound/spec.md` | Modify | Add modern upstream negotiation and explicit legacy fail-closed scenarios |

No generated protocol files, database schemas, migrations or public MCP message shapes change.

## Testing strategy

| Layer | What to test | Method |
|---|---|---|
| App unit | Complete-key reuse and no reuse after target, pin, credential, protocol or capability change | Fake connector with deterministic prepared identities; table-driven tests |
| App unit | Global/per-origin cap accounting and rollback of partial multi-registry attach | Small capacities, forced prepare/start failures, post-failure state assertions |
| App unit | Independent gateway/consumer/principal/AuthID/registry/role-scope authorization | Two or more bindings per listener; mutate one dimension at a time |
| App unit | Queue saturation | Queue size one, pause one consumer, assert typed termination and uninterrupted healthy consumer |
| App unit | Reconnect | Injectable clock/backoff and scripted connector; same identity reconnects, any drift terminates |
| App unit | Lifecycle | Cancel attach, last detach, concurrent detach and `Close`; assert every goroutine joins |
| Infra unit | Capability decode | Missing, false, true, malformed and unknown capability fields |
| Infra unit | SSE framing | Fragmented reads, CRLF, comments, multiline data, blank dispatch, EOF, oversize and cancellation |
| Infra integration | Modern POST/listen | `httptest.Server` verifies protocol header, auth headers, JSON-RPC request/ack and streaming events |
| Infra integration | Fail closed | Legacy probe, unsupported modern version, absent listen/trio and auth failure create no read loop |
| Handler unit | Ack and event contract | Existing fake Fiber sink plus fake `SubscriptionSource`; exact trio and terminal ordering |
| Handler unit | Watchdog drift | Registry, AuthID, role and capability changes terminate without emitting a polling-derived event |
| Telemetry unit | Cardinality and privacy | Enumerate labels/log fields; assert no payload, URI, IDs, target, origin or pool key |
| Container unit | Wiring and shutdown order | Dig graph for flag off/on; blocking fake listener proves close before northbound drain |
| Race/stress | Concurrent attach/detach/fan-out/reconnect/close | Repeated focused `go test -race` with bounded goroutine and queue assertions |
| Repository | Regression | `go test -race ./pkg/app/mcp/... ./pkg/infra/mcp/client/... ./pkg/api/handler/http/mcp/... ./pkg/container/modules/...` |
| Repository | Static checks | `go vet ./...` and `golangci-lint run` |

Tests use injectable clocks and deterministic channels; no test waits on arbitrary `time.Sleep`.
Wire tests may use deadlines only as a final deadlock guard.

Required behavioral matrix:

| Source | Credentials | Capabilities | Expected |
|---|---|---|---|
| Same modern target | Same pin and fingerprint | Same trio | One physical listener, isolated bindings |
| Same origin | Different fingerprint | Same trio | Two listeners; no cross-event delivery |
| Same credentials | Same modern target | Different trio/version | Old leases terminate; no transparent migration |
| Legacy | Any | None | No listener; contributes no honoured kind |
| Modern | Any | URI updates/tasks only | No listener; contributes no honoured kind |
| Modern | Same identity | Transient close | Bounded transparent reconnect |
| Modern | Changed auth/capabilities | Any retry | Terminate all attached leases |

## Failure and terminal semantics

| Condition | Physical listener | Affected northbound lease |
|---|---|---|
| Global/per-origin capacity at attach | No new listener | Existing capacity terminal behavior; no partial attach |
| Unsupported/legacy registry | No listener for registry | Continue only if another registry supplies an honoured kind |
| Authentication failure during prepare | No listener | Terminal internal/auth-safe reason; no upstream detail |
| Queue full | Other listeners/subscribers continue | Slow lease terminates |
| Idle/transport close with equivalent identity | Reconnect within bounds | Remains open |
| Reconnect attempts exhausted | Stops and releases slots | All attached leases terminate |
| Credential/protocol/capability drift | Stops and releases slots | All attached leases terminate to renegotiate |
| Unknown/URI/task/oversize notification | Protocol failure; no reconnect | All attached leases terminate |
| Last subscriber detaches | Cancel and join | Already closed/detached |
| Server shutdown | Cancel all and join | Deterministic shutdown terminal |

## Rollout and rollback

### Rollout

1. Merge PR #464 first or keep this PR explicitly stacked on its feature branch.
2. Deploy slice 2 with `MCP_SUBSCRIPTIONS_UPSTREAM_ENABLED=false`.
3. In development, enable with conservative listener and queue limits.
4. Verify one-listener reuse for equal source identities and separate listeners for distinct
   credential fingerprints.
5. Exercise idle reconnect, connection close, auth rotation, capability change and slow consumer.
6. Confirm process listener gauge returns to zero after cancellation and shutdown.
7. Inspect telemetry schemas before widening deployment; values must be from the fixed enums only.
8. Enable production gradually and tune only numeric bounds, not sharing identity.

### Rollback

- Set `MCP_SUBSCRIPTIONS_UPSTREAM_ENABLED=false` and restart. The multiplexer close hook cancels and
  joins all listeners; newly opened streams use PR #464's gateway-derived source.
- If code rollback is required, revert only the second stacked slice. No persisted state,
  migrations, cursors or client protocol changes require cleanup.
- Do not weaken source-key identity or increase queue capacity as an incident workaround. Disable
  the upstream path instead.

## Rejected approaches

### Keep gateway-derived polling as the final implementation

It is retained as the flag-off fallback, but it cannot deliver upstream-originated change timing and
duplicates list work for every subscriber. It also leaves RUN-1104's explicit southbound
multiplexing scope incomplete.

### One upstream listener per northbound stream

This is simple and strongly isolated, but scales physical connections with clients rather than
distinct authorized sources. It wastes upstream and gateway resources and does not meet the
multiplexing requirement.

### One listener per origin

It maximizes reuse but is unsafe: an origin can host multiple registries, credentials, principals
and negotiated capability sets. No application-layer filter can repair data already read over the
wrong credentialed connection.

### Share one event bus and filter in Fiber

This gives the ingress adapter authorization and routing responsibility, bypasses the app layer and
makes shutdown dependent on request lifetimes. It also encourages unbounded or lossy broadcast
semantics.

### Silently coalesce list-changed events

Although list changes invite deduplication, coalescing is still silent event loss and hides which
subscriber exceeded its budget. Explicit slow-consumer termination is observable and preserves the
contract.

### Transparent credential/capability rotation

Changing a listener in place invalidates both the northbound acknowledgement and the pool-sharing
proof. Lease termination gives the client a clean negotiation boundary and prevents cross-identity
reuse.

## Open questions

None. Numeric defaults are conservative rollout values and can be tuned through validated
configuration without changing the design.
