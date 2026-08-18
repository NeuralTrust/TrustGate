# Proposal: RUN-1104 complete bounded MCP subscriptions

**Change**: `run-1104-bounded-mcp-subscriptions`
**Linear**: [RUN-1104](https://linear.app/neuraltrust/issue/RUN-1104/featmcp-add-bounded-mcp-subscriptions)
**Slice 1**: `feat/run-1104-bounded-mcp-subscriptions` / [PR #464](https://github.com/NeuralTrust/TrustGate/pull/464)
**Slice 2 branch**: `feat/run-1104-upstream-subscription-multiplex`
**Slice 2 base**: `feat/run-1104-bounded-mcp-subscriptions`

## Intent

PR #464 establishes the modern northbound `subscriptions/listen` contract: bounded SSE leases,
explicit negotiation, re-authorization, stream accounting, deterministic shutdown and safe
telemetry. It derives `list_changed` notifications by periodically recomposing each subscriber's
surface. That implementation is a safe foundation, but it does not complete RUN-1104's requirement
to multiplex authorized upstream notifications.

The second stacked slice adds one shared modern southbound listener per safe source identity and
fans its negotiated `toolsListChanged`, `promptsListChanged` and `resourcesListChanged` events into
bounded, authorization-isolated northbound queues. Sharing is allowed only when the canonical
target, credential pin and credential fingerprint, modern protocol version and negotiated
capability set all match. A credential or capability change never migrates a live subscriber to a
different listener: it terminates the affected northbound lease so the client must renegotiate.

## Scope

### In scope

- Modern `2026-07-28` southbound `subscriptions/listen` over POST and SSE.
- Retention of the bounded `listChanged` capability trio from `server/discover`.
- An app-layer subscription multiplexer behind explicit outbound transport and target-resolution
  ports; the modern HTTP/SSE implementation remains in `pkg/infra/mcp/client`.
- Pooling by canonical target plus credential and protocol/capability identity, with no sharing
  across credentials.
- Northbound subscriber bindings isolated by gateway, consumer, principal, AuthID, registry and
  role-scope fingerprints.
- Per-event re-authorization before a southbound event may become a northbound notification.
- Process-wide and per-origin physical-listener caps, bounded per-northbound-stream queues,
  `MCP_SUBSCRIPTIONS_MAX_EVENT_BYTES`, and a southbound idle timeout.
- Slow-consumer termination on queue saturation. Events are never silently dropped or replaced.
- Bounded transparent reconnect only while target, credentials, protocol version and capabilities
  are unchanged.
- Start, stop and join ownership for every listener and queue, rooted in the MCP server lifecycle.
- Bounded-cardinality listener and fan-out telemetry without source keys, payloads or identifiers.
- A dedicated upstream kill switch so this slice can roll back to PR #464 without reverting it.

### Out of scope

- Legacy upstream subscriptions, legacy cached-session reuse for subscriptions, the deprecated
  standalone GET SSE transport, or `Mcp-Session-Id`.
- `resourceSubscriptions`, `notifications/resources/updated`, resource URI namespacing or URI
  fan-out.
- Task notifications or any extension notification.
- Persisted subscription state, cross-pod pooling, resumption cursors and `Last-Event-ID`.
- Sharing listeners across different credential pins or fingerprints, even when origins match.
- Silently moving a live northbound lease after an authorization, credential, protocol or
  capability change.

## Chosen approach

`SubscriptionMultiplexer` is an application service. At northbound open it resolves the
role-scoped registries to credentialed targets, asks a `SubscriptionConnector` port to prepare the
modern source identity and negotiated trio, and attaches the subscriber to existing or newly
created listeners. The multiplexer owns listener caps, subscriber queues, fan-out, reconnect
supervision and stop/join. The connector adapter owns modern wire framing, bounded SSE parsing and
the `subscriptions/listen` connection.

PR #464 remains intact as the fallback mode:

- `MCP_SUBSCRIPTIONS_UPSTREAM_ENABLED=false`: existing gateway-derived polling behavior is
  byte-for-byte the active source.
- `MCP_SUBSCRIPTIONS_UPSTREAM_ENABLED=true`: upstream events are the source. The periodic pass is
  retained as an authorization and binding watchdog; it terminates on role, registry, credential,
  protocol or capability drift instead of emitting a duplicate polling-derived event.

The northbound ack remains definitive. It contains the intersection of the client's requested trio,
the role-scoped local surface and the kinds actually negotiated by at least one eligible modern
upstream listener. Legacy and unsupported upstreams contribute nothing. If the intersection is
empty, the existing ack-then-terminal behavior applies.

## Locked decisions

1. **Physical listener pooling is narrower than endpoint equality.** The internal key is the digest
   of canonical origin and canonical target URL, `Target.PinKey`, the credentialed header
   fingerprint, modern protocol version and the exact negotiated capability bitset. Raw headers,
   tokens, pins and target URLs never become labels or log fields.
2. **Subscriber identity is not a pool key.** A physical listener may serve multiple authorized
   northbound streams, but every binding retains
   `{gatewayID, consumerID, principalFingerprint, authID, registryID, roleScopeFingerprint}` and is
   re-authorized independently before emission.
3. **Only the list-changed trio crosses the boundary.** The adapter rejects
   `notifications/resources/updated`, task notifications and unknown methods. They are never
   advertised, acknowledged or forwarded.
4. **Queue overflow terminates.** Each northbound stream has one fixed-capacity queue. A non-blocking
   enqueue that finds it full closes that subscriber with `ErrSubscriptionSlowConsumer`; no event is
   dropped, coalesced or replaced.
5. **Reconnect is identity-preserving or not performed.** A listener retries only transport close,
   clean upstream terminal and idle timeout, with bounded exponential backoff. Every retry
   revalidates the source identity and ack. Authentication failure or any identity/capability
   mismatch closes the listener and all attached northbound leases.
6. **No direct event-to-socket path.** A dequeued event is authorized against freshly resolved
   consumer data, AuthID, role scope, registry attachment and source identity before the existing
   northbound frame is emitted.
7. **No idle shared listener.** The last subscriber detaches, cancels the southbound request and joins
   the listener. This avoids a hidden listener TTL and makes shutdown deterministic.
8. **One independent rollback switch.** `MCP_SUBSCRIPTIONS_UPSTREAM_ENABLED=false` disables creation
   of the multiplexer and preserves PR #464's behavior. It does not disable northbound subscriptions.

## Resource bounds

All values are env-only and validated when both subscription flags are enabled.

| Environment variable | Default | Purpose |
|---|---:|---|
| `MCP_SUBSCRIPTIONS_UPSTREAM_ENABLED` | `false` | Slice-2 kill switch; off returns to PR #464 |
| `MCP_SUBSCRIPTIONS_MAX_UPSTREAM_LISTENERS` | `256` | Process-wide physical listener cap |
| `MCP_SUBSCRIPTIONS_MAX_UPSTREAM_PER_ORIGIN` | `16` | Prevent one origin consuming the process budget |
| `MCP_SUBSCRIPTIONS_STREAM_QUEUE` | `16` | Fixed queue per northbound stream |
| `MCP_SUBSCRIPTIONS_UPSTREAM_IDLE_TIMEOUT` | `60s` | Reconnect if no valid SSE frame or comment arrives |
| `MCP_SUBSCRIPTIONS_RECONNECT_MAX_ATTEMPTS` | `3` | Consecutive transparent reconnect attempts |
| `MCP_SUBSCRIPTIONS_RECONNECT_BACKOFF_MIN` | `250ms` | Jittered exponential reconnect floor |
| `MCP_SUBSCRIPTIONS_RECONNECT_BACKOFF_MAX` | `5s` | Jittered exponential reconnect ceiling |
| `MCP_SUBSCRIPTIONS_MAX_EVENT_BYTES` | `8192` | Existing bound, applied before southbound JSON decode and before northbound write |

Listener caps count physical listeners, not subscribers. Reusing an existing key consumes no new
listener slot. The existing process, consumer and principal northbound stream caps from PR #464
remain unchanged.

## Delivery

This is a stacked PR:

```text
develop
  └─ feat/run-1104-bounded-mcp-subscriptions       PR #464
       └─ feat/run-1104-upstream-subscription-multiplex
```

The second PR targets `feat/run-1104-bounded-mcp-subscriptions` until PR #464 lands. After #464 is
merged, its base is retargeted to the integration branch without rebasing away the reviewed
northbound commits.

The implementation should be split into reviewable commits:

1. Source identity, retained capabilities, app ports and configuration.
2. Bounded modern SSE adapter and transport tests.
3. Multiplexer pooling, queueing, reconnect and lifecycle.
4. Northbound integration, per-event authorization and isolation tests.
5. Telemetry, operator docs and rollout verification.

The expected implementation is above the 400-line review budget; keep the stacked PR narrowly
limited to southbound multiplexing and call out commits 2–4 as reviewer focus.

## Rollout and rollback

1. Ship with `MCP_SUBSCRIPTIONS_UPSTREAM_ENABLED=false`. PR #464 remains the production behavior.
2. Enable in development with low listener caps and exercise one modern upstream per supported
   credential mode.
3. Confirm listener reuse, queue saturation termination, reconnect bounds, zero leaked goroutines
   and zero payload/identifier telemetry.
4. Raise development caps, then enable production gradually.
5. Roll back by setting `MCP_SUBSCRIPTIONS_UPSTREAM_ENABLED=false` and restarting. Shutdown cancels
   and joins physical listeners before Fiber drains northbound streams; after restart PR #464's
   gateway-derived behavior is restored.
6. A full revert has no migration or persisted-state concern.

## Success criteria

- [ ] Two subscribers with the same canonical target, credential pin/fingerprint, protocol and trio
  share one physical southbound listener.
- [ ] Changing any credential, target, protocol or capability component creates no cross-identity
  sharing and terminates old northbound leases.
- [ ] Legacy and modern-incompatible upstreams open no listener and contribute no honoured kind.
- [ ] Tools, prompts and resources list changes are negotiated explicitly; URI updates and task
  notifications are rejected and never forwarded.
- [ ] No event crosses gateway, consumer, principal, AuthID, registry or role-scope boundaries.
- [ ] Global/per-origin caps, per-stream queues, idle timeout and event-size limits remain bounded
  under load and `-race`.
- [ ] A full queue terminates the slow northbound stream without dropping an event or disturbing
  other subscribers.
- [ ] Transparent reconnect stops after the configured attempts and only succeeds when source
  identity and capabilities are byte-equivalent.
- [ ] Cancellation, last-detach and shutdown cancel every southbound request and join every goroutine.
- [ ] Metrics and logs use fixed outcomes only and contain no payload, URI, subscription/request id,
  gateway/consumer/principal/AuthID/registry id, credential, target or pool-key value.
