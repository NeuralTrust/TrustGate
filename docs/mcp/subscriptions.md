# MCP subscriptions

TrustGate streams `subscriptions/listen` (SEP-2575) on the modern northbound
plane. A stream is **not a session**: it is a periodically re-authorized lease
over one policy decision, hard-capped below the server write timeout. Every
notification it emits is the product of a fresh, full authorization pass —
consumer lookup, path match, protocol acceptance, role scope, composition, and
the same tools-discovery response-plugin verdict used by `tools/list`.
TrustGate persists no subscription state and holds no session handle.

The feature is off by default. It turns on with
`MCP_SUBSCRIPTIONS_ENABLED=true`.
Modern southbound fan-out is a second, independent feature flag:
`MCP_SUBSCRIPTIONS_UPSTREAM_ENABLED=true`. Leaving that flag false preserves
the gateway-derived Slice 1 behavior.

## Streams are ephemeral by design

**A lease always ends, and a well-behaved client always re-issues.** There is no
resumption cursor: frames carry no SSE `id:`, so `Last-Event-ID` has nothing to
replay against.

Every termination — deadline, revocation, three inconclusive re-auth passes, an
oversize frame, shutdown, or the feature being switched off mid-flight — produces
the *same* wire shape: one terminal `subscriptions/listen` result carrying the
honoured notification subset, then a clean close. Nothing in that frame says why
it ended, deliberately: a client cannot use a closed stream to probe another
tenant's capacity or another principal's grants.

On the terminal frame, re-issue `subscriptions/listen`. If the reason the lease
ended was a lost grant, the fresh request is refused by the ordinary prologue
with the ordinary error — the stream never served a narrowed surface.

**Why the lease is bounded at all.** fasthttp applies `SERVER_WRITE_TIMEOUT` to
the *whole response*, and flushing a frame does **not** reset it. A stream that
outlived the write deadline would be severed mid-frame, so the lease is capped
below the deadline with a fixed margin and always closes itself first.

## Controls

All env-only. Read at boot; nothing here is per-consumer configuration.

| Env var | Default | Effect, derivation, clamp |
|---------|---------|---------------------------|
| `MCP_SUBSCRIPTIONS_ENABLED` | `false` | Kill switch. While false, `subscriptions/listen` stays out of the modern method set (`-32601`), no `listChanged` capability is advertised, the lifetime rule is skipped at boot, and no registry or policy is constructed. |
| `MCP_SUBSCRIPTIONS_MAX_LIFETIME` | derived | Lease lifetime. When unset or `≤ 0` it derives as `min(SERVER_WRITE_TIMEOUT − 10s, 30m)` — 290 s against a 300 s production write timeout. The `10s` margin and the `30m` ceiling are constants, not env vars: TrustGate promises a clean terminal frame, so it owns the headroom that guarantees one. Each lease subtracts up to 10 % of jitter, so concurrent streams do not all expire together. |
| `MCP_SUBSCRIPTIONS_REAUTH_INTERVAL` | `30s` | How often the lease is re-authorized and the surface re-composed. Floor `5s`, ceiling `MaxLifetime`. The floor exists because nothing upstream changes faster than the 5-minute discovery TTL, so a shorter interval buys no detection and only amplifies recomposition. |
| `MCP_SUBSCRIPTIONS_KEEPALIVE` | `15s` | SSE comment interval. Also the disconnect detector — see the limitations below. Floor `1s`, ceiling `MaxLifetime`. |
| `MCP_SUBSCRIPTIONS_MAX_STREAMS` | `128` | Conservative process-wide live-stream cap until southbound multiplexing lands. Must be `> 0`. |
| `MCP_SUBSCRIPTIONS_MAX_PER_CONSUMER` | `16` | Per-consumer cap. Must be `> 0`. |
| `MCP_SUBSCRIPTIONS_MAX_PER_PRINCIPAL` | `4` | Per-principal cap. Must be `> 0`. |
| `MCP_SUBSCRIPTIONS_MAX_EVENT_BYTES` | `8192` | Per-frame size bound. A frame over the bound is not emitted; the lease terminates instead, because a truncated JSON-RPC envelope is indistinguishable from a corrupt transport. Must be `> 0`. |
| `MCP_SUBSCRIPTIONS_MAX_URIS` | `32` | Bound on `params.resourceSubscriptions`. Parsed, bounded, then discarded — see *Not in this change*. Must be `> 0`. |
| `MCP_SUBSCRIPTIONS_UPSTREAM_ENABLED` | `false` | Enables modern `2026-07-28` southbound listeners only when the northbound feature is also enabled. Set false and restart to return to Slice 1 polling without changing the public stream shape. |
| `MCP_SUBSCRIPTIONS_MAX_UPSTREAM_LISTENERS` | `256` | Process-wide cap on physical southbound listeners. Must be `> 0` while upstream fan-out is enabled. Equal complete source identities can still reuse an existing listener at the cap. |
| `MCP_SUBSCRIPTIONS_MAX_UPSTREAM_PER_ORIGIN` | `16` | Per-canonical-origin physical-listener cap. Must be `> 0` while upstream fan-out is enabled. Origin is used only for in-memory accounting and is never exported. |
| `MCP_SUBSCRIPTIONS_STREAM_QUEUE` | `16` | Fixed event queue capacity per northbound stream. Must be `> 0` while upstream fan-out is enabled. A full queue terminates only that slow stream; events are never dropped, overwritten, coalesced, or sampled. |
| `MCP_SUBSCRIPTIONS_UPSTREAM_IDLE_TIMEOUT` | `60s` | Maximum interval without a syntactically valid upstream SSE frame or comment before the connection enters bounded reconnect. Must be positive while upstream fan-out is enabled. |
| `MCP_SUBSCRIPTIONS_RECONNECT_MAX_ATTEMPTS` | `3` | Maximum consecutive identity-preserving reconnect attempts. `0` disables reconnect; negative values are invalid. One valid event resets the consecutive-attempt count. |
| `MCP_SUBSCRIPTIONS_RECONNECT_BACKOFF_MIN` | `250ms` | Positive minimum for context-cancellable jittered exponential reconnect backoff. |
| `MCP_SUBSCRIPTIONS_RECONNECT_BACKOFF_MAX` | `5s` | Positive reconnect backoff ceiling. Must be greater than or equal to `MCP_SUBSCRIPTIONS_RECONNECT_BACKOFF_MIN`. |

**Fail-fast lifetime rule.** When the feature is enabled, boot refuses if
`MCP_SUBSCRIPTIONS_MAX_LIFETIME` plus the fixed `10s` margin exceeds
`SERVER_WRITE_TIMEOUT`. The error names both variables and both values. A
`SERVER_WRITE_TIMEOUT` at or below `10s` makes the derived lifetime
non-positive and hits the same branch — a 0 s lease is not a lease. While the
feature is disabled the rule is skipped entirely, so the default build boots
exactly as it did before.

The seven upstream bounds are validated only when
`MCP_SUBSCRIPTIONS_UPSTREAM_ENABLED=true`; the upstream flag itself has no
effect unless `MCP_SUBSCRIPTIONS_ENABLED=true`. This keeps rollback tolerant of
temporarily stale upstream values while preventing an enabled listener pool
from starting with an unbounded or contradictory configuration.

## What the client sees

`server/discover` advertises `listChanged: true` on each allowed primitive kind
only when the request is modern, the feature is enabled, and at least one bound
registry is not `protocol_mode=legacy`. Discovery never dials an upstream to
decide, so the advertisement means *TrustGate can stream list changes* — never
that a particular upstream pushes them. `resources.subscribe` is never
advertised.

The request is an ordinary modern POST to `/{consumer_slug}/mcp` with
`Mcp-Method: subscriptions/listen`, **no** `Mcp-Name`, and
`Accept: text/event-stream, application/json` — both members are required.
`params.notifications` lists the requested kinds:
`toolsListChanged`, `promptsListChanged`, `resourcesListChanged`.

| Refusal | Code |
|---------|------|
| `Accept` missing either member, or `Mcp-Name` / `Mcp-Param-*` present | `-32020`, at the boundary before any policy effect |
| `params.notifications` missing, malformed, or over three entries, or `resourceSubscriptions` malformed or over `MAX_URIS` | `-32602` |
| Any capacity cap reached | `-32026`, one constant message, no `data`, no indication of which cap |
| Feature disabled, or legacy era | `-32601` |

An honoured listen answers `200 text/event-stream` with
`Cache-Control: no-cache, no-transform` and `X-Accel-Buffering: no`, and no
`Mcp-Session-Id`. The frames, in order:

1. `notifications/subscriptions/acknowledged`, carrying exactly the **honoured**
   subset. With upstream fan-out disabled this is the Slice 1 intersection of
   the request and role-scoped local surface. With upstream fan-out enabled it
   is definitive:
   `requested ∩ role-scoped surface ∩ union(eligible upstream listChanged capabilities)`.
   Unsupported registries contribute nothing. An empty intersection acks,
   writes the terminal frame, and closes.
2. `: keepalive` comments every `MCP_SUBSCRIPTIONS_KEEPALIVE`.
3. `notifications/tools/list_changed`,
   `notifications/prompts/list_changed`, or
   `notifications/resources/list_changed` — one frame per changed kind, per tick,
   and only for honoured kinds.
4. The terminal `subscriptions/listen` result.

Every frame carries `_meta["io.modelcontextprotocol/subscriptionId"]` equal to
the client's own JSON-RPC id, so a client multiplexing several leases can
correlate them. Notification frames are notifications, not results: they carry no
`resultType`, `ttlMs`, or `cacheScope`. The terminal frame does
(`resultType: "complete"`, `ttlMs: 0`, `cacheScope: "private"`).

## What a change means, and when it becomes visible

| Origin | Path | Latency |
|--------|------|---------|
| Config edit — toolkit change, registry attach/detach, role change | Event-invalidated: the subscriber drops the cached consumer data, the next tick loads fresh | Within one `MCP_SUBSCRIPTIONS_REAUTH_INTERVAL` (30 s by default) |
| Upstream edit with upstream fan-out disabled | Visible once the 5-minute `mcp_tools` discovery TTL rolls for that cache key | Up to 5 minutes — **a 290 s lease can end without ever observing it** |
| Eligible modern upstream emits an acknowledged `list_changed` with upstream fan-out enabled | Shared listener, fresh per-binding authorization, then the stream's bounded queue | Immediate apart from transport and scheduling latency |

The polling limitation remains the deliberate rollback behavior. When upstream
fan-out is enabled, the periodic tick becomes an authorization and binding
watchdog only; it updates the internal snapshot but emits no `list_changed`
frame. This prevents duplicate notifications.

## Southbound sharing and fail-closed behavior

TrustGate opens one stateless POST listener only for MCP `2026-07-28` targets
that explicitly negotiate `subscriptions/listen` and at least one of
`tools.listChanged`, `prompts.listChanged`, or `resources.listChanged`. It never
adapts a legacy cached session, opens a standalone GET SSE route, or sends
`Mcp-Session-Id`. Legacy targets, other modern revisions, missing listen
support, and an empty capability trio contribute no honoured kinds.

Physical reuse requires equality of canonical target and origin, registry
target, pin, final credential-header fingerprint, protocol version, and exact
capability trio. These values remain process-local equality inputs. A difference
in any component creates a separate listener; there is no cross-pod pool.
Sharing never replaces fresh gateway, consumer, principal, AuthID, registry,
role-scope, and source authorization for each event.

A transport close, clean upstream terminal, or idle timeout can reconnect only
within the configured attempt and backoff bounds. Credentials and capabilities
are prepared again before each attempt. Any complete-key or acknowledged-trio
change terminates attached leases instead of migrating them. TrustGate retains
no cursor, SSE event id, `Last-Event-ID`, resumable state, or persisted
subscription state.

**A config edit terminates live streams.** The lease's isolation key includes a
surface fingerprint over registry `UpdatedAt` and toolkit entries, so any config
edit that moves it revokes the lease: the client gets the normal terminal frame
and re-issues against the new configuration. This is correct-but-conservative —
an edit unrelated to that principal's grants still ends the stream — and it is
the reason a client must treat re-issue as normal operation rather than an error
path.

## Limitations to plan for

- **Disconnect detection is bounded by the keepalive interval, not immediate.**
  fasthttp does not cancel a body-stream writer's context on peer close, so a
  dead peer is discovered by the write error on the next frame. It occupies a
  capacity slot for up to `MCP_SUBSCRIPTIONS_KEEPALIVE` (15 s by default).
  Weigh that against `MCP_SUBSCRIPTIONS_MAX_PER_PRINCIPAL`.
- **Cancelling a lease is a transport-level abort of the listen request.** Close
  the HTTP request; the stream observes it as a disconnect. A separate
  `notifications/cancelled` POST stays a 202 no-op and cancels nothing —
  addressing a live stream from another request would require cross-request
  session state, which this design deliberately does not keep.
- **A client that never reads is severed by `SERVER_WRITE_TIMEOUT`, not by its
  lease.** It sees `unexpected EOF` instead of the terminal frame. This is the
  one path that is not byte-identical to a normal close, and it is self-inflicted:
  a client that refuses to read cannot observe the shape it refuses to read.
- **Upstream-originated changes lag the discovery TTL** — see the table above.
  This applies only while upstream fan-out is disabled.

## Load balancers and ingress

A stream only works end to end if nothing between TrustGate and the client
buffers it:

- Keep `Cache-Control: no-transform` and `X-Accel-Buffering: no` intact. Do not
  let an ingress rewrite or strip them.
- Disable response buffering on the MCP route (`proxy_buffering off` on nginx,
  the equivalent on your ingress controller).
- Every hop's idle timeout must exceed `MCP_SUBSCRIPTIONS_KEEPALIVE`; set the
  keepalive below the **shortest** hop timeout on the path, not just below
  TrustGate's own.
- Read timeouts on intermediaries must exceed `MCP_SUBSCRIPTIONS_MAX_LIFETIME`,
  or the hop — not the lease — decides when the stream ends, and the client loses
  the clean terminal frame.

## Shutdown

When upstream fan-out is enabled, shutdown first stops attachments, cancels and
joins every physical listener, and only then drains the northbound registry.
The registry drain cancels every lease and reclaims every slot without waiting
for its body writer. A responsive writer emits the terminal frame and returns; a
writer already blocked in fasthttp `Flush` may remain there until
`SERVER_WRITE_TIMEOUT`, so `Router.Shutdown` is bounded by that timeout rather
than by registry accounting.

## Rollback without redeploy

Set `MCP_SUBSCRIPTIONS_UPSTREAM_ENABLED=false` and restart to stop physical
listeners and return to byte-for-byte Slice 1 gateway-derived polling. Existing
northbound leases terminate through the uniform terminal frame and clients
re-issue against the polling path. No migration, cursor, or persisted state
needs cleanup.

To disable northbound subscriptions as well, set
`MCP_SUBSCRIPTIONS_ENABLED=false`. Live streams self-terminate within one
lifetime (≤ 290 s in production); new listens answer `-32601` and discovery
stops advertising `listChanged`.

## Dashboards

Require `OPS_METRICS_ENABLED=true`:
`mcp.northbound.subscriptions.outcome_total{kind,outcome,era}` and
`mcp.northbound.subscriptions.live`. Upstream fan-out additionally exposes
`mcp.upstream.subscriptions.listeners.live`,
`mcp.upstream.subscriptions.listener.lifecycle_total{outcome}`,
`mcp.upstream.subscriptions.fanout_total{kind,outcome}`,
`mcp.upstream.subscriptions.reconnect_total{outcome}`,
`mcp.upstream.subscriptions.queue_total{kind,outcome}`, and
`mcp.upstream.subscriptions.listener.terminal_total{outcome}` — see
[operational metrics](../operational-metrics.md). Subscription ids, JSON-RPC ids,
resource URIs, notification payloads, gateway/consumer/principal/AuthID/registry
identifiers, credentials, pins, fingerprints, targets, origins, pool keys, and
consumer slugs are never labels and never logged.

## Not in this change

`notifications/resources/updated` and per-resource subscriptions are not
honoured: `params.resourceSubscriptions` is validated and bounded so a client
cannot use it as an amplifier, then discarded, and `resources.subscribe` is never
advertised. Per-resource delivery is blocked on per-registry resource URI
namespacing.
