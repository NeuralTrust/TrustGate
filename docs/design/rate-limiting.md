# Plan rate limiting

TrustGate meters proxied LLM requests and MCP calls against the plan of the tenant that owns the gateway. This document describes the model: what is counted, where the numbers live, how a request is decided without waiting on Redis, how pods reconcile with each other, and what happens when something fails.

> **What changed (RUN-1747).** The counter is now **per tenant**, not per gateway, and it is kept **in memory**: a request never waits on Redis. Each pod reconciles with Redis in the background (section 3b). TrustGuard adopted the same model; the two products keep **independent** budgets.

The plan limiter is **not** the `rate_limiter`, `token_rate_limiter` or `per_tool_rate_limiter` policy plugins. Those are a different mechanism, configured per policy by the customer.

---

## Summary

| Product | Unit (data plane) | Counter | Redis |
|---------|-------------------|---------|-------|
| **TrustGate** | One proxied LLM request, or one metered MCP call | per **tenant** (`metadata.tenant_id`), shared by all of its gateways | Shared cluster, key prefix `gt:rl:`; only the background sync touches it |
| **TrustGuard** | One `POST /v1/evaluate` | per tenant, in its own Redis database | prefix `tg:rl:`; see the TrustGuard document |

| Actor | Role |
|-------|------|
| **TrustGate data plane** | Resolves `gateway -> tenant -> caps` from memory, counts in memory, answers 429, syncs to Redis every `RATE_LIMIT_SYNC_INTERVAL` |
| **Control plane** | Stores the tenant's caps in `tenant_entitlements`, publishes them in the config snapshot, recompiles it when a plan changes |
| **TrustGuard** | If a policy uses the TrustGuard plugin, each evaluate is a Guard unit. Independent from the Gate unit |

**Unmetered (OSS).** A gateway with no `tenant_id`, or a tenant with neither stored caps nor a stamp on the gateway, is not metered: no check, no counter, no Redis key, no meter entry. Self-hosted installs behave as before the plan existed.

Switch: `RATE_LIMIT_ENABLED` (default **on**; `false` disables the limiter, the sync and its Redis client).

Outside the plan: health and readiness probes, public docs, OAuth discovery, the whole admin and control API (protected at the edge), and the policy-level rate limiter plugins.

---

## 1. Contract versus usage

```
Contract (tenant / organisation)           Usage (TrustGate)
────────────────────────────────           ───────────────────────────────
Plan free | standard | enterprise  ──►     ONE counter per tenant
  · burst and quota of the plan              shared by ALL its gateways
  · max instances                            and by ALL pods
```

The tenant buys the plan and usage is measured per tenant. **Creating more gateways does not multiply the budget.**

| | Meaning |
|---|---------|
| **Contract** | Burst per minute, quota per month and the instance cap, bought by the tenant |
| **Usage** | One quota counter and one burst counter per tenant, summed across its gateways and pods |
| **Total capacity** | The quota of the plan: two `standard` gateways share 100 000 requests a month, not 200 000 |

### Where the caps come from

1. **`tenant_entitlements`** (Postgres): one row per tenant. It is written by `PUT /v1/tenants/{id}/entitlements` (the restamp, platform JWT only) **in the same transaction** that stamps the gateways, even when the tenant has no gateway yet. A stamped gateway create **fills the row only if there is none** and never overwrites one.
2. **The snapshot compiler** publishes the rows in the typed field `tenant_caps` (field 14). A snapshot scoped to one gateway carries **only the row of its own tenant**. If the table cannot be read while compiling, the snapshot is published anyway with the **last listing that succeeded** (a counter and a warning record it); only a compiler that never listed them publishes none.
3. **A DB-less data plane** resolves `gateway -> tenant -> caps` from the snapshot, in memory. **A plane that reads Postgres** (`run`, or `proxy`/`mcp` without config sync) resolves the gateway as before and reads the caps from an in-memory copy of `tenant_entitlements` reloaded every **30 s** (one query per reload and pod, never per request). The copy is loaded once, synchronously and bounded to 2 s, **before the servers start**; if that fails the plane starts anyway on the gateway stamp and retries with a backoff of 2 s doubling up to 30 s.

The restamp **always** signals the snapshot, whether or not it touched a gateway, because the tenant's row is part of the snapshot.

| Situation | Result |
|-----------|--------|
| Tenant has a caps row | Those caps are used |
| No row, gateway has a stamp | The gateway stamp is the number, **counted against the tenant's counter** |
| Caps copy not loaded yet, or a reload failed | Behaves as "no row". A failed reload keeps the last good copy and is counted (`tenant_caps.load_errors`) |
| No row and no stamp | Unmetered |
| Gateway has no tenant | Unmetered |
| Entitlements lookup fails (not "not found") | Fail-open + `fail_open{reason=tier_load}` |
| Gateway not found | Fail-open + `fail_open{reason=tier_load}` (the request then gets its own 404) |
| Redis slow or down | Requests do not notice. The sync fails, is logged, and requests are served from memory (fail-open) |

A tier change is applied **to the next request** of each pod: the decision compares the cached total with the *current* caps.

**A per-gateway entitlements edit** (`PUT /v1/gateways/{id}` with `entitlements`) changes the stamp of that gateway only. Once the tenant has a row, the row wins, so metering follows the restamp, not the single-gateway edit.

### Seed and rollback

The migration `20261001120000_tenant_entitlements` creates the table and seeds one row per tenant from the stamped gateways. When the gateways of a tenant disagree, the tenant gets the **largest** caps any of them carries: `burst_per_min` by maximum, `quota_per_month` and `max_instances` by maximum with `0` (unlimited) counting as the largest, and the tier of the gateway with the largest quota (ties: burst, then most recent `updated_at`, then id). It does not pick the most recently updated gateway, because `updated_at` moves on any edit and not only on a stamp. Among the gateways whose stamp is usable (see below), a stale sibling therefore never lowers a tenant's plan; the price is that an upgraded and then left-behind gateway keeps the higher plan until the next restamp writes the real one. A skipped stamp is not usable: if a sibling carrying larger caps is skipped, the tenant is seeded from the remaining gateways and can sit on their lower caps until the next restamp.

Only stamps whose three caps are **integral JSON numbers within 0..2 147 483 647**, with a `burst_per_min` of **at least 1**, are used. The domain requires burst > 0, and a seeded burst of 0 would answer 429 to every request of the tenant.

- A gateway with **none** of the three caps present was never stamped and is ignored without a message.
- A gateway with a stamp that cannot be stored is **skipped** instead of aborting the migration, and its tenant is listed in a `WARN` (`tenant_ids`, up to 200): a fractional or negative cap, one above 2 147 483 647 (the columns are `INTEGER`, and the API rejects the same with 422), a string or `null`, a partial stamp, or a `burst_per_min` of 0.
- A tenant left with no storable gateway gets no row and keeps the per-gateway stamp until the control plane restamps it.
- The tenants whose gateways disagreed are listed in a separate `WARN` (up to 200 ids).

The caps written by the API are validated to the same upper bound (`2 147 483 647`), because they are stored as `INTEGER` and travel in the snapshot as `int32`.

An older release neither reads nor writes `tenant_entitlements`. After a rollback that leaves the table, its rows go stale, and rolling forward again does not re-seed (`ON CONFLICT DO NOTHING`). Either roll the schema back too (`Down` drops the table and the next `Up` re-seeds it) or re-push the plans so the restamp re-asserts every row.

### Compatibility during the rollout

A snapshot without `tenant_caps` decodes without caps; the stamped gateway caps are used, **already against the tenant's counter**. A binary from before this change reading a new snapshot ignores the unknown field.

---

## 1b. Flag behaviour

| Capability | Honours `RATE_LIMIT_ENABLED`? | Notes |
|------------|-------------------------------|-------|
| Burst / quota | Yes: no-op checker when off | Default on |
| Max instances (create returns 409) | Yes | Unchanged by this change. Applies only with the flag on, with a tenant and a cap |
| Background sync | Yes | With the flag off there is no meter, no goroutine and no Redis sync client use |
| Entitlements stamp | Platform JWT only | A tenant JWT that sends `entitlements` gets 422 |

---

## 2. Scope

| Surface | Plan |
|---------|------|
| Proxy LLM (`ALL /*`) | Yes: one request, one unit of the tenant's counter |
| MCP `POST /*` (`tools/list`, `tools/call`, `resources/list`, `resources/read`, `resources/templates/list`, `prompts/list`, `prompts/get`) | Yes: one call, one unit |
| Admin / control API, catalogs, playground traces, config sync | No (edge protection) |
| OAuth and MCP discovery | No |
| Policy plugins `rate_limiter`, `token_rate_limiter`, `per_tool_rate_limiter` | No (another mechanism) |

The unit is the **admitted attempt**: the plan is charged when the request enters `Forward` (or the metered MCP method), not after the upstream succeeds. Attempts rejected by a later plugin still consume budget; attempts rejected by the plan itself do not.

---

## 3. Redis

```
gt:rl:quota:{<tenant>}:<YYYY-MM>        TTL until 00:00 UTC on the 1st of the next month
gt:rl:burst:{<tenant>}:<unix_minute>    TTL 2 min
gt:rl:tok:{<tenant>}:<pod>-<round>      TTL max(2 x retention, 1 min): idempotency token of one sync round
gt:rl:audit:per-tenant-rollout:<YYYY-MM>  rollout audit claim (SET NX, 40 days; DEL if the scan fails)
```

- The subject is a **hash tag** (`{...}`): the quota, the burst and the token of one tenant land in one Redis Cluster slot, which the multi-key script requires. Braces inside the tenant id are replaced by `_`.
- The prefix `gt:` keeps the Gate keys apart from the TrustGuard keys (`tg:rl:`) even if both are pointed at one database. Neither product reads or writes the other's counters.
- **Burst is the calendar minute** (`unix_minute`), not a sliding window.
- The **previous per-gateway keys** (`gt:rl:burst:<gateway_id>`, `gt:rl:quota:<gateway_id>:<month>`) are no longer written. They expire by themselves.
- A Lua script per tenant does `INCRBY delta` on quota and burst, sets the TTL when a key has none, and returns both totals. With `delta = 0` it is a read and creates nothing. **One pipeline per sync round**, one `EVALSHA` per active tenant. The script is loaded with `SCRIPT LOAD` and reloaded on `NOSCRIPT` (go-redis does not fall back inside a pipeline).
- **Idempotency by token.** A round with deltas carries a token `<random pod id>-<round number>`. The script first does `SET <token> NX PX <ttl>`; if the token already existed the `INCRBY` is **not applied** and the current totals are returned. The token key shares the tenant's hash tag, so the script stays single-slot.

---

## 3b. In-memory counter and background sync

A request **never calls Redis**. It counts in memory, and one loop per pod reconciles.

### Request path (memory only)

For each tenant the pod keeps, for quota and for burst: `synced` (the tenant total the last time the pod looked at Redis), `inflight` (on its way to Redis) and `pending` (admitted since the last sync).

1. Resolve `gateway -> (tenant, caps)` from the context, the gateway cache and the snapshot (or the polled copy).
2. If `synced + inflight + pending + 1 > cap`, answer **429** (`Retry-After` comes from the local clock: seconds to the next minute, or to the 1st of next month).
3. Otherwise admit and add 1 to `pending`. **The plan's own 429s add nothing.**
4. Quota is counted **also for plans without a monthly cap** (enterprise), so the number exists the day the plan gets one.

No I/O and no goroutine per request. The headers, the `Retry-After` and the 429 body are the same as before. This is proved with a call-counting hook on **both** Redis clients (the process-wide one and the sync one): 0 commands on the proxy forward path and on the MCP `tools/call` path.

### Sync loop (one goroutine per pod)

Every `RATE_LIMIT_SYNC_INTERVAL` (default **1 s**):

1. Freeze each tenant's `pending` into `inflight`.
2. One pipeline with one script per tenant adds the delta and returns the totals.
3. Write the totals into `synced`: every pod learns the whole tenant's total.

**Early flush (kick).** A request sends a **non-blocking** signal (channel of capacity 1) when a tenant's `pending` reaches `max(1, 10 % of the cap)`, and **on the first request that creates a tenant's counter** on the pod (a cold pod or an evicted tenant: until its first sync the pod does not know what the others spent). The loop then syncs early, with **at least 50 ms between syncs**. The request still does not call Redis. A kick is suppressed only while the last sync *round* failed (the call failed, or every tenant in a round of several did); one tenant's own failure does not silence the others.

Other properties:

- **A failed round is resent unchanged.** A timeout or a cancellation does not say whether Redis applied the round. The pod keeps the failed round (same deltas, **same token**) and resends it on the next tick: if Redis had applied it the token detects it; if not, it is applied then. Usage admitted after the failure **never joins the failed round**: it travels in a new round with a new token. Meanwhile the failed round's usage still counts as `inflight`, so the decision does not change.
- **Redis down.** A round counts as an outage when a call fails, or when **every tenant** of a round with several fails. Tenants are counted, not entries: a tenant with a retained round and a new one is still one tenant, and a single tenant failing on its own item is not an outage. While the last sync failed there are no early flushes: the loop keeps its cadence (one attempt per interval) instead of one per 50 ms. The "sync failed" warning is logged at most **once every 30 s**, with the number of failures since the last log.
- **Time-based retention.** The usage of a failed round is kept for `RATE_LIMIT_FAILED_RETENTION` (default **30 s**) from that round's *first* failure, then dropped and counted in `sync.dropped`. It is time and not a number of attempts so that the retry cadence does not decide how much is lost. A round that fails once past the retention is dropped; if Redis returns earlier, even an old round is sent (it is billing).
- **Token TTL.** `max(2 x retention, 1 min)`. Every resend that finds its token renews it to the full TTL (`PEXPIRE` inside the script), so a round sent in several chunks, whose later chunks go out late, does not lose its token between two sends: the TTL only has to cover the gap between sends. Start-up rejects any configuration where `retention + sync interval + 2 x sync timeout + 5 s` is not below that TTL (the first failing call spends one timeout before the retention clock starts, and the last resend another), and a retention above **10 min** or a sync timeout above **5 s**. Live token keys are of the order of `active tenants x TTL / interval` in the worst case; a tick without usage writes no token.
- The sync call **does not inherit the loop's cancellation** (`context.WithoutCancel` plus `RATE_LIMIT_SYNC_TIMEOUT`): a SIGTERM does not abort a round already on the wire.
- **Shutdown (SIGTERM).** After the servers stop and **before the sync client closes**, one last sync flushes the deltas, bounded by `FlushTimeout` (2 s): once it expires it stops starting new chunks but never cancels the one already on the wire, and the usage not yet sent is counted in `sync.dropped` with `reason=shutdown`. A crash loses at most one interval (accepted undercount).
- **Dedicated Redis client** for the sync: `ContextTimeoutEnabled`, read, write and pool timeouts of `RATE_LIMIT_SYNC_TIMEOUT` (default **200 ms**, capped at 5 s) and a dial timeout of `max(RATE_LIMIT_SYNC_TIMEOUT, 1 s)` (also capped at 5 s), because a cold connection pays for the TCP connect and the TLS handshake that a warm round trip does not. The pool keeps **one connection dialed in the background** (`MinIdleConns = 1`): go-redis dials it on its own context, bounded by the dial timeout only, at boot and again whenever the connection is removed, so the cold dial never competes with the 200 ms deadline of a sync call. What still runs inside the call is the handshake of that already open connection (the IAM auth token and `HELLO`/`AUTH`); the AWS credentials cache keeps retrieving after a call gives up, so a slow first retrieval is cached for the next tick. Also `MaxRetries = -1` (go-redis would otherwise retry three times), a pool of 2, and **no ping at boot**: the warm-up is a goroutine, so Redis being down neither blocks nor stops the process. Its failure is not silent: go-redis logs `failed to dial after N attempts` through its internal logger (5 attempts with a 100 ms backoff per dial, then a probe about once a second), it does not hammer Redis.
- **Month change.** The usage not yet sent for the month that just ended is sent to *that* month's key; billing is not lost at the boundary.
- **Idle tenants** (10 min without traffic and nothing pending) are evicted from memory. A request holding an evicted counter looks it up again; nothing spins.
- **Observability.** All instruments are under the `trustgate.ratelimit.` prefix except the snapshot one. `trustgate.ratelimit.sync.duration` (histogram, and a `ratelimit.sync` span with `ratelimit.tenants`, `ratelimit.failed` and `ratelimit.outage` attributes), `sync.errors`, `sync.dropped` (attribute `reason`: `retention` or `shutdown`), `sync.kicks`, `tracked_tenants`, `tenant_caps.load_errors`, `trustgate.configsnapshot.tenant_caps.errors` and `fail_open` (`trustgate.ratelimit.fail_open`). A round with nothing to do emits no span, and a request emits none.

### Measured overshoot (deterministic simulation)

A pod that has not seen a tenant yet admits its requests until its first sync, and at each new minute every pod starts the burst bucket at 0. So the limit is crossed a little before it blocks. The numbers come from `pkg/app/ratelimit/meter_simulation_test.go` (virtual clock of 1 ms, 1 s tick staggered between pods, 5 ms RTT, burst cap of 300/min):

| Scenario | Measured overshoot | Test bound |
|----------|--------------------|------------|
| Sustained load above the cap, 2 pods (20 rps) | 10 | <= rps x interval = 20 |
| Same, 3 pods (30 rps) | 20 | <= 30 |
| Same, 5 pods (50 rps) | 40 | <= 50 |
| **Flood at the minute edge**, 3 pods x 1000 rps, **without** early flush | 600 (admits **3.0x** the cap) | >= 0.9 x pods x cap (documents the problem) |
| Same, **with** early flush | 118 (**1.4x**) | <= cap + pods x (10 % of cap + rps x (50 ms + RTT)) |
| Flood, 10 pods x 1000 rps, without early flush | 2586 (**9.6x**) | >= 0.9 x pods x cap |
| Same, with early flush | 512 (**2.7x**) | <= cap + pods x (...) |

Reading it: under sustained load the overshoot is **the tenant's rps x the sync interval** (the burst limits the rps: an enterprise tenant at 1000/min is about 17 rps, so on the order of 20 requests). A synchronized flood of every pod at the minute edge is the worst case: the early flush brings it from about P x to cap + P x (threshold + what a pod admits during a 50 ms gap and one RTT). It does not eliminate it; with many pods and extreme traffic a bounded overshoot remains.

### Failure behaviour

| Failure | What happens |
|---------|--------------|
| Redis slow or unreachable | Requests unaffected (memory only). Sync fails after `RATE_LIMIT_SYNC_TIMEOUT`, is logged (throttled), counted in `sync.errors`; no kicks while it lasts |
| Reply lost after Redis applied the round | The round is resent under the same token; Redis returns totals without applying twice |
| Redis down longer than the retention | The round is dropped, `sync.dropped` counts the units; undercount bounded by the retention, never an unbounded queue |
| Redis restarts (script cache lost) | `NOSCRIPT` triggers a reload and one retry of the affected items |
| One tenant's keys fail in a batch | Only that item fails; the others count. It does not read as an outage and does not silence kicks |
| Pod crash | Loses at most one interval of usage |
| Pod receives SIGTERM | Servers drain, then one final flush, then the sync client closes |
| Caps table unreadable at compile time | Snapshot published with the last good caps (or none, on a compiler that never read them) |
| Caps table unreadable on a Postgres plane | The last good copy is kept; before the first load the gateway stamp applies |

### Rollout month: counters restart and the audit

The month in which the per-tenant keys are introduced **starts from zero**: the old per-gateway counters are not summed in, because they cannot be summed safely while old pods still write them. A tenant that had already spent part of its quota recovers it for that month.

So that this is not invisible, a one-off audit adds up the old `gt:rl:quota:<gateway_id>:<YYYY-MM>` counters by tenant and logs a `WARN` for every tenant whose sum already exceeded its monthly cap.

- **Enabled by month:** `RATE_LIMIT_ROLLOUT_AUDIT_MONTH=YYYY-MM` (empty = **off**, the default). It runs only if the current month is that one, so it never repeats each month. Set it in the month the per-tenant keys roll out; remove it afterwards.
- **Only on planes that see every tenant**, those that resolve gateways from Postgres. A plane answering from the snapshot may hold one scoped to a single gateway, would resolve almost none of the old keys, and the report would be false, so it does not run it.
- **One pod per month** (about 90 s after start, to let the caps copy load): the claim key is taken with `SET NX` before scanning. **If the scan fails the claim is released (`DEL`)**, so another pod, or this one on its next boot, can retry; a finished audit keeps the key for the rest of the month (40 days TTL). Keys already in the per-tenant format (the subject in braces) are skipped.

---

## 4. Tiers

| Tier | Burst/min | Quota/month | Max gateways *(contract)* |
|------|-----------|-------------|---------------------------|
| free | 60 | 10 000 | 5 *(temporary)* |
| standard | 300 | 100 000 | 5 *(temporary)* |
| enterprise | 1 000 | unlimited *(counted, never checked)* | 5 *(temporary)* |

These are the values the control plane stamps; the data plane has no built-in catalogue. All gateways of a tenant share that burst and quota.

Common rules:

- `enterprise`: only the burst is **checked**; the quota is still **counted**, with no cap.
- Redis failures are fail-open (metric and log); requests do not notice.
- A tier change is a restamp in Postgres (`tenant_entitlements`) followed by a snapshot recompile, applied to each pod's next request.
- Max instances is unchanged: create and update are checked under a per-tenant advisory lock, and a downgrade is applied even when the tenant is already above the new cap (the response reports `over_cap`).

---

## 5. Storage and settings

| | Postgres | Redis |
|---|----------|-------|
| What | Tier and caps of the tenant | Usage (shared counters) |
| Where | `tenant_entitlements` (`tenant_id`, `tier`, `burst_per_min`, `quota_per_month`, `max_instances`, `updated_at`). `gateways.entitlements` remains the per-instance stamp (rollout fallback and retention data) | `gt:rl:burst:{tenant}:<unix_minute>`, `gt:rl:quota:{tenant}:YYYY-MM` |

| Variable | Default | Effect |
|----------|---------|--------|
| `RATE_LIMIT_ENABLED` | `true` | Turns off the limiter, the sync and its client: with `false` no meter and no sync Redis client are built (nor the credentials provider) |
| `RATE_LIMIT_SYNC_INTERVAL` | `1s` | How often a pod reconciles with Redis. Sustained overshoot is about the tenant's rps x this value |
| `RATE_LIMIT_SYNC_TIMEOUT` | `200ms` | Bound of each **sync** round trip (never of a request). Maximum 5 s |
| `RATE_LIMIT_FAILED_RETENTION` | `30s` | How long, from its first failure, the usage of a sync that did not reach Redis is kept before it is dropped. Maximum 10 min; it sets the token TTL |
| `RATE_LIMIT_ROLLOUT_AUDIT_MONTH` | empty (off) | Month `YYYY-MM` in which the one-off rollout audit runs, on Postgres planes only |

`REDIS_DB` selects the database as for every other Redis use of the process.

Customer-run (hybrid) data planes meter against their scoped snapshot and sync to the Redis they are configured with; they never run the audit.

---

## 6. Flow

```
Client ──proxy/MCP──► TrustGate data (gateway G, tenant T)
                        │
                        ├─ in-memory counter of T (Gate) ──429?──► stop
                        │
                        └─ plugins… (if TrustGuard → guard H)
                               │
                               └─ POST /v1/evaluate ──► TrustGuard data
                                                          │
                                                          └─ in-memory counter of H's tenant (Guard) ──429?──► Gate propagates the 429

         (in the background, every pod, every ~1 s: one pipeline to Redis with T's deltas)
```

**Budgets are not mixed.** A request that goes through the proxy and triggers the TrustGuard plugin spends **1 Gate unit + 1 Guard unit per evaluate** (one per request leg inspected, one per streamed block that owns a charge). Each product charges its own counter in its own key space. The plugin propagates a TrustGuard 429 and a 503 (entitlements unavailable) instead of failing open; other transport errors and 5xx fail open as before.

### Streamed responses and `attributes.stream.block`

A streamed response inspected block by block costs the Guard side one unit per 64 blocks. The plugin sends `attributes.stream.block`: the **1-based position among the evaluates it actually sent** for that stream (`seq` also counts segments the plugin skipped, such as empty text or a stream retired after repeated failures, so it could never reach `1`). The position is counted after every check that can skip the call, kept per stream and policy, dropped on the closing segment and swept when a closing never arrives: a counter untouched for 10 minutes is dropped, so a stream that resumes after that restarts at block 1 and spends one extra Guard unit. The stream is identified by the trace id of the gateway request, so sequential streams of one trace share a single counter until a closing segment drops it. A TrustGuard that does not know the field ignores it, since the attributes object is free-form.

---

## 7. 429 response

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 42
X-RateLimit-Limit: …
X-RateLimit-Remaining: 0
X-RateLimit-Reason: burst|quota
```

MCP: JSON-RPC `-32004` plus the same HTTP headers. Headers, `Retry-After` and body are unchanged by the in-memory counter.

---

## Annex A. Counter semantics

- **Fixed window (burst):** calendar minute. At the edge between windows each pod starts its bucket at 0, so an aggressive client can approach 2x `burst_per_min` over a short interval (plus the overshoot above); it is not a sliding window.
- **Decision:** `synced + inflight + pending + 1 > cap`. The plan's own 429s add nothing. A pod that has not seen the tenant admits until its first sync (at most one interval, shortened by the early flush).
- **Redis fail-open:** a failed sync keeps the last total and requests continue. Unsent deltas are kept with their token and resent on the next tick, then dropped after the retention (`sync.dropped`).
- **Unit = admitted attempt** (see section 2).
- **Tenant, not gateway:** the counter key has no gateway id. Two gateways of one tenant add to one counter; a gateway with no tenant is not metered.

## Annex B. Not covered here

- A single counter per tenant means a tenant's burst is shared across **all** its gateways and pods; the overshoot table is the price of not calling Redis on the request path.
- When a create carries only the default free tier, the creator still gives the new gateway the highest tier among its sibling gateways. That stamp only seeds `tenant_entitlements` when the tenant has no row; it never changes an existing one.
