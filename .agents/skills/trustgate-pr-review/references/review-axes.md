# Review axes

Each reviewer owns exactly one axis. Stay in your lane: if you spot something
for another axis, add it with `axis_hint` and keep going — do not expand on it.

## 1. Bugs (correctness)

- Does the code do what the PR title/body/Linear ticket claims? Read the claim first.
- Wrong branch, inverted condition, swapped args, shadowed `err`, `err` checked on the wrong var.
- Error swallowed, returned unwrapped where callers use `errors.Is`, or wrapped with `%v` instead of `%w`.
- Nil deref: map/pointer/interface from a finder that can return `nil, nil`; typed-nil interface returned as `error`.
- Loop variable captured by a closure/goroutine that outlives the iteration; slice aliasing (`append` onto a shared backing array).
- HTTP: status code vs body mismatch; response written twice; handler returns before writing on error.
- Fiber/fasthttp: `c.Body()`, `c.Params()`, header bytes used after the handler returns (buffers are reused) — must be copied.
- Streaming (SSE): partial chunk handling, `[DONE]`, usage only on last event, flush ordering, provider-specific framing (OpenAI, Anthropic, Bedrock event-stream, Vertex, Azure).
- Proxy: `stampTarget` before `pre_request` and on every failover retarget; executor is the single writer of `req.Body`/`resp.Body`.
- Caches: every mutation invalidates the gateway-level aggregate; junction changes invalidate every projection that reads them; `create` does not publish.
- DB-less parity: a new domain field / repository method must exist in the Postgres repo **and** the snapshot repo + proto + compiler, or the data plane silently drops it.
- `dig`: new segregated interface without a view provider → boot failure on one plane only (admin vs proxy vs mcp vs dbless).
- Migrations: idempotent up and down in one tx, timestamp ordering, `NOT NULL` without default on populated tables.
- Tests: new branches without tests; tests that assert the bug instead of the behaviour; functional tests not compiling under `-tags functional`.

## 2. Race conditions & memory leaks

- Shared mutable state (maps, slices, struct fields) touched from goroutines, handlers or plugins without a mutex/atomic; `concurrent map writes` risk.
- Parallel plugin batches: plugin mutates `req`/`resp`/`Headers`/`Metadata` instead of its isolated clone, or returns body changes outside `Result`.
- Check-then-act on caches (`TTLMap`, Redis) without atomicity; double-checked locking without re-check under the lock.
- Lock held across I/O, a channel send, or a callback; lock ordering inversions (deadlock); `RWMutex` read lock upgraded.
- Goroutine lifecycle: who starts, who stops, who joins. Missing `ctx.Done()` in loops, sends on channels nobody reads, `errgroup` without `WithContext`.
- `context.WithCancel/WithTimeout` without `defer cancel()`; `context.Background()` mid-chain (detaches cancellation); ctx stored in a struct.
- `time.NewTicker`/`time.NewTimer` without `Stop`; `time.After` inside a hot loop.
- `resp.Body` not closed / not drained on every path, including errors and streaming aborts; `io.ReadAll` on unbounded upstream bodies.
- Unbounded growth: maps keyed by tenant/consumer/session/trace with no eviction or TTL; per-request goroutines that wait on upstream without timeout.
- `sync.Pool` objects reused after `Put`; byte slices retained from pooled buffers.
- Pub/sub or gRPC streams (config sync `Sync`, Redis subscriptions) not closed on shutdown or reconnect → leaked goroutines per reconnect.
- Evidence: cite the `-race` result from the evidence step; if no test exercises the concurrent path, say so.

## 3. TrustGate rules

Use `trustgate-rules.md`. Flag only violations introduced by the diff. Each finding cites the rule source.

## 4. Corner cases

Enumerate inputs the author probably did not test and trace them through the changed code:

- Empty / nil: empty body, `null` JSON, empty slice vs nil slice in JSON output, zero UUID, empty tenant/gateway id, missing header.
- Boundaries: 0, 1, max, negative config values, duration `0`, limits exactly at the threshold, off-by-one on windows.
- Size: very large payload, payload over provider limits (Model Armor/Bedrock), huge tool lists, deep JSON nesting.
- Encoding: unicode/multibyte when slicing strings, gzip/br upstream responses, non-JSON error bodies from providers.
- Lifecycle: client disconnect mid-stream, upstream timeout, ctx cancelled during failover, retry after partial write.
- Multi-tenant: data from tenant A reachable from tenant B; global vs consumer-scoped policy with the same slug.
- Planes: behaviour on admin vs proxy vs mcp vs `run`, DB-less flag on/off, first boot without snapshot/LKG.
- Config: feature flag off path still works; env var unset uses a sane default; rollout with old and new pods side by side.
- Data compat: rows written by the previous version, cached entries serialized by the previous version, telemetry consumers reading old keys.

## 5. Anti-patterns & SOLID

- **S**: a use case file/struct doing several jobs; handler with business logic; god structs growing new fields per feature.
- **O**: `switch provider` / `if slug ==` chains extended instead of a strategy/registry; boolean flags that fork behaviour.
- **L**: an implementation that panics, no-ops or returns `nil, nil` where the port promises a value; snapshot repo weaker than Postgres repo.
- **I**: fat interfaces; consumer depending on methods it never calls; aggregated `interfaces.go`.
- **D**: `pkg/app` importing `pgx`, `fiber`, infra packages or concrete adapters; domain importing anything upward.
- Other: stringly-typed enums, primitive obsession for ids, duplicated logic that already exists in `pkg/common` or a sibling package, premature abstraction with one implementation and no test seam, global mutable state, `init()` side effects beyond migration registration, magic numbers/timeouts outside `pkg/config`.
- Rate each finding by real cost (bug risk, change amplification), not purity. Pure taste → 🔵.
