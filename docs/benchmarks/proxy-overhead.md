# Proxy overhead benchmark (no policies)

What the proxy plane costs on its own: one gateway, one consumer, one OpenAI
registry, one api key, **no policy attached**, forwarding to an upstream mock
that answers instantly. Every request is sent twice, once straight to the mock
(`direct`) and once through the proxy (`gateway`); the difference is the
gateway's overhead.

## How to run it

Needs a reachable Postgres (`DB_*`, default `postgres:postgres@localhost:5432`)
and Redis (`REDIS_*`, default `localhost:6379`, db 5). The script creates and
drops its own database (`trustgate_bench`) and flushes its Redis db.

```bash
scripts/bench/overhead.sh
```

```bash
PROFILE=minimal scripts/bench/overhead.sh -- -concurrency 1,8 -rates 500,1000 -duration 30s
```

```bash
PROFILE=prod scripts/bench/overhead.sh -- -concurrency 1,8 -prompt-bytes 65536
```

The script builds `bin/trustgate` and `bin/bench-overhead`, boots

| process | role | default CPUs (4-core box) |
|---|---|---|
| `bench-overhead mock` | OpenAI-compatible upstream, canned 400-byte completion (or a 20-chunk SSE stream) | `nproc-2` |
| `bench-overhead mock` | OTLP sink for the telemetry exporters (prod profile) | `nproc-2` |
| `trustgate admin` | control plane + config-sync gRPC | `nproc-2` |
| `trustgate proxy` | the system under test, DB-less like production (`DBLESS=false` for the Postgres-backed finders) | `0..nproc-3` |
| `bench-overhead run` | load generator | `nproc-1` |

provisions the fixtures through the admin API, waits until the proxy serves
them and runs every scenario against both targets. Results (markdown + JSON)
and every process log land in `var/bench/<timestamp>-<profile>/`.

Scenarios:

- **closed loop** `-concurrency 1,8,32,64`: N workers sending back to back. `c=1`
  is the cleanest read of added latency; higher levels show the throughput
  ceiling.
- **open loop** `-rates 250,500,1000`: requests are fired at a fixed rate, each
  on its own goroutine, so a slow response never delays the next send (no
  coordinated omission). Latency is measured from the actual send, not the
  scheduled tick: on a one-core load generator `time.Sleep` overshoots by up
  to a millisecond and would otherwise be charged to the target.

`proxy CPU µs/req` is the proxy's `utime+stime` over the measured window divided
by the requests served in it: the number that sizes a fleet (`cores = rps ×
µs/req / 1e6`).

### Profiles

| | `prod` | `minimal` |
|---|---|---|
| `LOG_LEVEL` | `info` (one access log line per request) | `warn` |
| plan rate limit (`RATE_LIMIT_ENABLED`) | on | off |
| product telemetry (`TELEMETRY_ENABLED`, `METRICS_ENABLED`) | on, OTLP/HTTP to the local sink | off |
| ops traces + metrics (`OPS_TRACES_ENABLED`, `OPS_METRICS_ENABLED`) | on, sampling 1.0 | off |
| playground trace store | default (on) | off |

`prod` mirrors `k8s/overlays/prod/config.env`; `minimal` is the floor of the
forwarding path.

## Results — 2026-10-30, commit `6eca10f` (v0.75.0)

4 vCPU Intel Xeon @ 2.10 GHz VM, 15 GiB, Linux 6.18, Go 1.27.3. The proxy is
pinned to **2 vCPUs** (`GOMAXPROCS=2`); upstream + admin + Postgres + Redis +
OTLP sink share one vCPU and the load generator has the last one. Requests are
OpenAI chat completions with a 668-byte body (512-byte user message) unless
stated; the upstream answers a 400-byte completion. 20 s measured after 3 s of
warmup, per target and scenario.

### Headline

| | `prod` | `minimal` |
|---|---:|---:|
| added latency, 1 client in flight (p50 / p90 / p99) | **+1.02 / +1.68 / +4.0 ms** | +0.64 / +0.98 / +2.1 ms |
| added latency, open loop 250–1000 req/s (p50 / p90) | +0.84–1.02 / +1.74–1.98 ms | +0.79–0.89 / +1.04–1.22 ms |
| proxy CPU per request at saturation | **570–630 µs** | 257–284 µs |
| throughput ceiling on 2 vCPUs | ~2.9–3.3 k req/s | ~5.9–7.1 k req/s |
| ≈ req/s per vCPU | **~1.6 k** | ~3.5 k |
| RSS | 65–85 MiB | 57–64 MiB |

The upstream itself answers in 0.08–0.4 ms on the same box, so against a real
model (hundreds of ms to seconds per completion) the latency the gateway adds
is noise. What it costs is **CPU**: half of it is telemetry and logging, and
the rest grows with the size of the body.

### `prod` profile, closed loop

| concurrency | direct req/s | gateway req/s | added p50 | added p90 | added p99 | proxy CPU µs/req | proxy cores |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 8 076 | 741 | +1.02 ms | +1.68 ms | +4.03 ms | 1 191 | 0.88 |
| 8 | 27 484 | 2 931 | +1.91 ms | +4.33 ms | +9.85 ms | 629 | 1.84 |
| 32 | 30 996 | 3 102 | +7.92 ms | +16.89 ms | +27.36 ms | 611 | 1.90 |
| 64 | 30 834 | 3 328 | +15.78 ms | +29.95 ms | +42.55 ms | 568 | 1.89 |

From `c=8` up the proxy is CPU-bound (1.84–1.90 of its 2 cores) and extra
concurrency only queues. CPU per request at `c=1` is inflated by background
work (exporters, sync loops) and Go scheduler spinning amortised over few
requests; size fleets with the saturated figure.

### `prod` profile, open loop

| req/s | direct p50 / p90 | gateway p50 / p90 / p99 | added p50 / p90 | proxy CPU µs/req | proxy cores |
|---:|---:|---:|---:|---:|---:|
| 250 | 0.43 / 0.73 ms | 1.45 / 2.48 / 8.9 ms | +1.02 / +1.74 ms | 1 358 | 0.34 |
| 500 | 0.42 / 0.74 ms | 1.37 / 2.72 / 28.7 ms | +0.95 / +1.98 ms | 1 245 | 0.62 |
| 1 000 | 0.31 / 0.58 ms | 1.15 / 2.37 / 15.8 ms | +0.84 / +1.79 ms | 956 | 0.96 |
| 1 500 | 0.25 / 0.44 ms | 1.10 / 5.73 / 26.4 ms | +0.85 / +5.29 ms | 804 | 1.21 |
| 2 000 | 0.24 / 0.44 ms | 1.32 / 9.46 / 46.6 ms | +1.09 / +9.02 ms | 706 | 1.41 |

The median stays around +1 ms up to 70 % CPU; p90 starts degrading past ~50 %
(1 500 req/s on 2 vCPUs). p99 and beyond are dominated by the shared VM (the
direct target alone shows 35–50 ms p99.9), so read them as an upper bound.

### `minimal` profile, closed loop

| concurrency | direct req/s | gateway req/s | added p50 | added p90 | added p99 | proxy CPU µs/req | proxy cores |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 9 665 | 1 230 | +0.64 ms | +0.98 ms | +2.12 ms | 579 | 0.71 |
| 8 | 30 275 | 5 868 | +0.87 ms | +1.95 ms | +4.68 ms | 278 | 1.63 |
| 32 | 30 592 | 7 089 | +2.81 ms | +6.63 ms | +10.86 ms | 257 | 1.82 |
| 64 | 32 196 | 6 517 | +6.73 ms | +14.23 ms | +23.60 ms | 284 | 1.85 |

Open loop at 250 / 500 / 1 000 / 1 500 req/s adds +0.89 / +0.87 / +0.79 /
+0.67 ms at p50 and +1.0–1.3 ms at p90.

### Body size

Same consumer, `c=1` for latency and `c=8` (CPU-bound) for cost:

| user message | `prod` added p50 (c=1) | `prod` µs/req | `prod` req/s | `minimal` added p50 (c=1) | `minimal` µs/req | `minimal` req/s |
|---:|---:|---:|---:|---:|---:|---:|
| 0.5 KB | +1.02 ms | 629 | 2 931 | +0.64 ms | 278 | 5 868 |
| 8 KB | +1.23 ms | 918 | 2 015 | — | 477 | 3 599 |
| 64 KB | +2.29 ms | 2 810 | 665 | +2.00 ms | 1 694 | 1 063 |

Cost grows linearly: **~22 µs of CPU per KB of request body** on the forwarding
path alone, ~34 µs/KB with telemetry on. Agent traffic with long histories and
tool schemas routinely sends 10–100 KB, where this term, not the fixed cost,
sizes the fleet (64 KB ≈ 350 req/s per vCPU in `prod`).

### Where the CPU goes

CPU profiles of the proxy at `c=8`, 20–25 s each, taken with a throwaway build
that exposes `net/http/pprof` (not part of the tree):

**`minimal`** (~290 µs/req):

| share | what |
|---:|---|
| ~26 % | `encoding/json`: the request body is fully decoded ~10 times per request by independent probes (`NormalizeOpenAIRequest`, `isResponsesAPIRequest`, `normalizeMaxCompletionTokens`, `EnforceModel`, `ExtractModel`, `ExtractModelField`, `OmitUnsupportedReasoningEffort`, `ChatMessagesNotArray`, `RequestWantsStream`, `HasAmbiguousKeys` in `pkg/infra/providers/adapter`), the response twice (`decodeCompletionsResponse`, `isResponsesAPIResponse`) |
| ~7 % | `catalogRepository.FindModel` deep-clones the catalog model through a JSON marshal/unmarshal round trip on every request (`pkg/runtimeconfig/snapshot/adapters/catalog_repository.go:44`), only for `checkContextBudget` to read `ContextWindow` (`pkg/app/proxy/context_budget.go:45`) |
| ~14 % | socket syscalls (client and upstream reads/writes) |
| ~12 % | upstream round trip through `net/http` |
| ~17 % | allocation (`mallocgc` ~11 %) and GC marking (~6 %) |

The JSON probes are why cost scales with body size: each one scans the whole
body even when it only needs one key.

**`prod`** (~700 µs/req):

| share | what |
|---:|---|
| ~54 % | the synchronous request path (everything above), of which ~7.5 % is the per-request access log (`slog` → credential redaction → OTLP log bridge) and ~4 % the ops trace/metrics middleware |
| ~18 % | async product-telemetry worker: building the event (`metrics.Builder`, including body sanitisation/redaction) and exporting it over OTLP |
| ~7.5 % | OTLP batch export of log records |
| ~6.5 % | GC |

In other words, with no policy attached, telemetry and logging cost roughly as
much CPU as forwarding the request.

### Streaming

SSE completions, `c=8`, the mock flushing every chunk as fast as it can:

| chunks per response | `prod` µs/req | `prod` req/s | `minimal` µs/req | `minimal` req/s |
|---:|---:|---:|---:|---:|
| non-streamed | 629 | 2 931 | 278 | 5 868 |
| 20 | 1 362 | 1 318 | 984 | 1 750 |
| 200 | 3 230 | 568 | 2 794 | 611 |

A streamed response costs **~0.5 ms of fixed CPU more than a buffered one,
plus ~10 µs per SSE chunk** (each chunk is decoded, adapted, re-encoded and
flushed). Added latency at `c=1` is +1.2 ms (20 chunks, `prod`) and +2.0 ms
(200 chunks, `minimal`). With 200 chunks the upstream mock and the load
generator start to share the bottleneck, so treat that row's req/s as a floor.

### Redis

With the plan rate limit on, the hot path makes **no Redis round trip**: over
an 8 s window at ~3.3 k req/s Redis saw 60 commands in total (rate-limit
counter sync, traffic-label stream reads, leases), i.e. background work, not
per request. Production's Redis network latency therefore does not add to
request latency.

## Caveats

- Everything is loopback, plain HTTP. Production adds TLS at the load
  balancer and real network hops on both sides; those are not gateway cost
  and are not measured here.
- One 4-vCPU VM. Medians and p90 are stable across runs (±0.2 ms); p99 and
  above move with VM noise and the one-core load generator. The direct
  target alone shows tens of ms at p99.9.
- fasthttp caps connections per client IP at 1024 (`MaxConnsPerIP`,
  `pkg/server/server.go:60`) and answers **429 before any middleware** (so the
  access log never sees it) once a single address holds more. A single-IP
  load generator hits it as soon as the proxy falls behind; behind a load
  balancer the proxy sees few source addresses, so long-lived streams at scale
  could reach it too.

## Takeaways

1. Latency overhead with no policies is **~1 ms at p50 and ~2 ms at p90**
   (prod-like), ~0.6–0.9 ms in the minimal profile, flat until the proxy goes
   past ~50 % CPU.
2. Capacity, not latency, is the cost: **~600 µs of CPU per small request**
   in production configuration, ~1.6 k req/s per vCPU.
3. About half of that is telemetry and logging (product events with body
   sanitisation, OTLP export of logs and events, the access log, ops traces).
4. The rest grows with the payload, ~22 µs/KB, mostly because the request body
   is JSON-decoded ~10 times by independent probes. Parsing it once and
   sharing the result, plus dropping the per-request JSON deep clone in
   `catalogRepository.FindModel`, are the cheapest wins.
5. Streaming is ~0.5 ms of fixed CPU more per request plus ~10 µs per chunk.
