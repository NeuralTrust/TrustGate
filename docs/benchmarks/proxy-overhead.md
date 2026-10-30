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
