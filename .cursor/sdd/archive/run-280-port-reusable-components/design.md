# Design: RUN-280 Port Reusable Components

## Technical Approach

Use Approach B: phased ports with adapter shims. Port TrustGate hot-path behavior without semantic redesign, but adapt it to AgentGateway boundaries: `slog`, env-only config, Fiber v2 handlers/middleware, `uber/dig` modules, no Cobra, no Viper/YAML, no GORM, and no infra imports from `pkg/domain` or `pkg/app`.

This design is based on `proposal.md` and `explore.md`; no spec files were present when this ran. Reconcile this design after the parallel spec phase completes.

## Architecture Decisions

| Decision | Choice | Alternatives considered | Rationale |
|---|---|---|---|
| Port style | Phased port with thin adapters | Big-bang copy; rewrite while porting | Preserves TrustGate behavior while keeping review slices small and reversible. |
| Logging/config | Replace `logrus` with `*slog.Logger`; add env-only config fields | Keep `logrus`; port TrustGate config shape | Matches AgentGateway conventions and avoids stack drift. |
| Cache | Create `pkg/infra/cache` Redis client, TTL maps, pub/sub/event pieces, wired by `modules.Cache` | Put cache in app/domain; defer all cache | Cache is infra and already has a module stub; domain-specific methods should be behind later narrow interfaces. |
| Metrics/exporters | Create metrics collector/worker plus Kafka and TrustLens telemetry; defer Prometheus and detection exporter | Include detection; Prometheus/observability layer | Detection depends on plugin decisions and `event-schemas`; Prometheus and broader observability will be investigated separately. |
| Providers/load balancer | Split RUN-292 into adapter, client, factory, and non-semantic strategy slices | Single RUN-292 port; semantic load balancing with embeddings | RUN-292 exceeds the 400-line review budget; embeddings, embedding factory/repository, semantic strategy, and semantic provider selection are deferred. |
| Forwarding | Add non-streaming `ForwardedHandler` and catch-all proxy route after collaborators exist | Activate streaming/plugins/auth/session now | RUN-290 should preserve non-streaming forwarding semantics only and keep later B.x pressure out. |
| Helpers | Allow only transitive `httpx`, `crypto`, and `fingerprint` files owned by RUN-289/290/291/292 when directly required | Standalone RUN-294 utility phase; Prometheus/embedding helper ports | RUN-294 is deleted and must not be implemented; Prometheus and embedding helpers are explicitly deferred. |

## Data Flow

```text
client
  -> proxy Fiber app
  -> proxy middleware chain
     -> request id / security / cors / recover / access log / metrics collector
  -> catch-all ForwardedHandler
     -> gateway/rule/upstream lookup interfaces
     -> cached load balancer
     -> provider adapter + provider client OR raw upstream forwarding
     -> response normalization + metrics events
  -> metrics worker
     -> Kafka exporter / TrustLens exporter
  -> client response
```

## File Changes

| File | Action | Description |
|---|---|---|
| `pkg/config/config.go` | Modify | Add env-only Redis TLS, Kafka topic/security, metrics, upstream timeout/error-passthrough, and provider defaults as needed. |
| `.env.example` | Modify | Document new env vars. |
| `pkg/infra/cache/**` | Create | Redis client, TTL maps, pub/sub listener/publisher, invalidation events. |
| `pkg/container/modules/cache.go` | Modify | Provide cache client, TTL maps, and lifecycle-safe subscribers. |
| `pkg/infra/metrics/**` | Create | Collector, events, worker, and request metric support without Prometheus registry/exporter code. |
| `pkg/api/middleware/metrics.go` | Create | Fiber middleware that creates/flushes metrics collector. |
| `pkg/infra/telemetry/**` | Create | Exporter contracts, Kafka base/exporter, TrustLens exporter. |
| `pkg/container/modules/telemetry.go` | Modify | Wire exporters and metrics worker with shutdown path. |
| `pkg/infra/providers/**` | Create | Provider DTOs, clients, adapter registry, factories. Split by provider/adapter slices. |
| `pkg/infra/loadbalancer/**` | Create | Factory, non-semantic strategies, and health-state handling. Exclude semantic strategy and embedding dependencies. |
| `pkg/container/modules/backend.go` | Modify | Wire provider locator, adapter registry, and load-balancer factory. |
| `pkg/api/handler/http/forwarded_handler.go` | Create | Non-streaming forwarding handler with retry, target selection, provider adaptation, error passthrough. |
| `pkg/api/handler/http/request/**` | Create | Minimal request helpers needed by non-streaming forwarding. |
| `pkg/api/handler/http/response/**` | Create | Minimal response helpers needed by non-streaming forwarding. |
| `pkg/server/router/proxy_router.go` | Modify | Register proxy catch-all after health routes. |
| `pkg/container/modules/api.go` | Modify | Provide metrics middleware and forwarded handler. |
| `pkg/container/modules/server_proxy.go` | Modify | Add metrics middleware to proxy transport and handler dependency to router params. |
| `pkg/infra/httpx/**`, `pkg/infra/crypto/**`, `pkg/infra/fingerprint/**` | Create if required | Minimal transitive helpers only, owned by the active slice that needs them. |
| `pkg/infra/prometheus/**`, `pkg/infra/embedding/**` | Defer | Explicitly out of B.1; future observability/semantic-routing workstreams own these. |

## Interfaces / Contracts

```go
type UpstreamFinder interface {
	FindForRule(ctx context.Context, gatewayID string, ruleID string) (*domain.Upstream, error)
}

type RuleMatcher interface {
	Match(ctx context.Context, req ProxyRequest) (*domain.ForwardingRule, error)
}

type MetricsWorker interface {
	StartWorkers(n int)
	Process(collector *metrics.Collector, req ProxyRequest, resp ProxyResponse, startedAt time.Time, endedAt time.Time)
	Shutdown()
}
```

Define interfaces where consumed. B.1 may provide temporary adapters, but no concrete `pgx`/GORM dependency should enter providers, load balancer, or handlers.

## Testing Strategy

| Layer | What to Test | Approach |
|---|---|---|
| Unit | TTL maps, Redis key behavior, exporter validation, adapters, load-balancer strategies, handler error mapping | Table-driven tests beside packages; mocks/fakes for Redis/provider/exporter interfaces. |
| Integration | Redis ping/pub-sub, Kafka producer lifecycle, proxy route wiring | Gated env tests; no mandatory local services for default `go test ./...`. |
| E2E | Non-streaming proxy request to fake upstream/provider | Fiber app with fake collaborators; assert status, headers, body, retry/error-passthrough. |

## Migration / Rollout

No data migration required. Roll out in dependency order: RUN-291 cache, RUN-289 metrics/telemetry without Prometheus or detection exporter unless clarified, RUN-292 split providers/load balancer without semantic strategy or embeddings, then RUN-290 split forwarding/router. Revert in reverse order. RUN-292 and RUN-290 must be split into multiple PRs to respect the 400-line review budget.

## Open Questions

- [ ] What exact Redis TLS env names and verification posture should AgentGateway use?
- [ ] Should provider interfaces keep dormant streaming methods for source compatibility, or expose non-streaming-only B.1 contracts?
- [ ] Should RUN-289 include only Kafka/TrustLens telemetry, or should detection exporter remain deferred until plugin decision semantics are available?
