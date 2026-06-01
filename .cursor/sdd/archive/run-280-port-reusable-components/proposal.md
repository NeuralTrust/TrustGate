# Proposal: RUN-280 Port Reusable Components

## Intent
Port proven TrustGate proxy hot-path components into AgentGateway B.1 with no semantic redesign, adapted to Go 1.26, `slog`, env-only config, Fiber v2, `pgx/v5`, and `uber/dig`.

## Scope
### In Scope
- RUN-291: `pkg/infra/cache`, `pkg/container/modules/cache.go`, Redis config.
- RUN-289: `pkg/api/middleware` metrics plus `pkg/infra/metrics` and `pkg/infra/telemetry` Kafka/TrustLens exporters.
- RUN-292: `pkg/infra/providers`, `pkg/infra/loadbalancer` adapters, clients, and non-semantic strategies.
- RUN-290: `pkg/api/handler/http/forwarded_handler.go` and `pkg/server/router/proxy_router.go`.
- Minimal shared helpers required by the active sub-issues, ported inside the owning slice rather than as a standalone RUN-294 workstream.

### Out of Scope
- Plugin manager/catalog, supporting middleware/types/websocket/audit service/test harness/scripts, policies, streaming activation, auth, sessions, B.2 repository implementations.
- Detection exporter, audit SDK glue, semantic load-balancer storage, Prometheus/observability, embeddings, behavior redesign.
- RUN-294 as a standalone shared-utilities sub-issue; it was deleted and MUST NOT be implemented as part of RUN-280.

## Capabilities
### New Capabilities
- `cache-subsystem`: Redis cache, TTL, pub/sub, invalidation.
- `metrics-telemetry`: metrics collection and exporter lifecycle.
- `llm-provider-adapters`: clients, adapters, factories, balancing strategies.
- `proxy-forwarding`: non-streaming forwarding and response handling.

### Modified Capabilities
- `dependency-injection`: wire cache, telemetry, provider, load-balancer, proxy handler modules.
- `http-server`: add proxy metrics middleware and catch-all non-streaming route.
- `database-infra`: no requirement change; B.2 repository/semantic storage stay behind interfaces.

## Approach
Choose phased ports with adapter shims: cache, metrics/exporters, providers/load balancer in small slices, then forwarded handler. Port only the minimal shared helpers needed by each active slice; do not create a RUN-294 utility workstream. Replace `logrus`, Viper-like config, GORM, and broad `types` coupling with `slog`, env config, narrow interfaces, and AgentGateway packages. Preserve streaming-capable provider interfaces only where needed, without activating streaming. Do not include Prometheus, observability, embeddings, or semantic load balancing in B.1.

## Affected Areas
| Area | Impact |
|---|---|
| `pkg/api/handler/http` | New non-streaming handler and helpers. |
| `pkg/api/middleware` | Proxy metrics middleware. |
| `pkg/server/router/proxy_router.go` | Proxy catch-all wiring. |
| `pkg/infra/{cache,metrics,telemetry,providers,loadbalancer}` | Reusable infra from active sub-issues. |
| `pkg/infra/{httpx,crypto,fingerprint}` | Minimal helper code only when required by RUN-289/290/291/292; no standalone RUN-294 scope. |
| `pkg/config/config.go` | Env-only Redis, Kafka, metrics, provider, timeout, encryption. |
| `pkg/container/modules/*` | DI modules for ported components. |

## Risks
| Risk | Mitigation |
|---|---|
| RUN-292 exceeds 400-line review budget. | Split providers/adapters/load-balancer into slices. |
| RUN-289 exporter scope mismatch. | Include Kafka/TrustLens; defer detection to B.3 unless re-scoped. |
| RUN-294 was deleted but appears in older exploration notes. | Treat RUN-294 as out of scope; only port transitive helpers required by active sub-issues. |
| Prometheus/observability needs separate investigation. | Exclude Prometheus and observability from B.1 entirely. |
| Embeddings imply repository/semantic-routing design. | Exclude embeddings and semantic load balancing from B.1. |
| RUN-290 has B.2/B.3/B.4 pressure. | Use interfaces; defer plugins, repositories, streaming, auth. |

## Rollback Plan
Revert slices in reverse order: forwarded handler/router, providers/load balancer, metrics/exporters, cache, then any helper files introduced by those slices. Remove DI registrations and routes before deleting packages.

## Dependencies
- TrustGate source packages for RUN-289, RUN-290, RUN-291, RUN-292.
- Minimal TrustGate helper packages only when directly required by those active sub-issues.
- Go dependencies for Redis, Kafka, provider SDKs, compression, HTTP clients.
- Existing `dependency-injection`, `http-server`, `database-infra` specs.

## Success Criteria
- [ ] Components compile without `logrus`, GORM, Viper, Cobra, or infra leaks.
- [ ] Proxy behavior matches TrustGate non-streaming semantics.
- [ ] Cache, metrics/exporters, providers, load balancer are DI-wired and testable.
- [ ] Deferred B.2/B.3/B.4 behavior is not activated.
