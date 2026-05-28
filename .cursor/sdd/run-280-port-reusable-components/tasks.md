# Tasks: RUN-280 Port Reusable Components

Scope guard: no standalone RUN-294, Prometheus/observability, detection exporter, audit SDK glue, embeddings, semantic load balancing, plugins, auth, sessions, concrete B.2 repositories, or streaming activation. PR budget: ship RUN-291 and RUN-289 separately; split RUN-292 into adapter/client/strategy PRs and RUN-290 into helper/handler/router PRs because each exceeds 400 changed lines if bundled.

## Phase 1: Foundation, Config, and DI Surfaces

Architectural rule (see `.agents/AGENT.md` §10): collaborator interfaces
**must** live next to their implementation in `pkg/app/<entity>/<usecase>.go`
with a `//go:generate mockery` directive. We do **not** create cross-cutting
"contracts" files in `pkg/api/handler/http/`. Therefore Phase 1 does not
declare B.1 collaborator interfaces in isolation — each contract is created
inside the phase that builds its implementation (Phases 2-5).

- [x] 1.1 Update `pkg/config/config.go` and `.env.example` with env-only Redis TLS, Kafka/TrustLens telemetry, metrics toggles, upstream timeout/error-passthrough, and provider defaults.
- [ ] 1.2 Wire empty-safe module surfaces in `pkg/container/modules/cache.go`, `pkg/container/modules/telemetry.go`, `pkg/container/modules/backend.go`, and `pkg/container/modules/api.go` so missing required proxy dependencies fail at boot. Collaborator interfaces themselves are added by their owning phase.

## Phase 2: RUN-291 Cache Subsystem

- [ ] 2.1 Create `pkg/infra/cache/**` Redis client with TLS config, ping readiness, and fail-fast required-cache startup behavior.
- [ ] 2.2 Add TTL-aware set/get/delete maps in `pkg/infra/cache/**` covering Cache Subsystem scenarios “Entry is within TTL” and “Entry is expired”.
- [ ] 2.3 Add cache pub/sub publisher, listener, event types, and stop path in `pkg/infra/cache/**` for “Invalidation event is received” and “Subscriber is stopped”.
- [ ] 2.4 Add invalidation subscriber/index creator only where covered by `cache-subsystem/spec.md`; wire lifecycle in `pkg/container/modules/cache.go`.

## Phase 3: RUN-289 Metrics and Telemetry

- [ ] 3.1 Create `pkg/app/metrics/worker.go` (Worker interface + impl + `//go:generate mockery`) and the supporting collector + request event context under `pkg/infra/metrics/**` for “Proxy request completes” and collaborator outcome association.
- [ ] 3.2 Create `pkg/api/middleware/metrics.go` and register it for proxy traffic in `pkg/container/modules/api.go` and `pkg/container/modules/server_proxy.go`. The middleware depends on `app/metrics.Worker`, not the concrete struct.
- [ ] 3.3 Create `pkg/app/telemetry/exporter.go` (Exporter interface + `//go:generate mockery`) and Kafka + TrustLens exporter implementations under `pkg/infra/telemetry/**`; explicitly omit Prometheus, detection, and audit SDK paths.
- [ ] 3.4 Wire telemetry worker startup/shutdown in `pkg/container/modules/telemetry.go` for Exporter Lifecycle scenarios, ensuring exporter failures do not block forwarding.

## Phase 4: RUN-292 Providers, Adapters, and Load Balancing

- [ ] 4.1 In a dedicated PR slice, create `pkg/app/provider/adapter.go` (Adapter interface + `//go:generate mockery`) and the registry + factory implementation under `pkg/infra/providers/adapter/**`. Normalization DTOs live in `pkg/api/handler/http/request/` and `pkg/api/handler/http/response/` per §10.3/§10.4.
- [ ] 4.2 In separate provider PR slices, add non-streaming provider clients under `pkg/infra/providers/**`; keep streaming methods dormant or excluded per chosen B.1 contract.
- [ ] 4.3 Create `pkg/app/loadbalancer/selector.go` (Selector interface + `//go:generate mockery`) and the round-robin / weighted / least-connections / random strategy implementations under `pkg/infra/loadbalancer/**` with health eligibility and no semantic/embedding dependencies.
- [ ] 4.4 Wire provider locator, adapter registry, and load-balancer factory in `pkg/container/modules/backend.go`.

## Phase 5: RUN-290 Non-Streaming Forwarding and Router

- [ ] 5.1 Add only directly required `pkg/infra/httpx/**`, `pkg/infra/crypto/**`, or `pkg/infra/fingerprint/**` helpers inside the RUN-290 PR slice.
- [ ] 5.2 Create one request DTO per file in `pkg/api/handler/http/request/` (e.g. `forward_proxy_request.go`) and one response DTO per file in `pkg/api/handler/http/response/` (e.g. `forward_proxy_response.go`) covering request extraction, safe headers, error passthrough, and response preservation. Follow §10.3/§10.4.
- [ ] 5.3 Create `pkg/app/rule/matcher.go` (Matcher interface + `//go:generate mockery`) and `pkg/app/upstream/finder.go` (Finder interface + `//go:generate mockery`) co-located with their implementations per §10.2, then create `pkg/api/handler/http/forwarded_handler.go` that depends on those interfaces (plus `app/loadbalancer.Selector`, `app/provider.Adapter`, `app/metrics.Worker`) for non-streaming target resolution, retry/selection, provider/raw upstream execution, and deferred-behavior guardrails.
- [ ] 5.4 Register the catch-all proxy route in `pkg/server/router/proxy_router.go` after health/explicit routes, and wire the handler through `pkg/container/modules/api.go` and `pkg/container/modules/server_proxy.go`.

## Phase 6: Tests, Verification, and Docs

- [ ] 6.1 Add package tests beside `pkg/infra/cache/**`, `pkg/infra/metrics/**`, `pkg/infra/telemetry/**`, `pkg/infra/providers/**`, and `pkg/infra/loadbalancer/**` for the named spec scenarios.
- [ ] 6.2 Add Fiber/router tests for `pkg/api/middleware/metrics.go`, `pkg/api/handler/http/forwarded_handler.go`, and `pkg/server/router/proxy_router.go` covering HTTP Server and Proxy Forwarding scenarios. Drive them from `pkg/app/<entity>/mocks/*` (mockery-generated) for collaborator boundaries.
- [ ] 6.3 Add DI tests for `pkg/container/modules/*` covering “Proxy modules resolve”, “Proxy module dependency is missing”, shared singletons, and test overrides.
- [ ] 6.4 Run `go generate ./...` followed by `go test -race ./...` and verify no forbidden dependencies or deferred features were introduced, and that no hand-rolled mocks were committed.
