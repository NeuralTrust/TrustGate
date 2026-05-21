---
linear: ENG-415
team: ENG
status: in-progress
type: breaking
---

# Proposal: Deprecate the Service entity

## Why

The `Service` entity in `pkg/domain/service` is dead weight in the data plane: at runtime, the forwarded HTTP and WebSocket handlers only honor `TypeUpstream` services and immediately resolve the linked upstream. `TypeEndpoint` services are effectively unreachable through the gateway hot path (see `pkg/handlers/http/helpers/upstream.go` and `pkg/handlers/websocket/forwarded_handler.go`).

This indirection costs us:

- An extra DB lookup and cache layer per request (service → upstream).
- A duplicated configuration surface (host/port/protocol/headers/credentials live on both `Service` for endpoint type and `Upstream.Target` for provider type).
- A whole bounded context to maintain: domain entity, repository, app services, 5 HTTP handlers, cache invalidation events, audit constants, and ~15 functional tests that go through `apiCreateService` before creating rules.

Removing the entity simplifies the model: a `forwarding_rule` points to an `upstream`, full stop.

## What Changes

- **Schema**: `forwarding_rules.service_id` is replaced with `forwarding_rules.upstream_id` (NOT NULL, FK to `upstreams(id)` with `ON DELETE CASCADE`). The `services` table is dropped.
- **Data migration**: A one-shot transactional migration (`20240007_drop_services_and_link_rules_to_upstreams`) backfills `upstream_id`:
  - `type='upstream'` services: relink rule directly to the existing upstream.
  - `type='endpoint'` services: synthesize a new upstream with a single target carrying the service's host/port/protocol/path/headers/credentials.
  - Aborts with `orphan rules detected: N` if any rule cannot be relinked.
- **Admin API (breaking)**: The `/api/v1/gateways/:gateway_id/services` endpoints are removed. Rule create/update payloads use `upstream_id` instead of `service_id`.
- **Code removal**: `pkg/domain/service`, `pkg/app/service`, `pkg/infra/repository/service_repository.go`, all `*_service_handler.go` files, the `DeleteServiceCacheEvent` and its subscriber, `cache.Client.GetService`/`SaveService` and related TTL/key patterns, and the service-related audit constants.
- **Runtime simplification**: The forwarded HTTP and WebSocket handlers drop their `service.Finder` dependency and call `upstream.Finder` directly using `rule.UpstreamID`.
- **Observability (breaking)**: Prometheus labels `service_id` are renamed to `upstream_id` on `GatewayDetailedLatency` and `GatewayUpstreamLatency`.

## Capabilities

### Modified Capabilities

- `forwarding_rule` — schema, request/response DTOs, app services, and runtime resolution.

### New Capabilities

- `data-migration` — the `20240007` migration and its operational contract (timeout uplift, orphan assertion, best-effort Down).

### Removed Capabilities

- `services` — entity, repository, app services, HTTP routes, cache, events, audit constants.

## Affected Areas

- `pkg/domain/{forwarding_rule,service}` · `pkg/app/{rule,service,gateway}` · `pkg/infra/{repository,cache,migrations,auditlogs,prometheus}` · `pkg/handlers/{http,websocket}` · `pkg/server/{router,middleware}` · `pkg/dependency_container` · `tests/functional` · `docs/swagger.*`.

## Rollout

Single-PR breaking change. Production rollout requires DB backup before deploy. Migration is gated by an advisory lock and runs under an elevated startup timeout (default 5 minutes, configurable). Rollback is supported via the migration `Down` function, but endpoint-type services synthesized into upstreams are NOT collapsed back (one-way for endpoint type, documented).
