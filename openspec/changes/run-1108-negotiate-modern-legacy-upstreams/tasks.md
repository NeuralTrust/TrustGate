# Tasks: Negociar upstreams MCP modernos y legacy

## Review Workload Forecast

| Campo | Valor |
|---|---|
| Estimación total | 2010–2660 líneas |
| Estrategia | `ask-on-risk`, cinco PRs apiladas |
| Riesgo | Alto |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: stacked-to-main
400-line budget risk: High

| Slice | Rama / base lógica | Líneas | Dependencia |
|---|---|---:|---|
| 1 Contrato | `feat/run-1108-contract` / `origin/main` | 320–390 | ninguna |
| 2 HTTP/probe | `feat/run-1108-http-probe` / slice 1 | 420–560 | contrato; `size:exception` si >400 |
| 3 Legacy | `feat/run-1108-legacy` / slice 2 | 320–430 | HTTP/probe; SDK v1.7.0 y guard aterrizan juntos |
| 4 Moderno | `feat/run-1108-modern` / slice 3 | 390–520 | transporte HTTP y guard legacy desplegable; excepción si >400 |
| 5 Coordinación | `feat/run-1108-negotiation` / slice 4 | 560–760 | ambos adaptadores; `size:exception` |

## Phase 1: Contrato y propagación

- [x] 1.1 RED: ampliar `mcp_target_test.go`, `app/mcp/target_test.go`, `updater_test.go`, request/response/handler tests, repository JSONB y `codec_secret_test.go` para default/invalid/update/JSONB/snapshot.
- [x] 1.2 GREEN: mantener SDK v1.6.1 en el slice desplegable; añadir `MCPProtocolMode`, `Target.ProtocolMode` y `ErrProtocolIncompatible` en dominio/app.
- [x] 1.3 GREEN: propagar `protocol_mode` por create/update/response y `StaticTarget`; no tocar proto/generated.
- [x] 1.4 Done: focused tests verdes y findings de revisión resueltos.

## Phase 2: Seguridad HTTP y probe

- [x] 2.1 RED: crear `http_transport_test.go` y `probe_test.go` con origen/userinfo/IPv6, reserved headers, redirect, aislamiento, JSON/SSE/ID/64KiB y matriz HTTP.
- [x] 2.2 GREEN: crear `http_transport.go` con transporte compartido, requests clonadas, redirects rechazados y headers target-scoped.
- [x] 2.3 GREEN: crear `probe.go`; strict `server/discover`, `-32020/-32021/-32022`, retry único, versión común y mapping en `protocol.go`.
- [x] 2.4 Done: tests focused verdes y reviewer/fix loop.

## Phase 3: Paridad legacy

- [x] 3.1 RED: crear `legacy_transport_test.go` y ampliar `client_test.go`/`cached_dialer_test.go`: initialize primero, versión legacy en initialized/operaciones, peek 64 KiB y body ownership, lifecycle race, origen+URL+ProtocolMode+PinKey+credencial, TTL 30m y retry solo lecturas.
- [x] 3.2 GREEN: fijar SDK v1.7.0 junto con el interceptor HTTP acotado de `legacy_transport.go`; adaptar `client.go` y `cached_dialer.go` para `ConnectLegacy`, sin discover remoto, wrapper de conexión, colisiones de identidad ni retry de `tools/call`.
- [x] 3.3 Done: focused race tests verdes; reviewer externo sin blockers y límite inclusivo exacto cubierto.

## Phase 4: Adaptador moderno

- [x] 4.1 RED: crear `modern_upstream_test.go` para todas las operaciones, wire stateless, paginación/cursor cíclico, raw results, cancelación y errores.
- [x] 4.2 GREEN: crear `modern_upstream.go` con `mcp.Connection`, identidad `trustgate`/`pkg/version`, response adapter HTTP 400/404 con gates MIME request/response y validación JSON-RPC estricta, límites inclusivos de 4 MiB/100 mensajes/100 páginas/10.000 items y sin initialize/session/GET/DELETE/retries ni extensiones opcionales.
- [x] 4.3 Done: focused tests verdes y reviewer/fix loop.

Trazabilidad de la reordenación: las antiguas tareas Legacy `4.1–4.3` son ahora `3.1–3.3`; las antiguas tareas Modern `3.1–3.3` son ahora `4.1–4.3`. Se conservan sus checkboxes.

## Phase 5: Coordinación e integración

- [x] 5.1 RED: crear `era_test.go`/`negotiating_dialer_test.go`: singleflight, cancelación independiente, credenciales, CAS, contradicción única y overrides estrictos.
- [x] 5.2 GREEN: crear `era.go`/`negotiating_dialer.go`; caché por origen sin TTL/secretos, guarded retry de lecturas y observabilidad permitida.
- [x] 5.3 Integrar en `pkg/container/modules/mcp.go` y composer/target; `pkg/server/router` no cambia. La ausencia de efectos southbound de `server/discover` se verifica en el límite northbound de RUN-1103 (`TestHandler_ModernServerDiscoverNotificationSkipsDownstreamEffects`, PR #402).
- [x] 5.4 Ampliar `tests/functional/mcp_e2e_test.go`: matriz dual-era, aliases/toolkits, credenciales aisladas, fail modes y logs sin secretos.
- [x] 5.H Hardening: coalescing por credencial y contradicción sin poisoning cross-credential —incluido `legacy_candidate` inicial—, cancelación sin consumir reconcile, descarte de errores stale, cleanup automático de singleflight, lifecycle ref-safe, SHA-256 completo, telemetría estable y fixtures autenticados.
- [x] 5.5 Verificar `gofmt`, `goimports`, focused tests, `go test -race ./...`, `go vet ./...`, `golangci-lint run`, `make license-check`; reviewer/fix final. La suite funcional completa queda bloqueada por Kafka/harness no disponibles; la compilación con tag funcional pasa.
- [x] 5.P PR preflight: deduplicar cold connects legacy cacheables, aislar sesiones sin `PinKey`, normalizar modo efectivo y esquema HTTP(S), y rechazar headers canónicos duplicados antes de I/O.

## Approval gate

- [x] Usuario aprueba cinco slices, bases y excepciones antes de `sdd-apply`; commits, push y PR quedan fuera y requieren aprobación posterior/work gates.
