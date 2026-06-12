# Plan: merge de `develop` (Phase 1-6 auth/roles) en `feat/mcp_gateway` (PR #50)

Fecha: 2026-06-12
Estado: Fases 0-2 completadas (merge resuelto, build + tests + race + lint verdes).
D1 implementado durante la Fase 2: `FindActiveByPath` → `FindActiveBySlug`, el plano
MCP resuelve `/{consumer_slug}/mcp` (`PathResolver` extrae el slug del path). Las
migraciones de ambas ramas resultaron compatibles sin renumerar (toolkit/fail_mode se
añaden en 20260609, develop elimina `path` en 20260611 con `IF EXISTS`). Pendiente:
Fase 3 (D2 unificación auth entrante, D5 revisión oauthclient) y Fase 4 (smoke manual).

## Contexto

Las dos ramas divergen en `520000a` (merge PR #41):

- `develop` (+22 commits): refactor auth/roles (épica ENG-766, fases 1-6). Introduce
  `routing_mode` (inline/role_based), entidad `roles`, IdP/JWT (`infra/auth/idp`),
  `OAuth2Config`/`IDPConfig`/`OAuth2ClientConfig`, slug de gateway y consumer,
  **eliminación de `consumer.path`** (paths de proxy fijos: `/{consumer_slug}/v1/...`),
  pool-scoped LB, fallback autorizado, RoutingIntent y observabilidad de routing.
- `feat/mcp_gateway` (+33 commits): MCP gateway completo. Registry `Type` LLM/MCP +
  `MCPTarget`, composer/federación MCP, toolkit policies, OAuth proxy del MCP server
  (DCR, connect/consent), vault de credenciales, STS/token exchange, validación
  entrante OIDC/introspection/mTLS (`ChainIdentityResolver`), dominio del gateway.

Simulación con `git merge-tree`: **37 ficheros con conflicto de contenido** + 1
modify/delete. 64 ficheros tocados por ambas ramas.

Worktree de referencia con develop limpio: `/Users/edu/Neuraltrust/AgentGateway-develop`.

## Principio rector

**develop es el modelo base; el trabajo MCP se re-acomoda encima.** En cada conflicto
estructural (consumer, gateway, auth, proxy, container) gana la estructura de develop y
se re-añaden las extensiones MCP como capacidad adicional. Nunca al revés: no
arrastramos a develop hacia el modelo viejo (path custom, auth sin roles).

## Decisiones de diseño (cerradas antes de resolver conflictos)

| # | Decisión | Resolución |
|---|---|---|
| D1 | Direccionamiento del endpoint MCP sin `consumer.path` | Ruta fija `/{consumer_slug}/mcp` en el plano proxy, simétrica a `/{consumer_slug}/v1/...`. El matching por path custom (`FindActiveByPath`, `canonicalPath`) desaparece; se resuelve consumer por slug + gateway (dominio o `X-AG-Gateway-Slug`). |
| D2 | Validador JWT único | Sobrevive `infra/auth/idp` (develop), ya cableado a roles. De nuestra rama se portan: introspection (tokens opacos), mTLS/XFCC, y `domain/identity.Principal` con `RawToken` (lo necesitan passthrough/exchange/forwarded de MCP). El `Verifier` de develop debe producir/poblar un `Principal` en el contexto. `infra/auth/oidc` (nuestro) se elimina tras portar lo que falte (discovery con timeout, singleflight si develop no lo tiene). |
| D3 | Dónde viven las `mcp_policies` | Espejo de `model_policies` según lo decidido en el chat de Phase 1: en consumer cuando `routing_mode=inline` y en la entidad `role` cuando `routing_mode=role_based`. En este merge solo se integra el caso inline (`Consumer.MCP *MCPPolicy`); el soporte en role va en un follow-up. |
| D4 | `OAuth2Config` duplicado en `domain/auth` | Gana la versión de develop (integrada con `IDPConfig`). Nuestros añadidos (validación de scopes de protocolo OIDC, trimming de audiences) se portan a la versión de develop. |
| D5 | Cliente OAuth saliente | No son duplicados reales: `infra/auth/oauthclient` (client_credentials, develop) y `infra/oauth/provider_client` (authorization-code/refresh para federación MCP, nuestro) cubren flujos distintos. Se mantienen ambos. Revisar si comparten suficiente para extraer un helper común (no bloqueante). |

## Fases

### Fase 0 — Preparación

1. Rama de seguridad: `git branch backup/feat-mcp_gateway-pre-merge` sobre el HEAD actual.
2. `git merge origin/develop --no-commit` en `feat/mcp_gateway`.
3. Los ficheros sin conflicto se aceptan tal cual (auto-merge).

### Fase 1 — Resolución mecánica de los 37 conflictos

Agrupados por área, con criterio de resolución:

| Área | Ficheros | Criterio |
|---|---|---|
| Docs | `docs/run-277-fallback-investigation.md` (modify/delete) | Conservar la versión de develop (lo borramos nosotros, develop lo actualizó). |
| Domain consumer | `consumer.go`, `consumer_test.go`, `errors.go`, `repository.go`, mocks | Base develop (`Slug`, `RoutingMode`, `RoleIDs`, `LBConfig`, sin `Path`). Re-añadir: `Type` (LLM/MCP), `MCP *MCPPolicy` (toolkit, fail_mode), validación de toolkit, errores MCP. Regenerar mocks al final. |
| Domain gateway | `gateway.go`, `repository.go` | Base develop (slug). Re-añadir `Domain` + `NormalizeDomain` (validación endurecida) si develop no trae equivalente. |
| Domain auth | `config.go`, `repository.go`, `auth_test.go` | D4: base develop. Portar validaciones nuestras de `OAuth2Config.validate` (protocol scopes, trims). |
| Domain ids / registry errors | `ids.go`, `registry/error.go` | Unión trivial: develop añade `RoleID`; nosotros `RegistryID` usos MCP y errores MCP. Mantener ambos. |
| App consumer | `creator.go`, `updater.go`, `associator.go`, `consumer_data.go`, tests | Base develop (routing_mode, roles, slug). Re-añadir: validación de tipo en `AttachRegistry` (registry MCP ↔ consumer MCP), toolkit en create/update inline, `RoutableConsumer` con registries MCP. Eliminar lógica path-based (D1). |
| App gateway | `creator.go`, tests | Base develop. Re-añadir domain si aplica. |
| App proxy | `forwarder.go`, `provider.go`, tests | Base develop (RoutingIntent, CandidateSet, pool LB, fallback autorizado). Nuestro filtro "solo consumers LLM al forwarder" se traduce al modelo nuevo: el dispatcher por tipo vive en el router/handler (LLM → forwarder, MCP → composer). |
| HTTP handlers consumer | create/update handler, requests, response | Base develop. Re-añadir campos MCP del request (type, toolkit, fail_mode) con la normalización nuestra (ToUpper/Trim, nil vs vacío del toolkit). |
| HTTP handlers gateway | create/update handler, requests | Base develop (slug). Re-añadir `domain` si no existe. |
| Proxy handler | `proxy_handler.go` | Base develop (slug routing). Montar `/{consumer_slug}/mcp` → MCP handler (D1). |
| Middleware | `auth.go` | Base develop (`AuthMiddleware` + IdP + roles). La integración del resto de la cadena (introspection, mTLS) se hace en Fase 3, no aquí. `auth_chain.go` se conserva temporalmente sin cablear. |
| Config | `config.go` | Unión: claves de develop (IdP, roles) + nuestras (STS, vault, TRUST_XFCC_FROM, OAuth proxy). |
| Container | `api.go`, `auth.go` | Unión de providers; los conflictos de cableado se resuelven a favor de develop y los módulos MCP/OAuth/vault/STS se mantienen como módulos propios. |
| Infra repos | `auth`, `consumer`, `gateway` repository | Base develop (esquema con slug/roles, sin path). Re-añadir columnas MCP (type, toolkit, fail_mode) vía migración nueva post-merge, no editando las de develop. |
| Infra cache | subscriber + test | Unión de invalidaciones (develop añade roles; nosotros MCP discovery). |

### Fase 2 — Compilar y reparar referencias

1. Migraciones: renumerar las nuestras para que ordenen después de las de develop
   (`add_mcp_registry_and_toolkit`, `add_vault_credentials`, `add_gateway_domain` —
   esta última revisar si develop ya cubre gateway slug/domain) y adaptarlas al esquema
   nuevo (toolkit/type sobre el consumer sin path).
2. `go build ./...` hasta verde; regenerar mocks (`go generate ./...`).
3. `go test ./pkg/...`: los tests de ambos lados deben pasar. Los tests nuestros
   path-based de consumer se reescriben contra slug.
4. Commit del merge.

### Fase 3 — Reconciliación semántica (post-merge, misma PR)

1. **D1**: implementar la ruta `/{consumer_slug}/mcp`; eliminar `FindActiveByPath`,
   `canonicalPath` y el `PathResolver` orientado a path custom; el `oauth_challenge`
   y los metadata endpoints OAuth del MCP server pasan a resolver por slug.
2. **D2**: unificar auth entrante.
   - `infra/auth/idp.Verifier` produce `identity.Principal` (subject, issuer, scopes,
     claims, `RawToken`, `Method`).
   - Portar introspection y mTLS/XFCC como ramas del `AuthMiddleware` de develop
     (o integrar `ChainIdentityResolver` como resolutor del middleware: decidir lo que
     menos toque develop).
   - Eliminar `infra/auth/oidc` tras portar discovery con timeout y singleflight.
3. **D3**: `MCPPolicy` solo en consumer inline; validar que `routing_mode=role_based`
   + type MCP devuelve error claro (soporte en role = follow-up, issue nueva).
4. **D5**: revisar solape `oauthclient` vs `provider_client`; dejar nota o extraer
   helper si es trivial.

### Fase 4 — Verificación final

1. Suite completa + `golangci-lint run ./pkg/...`.
2. Smoke manual: crear gateway + consumer MCP inline + registry MCP, `tools/list` y
   `tools/call` vía `/{consumer_slug}/mcp`; flujo consent OAuth completo.
3. Confirmar que el flujo LLM de develop (roles, fallback, pools) no se ha degradado:
   tests de `app/proxy` y `app/role` intactos.
4. Push y actualización de la descripción de la PR #50 con el resultado del merge.

## Follow-ups fuera de esta PR

- `mcp_policies` en la entidad `role` (espejo de `model_policies`) para `role_based`.
- Posible helper común para clientes de token endpoint (D5).
- Revisar si el frontend (develop lo añadió en PR #41/#53) necesita superficie MCP.

## Riesgos

- **Volumen**: 37 conflictos + reconciliación semántica en una sola PR. Mitigación:
  commits separados por fase (merge mecánico / build verde / D1 / D2 / D3) para que la
  PR sea revisable por pasos.
- **Auth entrante**: D2 toca el camino crítico de autenticación de ambos planos.
  Mitigación: mantener los tests de ambos lados como red; añadir tests de integración
  del middleware unificado antes de borrar `infra/auth/oidc`.
- **Esquema de BBDD**: la base se recrea desde cero (decisión de Phase 1), así que las
  migraciones pueden reordenarse sin compatibilidad hacia atrás.
