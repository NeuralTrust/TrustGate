# TrustGate Code Review

Fecha: 2026-06-22

Alcance: revision completa de `TrustGate` (`github.com/NeuralTrust/TrustGate`) en busca de bugs, race conditions, code smells, anti-patterns, anti-clean-code y desviaciones de arquitectura hexagonal. Incluye backend Go, proxy runtime, auth/OAuth/MCP, persistencia, cache, telemetria, CI y documentacion.

## Metodologia

- Se revisaron las capas `pkg/domain`, `pkg/app`, `pkg/api`, `pkg/infra`, `pkg/container`, `pkg/server`, `cmd/trustgate`, `.github`, `docker-compose` y `docs`.
- Se hicieron revisiones separadas por arquitectura backend, proxy/plugins/providers, auth/OAuth/MCP/RBAC, persistencia/cache/telemetria y deploy/CI/docs.
- Se contrastaron los hallazgos criticos con busquedas locales y lecturas puntuales de codigo.
- Verificacion ejecutada:
  - `go test ./pkg/...` pasa.

Estos checks no cubren los fallos de seguridad/contrato descritos abajo.

## Resumen Ejecutivo

TrustGate tiene buena cobertura unitaria en muchos paquetes y una separacion nominal por capas, pero hay riesgos importantes:

1. **Auth/OAuth con gaps reales**: STS elige el primer OAuth2 global por issuer sin gateway scope, introspection no valida issuer y varios endpoints OAuth publicos no tienen rate-limit visible.
2. **Runtime proxy con bypasses de policy**: token rate limiter no funciona en `pre_request` si `Provider` no esta seteado; streaming no contabiliza tokens; `pre_response` falla abierto para errores que no sean `PluginError`.

Prioridad recomendada:

- **P0**: corregir STS multi-tenant, arreglar token rate limiter en pre_request/streaming y fail-closed coherente en pre_response.
- **P1**: scope SQL por gateway, arreglar JSONB/junction integrity, activar gosec/gitleaks y proteger OAuth public endpoints con rate limits.
- **P2**: reducir acoplamiento app->infra, modularizar DI por plano, mejorar cache invalidation, backpressure/shutdown, docs y tests funcionales/integracion.

## Estado de Remediacion

Trabajo aplicado en la rama `fix/code-review-phase-1` (pendiente de merge):

- Resuelto: #1 STS/OBO por gateway, #2 token rate limiter en pre_request, #3 streaming usage, #4 pre_response fail-closed.
- Resuelto: #5 introspection valida issuer, #7 create de auth invalida cache, #8 redirect URI allowlist.
- Resuelto: #10 UPDATE/DELETE/SetGlobal scopeados por `gateway_id` en repos de policy/auth/role/registry/consumer (defensa en profundidad en SQL).
- Resuelto: #11 junctions mismo-gateway via trigger `enforce_junction_same_gateway` (BEFORE INSERT en `consumer_registry`, `consumer_role`, `consumer_auth`, `consumer_policy`, `role_registry`); error `AG422` mapeado a conflicto.
- Mitigado: #12 las referencias a registries en JSONB (`fallback.chain`, `model_policies`, `lb_config.members`) ya deben estar asociadas (`ensureRegistryRefsAssociated` / `ensureRoleRegistryRefsAssociated`), y esas asociaciones quedan acotadas al gateway por el trigger de #11 y la FK; routing cross-gateway o a registry inexistente queda cerrado por capa app + DB.
- Resuelto: #22 `gitleaks_enabled: true` (con baseline `.gitleaks.toml` que allowlista falsos positivos: fixture de `cipher_test.go` y transcripts `cursor_phase_*.md`) y `gosec_args` sin `-no-fail` y acotado a `-severity high`. Nota: el workflow reutilizable `sast.yml` ejecuta gosec/gitleaks con `continue-on-error: true` (informativos); el unico SAST bloqueante es Trivy, que ya corre con `secret` scanning por defecto. Hacer gosec/gitleaks bloqueantes de verdad requiere cambiar el repo `NeuralTrust/workflows` (fuera de este repo).
- Pendiente: #6/#9 y resto de P1/P2.

## P0 - Bloqueantes y Riesgos Criticos

### 1. STS/OBO usa el primer OAuth2 global por issuer

- Severidad: **CRITICAL**
- Categoria: Identity / STS / multi-tenant
- Evidencia:
  - `pkg/app/identity/sts/exchanger.go` obtiene `OAuth2Auths(ctx)` globales y devuelve el primer auth cuyo `Issuer` coincide.
  - No filtra por `GatewayID` ni por `AuthID` del contexto.
- Trigger: dos gateways/tenants usan el mismo IdP issuer pero distintos `client_id/client_secret`.
- Impacto: exchange con credenciales de otro tenant o fallos intermitentes segun orden de datos.
- Recomendacion: pasar `gatewayID` y/o `authID` al exchanger y consultar credenciales scopeadas por gateway.

### 2. `token_rate_limiter` se salta siempre en `pre_request`

- Severidad: **CRITICAL**
- Categoria: Policy / rate limit
- Evidencia:
  - `pkg/infra/plugins/tokenratelimit/plugin.go` retorna OK si `in.Request.Provider == ""`.
  - El proveedor se estampa despues de `runPreRequest` en el flujo del proxy.
- Trigger: cualquier politica `token_rate_limiter` en stage `pre_request`.
- Impacto: el limite preventivo no se aplica; un burst puede superar cuota antes del primer `post_response`.
- Recomendacion: resolver/estampar provider/registry antes de `pre_request`, o hacer que el limiter use scope `gateway/consumer/policy` sin requerir `Provider`.

### 3. Streaming no consume cuota de tokens

- Severidad: **CRITICAL**
- Categoria: Policy / streaming
- Evidencia:
  - `tokenratelimit.extractTokens` en streaming lee `req.Metadata[adapter.MetadataUsageKey]`.
  - Esa metadata se usa en tests pero no se escribe en el flujo productivo; usage va a trace/observability.
- Trigger: request con `stream: true` y token rate limit.
- Impacto: bypass total del limite por tokens usando streaming.
- Recomendacion: escribir usage acumulado en `RequestContext.Metadata` o leerlo desde trace en `post_response`; test funcional streaming + token limiter.

### 4. `pre_response` falla abierto ante errores no `PluginError`

- Severidad: **CRITICAL**
- Categoria: Policy stages / fail-open
- Evidencia:
  - `pkg/app/proxy/plugin_runner.go` loguea warning y continua si `err != nil` y no es `PluginError`.
  - `finalizeBody` usa el path sin gate en algunos outcomes.
- Trigger: plugin de guardrail/cache/rate-limit falla por Redis, timeout o error de infra.
- Impacto: respuesta upstream llega al cliente aunque la politica no se haya podido evaluar.
- Recomendacion: en `ModeEnforce`, fail-closed para errores de infraestructura; fail-open solo en `ModeObserve`. Unificar `finalizeBody` y `finalizeBodyGated`.

## P1 - Bugs Reales y Riesgos Altos

### 5. Introspection no valida issuer

- Severidad: **WARNING (real)**
- Categoria: OAuth/OIDC
- Evidencia: `pkg/infra/auth/introspection/validator.go` valida `active`, audience y scopes, pero no compara `res.Iss` con `cfg.Issuer`.
- Trigger: token activo de mismo IdP con audience solapada.
- Impacto: token valido para otro contexto puede aceptarse.
- Recomendacion: exigir issuer si esta configurado, normalizado y testeado.

### 6. Cache de introspection mantiene tokens revocados

- Severidad: **WARNING (real)**
- Categoria: Auth cache
- Evidencia: respuestas `active=true` se cachean hasta 5 minutos o `exp`.
- Trigger: revocacion inmediata de token en IdP.
- Impacto: acceso aceptado durante ventana de cache.
- Recomendacion: TTL menor por defecto para prod sensible, invalidacion en revoke/logout o cache configurable por auth.

### 7. Create de auth no invalida cache de credenciales

- Severidad: **WARNING (real)**
- Categoria: Cache / auth
- Evidencia:
  - `pkg/app/auth/creator.go` no publica invalidacion.
  - `updater` y `deleter` si invalidan.
  - credential finder cachea OAuth2/OIDC habilitados.
- Trigger: crear un nuevo auth y usarlo inmediatamente en MCP/OAuth/proxy.
- Impacto: auth invisible o resolucion obsoleta hasta TTL.
- Recomendacion: publicar invalidacion en creator.

### 8. Redirect URI OAuth acepta esquemas arbitrarios

- Severidad: **WARNING (real)**
- Categoria: OAuth / redirect
- Evidencia: `IsAcceptableRedirectURI` acepta por defecto esquemas no `http/https`.
- Trigger: DCR con `myapp://...` o esquema custom no controlado.
- Impacto: codigo de autorizacion entregado a URI controlada si el flujo lo permite.
- Recomendacion: allowlist explicita de esquemas; custom schemes solo si estan registrados.

### 9. Endpoints OAuth publicos sin rate-limit visible

- Severidad: **WARNING (real)**
- Categoria: OAuth / DoS
- Evidencia: `mcp_router.go` monta `/oauth/register`, `/oauth/authorize`, `/oauth/token`, `/+/connect` antes de middleware auth.
- Impacto: DCR flooding, brute force de tickets, abuso de authorize/token.
- Recomendacion: rate limiting, quotas por IP/client, metricas y alertas.

### 10. UPDATE/DELETE sin `gateway_id` en repositorios

- Severidad: **WARNING (real)**
- Categoria: SQL / defensa en profundidad
- Evidencia: repos de policy/auth/registry/role/consumer usan patrones `WHERE id = $1` en mutaciones.
- Impacto: si un caller salta la app layer o hay un bug futuro en handlers, se abre mutacion cross-gateway por UUID.
- Recomendacion: metodos tenant-scoped/gateway-scoped en interfaces y SQL `WHERE id = $1 AND gateway_id = $N`.

### 11. Junction tables no fuerzan mismo gateway

- Severidad: **WARNING (real)**
- Categoria: Schema / multi-tenant
- Evidencia: tablas `consumer_registry`, `consumer_role`, `role_registry` tienen FKs por ID pero no restriccion compuesta de `gateway_id`.
- Impacto: consumer de un gateway puede enlazarse a registry/role de otro si se bypassa app.
- Recomendacion: triggers o constraints compuestas; validacion en repos.

### 12. JSONB sin integridad referencial

- Severidad: **WARNING (real)**
- Categoria: Schema / routing
- Evidencia: `fallback`, `model_policies`, `lb_config` guardan registry IDs en JSONB.
- Trigger: update con registry inexistente o de otro gateway.
- Impacto: routing roto en runtime.
- Recomendacion: validacion app/repo en update y, si es critico, normalizar a tablas.

### 13. Migracion destructiva de policies

- Severidad: **WARNING (real)**
- Categoria: Migraciones / data loss
- Evidencia: `20260603120000_collapse_policy_into_plugin.go` hace `DROP TABLE IF EXISTS consumer_policy; DROP TABLE IF EXISTS policies;`.
- Trigger: upgrade desde esquema anterior con datos.
- Impacto: perdida de policies si no es entorno greenfield.
- Recomendacion: guard de seguridad si hay filas, ETL o documentar breaking migration.

### 14. Cache invalidation hace `Clear()` global

- Severidad: **WARNING (real)**
- Categoria: Cache / rendimiento
- Evidencia: subscribers de invalidacion limpian caches enteras para cambios de un gateway/registry.
- Impacto: thundering herd contra DB/Redis y latencias tras mutaciones.
- Recomendacion: eviccion por `gateway_id`/prefijo.

### 15. Rate limiter de requests tiene TOCTOU

- Severidad: **WARNING (real)**
- Categoria: Race condition / Redis
- Evidencia: `ratelimit` hace check y record en operaciones separadas.
- Trigger: alta concurrencia contra mismo scope.
- Impacto: se admiten mas requests que el limite.
- Recomendacion: Lua script atomico o INCR/EXPIRE con ventana fija.

### 16. Semantic cache scope incorrecto en `pre_request`

- Severidad: **WARNING (real)**
- Categoria: Cache / routing
- Evidencia: `semanticcache` prefiere `RegistryID`, pero en `pre_request` aun no esta seteado, por lo que cae a `GatewayID`.
- Impacto: colisiones de cache entre registries/modelos del mismo gateway.
- Recomendacion: estampar registry antes de pre_request o usar scope compuesto estable.

### 17. Load balancer health check falla abierto

- Severidad: **WARNING (real)**
- Categoria: Load balancing / health
- Evidencia: errores Redis/unmarshal devuelven healthy; si todos estan unhealthy, devuelve candidato igualmente.
- Impacto: trafico a backends caidos y degradacion silenciosa.
- Recomendacion: modo configurable fail-closed/fail-open, metricas y alertas.

### 18. Streaming descarta chunks con errores de adaptacion

- Severidad: **WARNING (real)**
- Categoria: Streaming / providers
- Evidencia: errores de `AdaptStreamChunk` se loguean y se continua.
- Impacto: respuesta parcial/truncada sin evento error al cliente.
- Recomendacion: emitir SSE error o abortar stream con error claro.

### 19. `post_response` no corre si el cliente corta streaming

- Severidad: **WARNING (real)**
- Categoria: Streaming / policy
- Evidencia: wrapper solo dispara `post_response` si `completed == true`.
- Trigger: cliente desconecta a mitad de stream.
- Impacto: tokens parciales no registrados y metricas/cache incompletas.
- Recomendacion: `defer` best-effort con usage parcial.

### 20. Bedrock default a familia Claude para modelos desconocidos

- Severidad: **WARNING (real)**
- Categoria: Provider adapter
- Evidencia: adapter Bedrock usa Claude como default si no detecta familia.
- Trigger: nuevo model ID Bedrock.
- Impacto: request transformado con formato incorrecto y fallo downstream.
- Recomendacion: fail-closed con `unknown bedrock model family`.

### 21. `.env.example` no define `SERVER_SECRET_KEY`

- Severidad: **WARNING (real)**
- Categoria: DX / config
- Evidencia:
  - README e install script asumen `SERVER_SECRET_KEY`.
  - `.env.example` no lo incluye.
- Impacto: quickstart/admin tokens fallan o quedan inseguros.
- Recomendacion: valor dev seguro de longitud suficiente y validacion de startup.

### 22. `gosec` y `gitleaks` no bloquean

- Severidad: **WARNING (real)**
- Categoria: CI / seguridad
- Evidencia:
  - `gosec_args: "-no-fail ./..."`.
  - `gitleaks_enabled: false`.
- Impacto: SAST/secret leaks no bloquean merge.
- Recomendacion: baseline controlado, `gosec` bloqueante por severidad HIGH y gitleaks activado.

## P2 - Arquitectura, Clean Code y Deuda de Fiabilidad

### 23. App layer acoplada a cache/infra concreta

- Severidad: **WARNING (real)**
- Categoria: Anti-hexagonal
- Evidencia: servicios en `pkg/app/*` reciben `*cache.TTLMap`, `*cache.TTLMapManager`, `cache.EventPublisher`, providers/loadbalancer/adapters concretos.
- Impacto: casos de uso no son independientes; tests arrastran infra.
- Recomendacion: puertos app para cache, event bus, provider gateway, load balancer y telemetry.

### 24. `app/proxy` es una capa infra disfrazada

- Severidad: **WARNING (real)**
- Categoria: Anti-hexagonal
- Evidencia: `pkg/app/proxy` importa `infra/providers`, `infra/loadbalancer`, `infra/context`, `infra/trace`.
- Impacto: el caso de uso principal no tiene frontera limpia.
- Recomendacion: `Forwarder` orquesta puertos de app; adapters viven en infra.

### 25. Reglas auth duplicadas en middleware, resolver y handler proxy

- Severidad: **WARNING (real)**
- Categoria: Anti-clean-code / auth drift
- Evidencia: autorizacion consumer/roles aparece en `middleware/auth.go`, `api/resolver/*` y `proxy_handler.go`.
- Impacto: divergencias entre proxy/MCP/playground.
- Recomendacion: servicio unico `app/auth.AccessGuard`.

### 26. DI monta todos los planos siempre

- Severidad: **WARNING (real)**
- Categoria: Composition root
- Evidencia: `modules.All()` cablea admin, proxy, MCP, OAuth, vault, catalog, telemetry y cache para cualquier subcomando.
- Impacto: fallo de una dependencia no usada puede impedir arrancar otro plano; mayor superficie y memoria.
- Recomendacion: `modules.ForAdmin`, `modules.ForProxy`, `modules.ForMCP`.

### 27. OAuth connect ticket no esta bound a sesion

- Severidad: **WARNING (real)**
- Categoria: OAuth / session fixation
- Evidencia: flujo connect usa ticket en query como unica prueba.
- Impacto: URL filtrada puede vincular credenciales por un tercero.
- Recomendacion: tickets one-use, TTL corto, binding a bearer/sub o cookie.

### 28. Refresh token flow con client auth `none`

- Severidad: **WARNING (theoretical)**
- Categoria: OAuth
- Evidencia: metadata declara `token_endpoint_auth_methods_supported: ["none"]`.
- Impacto: si refresh token se filtra, no hay client secret adicional.
- Recomendacion: documentar threat model y soportar clientes confidenciales donde aplique.

### 29. Role/consumer/registry bounded contexts se mezclan

- Severidad: **SUGGESTION**
- Categoria: Bounded context
- Evidencia:
  - `role` aliasa `consumer.MCPPolicy`.
  - `consumer` importa reglas de `auth`.
  - `consumer.LBConfig` referencia `registry.EmbeddingConfig`.
- Impacto: cambios en un contexto rompen otros.
- Recomendacion: shared kernel explicito o value objects propios con mappers.

### 30. `RequestContext` en `infra/context` es shared kernel no declarado

- Severidad: **SUGGESTION**
- Categoria: Arquitectura
- Evidencia: usado por api, app/proxy, app/plugins, app/metrics e infra.
- Impacto: paquete llamado `infra` actua como contrato de aplicacion.
- Recomendacion: mover a `pkg/app/request` o `pkg/common/request`.

## Tests y Cobertura

### Verificacion ejecutada

```bash
go test ./pkg/...
```

Resultado:

- `go test ./pkg/...`: pasa.

### Gaps importantes

- No hay test que demuestre `token_rate_limiter` en `pre_request` con provider no seteado.
- No hay test funcional streaming + token limiter.
- No hay tests SQL negativos para `UPDATE/DELETE` cross-gateway ni junctions cross-gateway.

## Matriz de Remediacion

### Sprint 1 - Seguridad y runtime

1. Scopear STS/OBO por gateway/auth.
2. Arreglar token rate limiter pre_request y streaming usage.
3. Definir fail-closed de `pre_response` en enforce mode.

### Sprint 2 - Multi-tenant y contratos

1. Hacer repositorios gateway-scoped para mutaciones.
2. Reforzar junctions y JSONB con validaciones/triggers.
3. Activar gosec bloqueante y gitleaks.

### Sprint 3 - Arquitectura y operabilidad

1. Introducir puertos app para cache, providers, LB y telemetry.
2. Dividir DI por plano.
3. Consolidar auth/access guard.
4. Eviccion cache por gateway.
5. Mejorar backpressure/drops/shutdown.
