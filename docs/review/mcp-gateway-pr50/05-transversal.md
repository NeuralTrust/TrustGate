# Transversal — Domain, wiring, convenciones y plan de remediación

Ámbito: `pkg/domain/*` (cambios de la PR), `pkg/container/modules/*`, convenciones del
proyecto y deuda preexistente que la PR hereda o agrava.

## Deuda preexistente (no introducida por la PR, pero relevante)

### T-01 · `app → infra/cache` está generalizado en todo el repo

~40 archivos de `pkg/app` ya importaban `pkg/infra/cache` antes de esta PR (creators, finders,
deleters de todos los contextos). La PR sigue el patrón (`composer.go`, `path_resolver.go`).
**No es exigible arreglarlo en esta PR**, pero conviene decidir si `cache.TTLMap`/`Client` se
consagra como "shared kernel" o se extrae un puerto `Cache` en app. Mientras no se decida, los
hallazgos de imports de cache se consideran deuda aceptada — los de `infra/mcp/client` **no**,
porque ese contrato nació en esta PR y aún es barato invertirlo.

### T-02 · `domain → infra` preexistente

- `domain/registry/registry.go` → `infra/providers` (validación de provider LLM).
- `domain/consumer/consumer.go` → `infra/loadbalancer/algorithm`.

La PR toca ambos archivos sin corregirlo. Refactor (separable de la PR): puerto
`ProviderCatalog` en domain + constantes de algoritmo en domain.

## Hallazgos de la PR en domain

| ID | Sev. | Archivo | Hallazgo | Refactor |
|---|---|---|---|---|
| T-03 | **Alta** | `registry/registry.go` ~95–119 | `Rehydrate` no acepta `Type` ni `MCPTarget`: un registry MCP rehidratado por la API pública de dominio sale con `Type=""`, que `Validate` coerciona a `TypeLLM` (entidad corrupta o error). Hoy el repo de infra lo esquiva con scan manual, pero los tests de `app/registry` sí usan `Rehydrate` — bug latente para el siguiente caller | `Rehydrate(RehydrateParams)` con los campos nuevos + test que rehidrate un registry MCP; valorar que `scanRegistry` use `Rehydrate` (punto único de hidratación) |
| T-04 | **Alta** | `consumer/consumer.go` ~105–137 | `Rehydrate` sin `Toolkit` ni `FailMode`. Peor que T-03 por la semántica fail-open del toolkit ("vacío = expone TODO"): rehidratar un consumer MCP por esta vía **descarta el allowlist en silencio y abre acceso a todas las tools/prompts/resources**. `FailMode` se re-defaultea a `closed` (cambio silencioso si era `open`) | Ídem T-03, con test que verifique que un consumer MCP rehidratado conserva el toolkit. **El más urgente del bloque domain** |
| T-05 | Media | `consumer/consumer.go` ~139–197 | Sin validación type-aware: un consumer MCP acepta `ModelPolicies`, `EmbeddingConfig` y `Fallback` (semántica LLM); `FailMode` se acepta también en consumers LLM | `validateMCP()` que rechace campos LLM-only; `FailMode != ""` solo en MCP |
| T-06 | Media | `registry/registry.go` ~27–88 | `NewRegistry` + `NewMCPRegistry` duplican generación de ID/timestamps en vez del patrón `New(CreateParams)` único | Unificar con discriminante `Type` |
| T-07 | Media | `registry` vs `consumer` vs `catalog` | Enums paralelos: `registry.Type{LLM,MCP}`, `consumer.Type{LLM,MCP,A2A}`, `catalog.MCPServer.Transport/AuthHint` como strings que duplican `registry.MCPTransport/MCPAuthMode` | Compartir tipos (p.ej. `domain/mcp/types`) o documentar la divergencia |
| T-08 | Media | `catalog/mcp_server.go` | Tipo anémico: sin validación de URL/transport/auth_hint ni factoría (hoy lo salva que los datos son hardcoded en `app/catalog/mcp_servers.go`) | `Validate()` + tipos enum |
| T-09 | Media | `consumer/repository.go` ~26–30 | `FindActiveByPath` es una query cross-gateway en el repo del agregado (necesaria para el routing MCP) | Puerto de lectura `ConsumerPathIndex` separado o `FindByCriteria` |
| T-10 | Baja | `registry/mcp_target.go` | Sin factoría `New` (se construye por unmarshaling + `Validate()`); dependencia de `pkg/common/secret` (patrón preexistente); `ResolveSecretsFrom` es semántica de PATCH en domain | Aceptable a corto plazo; documentar como VO de configuración |
| T-11 | Baja | `consumer/toolkit.go` | Ver F2-13: el toolkit es política MCP en el contexto consumer | Decisión de bounded context al extraer la selección a domain |
| T-12 | Baja | `gateway/gateway.go` ~108 | `"name is required"` sin sentinel (preexistente); `ClientTLSConfig` con `Value/Scan` GORM en domain (patrón previo) | Deuda conocida |
| T-23 | Media | `identity/principal.go` ~83–95 | `WithPrincipal`/`PrincipalFromContext` son plumbing de request-scope (transporte) viviendo en domain; el dominio define *qué* es un Principal, no cómo viaja en el `context.Context` de una request | Mover el context-key a `pkg/api/middleware` o `pkg/common/requestcontext` |
| T-24 | Baja | `identity/principal.go` ~50 | `HasScopes` con receptor nil hace panic, y `PrincipalFromContext` devuelve nil legítimamente cuando no hay auth: la combinación natural de ambas APIs es un NPE esperando un caller descuidado | Guard `if p == nil` o documentar el contrato |
| T-25 | Baja | `registry`, `consumer`, `gateway` | `Validate()` muta estado (asigna `Type=TypeLLM`, llama `Normalize()`, re-defaultea `FailMode`/`Algorithm`): viola CQS; patrón heredado que la PR extiende | Separar `Normalize()` explícito de `Validate()` puro |
| T-26 | Baja | `consumer/toolkit.go` ~49–65 | `selector()` devuelve los kinds como strings mágicos (`"tool"`, `"prompt"`, `"resource"`) comparados luego en `Validate` | Tipo `selectorKind` con constantes |
| T-27 | Baja | `infra/repository/consumer` | Helper `failMode` en infra duplica el default `closed` que ya impone el dominio (regla de negocio duplicada) | Delegar el default en `Validate()`/`Rehydrate` |
| T-28 | Baja | `gateway/gateway.go` (`NormalizeDomain`) | Normaliza a minúsculas pero no valida formato de hostname (RFC 1123); el índice único parcial en BD sí está bien alineado | Validar con `net.ParseIP`/regex o documentar la laxitud |
| T-29 | Baja | Migración `20260609200000` | El `Down` no restaura los `NOT NULL` de `provider`/`auth`: rollback deja el esquema drifteado respecto a la migración original | `ALTER COLUMN ... SET NOT NULL` en el Down (con limpieza previa de filas MCP) |

`domain/ids/ids.go` (VaultKind/VaultID) y `gateway/repository.FindByDomain`: sin hallazgos.
**Contraejemplo positivo**: `gateway.Rehydrate` sí se actualizó con `domain` y todos los
call-sites de tests se ajustaron — es exactamente lo que falta en T-03/T-04. Los mocks de
`auth`/`gateway`/`consumer` están regenerados correctamente (los de `vault` no, ver F4-23).

## Wiring / container

| ID | Sev. | Hallazgo | Refactor |
|---|---|---|---|
| T-13 | Alta | `modules/mcp.go` registra tipos concretos de infra en el grafo DI: `*mcpclient.Client`, `*crypto.Cipher`, `*infraoauth.ConnectStore` (con conversión manual posterior a interfaces) | Providers que devuelven directamente los puertos |
| T-14 | Media | `modules/api.go` instancia los validators de auth inline contra interfaces definidas en middleware (ver F1-01) | Se resuelve al mover los puertos a `app/auth` |
| T-15 | Baja | `ProviderClient` se construye con HTTP client `nil` implícito | Inyectar el `*http.Client` configurado |
| T-16 | Media | `modules/api.go` ~57–71: el chain resolver sustituye al resolver de API key en **todos** los planos; el proxy LLM ahora ejecuta mTLS/JWT/introspection + lookup de path por request en su hot path | Confirmar el coste (el path scope cachea, pero `unverifiedIssuer` parsea JWT por request); si es intencional, eliminar `NewAPIKeyIdentityResolver` muerto (F1-15) |
| T-17 | Media | `oidc.NewValidator(nil)`, `introspection.NewValidator(nil)`, `NewAuthProxy(..., nil, ...)`, `NewMetadataService(..., nil)`, `NewProviderClient(nil)`, `NewExchanger(..., nil)`: seis componentes crean su propio `http.Client` por defecto | Un `*http.Client` outbound compartido en el container (timeouts/proxy/TLS centralizados) |

`modules/server_mcp.go` está limpio: solo ensambla middleware, handlers y router.

## Servicios de app modificados (CRUD) y API admin

| ID | Sev. | Archivo | Hallazgo | Refactor |
|---|---|---|---|---|
| T-18 | Media | `consumer/request/create_consumer_request.go` | El create define `ToolkitEntryRequest`/`parseToolkit` pero **no** expone campo `toolkit`: un consumer MCP con toolkit requiere create + update en dos llamadas (asimetría con `fail_mode`, que sí está en ambos) | Añadir `toolkit` al create (validando contra `registry_ids` del propio create) o documentar la asimetría |
| T-19 | Media | `gateway/creator.go` ~46–55 | `Domain` se asigna a mano tras la factoría y se llama `g.Validate()` manualmente: rompe el patrón `New(CreateParams)` (la factoría debería recibir Domain y validar) | Extender `CreateParams` del dominio |
| T-20 | Baja | `registry/updater.go` ~84–88 | Muta el parámetro de entrada (`in.MCPTarget.Normalize()` / `ResolveSecretsFrom`) antes de asignarlo | Trabajar sobre una copia |
| T-21 | Baja | `auth/guard.go` | TOCTOU: dos creates concurrentes de auths OAuth2 en conflicto pueden pasar ambos el check y persistir (no hay unique constraint que lo respalde) | Constraint funcional en DB o lock advisory; aceptable como guardrail admin-time si se documenta |
| T-22 | Baja | `handler/http/registry/request` | `MCPAuthRequest`: struct-unión plano de 16 campos para 4 modos de auth sin discriminación estructural (refleja `domain.MCPAuth`) | Al refactorizar domain (T-07), valorar sub-structs por modo |

## Operaciones (k8s / config)

| ID | Sev. | Hallazgo | Refactor |
|---|---|---|---|
| OPS-1 | Media | `k8s/base/deployment/agentgateway-mcp.yaml` ~69–78: la anti-affinity exige `key: app in [agentgateway-mcp]` pero ningún pod lleva el label `app` (los labels son `app.kubernetes.io/*`): la regla es un no-op y las 2 réplicas de prod pueden caer en el mismo nodo. Bug heredado del deployment del proxy y replicado | Usar `app.kubernetes.io/component: mcp` en el matchExpression (y corregir proxy/admin en una PR aparte) |
| OPS-2 | Media | `SERVER_SECRET_KEY` firma JWTs admin **y** deriva la KEK del vault (ver F4-16): rotación del secret de admin rompe el descifrado de todos los tokens vault | Separar `VAULT_ENCRYPTION_KEY` |
| OPS-3 | Alta | Prod corre `replicas: 2` y `STS_SIGNING_KEY` no está en `config.env` (debe venir del secret CSI); si queda vacía, claves RSA efímeras distintas por réplica → JWKS inconsistente (ver F4-17) | Fail-fast en arranque multi-réplica sin clave fija + entrada en el SecretProviderClass |
| OPS-4 | Baja | El selector del PDB mcp exige `app.kubernetes.io/name: agentgateway`, label que el pod template no declara (patrón heredado del PDB del proxy) | Verificar que kustomize inyecta el label o alinear selector con los labels reales |

## Convenciones del proyecto incumplidas (checklist)

- **Una interfaz por archivo**: incumplido en `composer.go` (4) y `proxy.go` (3).
- **`//go:generate mockery` en cada puerto**: faltan `Dialer`, `Upstream`, `Introspector`,
  `MetadataService`, `AuthProxy`, `FlowStore`, `ConsentChainer`, `Signer`/`TokenSigner`,
  `ProviderClient`, `UpstreamRegistrar`, validators de auth.
- **Constructores devuelven interfaz**: incumplido en `mcpclient.New`, `NewStore`,
  `NewConnectStore`, `NewValidator` (×3), `NewCipher`, `NewRepository` (vault),
  `NewSigner`, `NewProviderClient`, `NewUpstreamRegistrar`.
- **DTOs `request/` con `Validate()`**: ausentes en todo `handler/http/oauth` y
  `handler/http/mcp`.
- **Archivos < 500 líneas**: `composer.go` (640), `proxy.go` (590), `proxy_test.go` (604).
- **Errores**: sentinels bien usados en general; mapeo a HTTP inconsistente entre
  `helpers.WriteError`, `fiber.NewError`, `fiber.Map` ad hoc y `writeOAuthError`.

## Plan de remediación propuesto (PRs encadenadas)

El orden minimiza conflictos: primero se crean los puertos/tipos (sin romper nada), luego se
mueven implementaciones, y por último se adelgazan handlers.

1. **PR-A — Tipos y puertos MCP en app** (F2-01, F2-06, F2-07): tipos `Tool/Target/...` y
   puertos `Dialer/Upstream` en `app/mcp`; `infra/mcp/client` mapea desde el SDK; handlers y
   container dejan de importar infra. *Riesgo bajo, desbloquea todo el eje MCP.*
2. **PR-B — Trocear composer + mover session a infra** (F2-02, F2-03, F2-11, F2-12):
   selección/naming a domain, `cachedDialer` a `infra/mcp`, una interfaz por archivo, mockery.
3. **PR-C — Adelgazar `mcp_handler`** (F2-04, F2-05, F2-15): `RPCGateway` en app, mapeo de
   errores centralizado, autorización compartida con proxy.
4. **PR-D — Extraer adaptadores OAuth a infra** (F3-01..F3-05): DCR, provider client, metadata
   fetch, token client unificado, PKCE. Puertos + mockery.
5. **PR-E — Reorganizar `app/oauth`** (F3-06..F3-08, F3-10): una interfaz por archivo, trocear
   `ConnectService`, estado de flujo a domain, resolver OAuth2 compartido.
6. **PR-F — STS a infra + vault** (F4-01, F4-02, F4-06..F4-11): signer a infra tras puerto,
   exchanger sobre el token client común, `Encrypter`, convenciones de vault.
7. **PR-G — Puertos de auth inbound + fixes de caches** (F1-01..F1-05): interfaces a
   `app/auth`, audience matching único en domain, poda de caches (la fuga de introspection
   puede ir como hotfix independiente).
8. **PR-H — Domain hygiene** (T-03..T-09, T-23..T-29): Rehydrate, invariantes MCP del
   consumer, tipos compartidos, DTOs request/response y mapeo de errores uniforme en handlers.
9. **PR-I — Server lifecycle y planos en `pkg/server`** (F6-01, F6-02, F6-04, F6-08, F6-09):
   fusionar `http_server.go` en `server.go`, `plane_{mcp,admin,proxy}.go`, `MCPRouterDeps`,
   container `server_*` delgado (solo dig), actualizar `AGENT.md`. Ver
   [08-fase-6-server-lifecycle.md](08-fase-6-server-lifecycle.md). *Independiente del eje MCP;
   puede ir en paralelo con PR-A.*

Las PRs A, C y G contienen los arreglos con impacto funcional (acoplamiento al SDK, fuga de
memoria, fail-open del path scope); el resto es estructural y puede ir al ritmo que permita la
roadmap. **Excepción**: T-03/T-04 (Rehydrate) y F4-18/F4-19 (STS) son fixes puntuales de
seguridad/corrección que conviene adelantar como hotfix antes del refactor estructural.
