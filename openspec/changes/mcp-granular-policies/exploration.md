# Exploration: policies MCP granulares (todo el tráfico / consumer / grupo / usuario / registry / tool)

Fase SDD: **explore**. Cambio propuesto: `mcp-granular-policies`.
Repos: `TrustGate` (`develop` @ `e72553da`), `app` (`develop`). Fecha: 2026-09-16.
Fuente de decisiones de producto: reunión "Políticas de acceso MCP — roles, granularidad y configuración de token" (Edu / Victor, 2026-09-16) y "MCP Gateway flow and policies" (2026-09-15).

---

## Decisiones de producto ya tomadas (reunión 16-09)

| Decisión | Detalle |
|---|---|
| Solo plano MCP | El plano LLM (`:8081`) no se toca. Sin usuario, rol ni grupo; queda cubierto a nivel consumer. |
| Ámbitos | Todo el tráfico, consumer MCP, grupo, usuario (email del token), registry, tool. Componibles en la misma policy y en la misma request. |
| Roles fuera | El rol es interno de plataforma (qué ve cada persona en la consola). El identificador de moderación es el **grupo**. No se mintea `roles` en el token. |
| Dónde se configura | En **Policies**, no en Access. Cada policy gana un campo nuevo con su configuración de aplicación. Jerarquía UI deseada: Application → Registry → Tool. |
| Persistencia | El mapping policy ↔ grupo/email **no es entidad de dominio** de TrustGate. Va en un campo de la policy, al estilo `tenant_id` en `gateway.metadata`, para no romper el open source. |
| Tools | Backend soporta scope por tool; el frontend no lista tools todavía. |
| Refactor | El flujo `consumer → registry → tool` no permite saber si una policy aplica antes de llegar a la tool. Hay que cambiar el orden. |
| Entrega | Todo contra `develop`; se prueba junto arriba. |

**Sin decidir en la reunión:** regla de precedencia entre ámbitos, y qué campo exacto identifica al usuario (el token lleva `sub` y `email`). Cerradas el 2026-09-16 tras esta exploración (ver "Decisiones cerradas" al final).

---

## Current State

### Plano MCP: dónde corren hoy las policies

`RPCDispatcher.callTool` (`pkg/app/mcp/rpc_dispatcher.go:162-216`): rate limit del gateway → meta-tools `trustgate_*` (cortocircuitan) → `PluginRunner.PreRequest` con **todo** `rc.PolicyPlan` (`plugin_runner.go:123-128`) → `composer.CallTool`, que es donde `compose()` resuelve registry + tool nativa (`composer.go:107-129`) → `PreResponse` con el mismo plan completo. `buildRequestContext` no rellena `RegistryID` ni identidad del principal (`plugin_runner.go:315-336`); el body que ven los plugins es `{name: <nombre expuesto>, arguments}`.

`compose()` ya está cacheado: un `TTLMap.Get` por registry con caché caliente (`discovery.go:154-225`, TTL 5 min en `pkg/infra/cache/ttlmap_manager.go:56`), clave por `reg.ID`+`UpdatedAt` y hash del principal cuando el registry es per-principal (`discovery.go:268-281`).

Los nombres expuestos en consumers con más de un registry se reescriben a `mcp_<8hex(sha256(registryID))>_<name>_<8hex>` para **todas** las tools (`naming.go:52-66`), y `expose_as` del toolkit los renombra por consumer (`composer.go:360-362`). Cualquier scope por nombre expuesto es inestable; el par `(registry_id, nombre nativo)` es lo único estable.

### Configuración y plan de plugins

`dataFinder.load` (`pkg/app/consumer/data_finder.go:101-145`): globales + por consumer (`loadPolicies :174-197`), `composePolicies` con anulación por `slug` (`:288-311`), un `StagePlan` por consumer (`:142-147`). Tras RUN-1569 (`39a1f548`) el Store también recibe las policies gateway-wide: `data.StoreConsumer` con `globalPolicies` (`data_finder.go:136-141`, `consumer_data.go`). El Store no es un consumer persistido, así que una policy solo puede alcanzarlo siendo `global`.

`StagePlan` ordena por `priority`, `slug`, `id` y agrupa batches paralelos por `priority` igual (`pkg/app/plugins/plan.go:123-187`). `RuntimeScope` solo conoce gateway/consumer/global (`executor.go:180-187`, `plugin.go:79-101`).

En el data plane la policy llega como blob JSON del struct de dominio dentro del snapshot (`pkg/infra/configsnapshot/codec.go:88,156`; adaptador `pkg/runtimeconfig/snapshot/adapters/policy_repository.go`). Un campo nuevo con tag JSON viaja sin tocar el proto.

### Identidad disponible en el hot path

`identity.PrincipalFromContext(ctx)` está disponible en `callTool` (el handler lo estampa en `mcp_handler.go:450-471`). El `Principal` (`pkg/domain/identity/principal.go:100-107`) expone `Subject`, `Claims`, `Groups()` (claim `groups`, `:187-202`), `Email()` (claims `email`, `preferred_username`, `upn`… `:240-252`), `Org()`.

Tres formas de principal en MCP:

| Caso | `Subject` | `Groups()` | `Email()` |
|---|---|---|---|
| Login plataforma (default IdP) o IdP del cliente | `sub` del token (id de usuario de plataforma) | ids **y** nombres de grupo | email del token |
| Consumer `acts_for_users` source `app` (`X-NeuralTrust-End-User`) | `EndUserSubject(consumerID, endUser)` (`mcp_handler.go:479-497`) | vacío | vacío salvo que `end_user` sea un email (no se copia a claims `email`) |
| Consumer que actúa como la app (API key / mTLS) | `AppSubject(consumerID)` (`:521-538`) | vacío | vacío |

### Qué mintea la app en el access token MCP

`app/server/lib/mcpOAuth/tokens.ts:116-136`: `iss`, `aud=neuraltrust-mcp`, `exp` (+3600 s), `token_use`, `sub` (id de usuario), `email`, `org` (teamId), `groups[]`, `gateway`, `scope`. **No** hay `roles`. `groups` = grupos del IdP de la sesión ∪ `DirectoryGroup` del usuario, emitiendo id y nombre (`app/api/mcp/oauth/authorize/route.ts:254-274`, `resolveUserDirectoryGroups.ts`). El nivel de Store dejó de mintearse a propósito: el gateway evalúa en vivo (`authorize/route.ts:276`).

### Precedente de "principal" en TrustGate: Store Access

`pkg/domain/storeaccess/policy.go:27-36`: `PrincipalUser` = `sub`, `PrincipalGroup` = clave contra el claim `groups`. `Grant.Allows(groups, subject)` hace igualdad exacta tras `TrimSpace` (`grant.go:148-172`). La página Access envía como clave de usuario `user.userId` (`UserAccessSidePanel.tsx:159`) y como clave de grupo `externalId || displayName` (`groupGrantKey.ts:9-11`). Las policies de Store viven en TrustGate, escritas por la app vía Admin API (`storeAccessPolicyActions.ts:95`).

Precedente de "campo no-dominio": `gateway.Metadata map[string]string` con `MetadataTenantIDKey` y `MetadataStoreModeKey` (`pkg/domain/gateway/gateway.go:29-60,105-160`).

### Roles de la app

Platform Permissions v2: `PlatformRole` → `PlatformPermissionGrant` (producto × nivel × scope gateway) o flags Global Admin / Break-glass / Employee (`app/prisma/schema.prisma:607-681`). Son permisos de consola (`viewPolicies`, `editPolicies`…), evaluados en server actions (`withPlatformAuth.ts:68`). Quién puede crear o editar policies ya está resuelto por `TRUST_GATE` `EDITOR/ADMIN` (`withTrustGateAuth.ts:25`). TrustGate eliminó sus propios Roles y el `role_based` routing la semana pasada (`27256536`, migración `20260909120000_drop_roles_and_routing_mode`; `docs/consumers-identity-model.md:96-118`).

### Linear

No existe issue para esta feature. Relacionadas y cerradas: RUN-1569 (policies gateway-wide en el Store), RUN-966 (`SupportedProtocols` al asociar policy). Hay que crearla.

---

## Affected Areas

| Fichero | Por qué |
|---|---|
| `pkg/domain/policy/policy.go`, `mcp_scope.go` (nuevo), `errors.go`, `repository.go` | Campo `MCPScope`, `Validate`, `Matches`, `PruneRegistry`; `PruneRegistryReferences` |
| `pkg/infra/database/migrations/2026xxxx_add_policy_mcp_scope.go` | `ALTER TABLE policies ADD COLUMN mcp_scope JSONB NULL` |
| `pkg/infra/repository/policy/repository.go` | select/insert/update/scan del campo; prune; filtro `registry_id` |
| `pkg/runtimeconfig/snapshot/adapters/policy_repository.go`, `pkg/infra/configsnapshot/codec_test.go` | prune no-op; test de round-trip |
| `pkg/app/policy/creator.go`, `updater.go`, `validate.go` | validación del scope contra `registrydomain.Repository` |
| `pkg/app/consumer/associator.go` | rechazar policy con scope en consumer LLM |
| `pkg/app/consumer/consumer_data.go`, `data_finder.go`, `policy_plans.go` (nuevo) | plan base sin scope + índices por registry / tool; anulación por `slug` solo entre policies sin scope; aplicar también a `StoreConsumer` |
| `pkg/app/plugins/chain.go`, `plan.go` | `specificity` como desempate; entradas con `principals` |
| `pkg/app/mcp/composer.go` (+ `mocks/`) | `Resolve` / `Invoke` separados |
| `pkg/app/mcp/rpc_dispatcher.go` | reorden de `callTool` |
| `pkg/app/mcp/plugin_runner.go` | firmas con plan + target; `RegistryID`, tool nativa y principal en `RequestContext` |
| `pkg/domain/registry/registry.go`, `pkg/app/store/scoper.go` | `InstanceOf` en clones del Store |
| `pkg/container/modules/registry.go` | segundo `WithDeleteHook` para podar scopes de policies |
| `pkg/api/handler/http/policy/request/*.go`, `response/policy_response.go`, `docs/openapi.json` | contrato `mcp_scope` (con `except_*`) y `warnings` (G3) |
| `pkg/infra/plugins/toolallowlist/plugin.go`, `config.go`, `pkg/container/modules/plugins_test.go` | soporte `ProtocolMCP` y bloqueo por tool nativa (G1) |
| `pkg/infra/trace/span.go`, `pkg/app/metrics/builder.go`, `pkg/infra/metrics/events` | `SetMCPPolicyScope` y emisión de policies descartadas (G4) |
| `app`: `resolveUserDirectoryGroups.ts`, `groupGrantKey.ts`, `tokenManager.ts` | clave de grupo estable por `DirectoryGroup.id` (G2) |
| `multi-agent-tests`: `.env.dev`, `Makefile` | E2E contra dev (G5) |
| Tests: `pkg/app/mcp/composer_test.go`, `pkg/api/handler/http/mcp/rpc_dispatcher_test.go`, `pkg/app/consumer/data_finder_test.go`, `pkg/app/plugins/plan_test.go`, `tests/functional/mcp_plugin_chain_test.go` | unit + funcional |
| `app`: `features/policies` (form + `buildPolicyWriteRequest`), tipos `AgentGatewayPolicyItem` | enviar y mostrar `mcp_scope` (fase UI, fuera de este cambio) |

---

## Modelo de scope

```go
type MCPScope struct {
    RegistryIDs  []ids.RegistryID `json:"registry_ids,omitempty"`
    Tools        []MCPToolRef     `json:"tools,omitempty"`         // {registry_id, tool nativa}
    Users        []string         `json:"users,omitempty"`         // sub o email, tal cual llegan en el token
    Groups       []string         `json:"groups,omitempty"`        // clave de grupo = misma regla que Grant.Groups
    ExceptUsers  []string         `json:"except_users,omitempty"`  // negación (gap 1)
    ExceptGroups []string         `json:"except_groups,omitempty"`
}
// Policy.MCPScope *MCPScope `json:"mcp_scope,omitempty"`
```

Semántica de `Matches(target, principal)`:

- `MCPScope == nil` → aplica a todo el tráfico del consumer (hoy).
- Dimensión **destino**: si `RegistryIDs` o `Tools` no están vacíos, hace match si `registry ∈ RegistryIDs` o `(registry, toolNativa) ∈ Tools`. Vacíos → cualquier destino.
- Dimensión **principal**: si `Users` o `Groups` no están vacíos, hace match si `Subject` o `Email()` ∈ `Users`, o `Groups() ∩ Groups ≠ ∅`. Vacíos → cualquier principal. Después se aplica la negación: si `Subject`/`Email()` ∈ `ExceptUsers` o `Groups() ∩ ExceptGroups ≠ ∅`, **no** hace match. Un caller sin identidad nunca cae en una excepción, así que una policy "para todos excepto Finanzas" sí le aplica.
- Ambas dimensiones se combinan con **AND** (una policy "DLP para el grupo Finanzas en Snowflake"). Entre policies, **unión**: corren todas las que hacen match.
- Scope presente pero sin ninguna entrada → no hace match con nada (estado alcanzable solo por prune al borrar un registry; misma distinción `nil` vs vacío que el toolkit).
- Ámbito "consumer" = a qué consumers está asociada la policy (`consumer_ids`, sin cambios). Ámbito "todo el tráfico" = `global: true`. Una policy `global` con scope está permitida: es la única forma de alcanzar el Store.
- Las policies con scope no participan en la anulación por `slug` de `composePolicies`; son aditivas.
- Registry desasociado del consumer → dormida. Registry borrado → prune. Tool desaparecida → dormida. Consumers sin identidad de usuario (API key como la app) → un scope con `Users`/`Groups` nunca hace match.

Validación en Admin API: registries del mismo gateway y tipo MCP; `tool` no vacío; `users`/`groups` no vacíos y sin duplicados; al menos una entrada en total; un registry no puede estar a la vez en `registry_ids` y `tools`. No se valida contra discovery ni contra el directorio de la app (el gateway no lo conoce).

Clave de usuario: aceptar `sub` y email. Access ya usa `userId` (= `sub`); el email es lo que se dijo en la reunión y lo lleva el token. El matcher compara contra ambos, email en minúsculas.

---

## Approaches

### 1. Campo estructurado `mcp_scope` en la policy, filtro con binding resuelto antes de PreRequest, índices precompilados — **recomendada**

`callTool` pasa a: rate limit → meta-tools → `composer.Resolve(name)` (un `compose()`, hit de caché) → `plan := rc.MCPPlans.PlanFor(registry, toolNativa, principal)` → `PreRequest` → `composer.Invoke(target)` → `PreResponse` con el mismo plan.

`PolicyPlans` se construye en `DataFinder`: plan base (policies sin scope), plan por registry, plan por `(registry, tool)`. Las policies con dimensión principal se guardan aparte por clave de destino; solo cuando existen para esa clave se filtran por `Groups()`/`Subject`/`Email()` y se agrupan batches por request. Sin policies por principal, camino O(1) sin asignaciones.

- Pros: un solo `compose()`, un `RunStage` por stage, cero trabajo de plugin cuando no hay match; `sub`/`email`/`groups` son claims OIDC estándar, válidos en open source; un solo campo, una migración, viaja en el snapshot; el binding se resuelve antes de que un plugin pueda reescribir `name`.
- Cons: `Composer` cambia de interfaz (regenerar mocks); las calls bloqueadas pagan `compose()` (CPU con caché caliente); el filtro por principal es opt-in y cuesta un `groupBatches` por request cuando se usa.
- Effort: **Medium-High** (tres PRs).

### 2. `metadata map[string]string` genérico en la policy con clave reservada (literal de la reunión)

Como `gateway.Metadata`: la app escribe `metadata["mcp_scope"] = "<json>"` y el gateway lo parsea.

- Pros: cero vocabulario nuevo en el dominio; el mismo patrón que `tenant_id`.
- Cons: hay que parsear JSON dentro de un string al cargar configuración y validar sin tipo; el hot path necesita el scope tipado igualmente, así que se acaba con el mismo struct más una capa de indirección; la Admin API no puede validar registries ni rechazar scopes vacíos; el data plane open source vería un string opaco que sí ejecuta. El objetivo de la reunión ("no entidad, no romper el open source") lo cumple igual el campo estructurado: no hay tabla ni entidad nueva, y `sub`/`groups` no son conceptos de NeuralTrust.
- Effort: Medium, pero peor coste de mantenimiento.

### 3. Mantener el orden actual y ejecutar todas las policies; el plugin decide

- Cons: TrustGuard haría su RTT por policies que no aplican; cada plugin reimplementa el matching; contradice el requisito "cero trabajo del plugin".
- Effort: Low. **Rechazada.**

### 4. Dos fases: policies sin scope antes de compose, con scope después

- Cons: dos `RunStage` por stage; rompe el orden por `Priority` entre fases; duplica el fail-open.
- **Rechazada.**

### 5. Claim `roles` en el token o consulta a la app en request

- Descartado en la reunión (roles) y por diseño (RTT, acoplamiento del open source a un servicio propietario, hybrid).

---

## Recommendation

Approach 1. Es la propuesta del informe de diseño previo (`informe-policies-mcp-scope.md`) extendida con la dimensión principal por `users`/`groups`, que reutiliza exactamente el matcher de Store Access. Cubre los seis ámbitos de la reunión con un solo campo en la policy, un `compose()` y un `RunStage`, y deja el plano LLM intacto porque `PolicyPlan` pasa a ser el plan sin scope.

Orden de la cadena (a confirmar en propuesta): `Priority` ascendente como hoy; a igual prioridad, más específica primero (tool > registry > consumer; con principal > sin principal); después `slug`, `id`. Solo afecta al "primer escritor" dentro de un batch paralelo.

Plan de entrega en tres PRs encadenados sobre `develop`:

1. **Dominio + persistencia + Admin API**: `MCPScope`, migración, repositorio, snapshot, validación, prune al borrar registry, OpenAPI. Sin efecto en runtime.
2. **DataFinder + plan**: plan base sin scope, `PolicyPlans`, desempate por especificidad, anulación por `slug` acotada, Store incluido. Sin efecto en runtime todavía (el dispatcher sigue usando el plan base).
3. **Hot path MCP**: `Resolve`/`Invoke`, reorden de `callTool`, `PluginRunner` con plan + target, `RequestContext` con `RegistryID`, tool nativa y principal; funcionales con dos upstreams y TrustGuard stub.

La UI (Application → Registry → Tool, selector de grupos/usuarios en Policies) es un cambio aparte en `app`; el contrato que necesita es `mcp_scope` en create/update/response y un filtro `registry_id` en el listado.

---

## Risks

- **Nombre expuesto vs nativo.** El hash de `naming.go:56-63` hace inviable cualquier clave por nombre expuesto. Efecto colateral ya existente: `per_tool_rate_limiter` en MCP matchea sobre el nombre del body (expuesto) y no coincide con el nativo en consumers federados; rellenar `Metadata["mcp.tool"]` permite arreglarlo después.
- **Anulación por `slug`.** Sin acotarla, una TrustGuard con scope a una tool apagaría la TrustGuard global de todo el consumer (`data_finder.go:297,304`).
- **Ensanchamiento silencioso.** El prune al borrar un registry debe dejar `{}` y no `NULL`.
- **Clave de usuario.** Access usa `sub`; la reunión dijo email. Si solo se matchea email, un consumer con IdP del cliente que no emita `email` nunca hace match. Matchear ambos.
- **Store multi-instancia.** Los clones llevan `ID = install ID` (`pkg/app/store/scoper.go:279`); sin `InstanceOf` ningún scope por registry hace match en el Store.
- **Consumers `acts_for_users` source `app`.** El end-user no trae grupos; un scope por grupo es dormido ahí. Documentar en UI.
- **Rolling upgrade.** Un data plane antiguo ignora `mcp_scope` y ejecutaría la policy consumer-wide: desplegar data plane antes que control plane, o no crear policies con scope hasta terminar.
- **Coste opt-in del filtro por principal.** Un `groupBatches` por request solo cuando hay policies con `users`/`groups` para ese destino. Medir en benchmark.
- **Orden de errores.** Tool desconocida, denegada por toolkit o con consentimiento pendiente responde antes de tocar plugins; ajustar `TestRPCGateway_ToolsCall_PreRequestBlock_SkipsUpstream` (`rpc_dispatcher_test.go:296`).

---

## Decisiones cerradas (Edu, 2026-09-16)

| # | Decisión | Elegido | Descartado |
|---|---|---|---|
| 1 | Persistencia del scope | Campo estructurado `mcp_scope` (JSONB tipado en `policies`, struct `MCPScope` en dominio). Cumple el objetivo de la reunión: sin entidad ni tabla nueva, y `sub`/`email`/`groups` son claims OIDC estándar, no vocabulario de NeuralTrust. | `metadata map[string]string` con clave reservada: obligaría a parsear JSON en string al cargar configuración y a validar sin tipo. |
| 2 | Precedencia entre policies que hacen match | `Priority` ascendente como hoy; a igual prioridad, más específica primero (tool > registry > consumer; con principal > sin principal); después `slug`, `id`. Solo afecta al primer escritor dentro de un batch paralelo. | Especificidad como orden primario: segunda regla de orden, rompe el agrupamiento `Parallel` por `priority` y difiere del plano LLM. |
| 3 | Clave de usuario en `mcp_scope.users` | `sub` **y** email. El matcher compara contra `Principal.Subject` y `Principal.Email()` (email en minúsculas). Access ya usa `sub`; el token lleva ambos. | Solo email: un IdP del cliente que no emita `email` nunca haría match. |

## Gaps detectados tras la exploración y solución acordada

### G1. El scope selecciona, no autoriza

**Problema.** `mcp_scope` decide a quién y a qué se aplica una policy, pero la policy sigue siendo un plugin de inspección. No existe hoy un plugin de denegación para MCP: `tool_allowlist` solo soporta `ProtocolLLM` (`pkg/infra/plugins/toolallowlist/plugin.go:54-55`) y filtra tools del body de una petición LLM. "Solo Finanzas puede llamar `run_query`" no se puede expresar, y la reunión habló de *políticas de acceso*.

**Solución.** Dos piezas, ambas dentro del cambio:

1. **`tool_allowlist` soporta MCP.** `SupportedProtocols` gana `ProtocolMCP`. En MCP, PreRequest lee la tool nativa de `Request.Metadata["mcp.tool"]` (que el runner estampa tras `Resolve`) y, si no pasa `allow_tools` / `deny_tools`, devuelve `StopUpstream` con el error de policy (`-32001`). Con `deny_tools: ["*"]` se convierte en el plugin "denegar" que falta. Reutiliza catálogo, schema y validación existentes (`catalog_metadata.go:498`).
2. **Negación en el scope.** `except_users` / `except_groups` en `MCPScope`. Así "solo Finanzas puede `run_query`" es una policy `tool_allowlist deny *` con `tools: [run_query]` y `except_groups: [Finanzas]`. Sin negación, la unión entre policies hace imposible el patrón "todos menos".

Límite a documentar en UI: **Policies decide ejecución; el toolkit y Access deciden visibilidad.** Una tool denegada por policy sigue apareciendo en `tools/list` (discovery usa el plan base) y falla al llamarla. Ocultarla por principal exigiría filtrar el listado por caller, que es trabajo de Access, no de esta fase.

### G2. Clave de grupo por nombre

**Problema.** El token lleva ids y nombres; la clave de Access es `externalId || displayName` (`app/.../groupGrantKey.ts:9-11`). Los grupos manuales de la app no tienen `externalId`, así que se referencian por nombre: un rename los desvincula en silencio y dos IdPs con un grupo "Finanzas" colisionan.

**Solución.** En la app, no en TrustGate:

1. `resolveUserDirectoryGroups` y `groupGrantKey` emiten también `DirectoryGroup.id` (uuid interno, estable) para todo grupo, y ese id pasa a ser la clave preferente cuando no hay `externalId`. El nombre sigue viajando por compatibilidad con grants ya escritos.
2. La UI de Policies guarda siempre la clave estable y muestra el nombre resuelto desde el directorio; si una clave referenciada ya no existe, aviso "grupo eliminado del directorio" (misma lectura que Access hace hoy para grants huérfanos).

TrustGate no cambia: sigue comparando strings contra `Groups()`. El `MAX_BRIDGE_GROUPS = 200` del token (`tokenManager.ts:67`) hay que revisarlo porque ahora cada grupo aporta hasta tres valores.

### G3. Doble ejecución con `global` + scope

**Problema.** Al dejar las policies con scope fuera de la anulación por `slug`, un consumer con su TrustGuard sin scope y un TrustGuard global con scope a Finanzas ejecuta dos TrustGuard para un caller de Finanzas.

**Solución.** Se mantiene la regla (una policy con scope es aditiva por diseño: dos configuraciones del mismo plugin pueden ser intencionadas, con distinto `direction` o collector). Se añade una **advertencia no bloqueante** en la Admin API al crear o asociar: la respuesta incluye `warnings: ["consumer X already runs plugin trustguard without scope"]` y la UI la muestra. Además G4 deja rastro de las dos ejecuciones en el span.

### G4. Sin visibilidad de lo que no corrió

**Problema.** La telemetría solo registra los plugins que se ejecutan (`pkg/app/metrics/builder.go:218`). Una policy descartada por scope no deja rastro y "¿por qué no me bloqueó?" se depura a ciegas.

**Solución.** `PlanFor` devuelve además una `ScopeDecision{Evaluated int; Matched []PolicyRef; Skipped []SkippedPolicy{ID, Name, Reason}}` con `Reason ∈ {destination, principal, except}`. Solo se construye cuando hay un span activo (`trace.SpanFromContext(ctx) != nil`), a partir de slices precompilados, sin asignaciones en el camino sin traza. Se estampa con `Span.SetMCPPolicyScope(...)` junto a `SetMCPUpstream`, y el builder de eventos lo emite en el metadata MCP del evento de request, no como `PolicyEntry` (esa lista sigue siendo "lo que corrió").

### G5. Validación en dev

**Problema.** La suite E2E de `multi-agent-tests` apunta al gateway de producción (`.env`); "tirar contra dev y probar arriba" no se puede verificar con ella.

**Solución.** La puerta principal es la suite funcional de TrustGate (`tests/functional/mcp_plugin_chain_test.go`) con dos upstreams stub, TrustGuard stub y los casos por registry, tool, grupo, usuario y excepción. Para E2E en dev: `multi-agent-tests` gana `.env.dev` con `TG_ADMIN_URL`, `TG_PROXY_URL` y el endpoint MCP de dev, y el `Makefile` acepta `ENV_FILE=.env.dev`. Es un cambio pequeño en ese repo, previo a la fase 3.

### Dependencia: listado de tools por registry

La UI necesitará `GET /v1/gateways/{gw}/registries/{id}/tools` para el selector. No existe en la Admin API (el inventario es un meta-tool del plano MCP, `pkg/app/mcp/inventory.go`). Propuesta: endpoint que reutiliza `discoverTools` y su caché para un registry; los registries per-principal (URL variables o auth por usuario) devuelven `409` con motivo porque no hay principal en la Admin API. Cambio aparte, no bloquea las tres fases del backend.

## Ready for Proposal

**Sí.** Las tres decisiones abiertas están cerradas con las recomendaciones de esta exploración y los cinco gaps tienen solución acordada; la propuesta parte del Approach 1 con G1 y G4 incluidos en el alcance del backend, G2 y G5 como cambios en `app` y `multi-agent-tests`, y G3 como advertencia en Admin API.

Pendientes fuera del cambio: crear la issue en Linear (equipo Runtime), la fase UI en `app`, el listado de tools por registry para el selector, y decidir si el filtro por principal se limita a nivel registry en una primera entrega para evitar el `groupBatches` por request.
