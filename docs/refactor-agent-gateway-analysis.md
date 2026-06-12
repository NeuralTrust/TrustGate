# Refactor Agent Gateway: roles, routing y fallback

Este documento aterriza las decisiones de la reunión `Refactor Agent Gateway` del 9 de junio de 2026 sobre el repo `AgentGateway`. Queda fuera de alcance todo lo hablado sobre MCP; el foco es LLM routing, consumers, roles, autorización, load balancing, fallback y normalización del payload.

## Resumen Ejecutivo

El refactor debe separar tres responsabilidades que hoy están mezcladas en el `Consumer`: autorización, resolución del conjunto de registries candidatos y ejecución de routing. La decisión principal es permitir dos modos excluyentes de configuración:

| Área | Decisión |
|---|---|
| `Roles` vs `inline` | Un consumer debe configurarse con registries inline o mediante roles, pero no ambas cosas a la vez. |
| Autorización | Los roles pasan a ser una entidad propia y dueña de las policies (`model_policies` y, a futuro, `mcp_policies`); son el punto donde se expresa qué providers/modelos están permitidos. |
| LB | El load balancing solo actúa en consumers `inline`. Opera sobre el conjunto de registries del consumer y solo tiene efecto si hay más de un registry elegible. |
| Fallback | El fallback solo actúa en consumers `inline`, como subconjunto autorizado del propio consumer. En modo `role_based` no hay LB ni fallback: el routing se resuelve por intención explícita dentro de los permisos del rol. |
| Autenticación | El consumer puede autenticarse vía API key (actual), OAuth clásico o IDP. OAuth clásico e IDP son dos tipos de auth distintos con configuración separada: IDP es la única vía que habilita `role_based`; OAuth clásico solo aplica a `inline`. mTLS queda descartado por ahora. |
| Payload | El payload se normaliza antes de invocar providers. Se podrá expresar la intención de modelo/provider en el payload, pero el gateway debe transformarla a un formato interno de routing antes de adaptar la request al provider final. |

## Estado Actual Del Repo

### Consumer

`pkg/domain/consumer/consumer.go` ya concentra la mayor parte del routing:

- `RegistryIDs`: pool de registries asociados al consumer.
- `Algorithm`: algoritmo de LB.
- `Fallback`: cadena ordenada de registries de fallback.
- `ModelPolicies`: allow-list/default model por registry.
- `AuthIDs`: credenciales autorizadas para consumir ese path.

El read model en runtime está en `pkg/app/consumer/consumer_data.go` y `pkg/app/consumer/data_finder.go`. Actualmente `RoutableConsumer` resuelve:

- `Registries`: pool primario usado por el LB.
- `FallbackBackends`: chain de fallback.
- `Auths`: credenciales asociadas.
- `Policies`: plugins aplicables.

Un detalle importante: `poolRegistryIDs()` excluye del pool primario los registries que están en `Fallback.Chain`. Por tanto, la separación pool/fallback ya existe, pero siempre desde IDs asociados directamente al consumer.

### Registry

`pkg/domain/registry/registry.go` modela un registry como un target upstream único:

- `Provider`
- `ProviderOptions`
- `Auth`
- `Weight`
- `HealthChecks`

No hay entidad `Role` ni relación `Role-Registry`. Las relaciones existentes relevantes son:

- `consumer_registry`
- `consumer_auth`
- `consumer_policy`

### Autorización

El plano proxy usa `X-AG-API-Key` en `pkg/api/middleware/auth.go`. El middleware resuelve:

1. API key válida.
2. `GatewayID` y `AuthID`.
3. Data completa del gateway.
4. Consumer por path.
5. Verificación de que el `AuthID` pertenece al consumer.

Aunque `pkg/domain/auth/auth.go` define `api_key`, `oauth2` y `mtls`, hoy el dataplane solo acepta `api_key`. La autorización real sigue siendo `consumer + auth_id`, no `consumer + role`.

### LB Y Fallback

El forwarder actual está en `pkg/app/proxy/forwarder.go`:

- Selecciona un registry inicial con `lb.NextBackend(req, nil)`.
- Ejecuta pre-request plugins.
- Invoca el provider.
- Clasifica el outcome.
- Reintenta sobre el mismo backend según `Provider.MaxRetries`.
- Excluye registries ya intentados.
- Pide otro candidato al LB.
- Si no quedan candidatos de pool, recorre `FallbackBackends`.

El LB está en `pkg/infra/loadbalancer/load_balancer.go` y soporta:

- `round-robin`
- `random`
- `weighted-round-robin`
- `least-connections`
- `semantic`

El fallback tiene triggers declarados en `pkg/domain/consumer/fallback.go` y `pkg/app/proxy/classify.go` los respeta todos: `http_5xx`, `http_429`, `timeout`, `provider_error` y `plugin_rejection`. Los triggers gatean exclusivamente el salto a la fallback chain; los reintentos same-backend y el failover entre miembros del LB no se gatean. `MaxCostUSD` se eliminó del presupuesto (diferido a una fase futura con pricing/usage).

### Payload Y Modelo

El handler proxy construye `RequestContext` en `pkg/api/handler/http/proxy/proxy_handler.go`. El formato fuente se obtiene desde `X-Provider` o por detección del body.

`pkg/app/proxy/provider.go` prepara la invocación:

1. Resuelve formato fuente.
2. Resuelve formato target desde el registry.
3. Adapta request si hay cross-format.
4. Normaliza para el provider.
5. Aplica `EnforceModel()` con `AllowedModels` y `DefaultModel`.

`pkg/infra/providers/adapter/model.go` solo entiende `model` y `modelId`. No existe hoy una semántica estándar para que el payload indique `provider + model` como intención de routing. El provider upstream lo fija el registry elegido; el modelo viene del body o del default de la política.

## Objetivo Del Refactor

### 1. Separar Modo De Configuración Del Consumer

El consumer debe tener un modo explícito:

| Modo | Qué permite | Qué prohíbe |
|---|---|---|
| `inline` | Asociar registries/model policies/fallback directamente al consumer. | Asociar roles al mismo consumer. |
| `role_based` | Resolver registries/modelos desde uno o varios roles. | Asociar registries directos al mismo consumer. |

La regla crítica es la exclusividad. Si se permite mezclar ambos modos, el candidate set será ambiguo y el frontend tendrá que explicar combinaciones difíciles: qué pesa más, si fallback puede salir de un rol distinto, o si un modelo inline puede usar un provider autorizado por rol.

### 2. Introducir Roles Como Unidad De Autorización LLM

Un rol es una entidad propia y dueña de las policies. Representa un conjunto reutilizable de permisos de routing asociado a un IDP:

- Providers permitidos.
- `model_policies` (y, a futuro, `mcp_policies`) como propiedad del rol.
- Registries asociados mediante una tabla relacional `role_registry` que solo relaciona IDs.
- Mapping contra claims del IDP.

Decisión clave: el ownership de las policies pasa a la entidad `Role`. La tabla `role_registry` no contiene policies, solo enlaza `role_id` con `registry_id`. Las `model_policies`/`mcp_policies` cuelgan del rol, no del binding.

En este modelo no existen roles sin IDP. El rol no es solo una agrupación local de registries: es la unidad que conecta claims externos con permisos de LLM routing. Por tanto, conviene separar:

| Concepto | Responsabilidad |
|---|---|
| `Role` | Entidad dueña de las policies (`model_policies`, `mcp_policies`) y de los permisos de routing vinculados a claims del IDP. |
| `role_registry` | Tabla relacional que solo enlaza `role_id` y `registry_id`, sin policies. |
| `RoleBinding` / `ConsumerRole` | Qué roles puede usar un consumer. |
| `IDP mapping` | Cómo claims externos seleccionan roles para una request. |

Esto implica que el modo `role_based` requiere configuración de IDP. Si un consumer no usa IDP, debe permanecer en modo `inline`.

### 3. Resolver Un Candidate Set Antes Del LB

El cambio central debería ser introducir un resolver explícito:

```text
consumer + identidad + routing_intent -> candidate_set
```

El `candidate_set` debería contener:

- Registries permitidos.
- Model policies efectivas.
- Pesos.
- Indicación de si vienen de inline o roles.
- Subconjunto elegible para LB.
- Subconjunto elegible para fallback.

El forwarder no debería tener que saber si los registries vienen de inline o de roles. Su contrato debería ser: recibe un `RoutableConsumer` ya resuelto con candidatos autorizados.

### 4. LB Y Fallback Solo En Modo Inline

Decisión: LB y fallback solo actúan en consumers `inline`. En modo `role_based` no hay distribución automática ni chain de fallback declarativa; el routing se resuelve únicamente por la intención explícita del payload, filtrada por los permisos del rol.

El comportamiento objetivo en modo `inline`:

| Caso | Comportamiento |
|---|---|
| Registry/modelo del consumer | Puede ser llamado bajo demanda por el payload si está dentro del `model_policies` inline. |
| LB desactivado | No hay distribución automática; el routing respeta la intención explícita del payload dentro de lo permitido. |
| LB activado | El usuario configura qué providers/modelos forman el pool y qué algoritmo usa. El LB solo puede incluir elementos del `model_policies` inline del consumer. |
| Fallback desactivado | No se recorre una chain de fallback declarativa. |
| Fallback activado | El usuario define una chain ordenada que puede cruzar múltiples providers, pero cada salto debe estar permitido por el `model_policies` inline del consumer. |

Comportamiento en modo `role_based`:

| Caso | Comportamiento |
|---|---|
| Registry/modelo permitido por rol | Puede ser llamado bajo demanda por el payload si está dentro de las `model_policies` del rol. |
| LB | No aplica. |
| Fallback | No aplica. |

La regla de seguridad es que ni LB ni fallback pueden ampliar permisos: en inline seleccionan subconjuntos explícitos del `model_policies` del consumer para automatizar distribución o failover.

### 5. Normalizar El Payload A RoutingIntent

La reunión apunta a mantener los `paths` del consumer como están y hacer universal el payload. Es decir, el path sigue resolviendo el consumer; lo que cambia es que el body de chat completion debe poder expresar provider/modelo de forma estándar para que el gateway derive una intención de routing.

Para evitar acoplar todos los providers a un body híbrido, el gateway debería parsear una intención interna:

```text
payload -> RoutingIntent{provider?, model?, alias?, order?}
```

Ejemplos de semántica posible:

| Payload entrante | Interpretación interna |
|---|---|
| `model: "gpt-5"` | Buscar candidatos autorizados que soporten `gpt-5`. |
| `model: "openai/gpt-5"` | Buscar candidatos autorizados de provider `openai` que soporten `gpt-5`. |
| `model: "pool:fast-chat"` | Resolver alias/pool autorizado, después aplicar LB o fallback. |
| `models: ["openai/gpt-5", "anthropic/sonnet"]` | Orden de ejecución explícito si no hay LB activo. |

La recomendación es usar `provider/model` dentro del campo estándar `model` como sintaxis principal para selección explícita. Es una convención conocida en routers LLM como OpenRouter y LiteLLM, mantiene compatibilidad con bodies OpenAI-compatible y evita introducir un campo custom `provider` que habría que retirar antes de invocar el upstream.

Semántica recomendada:

- `model: "openai/gpt-5"` selecciona provider y modelo dentro de los permisos efectivos.
- `model: "gpt-5"` solo debería aceptarse si no es ambiguo dentro del `CandidateSet`.
- `model: "pool:fast-chat"` selecciona el pool/LB configurado con alias `fast-chat` (solo aplica en `inline`).
- Si el provider/modelo existe pero no está permitido, la respuesta debe ser `403`.
- Si el modelo corto es ambiguo, la respuesta debe ser `400` con una sugerencia de modelos válidos.
- Si el alias `pool:<alias>` no existe, la respuesta debe ser `400` con un mensaje claro, porque el valor del campo `model` no puede resolverse.
- Si el pool existe pero incluye miembros no permitidos por el `model_policies` inline, la respuesta debe ser `403`.
- `pool:<alias>` no aplica en `role_based`; en ese modo no hay LB/pool y el routing es por intención explícita.

La parte importante es que `RoutingIntent` no tiene por qué reenviarse al provider. Debe usarse para elegir registry y luego convertir el body al formato target real. Si el provider final no acepta la forma enriquecida, el gateway debe reescribirla al `model` nativo.

Esto no convierte el endpoint del consumer en una ruta predefinida global. El contrato queda separado:

- `Consumer.Path`: selecciona el consumer y su configuración.
- Payload universal: selecciona la intención de provider/modelo/pool dentro de lo permitido por ese consumer.
- `RoutingIntent`: representación interna usada para filtrar candidatos antes de LB/fallback.

### 6. Definir Los Métodos De Autenticación

El gateway debe soportar varias formas de que un usuario se conecte. Hoy solo existe API key; el refactor añade dos tipos de auth distintos: **IDP role-based** y **OAuth clásico**. mTLS queda descartado por el momento.

| Método | Estado | Cómo funciona | Modo de consumer |
|---|---|---|---|
| API key | Actual | `X-AG-API-Key` validada contra el `auth_id` del consumer. | `inline`. |
| OAuth clásico | Nuevo | El gateway actúa como cliente OAuth2 (`client_credentials`): el consumer registra credenciales y el gateway obtiene/renueva el token contra el authorization server. Es auth de identidad, no habilita roles. | `inline`. |
| IDP (role-based) | Nuevo, solo `role_based` | El IDP nos da la public key/JWKS; el gateway valida el JWT entrante, extrae los claims/scopes y comprueba que el usuario tiene acceso al recurso solicitado vía sus roles. | Solo `role_based`. |

Decisión clave: IDP y OAuth clásico son **dos tipos de auth diferentes con configuración separada**. El esquema `OAuth2Config` actual está modelado para validación entrante (Resource Server), que corresponde al tipo IDP. OAuth clásico necesita su propia configuración de cliente (`token_url`, `client_id`/`client_secret`, scopes, audience), distinta de la de validación IDP.

Puntos de diseño:

- IDP es el único método que habilita autorización por roles. Sin IDP, un consumer no puede estar en `role_based`.
- OAuth clásico y API key solo aplican a `inline`; son métodos de identidad y no resuelven roles.
- La coexistencia se simplifica al descartar mTLS: API key (`X-AG-API-Key`) y bearer token (OAuth/IDP) se distinguen por cabecera sin necesidad de client-auth a nivel de listener TLS.
- El spike de IDP cubre: entrega/rotación de la public key/JWKS, validación de firma del JWT, extracción de claims/scopes y mapeo claims → rol → recurso autorizado.
- El spike de OAuth define el grant (`client_credentials`), cómo se almacenan las credenciales y cómo se obtiene/renueva el token.

## Impacto Por Área

### Dominio Y Persistencia

Cambios esperados:

- Nueva entidad `Role`, dueña de `model_policies` (y, a futuro, `mcp_policies`).
- Nueva relación `role_registry` que solo enlaza `role_id` y `registry_id`, sin policies.
- Nueva relación `consumer_role`, permitiendo más de un rol por consumer.
- Mantener `consumer_registry` como relación necesaria para el modo `inline`.
- Configuración explícita para LB y fallback, acotada al modo `inline`. Cada consumer tiene una única configuración de LB, persistida como columna JSONB en `consumers` (incluye `enabled`, `algorithm`, alias del pool y providers/modelos seleccionados). No se añade tabla dedicada.
- Se elimina `Consumer.Algorithm`; su función la absorbe la config explícita de LB.
- Campo de modo en `Consumer`, por ejemplo `routing_mode: inline | role_based`.
- Validaciones que impidan mezclar `consumer_registry` y `consumer_role`, reforzadas además con constraint/trigger en BBDD.

Punto crítico: `ModelPolicies` vive hoy como JSONB en `consumers`. En modo `inline` puede seguir cumpliendo esa función dentro del consumer. En modo `role_based`, las policies son propiedad de la entidad `Role` (`role.model_policies`), no del binding `role_registry`. El permiso efectivo se deriva del rol y de los registries que tiene enlazados.

### API Admin

Hoy `CreateConsumerRequest` no incluye registries, auths ni model policies; parte de la configuración ocurre vía endpoints de asociación. Para el nuevo modelo conviene que el API permita expresar claramente:

- Crear consumer inline.
- Crear consumer role-based.
- Cambiar de modo solo si se limpian las relaciones incompatibles.
- Validar que LB/fallback referencian registries del modo seleccionado.

`consumer_registry` debe seguir siendo API pública, pero acotada al modo `inline`. Los endpoints actuales de attach/detach registry siguen teniendo sentido para configurar consumers sin roles:

- `POST /v1/gateways/{gateway_id}/consumers/{id}/registries/{registry_id}`
- `DELETE /v1/gateways/{gateway_id}/consumers/{id}/registries/{registry_id}`

Si el consumer está en `role_based`, esos endpoints deben rechazar la operación con `409 Conflict`, porque la request está bien formada pero es incompatible con el modo actual del recurso. Para roles deben existir endpoints separados, por ejemplo:

- `POST /v1/gateways/{gateway_id}/roles/{role_id}/registries/{registry_id}`
- `POST /v1/gateways/{gateway_id}/consumers/{id}/roles/{role_id}`

Si el frontend necesita una opción "sin distribución" vs "distribution strategy", el backend debería reflejarlo como estado explícito, no inferirlo únicamente de `algorithm`.

### Runtime Read Model

`RoutableConsumer` debería evolucionar desde:

```text
Consumer + Registries + FallbackBackends + Auths
```

hacia:

```text
Consumer + AccessMode + EffectiveRoles + CandidateSet + FallbackCandidates + AuthContext
```

El objetivo es que `forwarder.Forward()` reciba una vista ya autorizada y no tenga que consultar roles en mitad de la request.

### Autorización

El dataplane actual devuelve `403` cuando la API key no está asociada al consumer y `403 model_not_allowed` cuando `EnforceModel()` rechaza un modelo. En la reunión se mencionó responder `401` si el modelo no está permitido por el rol.

Hay que decidir la semántica HTTP antes de implementar:

| Situación | Estado actual | Recomendación |
|---|---:|---:|
| Sin credencial válida | `401` | Mantener `401`. |
| Credencial válida pero sin acceso al consumer | `403` | Mantener `403`. |
| Modelo/provider no permitido por rol | `403` | Mantener `403`. |

Técnicamente, un modelo no permitido es autorización fallida con identidad conocida, por lo que `403` encaja mejor que `401` y queda como decisión cerrada.

### Forwarder Y Load Balancer

El forwarder ya tiene piezas útiles:

- Exclusion set por request.
- Attempt loop.
- `FallbackBackends`.
- Spans con `Attempt` y `Fallback`.

Lo que debe cambiar es la entrada:

1. Parsear `RoutingIntent` antes de elegir registry.
2. Resolver `candidate_set` según modo inline/role.
3. Si el modo es `role_based`, seleccionar el candidato directamente por la intención del payload dentro de los permisos del rol, sin LB ni fallback.
4. Si el modo es `inline` y LB está desactivado, usar la intención explícita del payload para seleccionar un candidato permitido.
5. Si el modo es `inline` y LB está activado, usar la estrategia sobre el pool configurado por el usuario, filtrado por el `model_policies` inline.
6. Aplicar fallback solo en `inline`, sobre la chain configurada y compatible con el intent.

### Adapter Y Normalización De Provider/Modelo

`adapter.EnforceModel()` debe dejar de ser solo una validación posterior al target. Necesitamos una fase previa:

```text
ExtractRoutingIntent(body) -> ResolveCandidates(intent) -> NormalizeBodyForTarget(registry, intent)
```

Puntos críticos:

- No romper clientes OpenAI-compatible que solo mandan `model`.
- Soportar `modelId` para Bedrock.
- Evitar que `X-Provider` se confunda con provider upstream: hoy indica formato fuente, no autorización de provider.
- Evitar un campo custom `provider` en el body salvo que se demuestre necesario.
- Usar `provider/model` como separador recomendado para modelos provider-qualified (`openai/gpt-5`, `anthropic/claude-sonnet`, etc.).

## Puntos Críticos

### 1. No Duplicar La Lógica De Autorización

El riesgo principal es implementar roles en admin/API pero dejar `ModelPolicies` y `consumer_registry` como fuente real en runtime. La autorización debe resolverse una vez y producir un candidate set efectivo.

### 2. LB Y Fallback Solo Existen En Inline

LB y fallback solo se aplican en consumers `inline`. En `role_based` no hay distribución automática ni chain: el candidate set del rol se consume por intención explícita del payload. Dentro de inline, el usuario puede configurar pools y chains con múltiples providers, pero solo seleccionando providers/modelos permitidos por el `model_policies` inline del consumer; LB y fallback nunca amplían permisos.

### 3. LB Necesita Un Estado Explícito De Activación

Hoy siempre existe un `Algorithm` con default `round-robin`. Para producto, "LB desactivado" no es lo mismo que "round-robin con un solo registry". Como LB solo aplica en inline, esta configuración vive en el consumer inline. Si el frontend va a mostrar activado/desactivado, el backend debería tener una semántica propia:

- `distribution.enabled`
- `distribution.algorithm`
- `distribution.strategy_config`
- subconjunto de providers/modelos incluidos en el pool

Esta configuración vive como una única columna JSONB de LB en `consumers` (un solo pool por consumer), reemplazando a `Consumer.Algorithm`, que se elimina. El alias de `pool:<alias>` nombra ese pool único del consumer.

### 4. El Modelo En Payload Puede Ser Intención, No Target Final

Si el payload se usa para expresar orden de ejecución o provider, el gateway debe distinguir:

- Modelo pedido por el cliente.
- Alias/pool de routing.
- Modelo real enviado al provider.

Sin esa distinción, el gateway acabará reenviando identificadores internos a providers externos.

### 5. Roles Requieren IDP

En este diseño los roles no existen sin IDP. La API key puede seguir funcionando para consumers `inline`, pero no debería activar autorización por roles. Si un consumer está en modo `role_based`, la request debe aportar una identidad validable contra el IDP y claims suficientes para seleccionar roles.

### 6. La BBDD Se Recrea Desde Cero

No hace falta preservar compatibilidad de datos ni migrar consumers existentes. El proyecto sigue en desarrollo y la BBDD se recreará desde cero, así que el esquema puede modelar directamente el diseño objetivo sin shims de migración ni defaults pensados para datos antiguos.

## Propuesta De Fases

### Fase 1: Modelo Objetivo De Datos

- Añadir `routing_mode` a consumer.
- Crear `roles` como entidad dueña de `model_policies` (y reservar hueco para `mcp_policies`).
- Crear `role_registry` como tabla relacional que solo enlaza `role_id` y `registry_id`, sin policies.
- Crear `consumer_role` con soporte para más de un rol por consumer.
- Mantener `consumer_registry` como relación del modo `inline`.
- Definir estructura explícita para LB y fallback, acotada al modo `inline`, incluyendo enabled/disabled y los providers/modelos seleccionados.
- Asumir BBDD desde cero, sin compatibilidad con datos previos.

### Fase 2: Autenticación (Spikes + Implementación)

Esta fase introduce dos tipos de auth nuevos —IDP role-based y OAuth clásico—, cada uno con un spike de investigación previo. mTLS queda descartado por el momento.

- Spike IDP: entrega/rotación de public key/JWKS, validación de firma del JWT, extracción de claims/scopes y mapeo claims → rol → recurso. Solo aplica a `role_based`.
- Spike OAuth clásico: grant `client_credentials`, almacenamiento de credenciales y obtención/renovación del token.
- Separar la configuración de IDP (validación entrante) de la de OAuth clásico (cliente), evitando reusar un único `OAuth2Config` para ambos roles.
- Mantener API key (`X-AG-API-Key`) como método actual, solo en `inline`.
- Implementar validación IDP y resolución de roles por request a partir de los claims.
- Implementar OAuth clásico como método de identidad solo para `inline`.
- Validar que `role_based` solo se habilita con configuración IDP.
- Mantener `403` para provider/modelo no permitido.

### Fase 3: RoutingIntent Y CandidateSet

- Introducir `RoutingIntent`.
- Implementar sintaxis `provider/model` en el campo `model`.
- Permitir modelo corto solo si no es ambiguo dentro del `CandidateSet`.
- Implementar aliases de pool/LB con sintaxis `pool:<alias>`.
- Resolver candidatos antes de LB.
- Aplicar autorización por provider/modelo en el resolver.
- Mantener `forwarder` agnóstico al origen inline/role.

### Fase 4: Integración Con Forwarder, LB Y Fallback

- Pasar al forwarder un `CandidateSet` efectivo.
- En `role_based`, resolver el candidato por intención del payload sin LB ni fallback.
- En `inline`, hacer que LB opere solo sobre el pool configurado y autorizado.
- En `inline`, hacer que fallback opere solo sobre la chain configurada y autorizada.
- Revisar la cache del LB para el modo `inline`.
- Mantener trazas por intento, registry y fallback.

### Fase 5: Payload Normalizado Y Adapters

- Añadir parser y normalizador.
- Traducir el modelo enriquecido al modelo nativo antes del provider.
- Añadir tests cross-provider.

### Fase 6: Productización Y Observabilidad

- Completar triggers: `http_5xx`, `http_429`, `timeout`.
- `MaxCostUSD` queda fuera de scope (eliminado; diferido a una fase futura con pricing/usage).
- Añadir métricas/eventos de candidate set, registry elegido, intento, fallback y rechazo por autorización.

## Checklist De Implementación

- [ ] Existe un único modo activo por consumer: inline o roles.
- [ ] El candidate set efectivo se calcula antes del LB.
- [ ] Cada consumer puede tener más de un rol en modo `role_based`.
- [ ] La entidad `Role` es dueña de `model_policies` (y reserva `mcp_policies`).
- [ ] `role_registry` solo relaciona `role_id` y `registry_id`, sin policies.
- [ ] LB y fallback solo aplican en consumers `inline`.
- [ ] En `role_based` no hay LB ni fallback: routing por intención dentro del rol.
- [ ] LB solo opera sobre el pool configurado y autorizado (inline).
- [ ] Fallback solo recorre la chain configurada y autorizada (inline).
- [ ] Roles solo existen con IDP configurado.
- [ ] IDP filtra o selecciona roles mediante claims.
- [ ] API key, OAuth clásico e IDP están cubiertos como métodos de autenticación (mTLS descartado por ahora).
- [ ] IDP y OAuth clásico son tipos de auth separados, con configuración independiente.
- [ ] OAuth clásico y API key solo habilitan `inline`; IDP es la única vía para `role_based`.
- [ ] El payload enriquecido se normaliza antes de invocar el provider.
- [ ] `X-Provider` queda documentado como formato fuente o se sustituye por una semántica más clara.
- [ ] `model` soporta `provider/model` como sintaxis principal.
- [ ] `model` soporta `pool:<alias>` para pools/LB configurados.
- [ ] `consumer_registry` solo se puede usar con consumers `inline`.
- [ ] Attach/detach directo de registries en consumers `role_based` devuelve `409 Conflict`.
- [ ] `model_not_allowed` devuelve `403`.
- [ ] El esquema nuevo se puede recrear desde cero sin pasos de compatibilidad con datos antiguos.

## Archivos Más Afectados

| Área | Archivos |
|---|---|
| Dominio consumer | `pkg/domain/consumer/consumer.go`, `pkg/domain/consumer/model_policy.go`, `pkg/domain/consumer/fallback.go` |
| Runtime consumer | `pkg/app/consumer/consumer_data.go`, `pkg/app/consumer/data_finder.go` |
| Proxy routing | `pkg/api/handler/http/proxy/proxy_handler.go`, `pkg/app/proxy/forwarder.go`, `pkg/app/proxy/provider.go` |
| LB/fallback | `pkg/infra/loadbalancer/load_balancer.go`, `pkg/app/proxy/classify.go`, `pkg/app/proxy/budget.go` |
| Payload/modelo | `pkg/infra/providers/adapter/model.go`, `pkg/infra/providers/adapter/format.go` |
| Auth dataplane | `pkg/api/middleware/auth.go`, `pkg/domain/auth/auth.go` |
| Persistencia | `pkg/infra/database/migrations/`, `pkg/infra/repository/consumer/repository.go` |
| API consumer | `pkg/api/handler/http/consumer/request/create_consumer_request.go`, `pkg/api/handler/http/consumer/request/update_consumer_request.go`, `pkg/api/handler/http/consumer/association_handler.go` |

## Decisiones Cerradas

1. Si el modelo/provider no está permitido por rol, la respuesta debe ser `403`.
2. Un consumer en modo `role_based` puede tener más de un rol.
3. La entidad `Role` es dueña de las policies: las `model_policies` (y, a futuro, `mcp_policies`) cuelgan del rol, no del binding. `role_registry` solo relaciona `role_id` y `registry_id`.
4. LB y fallback solo actúan en consumers `inline`. En `role_based` no hay LB ni fallback.
5. LB y fallback pueden estar habilitados o deshabilitados explícitamente (en inline).
6. El LB tiene configuración propia: el usuario escoge qué providers/modelos forman el pool y qué algoritmo se usa (en inline).
7. Fallback usa una chain elegida por el usuario y puede cruzar múltiples providers, siempre dentro de lo permitido por el `model_policies` inline.
8. La autenticación soporta API key (actual, solo `inline`), OAuth clásico (solo `inline`) e IDP (solo `role_based`). IDP y OAuth clásico son tipos de auth distintos con configuración separada. mTLS queda descartado por el momento.
9. `consumer_registry` sigue siendo la tabla de relación necesaria para el modo `inline`, y sigue siendo necesario el endpoint que relaciona registry con consumer.
10. La sintaxis principal del payload universal será `provider/model` dentro del campo estándar `model`.
11. Los modelos cortos solo se aceptan si no son ambiguos dentro del `CandidateSet`.
12. Los pools/LB se referencian desde el payload con `model: "pool:<alias>"`.
13. Attach/detach directo de registries sobre un consumer `role_based` devuelve `409 Conflict`.
14. Un `pool:<alias>` inexistente devuelve `400 Bad Request` con mensaje de error explicativo.
15. La configuración de LB es única por consumer y se persiste como columna JSONB en `consumers`; no hay tabla dedicada. `pool:<alias>` nombra ese pool único.
16. Se elimina `Consumer.Algorithm`; la config explícita de LB lo reemplaza.
17. El tipo `ModelPolicies` se duplica de forma independiente en el dominio `consumer` (inline) y en el dominio `role`; no se comparte un tipo común.
18. El `409 Conflict` por mode mismatch usa un sentinel genérico `commonerrors.ErrConflict` con su caso en `MapDomainError`.
19. El mapping IDP→role se reserva como columna JSONB placeholder en `Role` en Fase 1; su forma concreta se define en Fase 2 (auth).
20. La exclusividad inline vs role_based se valida en app-layer y además con constraint/trigger en BBDD.

## Investigaciones Pendientes

1. Definir cómo interactúa `pool:<alias>` con fallback cuando el pool agota todos sus candidatos.

