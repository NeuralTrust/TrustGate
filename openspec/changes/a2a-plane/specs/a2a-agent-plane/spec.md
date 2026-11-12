# Delta para a2a-agent-plane

Cambio `a2a-plane`. Capability nueva: el plano de datos `agent`, que sirve a los consumers A2A. Cubre:

- el arranque y el despliegue;
- las rutas;
- la autenticación de quien llama;
- el card que se sirve;
- el reenvío JSON-RPC y qué métodos pasan;
- qué viaja al agente;
- los errores y la traza.

La propiedad de las tareas la fija `a2a-task-ownership`; las policies, `a2a-policy-chain`; la identidad hacia el agente, `a2a-delegated-identity`.

## ADDED Requirements

### Requirement: Un plano propio

`./trustgate agent` MUST arrancar un servidor HTTP propio en `SERVER_AGENT_PORT` (por defecto `8084`), con `/health`, `/healthz` y `/readyz` iguales a los del plano MCP.

Igual que `proxy` y `mcp`, MUST poder correr DB-less, desde el snapshot, cuando `CONFIG_SYNC_DATA_PLANE_ENABLED` está activo. En ese modo `/readyz` MUST responder 503 hasta tener snapshot.

El plano MUST tener su propia etiqueta en las métricas operativas (`o11y` plane `agent`).

Los planos `proxy` y `mcp` MUST seguir respondiendo 404 a un consumer A2A, y MUST NOT cambiar en nada más. El plano `agent` MUST responder 404 a cualquier consumer que no sea A2A.

#### Scenario: Consumer MCP en el plano agent

- GIVEN un consumer MCP con slug `tools-app`
- WHEN se llama a `POST /tools-app/agents/x` en el plano agent
- THEN 404, sin leer el cuerpo

#### Scenario: Consumer A2A en el plano MCP

- GIVEN un consumer A2A con slug `research-bot`
- WHEN se llama a `POST /research-bot/mcp` en el plano MCP
- THEN 404, como hoy

### Requirement: Host del plano y del gateway

El host público de un gateway en el plano agent MUST ser `{gateway_slug}.{AGENT_BASE_DOMAIN}`. `AGENT_BASE_DOMAIN` es una variable nueva sin valor por defecto.

El plano agent MUST resolver el gateway por ese host, igual que el plano MCP lo resuelve con `MCP_BASE_DOMAIN`, y el consumer por el primer segmento de la ruta.

`GET /v1/gateways/{id}` MUST devolver `hosts.agent` con ese host solo cuando `AGENT_BASE_DOMAIN` está definido en el admin plane. Si no lo está, `hosts` MUST NOT llevar `agent`, y la consola no ofrece agentes (`console-agents-plane`). Esta variable es el interruptor de A2A en un entorno, junto al despliegue de los pods.

#### Scenario: Entorno sin agentes

- GIVEN un admin plane sin `AGENT_BASE_DOMAIN`
- WHEN se pide `GET /v1/gateways/{id}`
- THEN `hosts` trae `proxy` y `mcp`, y no `agent`

### Requirement: Rutas y resolución del agente

El plano agent MUST servir solo:

- `GET /{consumer}/agents/{agent}/.well-known/agent-card.json`
- `POST /{consumer}/agents/{agent}`

`{consumer}` MUST resolverse por slug, como en los otros planos. `{agent}` MUST resolverse al id de un registry A2A habilitado y adjunto al consumer, o a su nombre cuando exactamente uno de esos registries lo tiene. En cualquier otro caso, y para cualquier otra ruta, MUST responder 404.

#### Scenario: Nombre ambiguo

- GIVEN un consumer A2A con dos registries A2A llamados `research`
- WHEN se llama a `POST /{consumer}/agents/research`
- THEN 404; llamando por id, cada uno responde

#### Scenario: Registry deshabilitado

- GIVEN un registry A2A adjunto pero con `enabled: false`
- WHEN se llama a su ruta
- THEN 404

### Requirement: Quién puede llamar

El plano agent MUST resolver la identidad con el mismo resolvedor en cadena que el plano MCP (`ChainIdentityResolver`), acotado al consumer de la ruta `/{consumer}/agents/…`. Acepta:

- API key (`X-AG-API-Key`, o `Authorization: Bearer ag_…`);
- certificado de cliente (mTLS o XFCC);
- un JWT de un IdP configurado en el gateway (`external_jwt` o introspección).

MUST NOT aceptar los tokens de sesión MCP del gateway (`token_use=mcp_session`) ni los del IdP por defecto: son del plano MCP.

Con una API key o un certificado, si llega la cabecera `X-NeuralTrust-End-User` (valor válido según `ValidateEndUser`), el principal MUST pasar a ser ese usuario final (`EndUserSubject`), como en el plano MCP. Sin ella, MUST ser la aplicación (`AppSubject`).

MUST aplicar las mismas comprobaciones que el plano MCP: la credencial pertenece al consumer (`AuthIDs`), y el principal es admitido por su `auth_binding`.

- Sin credencial válida: 401.
- Credencial de otro consumer, o principal no admitido: 403.

Las dos respuestas MUST darse antes de leer el cuerpo y antes de cualquier llamada al agente.

#### Scenario: Key de otra aplicación

- GIVEN una key adjunta solo al consumer A
- WHEN se llama a una ruta del consumer A2A B con esa key
- THEN 403, y el agente no recibe nada

### Requirement: El card servido es el fijado, reescrito

El `GET` del card MUST devolver el card fijado (`a2a-agent-registry`), nunca el vivo, con estos cambios y ninguno más:

- **Interfaz:**
  - en 0.3: `url` es `{agent_base}/{consumer}/agents/{registry_id}`, `preferredTransport` es `JSONRPC` y `additionalInterfaces` lleva solo esa interfaz;
  - en 1.0: `supportedInterfaces` lleva solo `{url, protocolBinding: "JSONRPC", protocolVersion}` con esa URL.
- **Seguridad:** `securitySchemes` y `security` (0.3) o `securityRequirements` (1.0) describen la API key del gateway en la cabecera `X-AG-API-Key`. Se quitan los `securityRequirements` de cada skill.
- **Capacidades:** `capabilities.pushNotifications` es `false`. `supportsAuthenticatedExtendedCard` (0.3) y `capabilities.extendedAgentCard` (1.0) son `false`.
- **Firmas:** se quita `signatures`.

`{agent_base}` MUST ser el origen de la petición en el plano agent (esquema y host), como hace el plano MCP con sus URLs. Los campos desconocidos MUST conservarse. El `GET` MUST pedir la misma credencial que una llamada.

#### Scenario: El agente cambia su endpoint

- GIVEN un card fijado y un agente que publica un card nuevo con otra URL
- WHEN un cliente pide el card al gateway
- THEN recibe el fijado, con la URL del gateway, y el tráfico sigue yendo al endpoint fijado

### Requirement: Solo pasan los métodos de la versión fijada, y los soportados

El handler MUST aceptar solo JSON-RPC 2.0 con un único objeto, sin batch, y con `Content-Type: application/json`. Si no, MUST responder `-32600`. Un cuerpo que no es JSON MUST responder `-32700`.

Para un registry 0.3 los métodos válidos MUST ser los de 0.3, y para 1.0 los de 1.0. Un método de la otra versión, o desconocido, MUST responder `-32601`. El gateway MUST NOT traducir entre versiones.

MUST rechazarse, con el error A2A de la versión y sin llamar al agente:

- configuración de push notifications (`tasks/pushNotificationConfig/*`, `*TaskPushNotificationConfig*`): `PushNotificationNotSupportedError`;
- card extendido (`agent/getAuthenticatedExtendedCard`, `GetExtendedAgentCard`): el error de card extendido no configurado de la versión;
- `ListTasks` (y `tasks/list` donde exista): `UnsupportedOperationError`.

Si el registry tiene `allowed_methods`, un método fuera de la lista MUST responder `-32601`.

#### Scenario: Push notifications

- GIVEN un registry 0.3
- WHEN se llama a `tasks/pushNotificationConfig/set` con una URL de webhook
- THEN error `-32003` y el agente no recibe nada

#### Scenario: Método de 1.0 contra un agente 0.3

- GIVEN un registry 0.3
- WHEN se llama a `SendMessage`
- THEN error `-32601`

### Requirement: Qué viaja al agente

La llamada al agente MUST ir al endpoint fijado (la interfaz JSON-RPC del card para la versión, o `url` si el registry la sustituye), por el cliente de `netguard`. MUST llevar:

- la credencial que dicta `auth` (`a2a-delegated-identity` para `exchange`) y los `headers` estáticos;
- `A2A-Version` con la versión fijada, solo en 1.0;
- `X-AG-Trace-Id` con la traza de esta petición;
- `Content-Type`, `Accept`, y la cabecera de extensiones A2A de la versión si quien llama la envió.

MUST NOT viajar ninguna otra cabecera de quien llama; en particular `Authorization`, `Cookie` y cualquier `X-AG-*`.

El cuerpo JSON-RPC MUST llegar igual que lo envió quien llama, salvo lo que reescriba un plugin. El `id` de JSON-RPC de la respuesta MUST ser el de quien llama.

#### Scenario: La credencial de quien llama no sale

- GIVEN una llamada con `X-AG-API-Key: k1` y `Authorization: Bearer t1` a un registry con `auth.mode: "static"`
- WHEN el gateway la reenvía
- THEN el agente recibe solo la credencial estática del registry, sin `k1` ni `t1`

### Requirement: Límites

| Límite | Variable | Por defecto | Qué pasa al superarlo |
|---|---|---|---|
| Cuerpo de la petición | límite de cuerpo del servidor | 8 MiB, el mismo que los otros planos | 413 antes del handler |
| Respuesta con buffer | `A2A_MAX_RESPONSE_BYTES` | 8 MiB | `-32092`; la respuesta no se entrega |
| Llamada con buffer | `A2A_UPSTREAM_TIMEOUT` | 300 s | `-32092` |
| Silencio entre eventos de un stream | `A2A_STREAM_IDLE_TIMEOUT` | 120 s | el stream se cierra con un evento `-32092` |
| Duración de un stream | `A2A_STREAM_MAX_DURATION` | 55 min | el stream se cierra con un evento `-32092` y `reason: "stream_max_duration"`; el cliente sigue con `tasks/resubscribe` o `SubscribeToTask` |

`A2A_STREAM_MAX_DURATION` MUST quedar por debajo del timeout de backend del balanceador de cada entorno. El cierre tiene que ser del gateway, explicado, y no un corte del LB.

#### Scenario: Agente lento

- GIVEN un agente que no responde en `A2A_UPSTREAM_TIMEOUT`
- WHEN se llama a `message/send`
- THEN error `-32092`, y el span dice `outcome=upstream_timeout`

### Requirement: Errores propios del gateway

Los errores del gateway dentro de JSON-RPC MUST usar códigos de `-32090` a `-32099`. Llevan HTTP 200, salvo los 401 y 403 de autenticación.

| Código | Cuándo | `error.data` |
|---|---|---|
| `-32090` | Una policy bloqueó la llamada o su respuesta | `{"reason": "policy_blocked" \| "mask_unsupported", "plugin": "<slug>"}` |
| `-32091` | Límite de tasa | `{"retry_after": <segundos>}` |
| `-32092` | El gateway no pudo completar la llamada: agente inalcanzable, tiempo agotado, respuesta no válida o demasiado grande, almacén de propiedad caído, o plan del gateway sin resolver (`plan_unavailable`, donde el plano MCP responde `-32005`) | `{"reason": "<motivo>"}` |
| `-32093` | El modo de identidad del registry necesita un usuario autenticado por un IdP y la llamada no lo tiene | `{"reason": "identity_required"}` |

Una respuesta del agente que no es JSON-RPC válido MUST llegar como `-32092` con `reason: "invalid_upstream_response"`, sin el cuerpo original.

#### Scenario: Bloqueo

- GIVEN una policy `requestsize` que rechaza el mensaje
- WHEN se llama a `message/send`
- THEN `-32090` con `plugin: "requestsize"`, y el agente no recibe nada

### Requirement: Un span por llamada

Cada `POST` MUST producir un span `a2a` con:

- registry id, nombre del agente, método y versión fijada;
- task id y context id cuando existan;
- estado final de la tarea cuando se conozca;
- estado HTTP del agente;
- resultado: `ok`, `blocked`, `refused`, `not_found`, `upstream_error` o `upstream_timeout`;
- el plugin que bloqueó, si alguno;
- el modo de identidad usado.

Los atributos nuevos de telemetría MUST ser aditivos y declararse en el descriptor de `pkg/metrics`, como pide `telemetry-event-contract.mdc`.

#### Scenario: Tarea ajena

- GIVEN un `tasks/get` sobre una tarea de otro caller
- WHEN responde el gateway
- THEN un span `a2a` con `outcome=not_found`, que para el admin dice `reason=not_owner`, aunque quien llama solo ve `TaskNotFound`
