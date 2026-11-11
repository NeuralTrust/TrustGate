# Delta para a2a-plane-routing

Cambio `a2a-plane`. Capability nueva: cómo el plano MCP (`:8082`) sirve a un consumer A2A. Cubre las rutas, la autenticación de quien llama, el card que se sirve, el reenvío JSON-RPC, qué métodos pasan, qué viaja al agente y la traza. La propiedad de las tareas la fija `a2a-task-ownership`; las policies, `a2a-policy-chain`.

## ADDED Requirements

### Requirement: Un consumer A2A se sirve en el plano MCP

Cuando `MatchPath` resuelve un consumer de tipo A2A, el plano MCP MUST pasarlo al handler A2A en lugar de responder 404. Un consumer MCP MUST seguir exactamente el camino actual, y un consumer LLM MUST seguir respondiendo 404. Las comprobaciones de credencial (`hasAuth`) y de principal (`consumerAdmitsPrincipal`) MUST ser las mismas que para un consumer MCP, y fallar igual (401/403) antes de leer el cuerpo.

Las rutas MUST ser:

- `GET /{consumer}/agents/{agent}/.well-known/agent-card.json`
- `POST /{consumer}/agents/{agent}`

`{agent}` MUST resolverse al id de un registry A2A habilitado y adjunto al consumer, o a su nombre cuando exactamente uno de esos registries lo tiene. En otro caso, y para cualquier otra ruta bajo un consumer A2A, MUST responder 404.

#### Scenario: Consumer MCP sin cambios

- GIVEN un consumer MCP que hoy sirve `tools/list`
- WHEN se despliega este cambio
- THEN `POST /{consumer}/mcp` responde igual que antes

#### Scenario: Nombre ambiguo

- GIVEN un consumer A2A con dos registries A2A llamados `research`
- WHEN se llama a `POST /{consumer}/agents/research`
- THEN 404; por id, cada uno responde

### Requirement: El card servido es el fijado, reescrito

El `GET` del card MUST devolver el card fijado (`a2a-agent-registry`), nunca el vivo, con estos cambios y ninguno más:

- La interfaz apunta al gateway: en 0.3, `url` es `https://{host}/{consumer}/agents/{registry_id}`, `preferredTransport` es `JSONRPC` y `additionalInterfaces` lleva solo esa interfaz; en 1.0, `supportedInterfaces` lleva solo `{url, protocolBinding: "JSONRPC", protocolVersion}` con esa URL.
- `securitySchemes` y `security` (0.3) o `securityRequirements` (1.0) describen la credencial del gateway (API key en `X-AG-API-Key`). Se quitan los `securityRequirements` de cada skill.
- `capabilities.pushNotifications` es `false`. `supportsAuthenticatedExtendedCard` (0.3) y `capabilities.extendedAgentCard` (1.0) son `false`.
- Se quita `signatures`.

Los campos desconocidos MUST conservarse. El `GET` MUST pedir la misma credencial que una llamada.

#### Scenario: El agente cambia su URL

- GIVEN un card fijado y un agente que ha movido su endpoint y publicado un card nuevo
- WHEN un cliente pide el card al gateway
- THEN recibe el fijado, con la URL del gateway, y el tráfico sigue yendo a la URL fijada

#### Scenario: Sin credencial

- WHEN se pide el card sin `X-AG-API-Key` ni token
- THEN 401, sin cuerpo de card

### Requirement: Solo pasan los métodos de la versión fijada, y los soportados

El handler MUST aceptar solo JSON-RPC 2.0 con un único objeto (sin batch). Para un registry 0.3 los métodos válidos MUST ser los de 0.3, y para 1.0 los de 1.0. Un método de la otra versión, o desconocido, MUST responder `-32601`. El gateway MUST NOT traducir entre versiones.

MUST rechazarse, con el error A2A de la versión y sin llamar al agente:

- configuración de push notifications (`tasks/pushNotificationConfig/*`, `*TaskPushNotificationConfig*`): `PushNotificationNotSupportedError`;
- card extendido (`agent/getAuthenticatedExtendedCard`, `GetExtendedAgentCard`): el error de card extendido no configurado de la versión;
- `ListTasks`: `UnsupportedOperationError`.

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

La llamada al agente MUST ir a la URL fijada (la del card, o `url` si el registry la sustituye), por el cliente de `netguard`, con:

- la autenticación del registry (`none`, `static`, `client_credentials`) y sus `headers` estáticos;
- `A2A-Version` con la versión fijada (solo en 1.0);
- `X-AG-Trace-Id` con la traza de esta petición;
- `Content-Type`, `Accept` y la cabecera de extensiones A2A de la versión, si quien llama la envió.

MUST NOT viajar ninguna otra cabecera de quien llama; en particular `Authorization`, `Cookie` y cualquier `X-AG-*`.

El cuerpo JSON-RPC MUST llegar al agente igual que lo envió quien llama, salvo lo que reescriba un plugin. El `id` de JSON-RPC de la respuesta MUST ser el de quien llama.

#### Scenario: La credencial de quien llama no sale

- GIVEN una llamada con `X-AG-API-Key: k1` y `Authorization: Bearer t1`
- WHEN el gateway la reenvía a un registry con `auth.mode: "static"`
- THEN el agente recibe solo la credencial estática del registry, sin `k1` ni `t1`

### Requirement: Errores propios del gateway

Los errores del gateway dentro de JSON-RPC MUST usar códigos de `-32090` a `-32099` y no reutilizar los de A2A (`-32001` a `-32007`):

- `-32090`: una policy bloqueó la llamada o su respuesta;
- `-32091`: límite de tasa (con `Retry-After` en `error.data`);
- `-32092`: el gateway no pudo decidir (almacén de propiedad caído, agente inalcanzable o tiempo agotado).

Una respuesta del agente que no es JSON-RPC válido MUST llegar a quien llama como `-32092`, sin el cuerpo original.

#### Scenario: Agente caído

- GIVEN un agente que no responde en `A2A_UPSTREAM_TIMEOUT`
- WHEN se llama a `message/send`
- THEN error `-32092`, y el span lo registra con `outcome=upstream_timeout`

### Requirement: Un span por llamada

Cada `POST` MUST producir un span `a2a` con: registry id, nombre del agente, método, versión fijada, task id y context id cuando existan, estado final de la tarea cuando se conozca, estado HTTP del agente, resultado (`ok`, `blocked`, `refused`, `upstream_error`, `upstream_timeout`) y el plugin que bloqueó, si alguno. Los atributos nuevos de telemetría MUST ser aditivos y declararse en el descriptor de `pkg/metrics`, como pide `telemetry-event-contract.mdc`.

#### Scenario: Llamada bloqueada

- GIVEN una policy que bloquea el mensaje
- WHEN se llama a `message/send`
- THEN un span `a2a` con `outcome=blocked` y el slug del plugin, y ninguna llamada al agente
