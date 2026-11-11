# Delta para a2a-agent-registry

Cambio `a2a-plane`. Capability nueva: el registry de tipo `A2A`, que apunta a un agente A2A, y el agent card que el gateway fija al registrarlo. Cómo se sirve ese card y cómo se enruta el tráfico lo fija `a2a-plane-routing`.

## ADDED Requirements

### Requirement: Registry de tipo A2A

La Admin API MUST aceptar `type: "A2A"` en la creación de un registry, con un `a2a_target` y sin `llm_target` ni `mcp_target`. `a2a_target` MUST llevar `card_url` (https, o http solo si la red privada está permitida como en `netguard`). MAY llevar `url` (sustituye la URL de interfaz del card), `headers` estáticos, `auth` y `allowed_methods`.

`protocol_version` MAY faltar. Si viene, MUST ser `"0.3"` o `"1.0"`, y cualquier otro valor MUST responder 422. Si falta, el gateway MUST elegirla del card descargado: `"1.0"` si el card ofrece una interfaz `JSONRPC` 1.0, si no `"0.3"` si ofrece 0.3, y 422 si no ofrece ninguna. La versión elegida MUST guardarse y devolverse como si la hubiera enviado el cliente.

`auth.mode` MUST ser `none`, `static` o `client_credentials`. `passthrough` MUST responder 422 siempre: el token de quien llama nunca llega a un agente. `exchange` y `forwarded` MUST responder 422 en este cambio.

Los `headers` estáticos y los secretos de `auth` MUST cifrarse en reposo y enmascararse en las respuestas igual que en un registry MCP. La base de datos MUST aceptar `'A2A'` en `registries_type_check`. El registry MUST viajar en el snapshot como JSON de dominio, sin cambiar el proto.

#### Scenario: Alta de un agente 1.0

- GIVEN un agente cuyo card en `https://agent.example.com/.well-known/agent-card.json` declara una interfaz `JSONRPC` con `protocolVersion: "1.0"`
- WHEN se crea un registry `type: "A2A"` con ese `card_url` y `protocol_version: "1.0"`
- THEN 201, con `a2a_target.card`, `card_digest` y `card_pinned_at` rellenos

#### Scenario: Versión detectada

- GIVEN un card que ofrece interfaces `JSONRPC` 0.3 y 1.0
- WHEN se crea el registry sin `protocol_version`
- THEN 201 con `protocol_version: "1.0"`

#### Scenario: Passthrough rechazado

- GIVEN una petición de alta con `auth.mode: "passthrough"`
- WHEN se crea el registry
- THEN 422, y no se guarda nada

#### Scenario: Snapshot sin cambio de proto

- GIVEN un registry A2A en un gateway con data planes DB-less
- WHEN el control plane recompila el snapshot
- THEN el data plane lo lee con `a2a_target` completo, y `snapshot.proto` no cambia

### Requirement: Solo consumers A2A llevan registries A2A

`AttachRegistry` MUST rechazar un registry A2A en un consumer LLM o MCP, y un registry LLM o MCP en un consumer A2A, con el error de tipo que ya usa (`registry of type … cannot be attached to a consumer of type …`).

#### Scenario: Registry A2A en un consumer MCP

- GIVEN un consumer MCP y un registry A2A del mismo gateway
- WHEN se adjunta el registry
- THEN 4xx con el error de tipo, y no se crea el enlace

### Requirement: El card se fija al registrar

Al crear el registry, y al actualizar `card_url` o `protocol_version`, el admin plane MUST descargar el card con el cliente HTTP de `netguard` (protección SSRF y redirecciones comprobadas), con un límite de 1 MiB. MUST validar que es un objeto JSON con `name` y con una interfaz para la versión fijada:

- en 0.3, `url` y, si existe, `protocolVersion` empezando por `0.3`;
- en 1.0, una entrada de `supportedInterfaces` con `protocolBinding: "JSONRPC"` y `protocolVersion` empezando por `1.0`.

Si la descarga falla o el card no valida, MUST responder 422 y no guardar nada. Si valida, MUST guardar el card tal cual llegó, `card_digest` y `card_pinned_at`.

`card_digest` MUST ser `sha256:` seguido del SHA-256 en hexadecimal del card sin `signatures`, serializado con claves ordenadas. Un card que solo cambia `signatures` MUST dar el mismo digest.

Un cliente MUST NOT poder escribir `card`, `card_digest` ni `card_pinned_at`: si los envía, se ignoran.

#### Scenario: Card de otra versión

- GIVEN un card que solo declara una interfaz `JSONRPC` con `protocolVersion: "0.3"`
- WHEN se crea el registry con `protocol_version: "1.0"`
- THEN 422 que nombra la versión, y no se guarda nada

#### Scenario: Card en una IP privada

- GIVEN `card_url` que resuelve a `10.0.0.5` y la red privada no está permitida
- WHEN se crea el registry
- THEN 422, y no se hace ninguna petición a esa IP

### Requirement: Vista previa de un card antes de registrarlo

`POST /v1/gateways/{gateway_id}/agent-cards/preview` con `{"card_url": "…"}` MUST descargar el card con las mismas reglas que el alta (cliente de `netguard`, 1 MiB, objeto JSON con `name`) y responder 200 con `card`, `card_digest` y `versions`, la lista de versiones (`"0.3"`, `"1.0"`) para las que el card ofrece una interfaz `JSONRPC`. MUST NOT escribir nada.

Si la descarga falla o el card no es válido, MUST responder 422 con el motivo. Un card válido que no ofrece ninguna versión soportada MUST responder 200 con `versions: []`, para que la consola pueda explicar por qué no se puede registrar. El endpoint MUST exigir el mismo permiso que crear un registry en ese gateway.

#### Scenario: Card con dos versiones

- GIVEN un card que ofrece interfaces `JSONRPC` 0.3 y 1.0
- WHEN se llama a `preview` con su URL
- THEN 200 con `versions: ["0.3", "1.0"]`, y no existe ningún registry nuevo

#### Scenario: Card sin JSON-RPC

- GIVEN un card 1.0 que solo ofrece una interfaz `GRPC`
- WHEN se llama a `preview`
- THEN 200 con `versions: []`

### Requirement: Refresh no escribe; approve fija solo lo revisado

`POST /v1/gateways/{gateway_id}/registries/{id}/agent-card/refresh` MUST descargar el card vivo con las mismas reglas y responder 200 con `changed`, `pinned_digest`, `fetched_digest`, `changed_fields` (las claves de primer nivel que difieren, sin contar `signatures`) y `fetched_card`. MUST NOT escribir nada.

`POST …/agent-card/approve` con `{"digest": "sha256:…"}` MUST volver a descargar el card. Si su digest es el enviado, MUST fijarlo e invalidar los datos del gateway como cualquier escritura de registry (`invalidation.GatewayData` y `Signal`). Si no, MUST responder 409 sin escribir. Aprobar el digest que ya está fijado MUST ser un no-op con 200.

Los dos endpoints MUST responder 404 para un registry de otro gateway, y 422 para un registry que no es A2A.

#### Scenario: El agente añade una skill

- GIVEN un registry con el card fijado y un agente que publica una skill nueva
- WHEN se llama a `refresh`
- THEN 200 con `changed: true` y `changed_fields: ["skills"]`, y el card que sirve el data plane no cambia

#### Scenario: El card cambia entre refresh y approve

- GIVEN un `refresh` que devolvió el digest D1
- WHEN el agente vuelve a cambiar su card y se llama a `approve` con D1
- THEN 409, y el card fijado sigue siendo el anterior
