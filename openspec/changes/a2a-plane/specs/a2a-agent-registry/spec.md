# Delta para a2a-agent-registry

Cambio `a2a-plane`. Capability nueva: el registry de tipo `A2A`, que apunta a un agente A2A; el agent card que el gateway resuelve, valida y fija al registrarlo; y los endpoints para previsualizarlo, comprobar si cambió y aprobar el cambio.

Cómo se sirve ese card y cómo se enruta el tráfico lo fija `a2a-agent-plane`. La identidad que se envía al agente, `a2a-delegated-identity`.

## ADDED Requirements

### Requirement: Alta de un registry A2A

`POST /v1/gateways/{gateway_id}/registries` MUST aceptar `type: "A2A"` con un `a2a_target` y sin `llm_target` ni `mcp_target`. Si llega cualquiera de los otros dos targets, MUST responder 422.

`a2a_target` admite:

| Campo | Obligatorio | Regla |
|---|---|---|
| `card_url` | sí | URL `https` (o `http` solo si la red privada está permitida, como en `netguard`). Puede ser la URL del card o la URL base del agente (ver "Resolución del card"). |
| `protocol_version` | no | `"0.3"` o `"1.0"`. Si falta, se detecta del card. |
| `url` | no | URL `https` que sustituye al endpoint JSON-RPC que nombra el card. |
| `headers` | no | Mapa de cabeceras estáticas que viajan al agente. No admite `Authorization`, `Cookie`, `Host`, `Content-Length`, `A2A-Version` ni nombres que empiecen por `X-AG-`. |
| `auth` | no | `{ "mode": … }`. Por defecto `none`. |
| `allowed_methods` | no | Lista de métodos JSON-RPC de la versión fijada. Si existe, el plano agent rechaza cualquier otro. |

`auth.mode` MUST ser uno de:

- `none`;
- `static`: con `header` y `value`, igual que en un registry MCP;
- `client_credentials`: con los mismos campos y validación que en un registry MCP;
- `exchange`: con `pattern` igual a `delegation`, `obo` o `token_exchange`, y opcionalmente `audience` (`a2a-delegated-identity`).

`passthrough`, `forwarded` y `exchange` con `pattern: "impersonation"` MUST responder 422, con un mensaje que diga por qué no se admiten en un agente.

Los valores de `headers` y los secretos de `auth` MUST cifrarse en reposo, y en las respuestas MUST enmascararse igual que en un registry MCP. La respuesta MUST incluir además los campos de solo lectura: `resolved_card_url`, `protocol_version` (la detectada si no se envió), `card`, `card_digest` y `card_pinned_at`.

La base de datos MUST aceptar `'A2A'` en `registries_type_check` y guardar el target en `registries.a2a_target`. El registry MUST viajar en el snapshot como JSON de dominio, sin cambiar `snapshot.proto`.

#### Scenario: Alta mínima

- GIVEN un agente cuyo card en `https://travel.example.com/.well-known/agent-card.json` ofrece una interfaz `JSONRPC` 1.0
- WHEN se envía `{"name": "Travel planner", "type": "A2A", "a2a_target": {"card_url": "https://travel.example.com"}}`
- THEN 201 con `protocol_version: "1.0"`, `resolved_card_url` igual a la URL del card, `auth.mode: "none"`, y `card`, `card_digest` y `card_pinned_at` rellenos

#### Scenario: Cabecera reservada

- WHEN se envía `headers: {"Authorization": "Bearer x"}`
- THEN 422 que nombra la cabecera, y no se guarda nada

#### Scenario: Passthrough rechazado

- WHEN se envía `auth: {"mode": "passthrough"}`
- THEN 422, y no se guarda nada

#### Scenario: Snapshot sin cambio de proto

- GIVEN un registry A2A en un gateway con data planes DB-less
- WHEN el control plane recompila el snapshot
- THEN el plano agent lo lee con `a2a_target` completo, y `snapshot.proto` no cambia

### Requirement: Resolución del card

Para una `card_url`, el admin plane MUST:

- si su ruta termina en `.json` o en `/agentCard/v1.0`, pedir esa URL;
- si no, probar en orden `{card_url}/.well-known/agent-card.json`, `{card_url}/.well-known/agent.json` y `{card_url}/agentCard/v1.0`, y quedarse con la primera que responda 200 con un objeto JSON.

Cada petición MUST ir por el cliente HTTP de `netguard` (protección SSRF y redirecciones comprobadas), con un límite de 1 MiB por respuesta y un tiempo máximo total de 10 s. La URL que dio el card MUST guardarse como `resolved_card_url`. Si ninguna ruta sirve, MUST responder 422 con las URLs probadas.

#### Scenario: URL base con card heredado

- GIVEN un agente que solo sirve `/.well-known/agent.json`
- WHEN se registra con su URL base
- THEN 201 y `resolved_card_url` termina en `/.well-known/agent.json`

#### Scenario: Card en una IP privada

- GIVEN `card_url` que resuelve a `10.0.0.5` y la red privada no está permitida
- WHEN se crea el registry
- THEN 422, y no se hace ninguna petición a esa IP

### Requirement: Versión y validación del card

El card MUST ser un objeto JSON con `name`. Las versiones que ofrece MUST calcularse así:

- **0.3:** el card tiene `url` y su `protocolVersion`, si existe, empieza por `0.3`; o alguna entrada de `additionalInterfaces` tiene `transport: "JSONRPC"`.
- **1.0:** alguna entrada de `supportedInterfaces` tiene `protocolBinding: "JSONRPC"` y un `protocolVersion` que empieza por `1.0`.

Si `protocol_version` no se envía, MUST fijarse `"1.0"` cuando el card lo ofrece, y si no `"0.3"`. Si el card no ofrece ninguna de las dos, o no ofrece la enviada, MUST responder 422 con las versiones que sí ofrece.

`card_digest` MUST ser `sha256:` seguido del SHA-256 en hexadecimal del card sin `signatures`, serializado con las claves ordenadas. Un card que solo cambia `signatures` MUST dar el mismo digest. Si un cliente envía `card`, `card_digest`, `card_pinned_at` o `resolved_card_url`, MUST ignorarse.

#### Scenario: Card con las dos versiones

- GIVEN un card con `supportedInterfaces` JSON-RPC 1.0 y `url` con `protocolVersion: "0.3.0"`
- WHEN se crea el registry sin `protocol_version`
- THEN `protocol_version: "1.0"`; con `protocol_version: "0.3"`, 201 con `"0.3"`

#### Scenario: Versión que el card no ofrece

- GIVEN un card que solo ofrece 0.3
- WHEN se crea el registry con `protocol_version: "1.0"`
- THEN 422 que dice que el card ofrece `["0.3"]`

### Requirement: Actualización de un registry A2A

`PUT /v1/gateways/{gateway_id}/registries/{id}` sobre un registry A2A MUST:

- volver a resolver, validar y fijar el card solo si cambia `card_url` o `protocol_version`;
- guardar los demás cambios (`name`, `url`, `headers`, `auth`, `allowed_methods`, `enabled`) sin descargar nada;
- conservar el valor guardado cuando un secreto de `headers` o de `auth` llega vacío o enmascarado (`***…`), igual que en un registry MCP.

El tipo no se puede cambiar: la petición de actualización no tiene campo `type`.

Toda actualización MUST invalidar los datos del gateway y señalar el recompilado del snapshot, como cualquier escritura de registry.

#### Scenario: Cambiar la cabecera estática no descarga el card

- GIVEN un registry A2A fijado
- WHEN se actualiza solo `headers`
- THEN 200, `card_digest` y `card_pinned_at` no cambian y no hay petición al agente

### Requirement: Solo consumers A2A llevan registries A2A

`AttachRegistry` MUST rechazar un registry A2A en un consumer LLM o MCP, y un registry LLM o MCP en un consumer A2A, con el error de tipo que ya usa (`registry of type … cannot be attached to a consumer of type …`).

#### Scenario: Registry A2A en un consumer MCP

- GIVEN un consumer MCP y un registry A2A del mismo gateway
- WHEN se adjunta el registry
- THEN 4xx con el error de tipo, y no se crea el enlace

### Requirement: Vista previa de un card

`POST /v1/gateways/{gateway_id}/registries/preview-agent-card` con `{"card_url": "…"}`, junto a `test-connection` y `validate-openapi` y con su mismo permiso, MUST resolver y descargar el card con las reglas de "Resolución del card", y responder 200 con:

```json
{
  "resolved_card_url": "https://travel.example.com/.well-known/agent-card.json",
  "card": { "name": "Travel planner" },
  "card_digest": "sha256:…",
  "versions": ["0.3", "1.0"],
  "default_version": "1.0"
}
```

MUST NOT escribir nada. Un card válido sin ninguna versión soportada MUST responder 200 con `versions: []` y sin `default_version`. Si la descarga falla o lo descargado no es un objeto JSON con `name`, MUST responder 422 con el motivo.

#### Scenario: Card solo gRPC

- GIVEN un card 1.0 que solo ofrece una interfaz `GRPC`
- WHEN se llama a `preview`
- THEN 200 con `versions: []`, y no existe ningún registry nuevo

### Requirement: Refresh no escribe; approve fija solo lo revisado

`POST /v1/gateways/{gateway_id}/registries/{id}/agent-card/refresh` MUST resolver y descargar el card vivo desde `resolved_card_url` y responder 200 con:

```json
{
  "changed": true,
  "pinned_digest": "sha256:…",
  "fetched_digest": "sha256:…",
  "changed_fields": ["skills", "supportedInterfaces"],
  "skills_added": ["refund_invoice"],
  "skills_removed": [],
  "fetched_card": { }
}
```

- `changed_fields` son las claves de primer nivel que difieren, sin contar `signatures`.
- `skills_added` y `skills_removed` comparan los `id` de `skills`.
- MUST NOT escribir nada.

`POST …/agent-card/approve` con `{"digest": "sha256:…"}` MUST volver a descargar el card:

- si su digest es el enviado, MUST fijarlo (`card`, `card_digest`, `card_pinned_at`), invalidar los datos del gateway, señalar el recompilado y responder 200 con el registry;
- si no, MUST responder 409 sin escribir;
- aprobar el digest que ya está fijado MUST ser un no-op con 200;
- si el card nuevo ya no ofrece la `protocol_version` del registry, MUST responder 422 sin escribir.

Los dos endpoints MUST responder 404 para un registry de otro gateway, y 422 para un registry que no es A2A.

#### Scenario: El agente añade una skill

- GIVEN un registry fijado y un agente que publica la skill `refund_invoice`
- WHEN se llama a `refresh`
- THEN 200 con `changed: true`, `changed_fields: ["skills"]` y `skills_added: ["refund_invoice"]`, y el card que sirve el plano agent no cambia

#### Scenario: El card cambia entre refresh y approve

- GIVEN un `refresh` que devolvió D1
- WHEN el agente vuelve a cambiar su card y se llama a `approve` con D1
- THEN 409, y el card fijado sigue siendo el anterior
