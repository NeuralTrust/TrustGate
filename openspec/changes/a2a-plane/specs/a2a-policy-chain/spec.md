# Delta para a2a-policy-chain

Cambio `a2a-plane`. Capability nueva: qué policies corren en un consumer A2A, sobre qué contenido y qué pasa con un bloqueo o una máscara. No cambia nada de lo que corre hoy en LLM ni en MCP.

## ADDED Requirements

### Requirement: Solo se adjuntan plugins que declaran A2A

`AttachPolicy` sobre un consumer A2A MUST validar el protocolo como hace hoy con LLM y MCP: si el plugin no declara `A2A`, MUST responder 422 con `ErrPolicyProtocolMismatch`. Una policy global MUST seguir saltándose esta comprobación, como hoy.

En este cambio declaran `A2A`: `ratelimit`, `requestsize` y `trustguard`. `trustguard_v2` comparte implementación con `trustguard`, pero MUST NOT declarar `A2A` mientras su motor salte `a2a` (`skip_reason=unsupported_protocol`). Adjuntarlo a un consumer A2A MUST responder 422, en lugar de aceptar una policy que no inspeccionaría nada.

#### Scenario: Plugin solo LLM

- GIVEN un consumer A2A y una policy `tokenratelimit`
- WHEN se adjunta
- THEN 422 que nombra el plugin y el protocolo A2A

#### Scenario: TrustGuard v2

- GIVEN un consumer A2A y una policy `trustguard_v2`
- WHEN se adjunta
- THEN 422 que nombra `trustguard_v2` y el protocolo A2A

### Requirement: El plan de un consumer A2A excluye plugins sin A2A

El `StagePlan` de un consumer A2A MUST excluir cualquier policy cuyo plugin no declare `A2A`, también las globales. Una policy `mcp_wide` MUST seguir sin entrar (`policy-inert-scope`). Este filtro MUST aplicarse solo a consumers A2A: los planes LLM y MCP MUST NOT cambiar en este cambio.

#### Scenario: Global de un plugin solo LLM

- GIVEN una policy global `tokenratelimit` y un consumer A2A
- WHEN se carga el plan del consumer A2A
- THEN `tokenratelimit` no está en ninguna etapa, y sigue en el plan de los consumers LLM

### Requirement: Contenido que ven los plugins

Para cada llamada inspeccionada, el gateway MUST construir un cuerpo normalizado con el método, el agente y la lista de partes, cada una con `type` (`text`, `data` o `file`) y su contenido:

- en 0.3, `kind: "text"` → `text`; `kind: "data"` → `data`; `kind: "file"` con `file.uri` → `file` con `url`; con `file.bytes` → `file` con `raw`;
- en 1.0, `text` → `text`; `data` → `data`; `url` → `file` con `url`; `raw` → `file` con `raw`.

`media_type` y `filename` MUST conservarse cuando existan. El `Content-Length` que ve `requestsize` MUST ser el del cuerpo real de la petición, no el del normalizado.

En `pre_request` las partes MUST ser las del mensaje enviado. En `pre_response` MUST ser:

- de una respuesta Message, sus partes;
- de una Task, las de `status.message`, las de cada `artifacts[*]` y las de cada mensaje de `history` con rol de agente.

#### Scenario: Mensaje con texto y fichero por URL

- GIVEN un `message/send` 0.3 con una parte `text` y una parte `file` con `uri`
- WHEN corre `pre_request`
- THEN el plugin ve dos partes: `{type: text}` y `{type: file, url}`

### Requirement: TrustGuard sobre A2A

`trustguard` MUST enviar el protocolo `a2a` y construir su carga desde el cuerpo normalizado:

- el texto de las partes `text`, más las partes `data` serializadas como JSON, como texto;
- las partes `file` con `url`, como adjuntos por URL;
- las partes `file` con `raw`, como adjuntos dentro del límite de tamaño que ya aplica, contando las omitidas como hoy.

Una llamada sin ninguna parte inspeccionable MUST contarse con el `skip_reason` que ya existe para ese caso, no pasar en silencio.

#### Scenario: Parte de datos

- GIVEN un mensaje con una parte `data` `{"iban": "ES91…"}`
- WHEN corre `trustguard` en `pre_request`
- THEN la carga de texto incluye ese JSON serializado

### Requirement: Bloqueo y máscara

Un bloqueo en `pre_request` MUST responder `-32090` sin llamar al agente. Un bloqueo en `pre_response` de una respuesta con buffer MUST responder `-32090` en lugar de la respuesta del agente.

Un veredicto de máscara MUST tratarse como bloqueo en A2A: `-32090`, y el motivo `mask_unsupported` en el span. El gateway no reescribe partes en este cambio, y entregar el contenido sin enmascarar filtraría justo lo que la policy quería ocultar.

#### Scenario: Máscara

- GIVEN `trustguard` en modo máscara y un mensaje con un número de tarjeta
- WHEN se llama a `message/send`
- THEN `-32090`, el agente no recibe nada y el span dice `mask_unsupported`

### Requirement: Inspección de streams evento a evento

En `message/stream`, `SendStreamingMessage`, `tasks/resubscribe` y `SubscribeToTask`, cada evento con contenido MUST pasar `pre_response` antes de reenviarse:

- un mensaje;
- una Task;
- un `status-update` o `statusUpdate` con mensaje;
- un `artifact-update` o `artifactUpdate`.

Los eventos sin contenido MUST reenviarse sin esperar.

Si un evento se bloquea, el gateway MUST:

1. enviar un evento de error JSON-RPC `-32090` en lugar del evento;
2. cerrar el stream con quien llama;
3. llamar a `tasks/cancel` o `CancelTask` contra el agente, sin esperar el resultado.

Los fragmentos de un artifact con `append` se inspeccionan uno a uno. Un contenido partido entre dos fragmentos puede no detectarse; es una limitación documentada de este cambio.

#### Scenario: Artifact bloqueado a mitad de stream

- GIVEN un stream cuyo tercer evento es un artifact que la policy bloquea
- WHEN el gateway lo inspecciona
- THEN quien llama recibe los dos primeros eventos y luego `-32090`, el stream se cierra y el agente recibe un `tasks/cancel` de esa tarea
