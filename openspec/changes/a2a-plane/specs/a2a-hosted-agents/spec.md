# Delta para a2a-hosted-agents

Cambio `a2a-plane`. Capability nueva: registrar agentes alojados en **Amazon Bedrock AgentCore Runtime**, **Microsoft Foundry Agent Service** y **Google Vertex AI Agent Engine** sin que el admin tenga que construir URLs ni firmar peticiones a mano.

Los tres hablan A2A de forma nativa (verificado en su documentación el 2026-11-11), así que esto **no es un puente de protocolo**: el gateway sigue reenviando A2A. Lo que cambia por proveedor es:

- cómo se localiza el agente;
- cómo se autentica el gateway ante él;
- unas pocas diferencias de transporte.

| | AgentCore Runtime | Foundry Agent Service | Vertex AI Agent Engine |
|---|---|---|---|
| Binding | JSON-RPC 2.0 | JSON-RPC (1.0 GA; 0.3 preview) | HTTP+JSON (REST) |
| Versión | La del contenedor (el ejemplo de AWS es 0.3) | 1.0 y 0.3 en la misma base | 0.3 (`a2a-sdk>=0.3.4`) |
| Card | `…/invocations/.well-known/agent-card.json?qualifier=` | `…/protocols/a2a/agentCard/v1.0` o `/v0.3` | `{base}/v1/card` (solo autenticado) |
| Card con credencial | Sí | Sí, siempre | Sí, siempre |
| Autenticación | SigV4, o Bearer de un JWT authorizer (Cognito, Okta, Entra…) | Solo Entra ID, scope `https://ai.azure.com/.default`, rol *Foundry Agent Consumer* | Token OAuth de Google, scope `cloud-platform` |
| Usuario final | Sí, si el authorizer confía en el IdP del usuario | Sí, OBO de Entra | No: el token es de una cuenta de servicio |
| Streaming | Sí (SSE) | No | No documentado |
| Particularidades | Cabecera de sesión; errores JSON-RPC con HTTP no 200 | Sin `A2A-Version` sirve 0.3; solo texto | Cuerpos de petición inconsistentes en la doc |

## ADDED Requirements

### Requirement: Proveedor de un registry A2A

`a2a_target` MUST aceptar `provider`, con uno de estos valores:

- `generic` (por defecto, el comportamiento de `a2a-agent-registry`);
- `bedrock_agentcore`;
- `azure_foundry`;
- `vertex_agent_engine`.

Con un proveedor distinto de `generic`:

- `card_url` y `url` MUST rechazarse con 422;
- el agente MUST localizarse con el objeto del proveedor:

| `provider` | Objeto | Campos |
|---|---|---|
| `bedrock_agentcore` | `bedrock_agentcore` | `runtime_arn` (`arn:aws:bedrock-agentcore:{region}:{account}:runtime/{id}`), `qualifier` (por defecto `DEFAULT`) |
| `azure_foundry` | `azure_foundry` | `project_endpoint` (`https://{account}.services.ai.azure.com/api/projects/{project}`), `agent_name` |
| `vertex_agent_engine` | `vertex_agent_engine` | `project`, `location`, `reasoning_engine_id` |

El gateway MUST derivar del objeto la URL del card y el endpoint. El endpoint derivado MUST tener prioridad sobre el `url` del card.

| `provider` | Card | Endpoint |
|---|---|---|
| `bedrock_agentcore` | `https://bedrock-agentcore.{region}.amazonaws.com/runtimes/{ARN escapado}/invocations/.well-known/agent-card.json?qualifier={q}` | `https://bedrock-agentcore.{region}.amazonaws.com/runtimes/{ARN escapado}/invocations/?qualifier={q}` |
| `azure_foundry` | `{project_endpoint}/agents/{agent_name}/endpoint/protocols/a2a/agentCard/v{versión}` | `{project_endpoint}/agents/{agent_name}/endpoint/protocols/a2a` |
| `vertex_agent_engine` | `{base}/v1/card` | `{base}`, con `base = https://{location}-aiplatform.googleapis.com/v1beta1/projects/{project}/locations/{location}/reasoningEngines/{id}/a2a` |

La forma exacta de `base` en Vertex MUST fijarse con una petición grabada contra un Agent Engine real antes de fusionar. La documentación da el resto de la ruta, pero no el host.

La región de AgentCore MUST salir del ARN. Un ARN de otro servicio o mal formado MUST responder 422.

`project_endpoint` MUST ser HTTPS con host bajo `.services.ai.azure.com`. Las nubes soberanas se añaden con `A2A_FOUNDRY_HOST_SUFFIXES`.

Un registry no puede cambiar de proveedor. El cambio MUST responder 422 y hay que crear otro registry.

#### Scenario: Alta de un agente de AgentCore

- WHEN se crea un registry A2A con `provider: "bedrock_agentcore"` y `runtime_arn: "arn:aws:bedrock-agentcore:eu-west-1:123456789012:runtime/travel-abc"`
- THEN el card se descarga de `https://bedrock-agentcore.eu-west-1.amazonaws.com/runtimes/arn%3Aaws%3Abedrock-agentcore%3Aeu-west-1%3A123456789012%3Aruntime%2Ftravel-abc/invocations/.well-known/agent-card.json?qualifier=DEFAULT`, y `endpoint` es la URL de invocación con el mismo qualifier

#### Scenario: Foundry con un host ajeno

- WHEN `project_endpoint` es `https://evil.example.com/api/projects/x`
- THEN 422 que dice que un agente de Foundry vive bajo `services.ai.azure.com`

#### Scenario: URL en un registry de proveedor

- WHEN se crea un registry `azure_foundry` con `card_url`
- THEN 422 que dice que un agente de Foundry se localiza por proyecto y nombre

### Requirement: Credenciales de nube

`auth.mode` MUST aceptar `cloud`, con `a2a_target.cloud_auth` en uno de estos tres formatos:

- `aws`: los mismos campos que `AWSAuth` de un registry LLM:
  - claves estáticas, con token de sesión opcional;
  - o `use_role` con `role` y, opcionalmente, `external_id`, que se pasa a `sts:AssumeRole`;
  - o ninguna de las dos, y entonces vale la credencial del pod (IRSA o Pod Identity).
- `azure`: los mismos campos que `AzureAuth`:
  - service principal (`tenant_id`, `client_id`, `client_secret`);
  - o `use_managed_identity` (managed identity o workload identity).
- `gcp`:
  - `service_account_json`;
  - o `impersonate_service_account` (email);
  - o ninguno, y entonces valen las Application Default Credentials del pod.

Qué modos admite cada proveedor:

| `provider` | Modos admitidos | Rechazados con 422 |
|---|---|---|
| `generic` | `none`, `static`, `client_credentials`, `exchange` (como hasta ahora) | `cloud` |
| `bedrock_agentcore` | `cloud` con `aws`; `client_credentials`; `exchange` con `obo` o `token_exchange` | `none`, `static`, `exchange/delegation`, `cloud` con `azure` o `gcp` |
| `azure_foundry` | `cloud` con `azure`; `exchange` con `obo` | `none`, `static`, `client_credentials`, `exchange` con `delegation` o `token_exchange`, `cloud` con `aws` o `gcp` |
| `vertex_agent_engine` | `cloud` con `gcp` | Todos los demás |

Los mensajes 422 MUST explicar el motivo:

- Foundry solo acepta tokens de Entra.
- Vertex solo acepta tokens de Google de una cuenta de servicio.
- AgentCore no puede validar todavía un token firmado por TrustGate (*Fuera de alcance*).

Cómo se autentica cada llamada:

| Proveedor y modo | Petición al agente |
|---|---|
| AgentCore, `cloud` | Firmada con SigV4, servicio `bedrock-agentcore` y la región del ARN, sobre el cuerpo exacto que se envía |
| AgentCore, `client_credentials` u `obo`/`token_exchange` | `Authorization: Bearer`, igual que en un agente genérico |
| Foundry, `cloud` | `Authorization: Bearer` de Entra con scope `https://ai.azure.com/.default`, en caché hasta 5 minutos antes de caducar |
| Foundry, `obo` | OBO de Entra con scope por defecto `https://ai.azure.com/.default` |
| Vertex, `cloud` | `Authorization: Bearer` de Google con scope `https://www.googleapis.com/auth/cloud-platform`, mediante `gcpauth` (cuenta de servicio, ADC o impersonación) |

`client_secret`, `secret_access_key`, `session_token` y `service_account_json` MUST cifrarse en reposo y enmascararse en las respuestas, igual que en un registry LLM.

Una credencial de nube MUST enviarse solo al host derivado del proveedor y solo por HTTPS.

#### Scenario: Foundry con clave estática

- WHEN se crea un registry `azure_foundry` con `auth: {"mode": "static", …}`
- THEN 422 que dice que Foundry solo acepta Microsoft Entra ID

#### Scenario: Foundry en nombre del usuario

- GIVEN un registry `azure_foundry` con `auth: {"mode": "exchange", "pattern": "obo", "identity_id": "<entra>"}`
- AND una llamada de un usuario autenticado por ese IdP de Entra
- WHEN el gateway llama al agente
- THEN envía un token OBO de ese usuario con audiencia `https://ai.azure.com`

En el SaaS, un rol asumido sin `external_id` MUST rechazarse con 422. Sin él, quien conozca el ARN del rol de otra organización podría hacer que el gateway lo asumiera (*confused deputy*). En híbrido y dedicado es opcional.

#### Scenario: Rol sin external id en SaaS

- GIVEN un gateway SaaS
- WHEN se crea un registry `bedrock_agentcore` con `use_role: true` y sin `external_id`
- THEN 422 que pide el external id configurado en la trust policy del rol

#### Scenario: AgentCore con el rol del pod

- GIVEN un registry `bedrock_agentcore` con `cloud_auth: {"aws": {"use_role": true, "role": "arn:aws:iam::123456789012:role/tg-agents", "external_id": "nt-7f3a"}}`
- WHEN el gateway llama al agente
- THEN la petición va firmada con SigV4 con credenciales obtenidas al asumir ese rol con ese external id

### Requirement: El card se descarga con credenciales

Con un proveedor distinto de `generic`, el alta, la vista previa, el refresh y el approve MUST descargar el card con la credencial del registry, firmada o como Bearer según el modo. Los tres proveedores exigen credencial para leer el card.

Con `exchange` (`obo` o `token_exchange`) no hay usuario en el alta. Para leer el card, el registry MUST tener una credencial de aplicación:

- en AgentCore, `card_auth: "client_credentials"` con sus campos;
- en Foundry, `card_auth: "cloud"` con `cloud_auth.azure`.

Si falta, MUST responder 422.

`preview-agent-card` MUST aceptar en el cuerpo:

- `provider`;
- el objeto del proveedor;
- `auth`;
- `cloud_auth`.

Como hasta ahora, no escribe nada. Las credenciales recibidas MUST usarse solo para esa descarga y MUST NOT registrarse en logs.

En un registry `generic`, `card_auth: "same"` MUST enviar la credencial del registry también al descargar el card, solo si el host del card es el del endpoint y solo por HTTPS. Por defecto la descarga es anónima, como hasta ahora.

#### Scenario: Card de Foundry sin credencial

- WHEN se pide la vista previa de un agente de Foundry sin `cloud_auth`
- THEN 422 que dice que Foundry exige Entra ID incluso para leer el card

#### Scenario: Card genérico protegido

- GIVEN un agente genérico cuyo card responde 401 sin credencial
- WHEN se crea con `auth: {"mode": "static", …}` y `card_auth: "same"`
- THEN el card se descarga con esa cabecera y el registry se crea

### Requirement: Versión con Foundry

En `azure_foundry`, `DetectVersions` MUST tratar como ofrecidas las dos versiones que Foundry sirve, `1.0` y `0.3`. La versión por defecto MUST ser `1.0`.

Cada llamada MUST llevar `A2A-Version` igual a la versión fijada, también con 0.3: sin la cabecera, Foundry sirve 0.3.

El card MUST descargarse de la ruta de la versión fijada.

#### Scenario: Agente de Foundry en 1.0

- GIVEN un registry `azure_foundry` fijado en 1.0
- WHEN un cliente llama a `SendMessage`
- THEN la petición a Foundry lleva `A2A-Version: 1.0`

### Requirement: Sesión de AgentCore

En `bedrock_agentcore`, cada llamada MUST llevar `X-Amzn-Bedrock-AgentCore-Runtime-Session-Id`, para que los mensajes de un mismo contexto A2A lleguen a la misma sesión del runtime:

- Si la llamada nombra un `contextId` que el gateway ya conoce, MUST usar la sesión guardada con la propiedad de ese contexto (`a2a-task-ownership`).
- Si no, MUST generar una sesión nueva de al menos 33 caracteres. Cuando la respuesta trae el `contextId`, MUST guardarla con la propiedad de ese contexto.

La sesión MUST NOT venir de quien llama: un cliente no puede elegir la sesión de otro.

#### Scenario: Segundo mensaje del mismo contexto

- GIVEN un primer `message/send` cuya respuesta trajo `contextId: "c-1"`
- WHEN el mismo cliente envía otro mensaje con `contextId: "c-1"`
- THEN la petición a AgentCore lleva el mismo session id que la primera

### Requirement: Errores de AgentCore

AgentCore devuelve errores JSON-RPC con el código HTTP real (403, 404, 409, 424, 429…), no con 200. Con este proveedor, el gateway:

- MUST leer el cuerpo JSON-RPC aunque el HTTP no sea 2xx, y pasar al cliente el `error` del agente con HTTP 200;
- MUST tratar un 401 con `WWW-Authenticate` como fallo de identidad (`-32093`);
- MUST tratar un 403 sin cuerpo JSON-RPC (SigV4 denegado) como `-32092` con motivo `upstream_auth_failed`;
- ante `-32054` con el mensaje `Session operation in progress, please retry`, MUST reintentar una llamada no-stream hasta 2 veces con espera exponencial (100 ms y 400 ms) antes de responder. AgentCore no la procesó, así que el reintento no duplica trabajo.

#### Scenario: Sesión ocupada

- GIVEN AgentCore responde 409 con `-32054` una vez y después 200
- WHEN un cliente llama a `message/send`
- THEN el cliente recibe la respuesta del segundo intento

### Requirement: Vertex por HTTP+JSON

Un registry `vertex_agent_engine` MUST fijarse en la versión 0.3. Quien llama MUST seguir hablando JSON-RPC 0.3 con el gateway, que traduce el binding hacia Vertex:

| Método JSON-RPC (cliente) | Petición a Vertex |
|---|---|
| `message/send` | `POST {base}/v1/message:send`, cuerpo `params` |
| `tasks/get` | `GET {base}/v1/tasks/{id}` (`historyLength` como query) |
| `tasks/cancel` | `POST {base}/v1/tasks/{id}:cancel` |
| `message/stream`, `tasks/resubscribe` | Rechazados con `UnsupportedOperationError` (`-32004`) |

Esto traduce el binding, no la versión: los objetos `Message` y `Task` son los mismos de 0.3. Q2 sigue en pie.

La respuesta 2xx MUST envolverse como `result`. Los errores HTTP MUST traducirse así:

| HTTP de Vertex | Error al cliente |
|---|---|
| 400 | `-32602` |
| 401 | `-32093` |
| 403 | `-32092` `upstream_auth_failed` |
| 404 en una tarea | `TaskNotFoundError` (`-32001`) |
| 429 y 5xx | `-32092` |

El card servido a quien llama MUST anunciar JSON-RPC (`preferredTransport: "JSONRPC"`) en la URL del gateway, y sin `additionalInterfaces`.

#### Scenario: Pedir una tarea a Vertex

- GIVEN un registry `vertex_agent_engine` y una tarea `t-1` del cliente
- WHEN el cliente llama a `tasks/get` con `id: "t-1"`
- THEN el gateway hace `GET {base}/v1/tasks/t-1` y responde la tarea como `result` JSON-RPC

#### Scenario: Stream contra Vertex

- WHEN un cliente llama a `message/stream` contra un agente de Vertex
- THEN recibe `-32004` sin que el gateway llame a Vertex

### Requirement: Streaming según el card

En cualquier proveedor, si el card fijado dice `capabilities.streaming: false` o no lo dice, los métodos de stream y de suscripción MUST responder `UnsupportedOperationError` sin llamar al agente. Foundry y Vertex caen en este caso.

#### Scenario: Stream contra Foundry

- GIVEN un agente de Foundry cuyo card dice `streaming: false`
- WHEN un cliente llama a `SendStreamingMessage`
- THEN recibe `UnsupportedOperationError`

### Requirement: Traza y respuesta del registry

El span `a2a` MUST llevar `a2a.provider` y, para nubes, el modo de credencial (`aws_sigv4`, `azure_entra`, `gcp_oauth`), nunca el secreto.

`RegistryResponse.a2a_target` MUST devolver:

- `provider`;
- el objeto del proveedor;
- `cloud_auth` enmascarado;
- `endpoint` derivado.

#### Scenario: Respuesta de un agente de Vertex

- WHEN se lee un registry `vertex_agent_engine` con cuenta de servicio
- THEN `cloud_auth.gcp.service_account_json` viene enmascarado y `endpoint` es la base derivada
