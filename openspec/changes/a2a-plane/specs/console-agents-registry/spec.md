# Delta para console-agents-registry

Cambio `a2a-plane`, repo `app`. Capability nueva: la pestaña **Agents** de la pantalla Registry, donde un admin registra agentes A2A, revisa su card y decide cómo se identifica el gateway ante ellos. Rutas bajo `app/[locale]/v2/features/registry` (abreviado `registry/`). Los contratos de API son los de `a2a-agent-registry`.

## ADDED Requirements

### Requirement: La pestaña Agents existe solo donde hay plano agent

`REGISTRY_TABS` MUST incluir la entrada `a2a` (tipo `A2A`, etiqueta *Agents*, acción *Add agent*, test id `REGISTRY_TEST_IDS.tabA2a`), detrás de las de modelos y MCP.

La pestaña MUST mostrarse solo cuando la conexión del gateway tiene host de agents (`console-agents-plane`). Si no, MUST NOT renderizarse, y `#registryTab=a2a` MUST caer en la pestaña por defecto.

Las filas MUST venir de `listRegistriesAction({type: 'A2A'})`, no del mock. `loadRegistryRowsForType` deja de usar `listRegistryMockAction` para A2A.

#### Scenario: Gateway sin plano agent

- GIVEN un gateway cuya conexión no tiene host de agents
- WHEN se abre Registry con `#registryTab=a2a`
- THEN se muestra la pestaña Models, y no hay pestaña Agents

#### Scenario: Gateway con agentes

- GIVEN un gateway con host de agents y dos registries A2A
- WHEN se abre la pestaña Agents
- THEN su etiqueta es "Agents (2)" y muestra dos cards con datos reales

### Requirement: Card de un agente en la cuadrícula

Cada registry A2A MUST mostrarse con `RegistryCard`, con:

- el icono del protocolo A2A (el mismo glifo `bot` que Topology);
- el nombre;
- la descripción del card fijado, o `card.descriptionA2a` si no tiene;
- el chip de estado (*Connected* si está habilitado, *Inactive* si no);
- la versión (`A2A 1.0` o `A2A 0.3`);
- el número de skills.

El botón MUST ser *Settings* y abrir el panel de detalle. Los filtros de la pestaña MUST ser solo de estado. El estado vacío MUST decir "No agents yet" y ofrecer *Add agent*.

#### Scenario: Pestaña vacía

- GIVEN un gateway con host de agents y ningún registry A2A
- WHEN se abre la pestaña Agents
- THEN se ve el estado vacío con el botón *Add agent*

### Requirement: Panel de alta en tres pasos

*Add agent* MUST abrir `AddAgentSidePanel` con tres vistas.

**1. URL**

- Un campo "Agent URL" con la ayuda "The agent's base URL or its agent card URL".
- *Continue* llama a `previewAgentCardAction`.
- Un error de la API se muestra con `formatAgentGatewayError`, nunca en crudo.

**2. Card**

- Muestra el card antes de guardar nada:
  - nombre y descripción;
  - proveedor (`provider.organization`) si existe;
  - la URL resuelta;
  - las versiones que ofrece;
  - las skills (nombre y descripción, como `SimpleList`);
  - qué autenticación pide el agente (`securitySchemes`, resumido en palabras).
- Con `versions: []` MUST decir que el agente no ofrece JSON-RPC 0.3 ni 1.0 y no dejar continuar.

**3. Settings**

- Nombre, precargado con el del card.
- Versión, preseleccionada con `default_version` y editable solo si hay dos.
- *How TrustGate signs in to this agent*, con estas opciones:

| Opción | `auth` enviado |
|---|---|
| No sign-in | `{mode: "none"}` |
| API key in a header | `{mode: "static", header, value}` |
| OAuth client credentials | Los campos de `client_credentials` del panel MCP |
| As the user, signed by TrustGate (recommended) | `{mode: "exchange", pattern: "delegation"}` |
| As the user, through your identity provider | `{mode: "exchange", pattern: "obo" \| "token_exchange", identity_id, scope}` |

- Las cabeceras estáticas y `allowed_methods` van en una sección *Advanced* cerrada por defecto.

*Pin and add* MUST llamar a `createA2aRegistryAction` con `card_url` igual a lo que escribió el admin y `protocol_version` igual a la seleccionada. Si va bien, MUST cerrar el panel, recargar la pestaña y abrir el detalle del agente nuevo. Si la API responde 422, MUST quedarse en el paso 3 con el error formateado.

#### Scenario: Alta por URL base

- GIVEN un agente en `https://travel.example.com` que ofrece 0.3 y 1.0
- WHEN el admin escribe esa URL, continúa, deja la versión 1.0 y "As the user, signed by TrustGate", y pulsa *Pin and add*
- THEN se crea el registry con `protocol_version: "1.0"` y `auth: {mode: "exchange", pattern: "delegation"}`, y se abre su detalle

#### Scenario: Card sin JSON-RPC

- GIVEN un card que solo ofrece gRPC
- WHEN el admin llega al paso 2
- THEN ve el aviso y el botón para continuar está deshabilitado

### Requirement: Panel de detalle de un agente

*Settings* sobre un agente MUST abrir `AgentDetailSidePanel` con estas secciones:

1. **Agent card:** el card fijado (versión, URL resuelta, fijado el `card_pinned_at`, skills) y el botón *Check for changes*.
2. **Sign-in:** las mismas opciones del paso 3 del alta. Los secretos guardados se muestran vacíos y se conservan si no se tocan.
3. **Verify TrustGate's token:** visible solo con `pattern: "delegation"`. Muestra la URL del JWKS, el `iss` y el `aud` que verá el agente, con botones de copiar y un snippet de verificación.
4. **Advanced:** cabeceras estáticas y `allowed_methods`.
5. **Pie:** *Disable* o *Enable*, *Delete* y *Save changes*.

*Save changes* MUST llamar a `updateA2aRegistryAction` sin `card_url` ni `protocol_version`, para no volver a fijar el card. Cambiar la URL del agente MUST hacerse con *Change URL*, que repite los pasos 1 y 2 del alta y guarda con la URL nueva.

#### Scenario: Cambiar solo el modo de identidad

- GIVEN un agente con `auth.mode: "none"`
- WHEN el admin elige "As the user, signed by TrustGate" y guarda
- THEN se envía `auth` y nada del card, y aparece la sección *Verify TrustGate's token*

### Requirement: Revisar un card que cambió

*Check for changes* MUST llamar a `refreshAgentCardAction`:

- Con `changed: false`, MUST mostrar "The agent's card has not changed since {fecha}".
- Con `changed: true`, MUST mostrar una lista en palabras (`agentCardDiff`):
  - skills añadidas y quitadas, por nombre;
  - "Endpoint changed" si cambian las interfaces o `url`;
  - "Security changed" si cambian `securitySchemes`, `security` o `securityRequirements`;
  - "Other details changed", con los nombres de los campos, para el resto.

  Debajo, la frase "Clients keep seeing the pinned card until you approve" y los botones *Keep current* y *Approve new card*.

*Approve new card* MUST llamar a `approveAgentCardAction` con `fetched_digest`. Un 409 MUST volver a pedir el refresh y mostrar el diff nuevo con el aviso "The agent changed its card again". Un 422 MUST mostrar que el card nuevo ya no ofrece la versión del agente.

#### Scenario: Aprobar una skill nueva

- GIVEN un agente que añadió la skill `Refund invoice`
- WHEN el admin pulsa *Check for changes* y luego *Approve new card*
- THEN el diff decía "Added skill: Refund invoice", y tras aprobar la sección *Agent card* muestra la skill y una fecha de fijado nueva

### Requirement: Server actions

Las escrituras y lecturas a TrustGate MUST ser server actions bajo `registry/actions/`, con `withTrustGateAuth` y `agentGatewayRequest`, devolviendo `ActionResult<T>`:

| Action | Llamada | Nivel |
|---|---|---|
| `previewAgentCardAction` | `POST /v1/gateways/{gw}/registries/preview-agent-card` | EDITOR |
| `createA2aRegistryAction` | `POST /v1/gateways/{gw}/registries` con `type: "A2A"` | EDITOR |
| `updateA2aRegistryAction` | `PUT /v1/gateways/{gw}/registries/{id}` | EDITOR |
| `refreshAgentCardAction` | `POST …/registries/{id}/agent-card/refresh` | EDITOR |
| `approveAgentCardAction` | `POST …/registries/{id}/agent-card/approve` | EDITOR |

`createA2aRegistryAction` y `approveAgentCardAction` MUST registrar un evento de auditoría v2 (`REGISTRY_CREATED` y uno nuevo, `AGENT_CARD_APPROVED`) y llamar a `revalidateRegistryPath(teamId)`.

#### Scenario: Error de TrustGate

- GIVEN TrustGate responde 422 "card offers ["0.3"]"
- WHEN `createA2aRegistryAction` lo recibe
- THEN devuelve `{success: false, error}` con ese mensaje, y el panel lo muestra formateado

### Requirement: Dónde vive el agente

El paso 1 de *Add agent* MUST empezar con *Where does this agent run?*, con cuatro opciones:

| Opción | `provider` | Campos |
|---|---|---|
| Any A2A URL | `generic` | "Agent URL", como hasta ahora |
| Amazon Bedrock AgentCore | `bedrock_agentcore` | "Agent runtime ARN" y "Endpoint qualifier" (por defecto `DEFAULT`) |
| Microsoft Foundry | `azure_foundry` | "Project endpoint" y "Agent name" |
| Google Vertex AI Agent Engine | `vertex_agent_engine` | "Project", "Location" y "Agent Engine ID" |

Los iconos MUST ser los de proveedor que ya usa Registry (`providerMapping`). La validación del ARN, el host de Foundry y los campos de Vertex MUST hacerse en el cliente con los mismos mensajes que la API.

Con un proveedor, el orden MUST ser **Location → Sign-in → Card → Settings**, porque los tres exigen credencial para leer el card. La vista previa MUST enviar la credencial que el admin acaba de escribir. Con *Any A2A URL* se mantiene **URL → Card → Settings**.

*Sign-in* MUST ofrecer solo los modos que el proveedor admite (`a2a-hosted-agents`):

| Proveedor | Opciones |
|---|---|
| AgentCore | "AWS IAM (SigV4)", con claves, rol o "Use the gateway's AWS identity"; "OAuth client credentials"; "As the user, through your identity provider" |
| Foundry | "Microsoft Entra ID", con service principal o "Use the gateway's managed identity"; "As the user, through Microsoft Entra (on-behalf-of)" |
| Vertex | "Google service account", con JSON (`GcpServiceAccountField`), "Impersonate a service account" o "Use the gateway's Google identity" |

Las opciones de usuario de AgentCore y Foundry MUST pedir también la credencial de aplicación con la que se lee el card (`card_auth`), con la ayuda "Used only to read the agent's card".

Los campos MUST reutilizar los componentes de Registry que ya existen:

- `GcpServiceAccountField`;
- `EntraOboAuthFields`;
- los campos de AWS y Azure del alta de proveedores LLM.

No se crean variantes nuevas.

En Foundry, el paso *Settings* MUST mostrar las dos versiones con 1.0 preseleccionada y la nota "0.3 is in preview on Foundry". En Vertex, la versión MUST mostrarse fija en 0.3.

#### Scenario: Agente de Foundry con managed identity

- GIVEN el admin elige Microsoft Foundry y escribe el endpoint del proyecto y el nombre del agente
- WHEN elige "Use the gateway's managed identity" y continúa
- THEN la vista previa se pide con `provider: "azure_foundry"` y `cloud_auth: {"azure": {"use_managed_identity": true}}`, y muestra el card de Foundry

#### Scenario: Opciones de Vertex

- WHEN el admin elige Google Vertex AI Agent Engine
- THEN *Sign-in* ofrece solo las tres variantes de cuenta de servicio de Google

### Requirement: El detalle muestra el proveedor

El detalle de un agente de proveedor MUST mostrar una sección **Location**, de solo lectura, con:

- el proveedor;
- los campos que lo localizan;
- el endpoint derivado.

*Change URL* MUST llamarse *Change location* y repetir Location, Sign-in y Card. El proveedor MUST NOT poder cambiarse: el panel sugiere crear otro agente.

La tarjeta de la cuadrícula MUST llevar el icono del proveedor junto al glifo de A2A. Los agentes de Foundry y Vertex MUST mostrar el chip *No streaming*.

En un agente genérico, *Advanced* MUST ofrecer "Send sign-in credentials when reading the card" (`card_auth: "same"`), desactivado por defecto.

#### Scenario: Agente de AgentCore en la cuadrícula

- GIVEN un registry `bedrock_agentcore`
- WHEN se abre la pestaña Agents
- THEN su tarjeta muestra el icono de AWS, "A2A 0.3" y su número de skills
