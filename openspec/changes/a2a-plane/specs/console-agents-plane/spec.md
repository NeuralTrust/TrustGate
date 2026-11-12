# Delta para console-agents-plane

Cambio `a2a-plane`, repo `app`. Capability nueva: **Agents** como tercer plano de una Application, junto a Models (LLM) y Tools (MCP). Sigue el modelo de `TrustGate/docs/applications-model.md`:

- nunca se pregunta "¿qué plano?";
- un plano nace al añadir lo primero;
- las keys de la Application llegan a todos sus planos.

Rutas bajo `app/[locale]/v2/features` (abreviado `F/`) y `app/[locale]/v2` (abreviado `V/`).

## ADDED Requirements

### Requirement: La conexión del gateway conoce el host de agents

`GatewayConnection` (`V/lib/gatewayConnection/types.ts`) MUST ganar `agentHost?: string | null` y `agentOrigin?: string | null`, opcionales para no romper a quien ya construye conexiones.

`resolveGatewayConnection` MUST rellenarlos:

- en SaaS, desde `hosts.agent` de `GET /v1/gateways/{id}`, que TrustGate solo devuelve cuando el entorno tiene `AGENT_BASE_DOMAIN`;
- en híbrido o dedicado, desde una columna nueva y nullable `TeamGateway.agentEndpoint` (migración de Prisma).

`gatewayPlaneOrigin`, `consumerBaseUrl` y `gatewayRootUrl` MUST aceptar el plano `'agent'`.

**Sin `agentHost`, la consola MUST NOT ofrecer nada de agentes:** ni la pestaña de Registry (`console-agents-registry`), ni la sección Agents de una Application.

#### Scenario: Gateway SaaS con plano agent

- GIVEN `GET /v1/gateways/{id}` devuelve `hosts: {proxy, mcp, agent: "gw-x.agents.neuraltrust.ai"}`
- WHEN se resuelve la conexión
- THEN `agentHost` es ese host, y `consumerBaseUrl(connection, 'agent', 'bot')` es `https://gw-x.agents.neuraltrust.ai/bot`

#### Scenario: Gateway híbrido sin endpoint de agents

- GIVEN un `TeamGateway` híbrido con `agentEndpoint` nulo
- WHEN se abre una Application
- THEN no hay sección Agents, y nada falla

### Requirement: A2A es un plano

`PLANES` (`F/applications/types.ts`) MUST ser `['MCP', 'LLM', 'A2A']`. Cada valor coincide con `PolicyProtocol`, del que depende `applicationPolicyScope`.

Todo `Record<Plane, …>` MUST tener entrada `A2A`, y todo literal de dos planos MUST pasar a recorrer `PLANES`. Eso incluye las líneas listadas en `design.md` (*app: every hard-coded plane*).

`planeOf` (`F/applications/lib/groupApplications.ts`) MUST conservar los consumers A2A, así que un consumer A2A creado por API aparece como una Application de uno. `consumerIdsOf` MUST incluir el consumer A2A. El nombre del consumer cuando hay dos o más planos MUST llevar el sufijo ` (Agents)` (`PLANE_NAME.A2A = 'Agents'`).

El orden visible de los planos MUST ser Models, Tools, Agents en General, Connect, la cabecera del panel y las keys.

#### Scenario: Consumer A2A suelto

- GIVEN un consumer A2A creado por la Admin API y sin Application guardada
- WHEN se abre la lista de Applications
- THEN aparece como una Application con el plano Agents

### Requirement: Sección Agents en General

General MUST mostrar una tercera `ApplicationPlaneRouting` con `plane="A2A"`, solo si hay `agentHost`.

- **Filas:** cada fila es un único selector de agente (registries con `type === 'A2A'`), con *Remove*. MUST NOT tener estrategia, modelo por defecto, selector de tools o modelos, ni pesos.
- **Estado vacío:** "This application calls no other agents through the gateway." con *Add agent*. Añadir la primera fila y guardar MUST crear el consumer A2A con `createConsumerAction({protocol: 'A2A', …})`, con los registries elegidos y sin `toolkit`, `model_policies`, `lb_config` ni `fallback`. `applyInlineRoutingToDraft` MUST producir para A2A solo `registries`.
- **Guardar:** al guardar la Application, sus keys MUST adjuntarse al consumer nuevo, igual que hoy con los otros planos.
- **Sin agentes registrados:** el selector MUST ofrecer un enlace a Registry → Agents.

#### Scenario: Primer agente

- GIVEN una Application con solo Models
- WHEN se añade "Travel planner" en Agents y se guarda
- THEN existe un consumer A2A con ese registry, agrupado en la Application, con las keys de la Application adjuntas

#### Scenario: Quitar el último agente

- GIVEN una Application con un agente
- WHEN se quita y se guarda
- THEN el consumer A2A sigue existiendo con cero registries, y la sección muestra el estado vacío

### Requirement: Connect para Agents

Connect MUST mostrar una sección Agents (`PLANE_PATH.A2A = '/agents'`) con:

- la URL base `consumerBaseUrl(connection, 'agent', slug) + '/agents'`;
- por cada agente del consumer: nombre, versión y la URL de su card en el gateway, `{base}/{registry_id}/.well-known/agent-card.json`, con *Copy*;
- snippets en un `TourCodeBlock` con pestañas cURL y Python.

| Pestaña | Contenido |
|---|---|
| cURL | Un `GET` del card con `X-AG-API-Key` y un `POST` de `message/send` (0.3) o `SendMessage` (1.0) según la versión del agente elegido |
| Python | a2a-sdk 1.x, resolviendo el card con la cabecera `X-AG-API-Key` y enviando un mensaje. El código exacto se fija contra el SDK en la implementación. |

Los snippets MUST usar `API_KEY_PLACEHOLDER`.

#### Scenario: Agente 0.3

- GIVEN una Application con un agente 0.3
- WHEN se abre Connect
- THEN el cURL usa `message/send` con partes `{"kind": "text"}`

### Requirement: Policies por protocolo del catálogo

`PLANE_PROTOCOL.A2A` MUST ser `'A2A'`, así que una policy cae en el consumer de agentes solo si el catálogo (`supported_protocols`) dice `A2A`.

`slugToProtocols` MUST devolver por defecto `['LLM', 'MCP']`, nunca `A2A`. Un slug que el catálogo no lista no se ofrece para agentes.

En la ficha de TrustGuard sobre una Application con Agents MUST aparecer la línea "On agents, masking blocks the call."

#### Scenario: Rate limit y token rate limit

- GIVEN una Application con Models y Agents, y el catálogo dice `ratelimit: [LLM, MCP, A2A]` y `tokenratelimit: [LLM]`
- WHEN se añaden las dos policies
- THEN `ratelimit` se adjunta a los dos consumers, y `tokenratelimit` solo al de Models

### Requirement: Keys, cabecera, analytics y topología

Las keys MUST mostrar el chip *Agents* (`planes.A2A`) cuando están adjuntas al consumer A2A. Extender y revocar MUST tenerlo en cuenta. `useApplicationAuthDraft` MUST caer en `consumers.A2A` cuando no hay MCP ni LLM.

La cabecera del panel MUST mostrar el badge del plano Agents. Los analytics de la Application MUST incluir el consumer A2A en `consumerIds`.

Topology MUST tratar A2A como plano (`TopologyPlane` incluye `'A2A'`) y dejar de descartar consumers A2A.

#### Scenario: Key de una Application con tres planos

- GIVEN una Application con Models, Tools y Agents
- WHEN se crea una key
- THEN la key queda adjunta a los tres consumers y muestra los tres chips

### Requirement: Un tono y filtros para A2A

A2A MUST tener un solo tono de badge, `lila`, en:

- policies (`policyProtocolBadgeTone`);
- requests (`requestKindBadgeTone`);
- Runtime Activity;
- `RegistryAccessTab`;
- el badge de protocolo de consumers;
- `PLANE_TONE`.

`GATEWAY_PROTOCOLS`, `KIND_FILTER_OPTIONS` (Requests, ENG-1203) y `PROTOCOL_FILTER_OPTIONS` (Runtime Activity, ENG-1347) MUST incluir A2A, y sus comentarios de exclusión MUST desaparecer.

#### Scenario: Filtrar requests de agentes

- GIVEN tráfico del plano agent
- WHEN se filtra Requests por *A2A*
- THEN se ven solo esas peticiones, con el badge lila

### Requirement: Copia y documentación

Todas las cadenas nuevas MUST ir en `messages/en` (`v2Registry.json`, `v2Applications.json`). `tabs.a2a` pasa a "Agents" y `actions.addA2a` a "Add agent". La palabra visible es *Agents*; "A2A" solo aparece como badge de protocolo y en la versión ("A2A 1.0").

Los componentes nuevos (`AddAgentSidePanel`, `AgentDetailSidePanel`, `AgentCardDiff`) MUST anotarse en `V/COMPONENTS.md`, y el plano y la pestaña en `docs/v2/SDD.md`.

#### Scenario: Copia del plano

- WHEN se abre una Application con Agents
- THEN la sección se llama "Agents" y en ningún sitio dice "A2A consumer"
