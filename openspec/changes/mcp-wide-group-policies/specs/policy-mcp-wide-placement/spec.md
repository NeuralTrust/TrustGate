# Delta para policy-mcp-wide-placement

Cambio `mcp-wide-group-policies` (RUN-1746). Capability nueva: la tercera ubicación de una policy, junto a `global` y los enlaces a consumers. Una policy MCP-wide corre en todos los consumers MCP del gateway y en el Store, acotada por su `mcp_scope`, y nunca en un plano LLM o A2A. Cubre los endpoints, el intercambio con `global`, la respuesta, el estado de plugin y los límites conocidos. Dónde entra en la carga lo fijan `policy-inert-scope` y `mcp-policy-plan-selection`; qué nivel ocupa, `policy-level-uniqueness`.

## ADDED Requirements

### Requirement: Endpoints de la ubicación MCP-wide

La Admin API MUST exponer `POST` y `DELETE /v1/gateways/{gateway_id}/policies/{id}/mcp-wide`, con la misma forma que `/global`: sin cuerpo, `200` con la policy. Una policy de otro gateway MUST responder 404. La bandera MUST guardarse en `policies.mcp_wide`, y viajar en el JSON de dominio del snapshot (`mcp_wide`, omitida cuando es `false`), sin cambiar el proto.

`POST` MUST pasar por el `LevelGuard` (409 `already runs plugin … at level …`, texto sin cambios) y MUST devolver 422 cuando el plugin no soporta MCP (`mcp-policy-scope`). Si la policy cambió entre la lectura y la escritura, MUST devolver 409 `ErrPlacementChanged` sin escribir nada. Promover una policy que ya es MCP-wide MUST ser un no-op con 200.

#### Scenario: Promoción

- GIVEN una policy `tool_allowlist` con `mcp_scope: {groups: [Finanzas]}`, sin consumers
- WHEN se llama a `POST .../mcp-wide`
- THEN 200 con `mcp_wide: true` y `global: false`, y `GET` devuelve lo mismo

#### Scenario: Policy de otro gateway

- GIVEN una policy del gateway A
- WHEN se llama a `POST /v1/gateways/B/policies/{id}/mcp-wide`
- THEN 404, y la policy no cambia

### Requirement: `global` y `mcp_wide` son excluyentes

Una policy MUST NOT ser `global` y `mcp_wide` a la vez. `POST .../mcp-wide` MUST poner `global` a `false` en la misma escritura, y `POST .../global` MUST poner `mcp_wide` a `false` en la misma escritura. El intercambio MUST pasar por el guard una sola vez y MUST NOT chocar con la propia policy. La base de datos MUST respaldarlo con un CHECK, y `Policy.Validate()` MUST rechazar las dos banderas juntas con `ErrInvalidPlacement`.

#### Scenario: De global a MCP-wide y vuelta

- GIVEN una policy `global: true`
- WHEN se llama a `POST .../mcp-wide` y después a `POST .../global`
- THEN tras la primera llamada es `mcp_wide: true, global: false`, y tras la segunda `global: true, mcp_wide: false`

### Requirement: `DELETE` quita solo su bandera y es idempotente

`DELETE .../mcp-wide` MUST poner `mcp_wide` a `false` y no tocar nada más. Sobre una policy que no es MCP-wide MUST responder 200 sin cambios, sea o no global. MUST NOT pasar por el guard, y MUST NOT responder nunca 409 ni 422: quitar una ubicación solo libera niveles. `DELETE .../global` sobre una policy MCP-wide MUST responder 200 y dejarla con `mcp_wide: true`.

#### Scenario: Doble `DELETE`

- GIVEN una policy MCP-wide
- WHEN se llama dos veces a `DELETE .../mcp-wide`
- THEN las dos responden 200 con `mcp_wide: false`

#### Scenario: `DELETE /global` sobre una MCP-wide

- GIVEN una policy MCP-wide
- WHEN se llama a `DELETE .../global`
- THEN 200, y sigue con `mcp_wide: true` y `global: false`

### Requirement: La respuesta lleva siempre `mcp_wide`

`PolicyResponse` MUST llevar `mcp_wide` siempre, también cuando es `false`, igual que `global`, en create, get, list, update, duplicate y en los dos verbos de `/global` y `/mcp-wide`. Una policy MCP-wide MUST responder `global: false`. `POST .../mcp-wide` MAY llevar `warnings` no bloqueantes; `DELETE` MUST NOT llevarlos. Una policy MCP-wide MUST NOT recibir el aviso de borrador (`mcp-policy-scope`).

#### Scenario: Borrador recién creado

- GIVEN una policy recién creada
- WHEN se lee
- THEN la respuesta lleva `global: false` y `mcp_wide: false`

### Requirement: Dónde corre una policy MCP-wide

Una policy MCP-wide MUST correr en todos los consumers MCP del gateway, también en los creados después de la promoción, y en `data.StoreConsumer`, acotada por su `mcp_scope`. Un `mcp_scope` nulo MUST significar todos los callers MCP. MUST NOT correr en un consumer LLM o A2A (`policy-inert-scope`). Sus enlaces a consumers MUST ignorarse en la carga y en la ocupación, como los de una global; el attach MUST NOT rechazarse por eso. Una policy sin scope adjunta a un consumer MUST anular, en ese consumer, a una MCP-wide sin scope del mismo slug, como anula a una global.

Un duplicado de una policy MCP-wide MUST nacer borrador: copia el scope, no la ubicación.

#### Scenario: Miembro y no miembro

- GIVEN una `tool_allowlist` `deny_tools: ["*"]` con `mcp_scope: {groups: [Finanzas]}`, promovida a MCP-wide, y un consumer MCP con auth OAuth
- WHEN llama a una tool un miembro de Finanzas y luego uno de Marketing
- THEN el primero recibe `-32001` sin llegar al upstream y el segundo recibe la respuesta del upstream

#### Scenario: Antes de la promoción no corre

- GIVEN la misma policy creada y no promovida
- WHEN llama un miembro de Finanzas
- THEN recibe la respuesta del upstream: es un borrador

#### Scenario: Consumer creado después

- GIVEN la policy ya promovida
- WHEN se crea otro consumer MCP del gateway y llama un miembro de Finanzas
- THEN recibe `-32001`

### Requirement: El estado de plugin de una MCP-wide es del gateway

El estado de plugin de una policy MCP-wide MUST particionarse por gateway, como el de una global (`RuntimeScope.Global = true`, vía `GatewayWide()`): un único presupuesto para todos los consumers MCP y el Store. Ese estado MUST reportar la dimensión `global`, como una global: `exceeded_type: global` y la etiqueta `global` en la clave de Redis (`ratelimit:<policy>:global:<gateway>`).

#### Scenario: Un presupuesto compartido

- GIVEN un `rate_limiter` `limit: 1` MCP-wide y dos consumers MCP del gateway
- WHEN cada consumer hace una llamada
- THEN la segunda llamada, en el otro consumer, ya excede el límite, con `exceeded_type: global`

### Requirement: Límites conocidos, documentados y sin cambio de comportamiento

Estos dos huecos MUST quedar documentados en `docs/mcp-policy-scope.md` y MUST NOT cambiarse en este cambio:

- Un caller por api-key de un consumer MCP normal MUST seguir saltándose la comprobación de grupo, como para cualquier scope por grupos (RUN-1621). El Store no admite api-keys.
- Una policy del mismo plugin y los mismos grupos adjunta a un consumer MCP ocupa el nivel de ese consumer, no el de consumer `∅`, así que el guard la deja pasar y las dos corren en ese consumer. Es el mismo hueco que hoy tiene `global` con grupos, y ningún warning lo avisa.

#### Scenario: Api-key en un consumer MCP

- GIVEN una policy MCP-wide con `mcp_scope: {groups: [Finanzas]}` y un consumer MCP que admite api-key
- WHEN llama un caller con api-key
- THEN la policy corre para él: el grupo es inerte para una api-key

### Requirement: Compatibilidad hacia atrás y rollback

Un binario que no conoce `mcp_wide`, antiguo o tras un rollback, MUST ubicar la policy solo por sus enlaces: sin enlaces es un borrador y no corre en ningún sitio; con enlaces corre en esos consumers, como antes de la promoción. La migración de bajada MUST eliminar el CHECK y la columna. Un admin antiguo sobre el esquema migrado responde 500 a `POST /global` sobre una fila MCP-wide, porque el CHECK la rechaza; el rollback MUST ir precedido de la migración de bajada o de un `DELETE .../mcp-wide` de esas filas.

#### Scenario: Data plane antiguo

- GIVEN una policy MCP-wide sin enlaces y un data plane que no conoce `mcp_wide`
- WHEN carga el gateway
- THEN la policy no corre en ningún consumer
