# Delta para policy-mcp-wide-placement

Cambio `mcp-wide-group-policies` (RUN-1746). Capability nueva: la tercera ubicación de una policy, junto a `global` y los enlaces a consumers. Una policy MCP-wide corre en todos los consumers MCP del gateway y en el Store, acotada por su `mcp_scope`, y nunca en un plano LLM o A2A. Cubre los endpoints, el intercambio con `global`, la respuesta, los enlaces que una MCP-wide no puede tener, el estado de plugin y los límites conocidos. Dónde entra en la carga lo fijan `policy-inert-scope` y `mcp-policy-plan-selection`; qué nivel ocupa, `policy-level-uniqueness`.

## ADDED Requirements

### Requirement: Endpoints de la ubicación MCP-wide

La Admin API MUST exponer `POST` y `DELETE /v1/gateways/{gateway_id}/policies/{id}/mcp-wide`, con la misma forma que `/global`: sin cuerpo, `200` con la policy. Una policy de otro gateway MUST responder 404. La bandera MUST guardarse en `policies.mcp_wide`, y viajar en el JSON de dominio del snapshot (`mcp_wide`, omitida cuando es `false`), sin cambiar el proto.

`POST` MUST pasar por el `LevelGuard` (409 `already runs plugin … at level …`, texto sin cambios) y MUST devolver 422 cuando el plugin no soporta MCP (`mcp-policy-scope`). Si la policy cambió entre la lectura y la escritura, MUST devolver 409 `ErrPlacementChanged` sin escribir nada, salvo que la fila releída ya sea MCP-wide: entonces MUST responder 200 con esa fila, como un no-op (`policy-level-uniqueness`). Promover una policy que ya es MCP-wide MUST ser un no-op con 200, así que un reintento de la misma promoción MUST responder siempre 200.

#### Scenario: Promoción

- GIVEN una policy `tool_allowlist` con `mcp_scope: {groups: [Finanzas]}`, sin consumers
- WHEN se llama a `POST .../mcp-wide`
- THEN 200 con `mcp_wide: true` y `global: false`, y `GET` devuelve lo mismo

#### Scenario: Reintento de una promoción que ya entró

- GIVEN dos `POST .../mcp-wide` sobre la misma policy, decididos sobre la misma lectura
- WHEN el primero aterriza antes de que escriba el segundo
- THEN los dos responden 200 con `mcp_wide: true`, y el segundo no escribe nada

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

### Requirement: Una policy MCP-wide no tiene enlaces a consumers

`POST .../mcp-wide` MUST borrar las filas `consumer_policy` de la policy en la misma transacción que pone el flag, y la respuesta y la copia en caché MUST NOT llevar `consumer_ids`. Una promoción rechazada (409 o 422) MUST NOT borrar ninguna. `POST .../global` MUST conservar los enlaces, como hasta ahora.

Mientras la policy sea MCP-wide, `POST .../consumers/{id}/policies/{policy_id}` MUST responder **422** `validation_failed` (`consumer: policy is MCP-wide: it already runs on every MCP consumer; demote it before attaching a consumer`) sin escribir el enlace, sea cual sea el tipo del consumer: el enlace no cambiaría nada en la carga y la consola mostraría el consumer como cubierto por él. El rechazo MUST decidirse sobre la fila tal como está al escribir el enlace (`FOR SHARE`), no solo sobre la lectura previa, para que un attach y una promoción concurrentes nunca dejen un enlace en una policy MCP-wide. El attach MUST bloquear antes la fila del consumer (`FOR KEY SHARE`) que la de la policy, el mismo orden que un borrado de registry, para no entrar en deadlock con él. Una global MUST seguir admitiendo attach.

`DELETE .../mcp-wide` deja la policy sin enlaces que revivir: queda en borrador, y MUST NOT correr en ningún sitio hasta que se le adjunte un consumer o se promueva de nuevo.

#### Scenario: Promoción de una policy enlazada

- GIVEN una policy adjunta a los consumers MCP X e Y
- WHEN se llama a `POST .../mcp-wide`
- THEN la respuesta no lleva `consumer_ids`, `GET` tampoco, y `consumer_policy` no tiene filas de la policy

#### Scenario: Attach a una policy MCP-wide

- GIVEN una policy MCP-wide y un consumer MCP X del mismo gateway
- WHEN se llama a `POST .../consumers/X/policies/{id}`
- THEN 422 `validation_failed` con `policy is MCP-wide`, y la policy sigue sin enlaces

#### Scenario: Attach y promoción concurrentes

- GIVEN un attach de X a una policy y su promoción a MCP-wide, en curso a la vez
- WHEN los dos confirman, en cualquier orden
- THEN la policy queda MCP-wide y sin enlaces: si la promoción va primero el attach responde 422, y si va después borra el enlace

#### Scenario: La degradación no revive nada

- GIVEN una policy que tenía enlaces antes de promoverse a MCP-wide
- WHEN se llama a `DELETE .../mcp-wide`
- THEN queda en borrador, sin enlaces, y no corre en ningún consumer

### Requirement: La respuesta lleva siempre `mcp_wide`

`PolicyResponse` MUST llevar `mcp_wide` siempre, también cuando es `false`, igual que `global`, en create, get, list, update, duplicate y en los dos verbos de `/global` y `/mcp-wide`. Una policy MCP-wide MUST responder `global: false`. `POST .../mcp-wide` MAY llevar `warnings` no bloqueantes; `DELETE` MUST NOT llevarlos. Una policy MCP-wide MUST NOT recibir el aviso de borrador (`mcp-policy-scope`).

#### Scenario: Borrador recién creado

- GIVEN una policy recién creada
- WHEN se lee
- THEN la respuesta lleva `global: false` y `mcp_wide: false`

### Requirement: Dónde corre una policy MCP-wide

Una policy MCP-wide MUST correr en todos los consumers MCP del gateway, también en los creados después de la promoción, y en `data.StoreConsumer`, acotada por su `mcp_scope`. Un `mcp_scope` nulo MUST significar todos los callers MCP. MUST NOT correr en un consumer LLM o A2A (`policy-inert-scope`). No tiene enlaces (ver arriba); si una fila MCP-wide los tuviera, escritos por un binario anterior a este cambio, la carga y la ocupación MUST ignorarlos, como los de una global. Una policy sin scope adjunta a un consumer MUST anular, en ese consumer, a una MCP-wide sin scope del mismo slug, como anula a una global.

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

Un binario que no conoce `mcp_wide`, antiguo o tras un rollback, MUST ubicar la policy solo por sus enlaces. Como una policy MCP-wide no tiene enlaces, allí es un borrador y no corre en ningún sitio. Eso solo es fail-closed en un sentido: la policy nunca corre más allá de sus grupos, pero mientras corra el binario antiguo no aplica nada, tampoco a sus grupos. Degradada o no, no vuelve a proteger hasta que sea MCP-wide en la versión nueva.

Todos los planos (admin, proxy y MCP, que sirve también el Store) MUST correr la versión nueva antes de desplegar la consola que promueve a MCP-wide.

No hay runner de migraciones de bajada: las migraciones solo suben, al arrancar. Un rollback de binario deja la columna, el CHECK y los flags tal cual. Por eso, antes de un rollback MUST degradarse por la API cada fila MCP-wide (`DELETE /v1/gateways/{gateway_id}/policies/{id}/mcp-wide`), después de listarlas con:

```sql
SELECT p.id, p.gateway_id, p.slug, p.name
  FROM policies p
 WHERE p.mcp_wide
 ORDER BY p.gateway_id, p.id;
```

Sin esa degradación:

- el admin antiguo responde 500 a `POST /global` sobre una fila MCP-wide, porque el CHECK la rechaza;
- el admin antiguo no rechaza el attach, así que puede dejarle enlaces;
- al volver a la versión nueva, la fila vuelve a correr MCP-wide en todos los consumers MCP y en el Store, con el scope que le dejara el binario antiguo.

Tras volver a la versión nueva, los enlaces que el admin antiguo añadiera a una fila MCP-wide rompen la regla de que no tiene ninguno. MUST listarse:

```sql
SELECT p.gateway_id, p.id AS policy_id, cp.consumer_id
  FROM policies p
  JOIN consumer_policy cp ON cp.policy_id = p.id
 WHERE p.mcp_wide
 ORDER BY p.gateway_id, p.id, cp.consumer_id;
```

y MUST quitarse, uno a uno con `DELETE /v1/gateways/{gateway_id}/consumers/{consumer_id}/policies/{policy_id}`, o con `DELETE` y después `POST .../policies/{id}/mcp-wide` sobre la policy, cuya promoción los borra todos (pasa otra vez por el guard, así que puede responder 409). Después se vuelven a promover las filas degradadas antes del rollback.

#### Scenario: Data plane antiguo

- GIVEN una policy MCP-wide, que no tiene enlaces, y un data plane que no conoce `mcp_wide`
- WHEN carga el gateway
- THEN la policy no corre en ningún consumer

#### Scenario: Vuelta a la versión nueva sin degradar

- GIVEN una policy MCP-wide que no se degradó antes de un rollback
- WHEN el admin y el plano MCP vuelven a la versión nueva
- THEN la policy corre otra vez en todos los consumers MCP y en el Store, sin que nadie la haya vuelto a promover
