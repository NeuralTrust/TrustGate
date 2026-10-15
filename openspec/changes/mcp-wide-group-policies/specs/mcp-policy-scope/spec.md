# Delta para mcp-policy-scope

Cambio `mcp-wide-group-policies` (RUN-1746). El aviso de policy huérfana pasa a aplicarse solo a los borradores: una policy MCP-wide sin consumers corre en todo el plano MCP y no lo recibe. La promoción a `mcp_wide` entra en la regla del 409, responde 422 cuando el plugin no soporta MCP y borra los enlaces de la policy; el attach de una policy MCP-wide responde 422.

## MODIFIED Requirements

### Requirement: Validación en la Admin API

Create/update MUST rechazar con 4xx: registries de otro gateway o no MCP; `tool` o `groups` vacíos o duplicados; `users` o `except_users` presentes; scope sin entradas; un registry a la vez en `registry_ids` y `tools`. En update, `mcp_scope` omitido MUST conservar el valor y `null` MUST eliminarlo. El listado MUST aceptar `registry_id`. La respuesta MAY incluir `warnings` no bloqueantes.

Create, update, attach y promoción a `global` o a `mcp_wide` (`POST .../global`, `POST .../mcp-wide`) MUST devolver además **409** cuando la escritura ocuparía un nivel que otra policy habilitada del mismo plugin ya ocupa (`policy-level-uniqueness`). 409 y 422 MUST NOT confundirse: el 422 dice que la petición está mal formada o que la dimensión no cruza de plano; el 409 dice que la petición está bien y el estado la rechaza.

`POST .../mcp-wide` MUST devolver **422** cuando el plugin de la policy no declara el protocolo MCP (`SupportedProtocols`), sin escribir nada: una policy MCP-wide de ese plugin no correría en ningún sitio. Un slug que el registro de plugins no conoce MUST NOT dar ese 422: no es una cuestión de protocolo. Un `PUT` que cambia el slug de una policy MCP-wide a un plugin sin MCP MUST recibir el mismo 422.

`POST .../mcp-wide` MUST borrar los enlaces de la policy a consumers en la misma transacción, y el attach de un consumer a una policy MCP-wide MUST devolver **422** `validation_failed` sin escribir el enlace (`policy-mcp-wide-placement`): el enlace no cambiaría dónde corre y haría pasar el consumer por cubierto. Una global MUST seguir admitiendo attach.

Los `warnings` MUST cubrir además: una policy dormida (`policy has an empty mcp_scope and runs nowhere; set mcp_scope to null to run it everywhere`), un borrador (`policy has no consumers and is not global: it runs nowhere`) y la coalescencia del plano inerte. Un borrador es una policy que no es global, ni MCP-wide, ni está adjunta a ningún consumer (`Policy.Draft()`). El texto del aviso MUST NOT cambiar, y una policy MCP-wide MUST NOT recibirlo, tenga o no consumers. Ningún warning MUST seguir afirmando que un scope no alcanza a un consumer no-MCP: eso ya solo es cierto para la dimensión de destino.

#### Scenario: Registry de otro gateway

- GIVEN un `registry_id` de otro gateway
- WHEN se crea la policy
- THEN 4xx

#### Scenario: Registry en ambas listas

- GIVEN `registry_ids: [snowflake]` y `tools: [{snowflake, run_query}]`
- WHEN se crea la policy
- THEN 4xx

#### Scenario: Update omitido frente a `null`

- GIVEN una policy con scope
- WHEN se actualiza sin `mcp_scope`
- THEN el scope se conserva; con `"mcp_scope": null` se elimina

#### Scenario: Filtro y aviso

- GIVEN el consumer X con `trustguard` sin scope
- WHEN se crea una `trustguard` global con scope
- THEN 2xx con `warnings` mencionando a X, y `GET ?registry_id=` la devuelve

#### Scenario: Nivel ya ocupado

- GIVEN una `trustguard` habilitada con `registry_ids: [snowflake]` en el consumer X
- WHEN se crea otra `trustguard` con `registry_ids: [snowflake, jira]` en el mismo consumer
- THEN 409 `"error": "conflict"`, porque los dos niveles se solapan en `snowflake`

#### Scenario: Policy dormida

- GIVEN una policy cuyo scope quedó en `{}` tras un prune
- WHEN se lee o se actualiza
- THEN la respuesta lleva el warning de que no corre en ningún sitio y cómo revivirla

#### Scenario: Borrador

- GIVEN una policy con `global: false`, `mcp_wide: false` y ningún consumer
- WHEN se crea o se actualiza
- THEN la respuesta lleva `policy has no consumers and is not global: it runs nowhere`

#### Scenario: MCP-wide de un plugin sin MCP

- GIVEN una policy `model_allowlist`, que solo soporta LLM
- WHEN se llama a `POST .../mcp-wide`
- THEN 422 `"error": "validation_failed"`, y la policy sigue con `mcp_wide: false`

#### Scenario: Attach a una MCP-wide

- GIVEN una policy con `mcp_wide: true` y un consumer MCP del mismo gateway
- WHEN se adjunta la policy al consumer
- THEN 422 `"error": "validation_failed"` con `policy is MCP-wide`, y la policy sigue sin `consumer_ids`

#### Scenario: MCP-wide sin consumers

- GIVEN una policy con `mcp_wide: true` y ningún consumer
- WHEN se escribe
- THEN la respuesta no lleva el aviso de borrador
