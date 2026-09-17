# Especificación: mcp-policy-scope

## Purpose

Define `Policy.MCPScope *MCPScope` (`pkg/domain/policy`): a qué destinos (`registry_ids`, `tools`) y principales (`groups`, `except_groups`) aplica una policy en el plano MCP, cómo decide `Matches(target, principal)`, qué valida la Admin API y cómo se poda al borrar un registry.

El campo sigue gateando **solo** en el plano MCP. Fuera de él, la dimensión de destino no llega y la de principal llega y no gatea: eso lo define `policy-inert-scope`, que es la capability a la que hay que ir para saber qué pasa en LLM y A2A. Lo que esta spec ya no promete es que "el plano LLM nunca lee este campo": una policy con scope de **solo grupo** sí puede estar en el plan de un consumer no-MCP.

## Requirements

### Requirement: `nil` frente a scope vacío

`MCPScope == nil` MUST aplicar a todo el tráfico MCP del consumer (comportamiento actual). Un scope presente sin entradas MUST NOT hacer match con nada.

Un scope presente sin entradas es además una **lápida**: MUST dejar la policy fuera de todos los planes, no solo del MCP, y MUST ocupar cero niveles. Esa parte la define `policy-inert-scope`; aquí basta con que `{}` no case nunca.

#### Scenario: Policy sin scope

- GIVEN una policy con `mcp_scope` ausente
- WHEN `Matches` se evalúa para cualquier `(registry, tool, principal)`
- THEN devuelve `true`

#### Scenario: Scope `{}`

- GIVEN una policy con `mcp_scope: {}`
- WHEN `Matches` se evalúa para cualquier destino
- THEN devuelve `false`

### Requirement: Destino AND principal; unión entre policies

Dentro de una policy, destino (`registry_ids` ∪ `tools`) y principal (`groups`) MUST combinarse con AND; una dimensión vacía acepta cualquier valor. Entre policies MUST aplicarse la unión.

#### Scenario: DLP para Finanzas en Snowflake

- GIVEN `mcp_scope{registry_ids: [snowflake], groups: [Finanzas]}`
- WHEN Finanzas llama a `snowflake`
- THEN hace match; Finanzas en `jira` o Marketing en `snowflake` no

#### Scenario: Dos policies coinciden

- GIVEN una policy por `registry_ids: [snowflake]` y otra por `groups: [Finanzas]`
- WHEN Finanzas llama a `snowflake`
- THEN ambas entran en el plan

### Requirement: Identificación del principal

El principal MUST ser siempre un grupo: `users` y `except_users` no existen como dimensión y una request que los traiga MUST ser rechazada con 422. `groups` MUST seguir la regla de `Grant.Allows` (`storeaccess/grant.go`): igualdad exacta tras `TrimSpace` contra `Principal.Groups()`. Un caller sin grupos MUST NOT hacer match con `groups`.

#### Scenario: Grupo del token

- GIVEN `groups: ["Finanzas"]` y token con `groups: ["Finanzas"]`
- WHEN se evalúa el principal
- THEN hace match

#### Scenario: Dimensión de usuario retirada

- GIVEN un `mcp_scope` con `users` o `except_users`
- WHEN se crea o actualiza la policy
- THEN 422, para que un scope no pierda su principal y se ensanche

#### Scenario: API key

- GIVEN `groups: [Finanzas]` y un caller con `AppSubject` sin claims
- WHEN se evalúa el principal
- THEN no hace match

### Requirement: Excepciones

Tras el match positivo, si `Groups() ∩ except_groups ≠ ∅`, `Matches` MUST devolver `false`. Un caller sin grupos MUST NOT caer nunca en una excepción.

#### Scenario: Todos menos Finanzas

- GIVEN `tools: [{snowflake, run_query}], except_groups: [Finanzas]`
- WHEN Marketing llama a `run_query`
- THEN hace match; Finanzas no

#### Scenario: Caller sin grupos

- GIVEN la misma policy y un caller con API key
- WHEN llama a `run_query`
- THEN hace match

### Requirement: Tools por `(registry_id, nombre nativo)`

`tools` MUST referenciar `{registry_id, tool}` con el nombre nativo del upstream. El match MUST NOT depender del nombre expuesto: ni del hash federado de `naming.go` ni de `expose_as`.

#### Scenario: Consumer federado

- GIVEN `run_query` expuesta como `mcp_ab12cd34_run_query_9f8e7d6c`
- WHEN se llama al nombre expuesto
- THEN `tools: [{snowflake, run_query}]` hace match

#### Scenario: `expose_as`

- GIVEN un toolkit que expone `run_query` como `consulta`
- WHEN se llama a `consulta`
- THEN el match se evalúa sobre `run_query`

### Requirement: Validación en la Admin API

Create/update MUST rechazar con 4xx: registries de otro gateway o no MCP; `tool` o `groups` vacíos o duplicados; `users` o `except_users` presentes; scope sin entradas; un registry a la vez en `registry_ids` y `tools`. En update, `mcp_scope` omitido MUST conservar el valor y `null` MUST eliminarlo. El listado MUST aceptar `registry_id`. La respuesta MAY incluir `warnings` no bloqueantes.

Create, update, attach y promoción a `global` MUST devolver además **409** cuando la escritura ocuparía un nivel que otra policy habilitada del mismo plugin ya ocupa (`policy-level-uniqueness`). 409 y 422 MUST NOT confundirse: el 422 dice que la petición está mal formada o que la dimensión no cruza de plano; el 409 dice que la petición está bien y el estado la rechaza.

Los `warnings` MUST cubrir además: una policy dormida (`policy has an empty mcp_scope and runs nowhere; set mcp_scope to null to run it everywhere`), una policy sin consumers y sin `global` (`policy has no consumers and is not global: it runs nowhere`), y la coalescencia del plano inerte. Ningún warning MUST seguir afirmando que un scope no alcanza a un consumer no-MCP: eso ya solo es cierto para la dimensión de destino.

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

### Requirement: `global` con scope; consumers no-MCP

Una policy `global: true` con scope MUST permitirse (alcanza el Store vía `data.StoreConsumer`).

Asociar una policy con scope a un consumer no-MCP MUST decidirse **por dimensión**, no por la presencia del campo:

| Scope que se adjunta a un consumer no-MCP | Resultado |
|---|---|
| Con destino (`registry_ids` o `tools`), con o sin grupo | **422** — el destino no cruza de plano |
| Solo principal (`groups` / `except_groups`), plugin **no** inert-safe | **422** — el plugin gatea por nombre de tool o de registry |
| Solo principal, plugin inert-safe | **aceptado** — la policy corre y el grupo es inerte |

Los dos motivos de 422 MUST dar mensajes distinguibles. `ErrPolicyScopeRequiresMCP` MUST dejar de prometer "requires MCP" para un scope de solo grupo.

Una policy `global: true` con destino MUST seguir sin alcanzar los consumers no-MCP del gateway: la promoción no es una puerta de atrás. Con solo grupo, sí los alcanza. El predicado y los buckets de carga los define `policy-inert-scope`.

#### Scenario: Global con scope

- GIVEN `global: true, registry_ids: [snowflake]`
- WHEN se crea
- THEN se acepta y forma parte de `StoreConsumer`

#### Scenario: Consumer LLM con destino

- GIVEN una policy con `registry_ids` o `tools`
- WHEN se asocia a un consumer LLM
- THEN 422, con el mensaje que nombra la dimensión de destino

#### Scenario: Consumer LLM con solo grupo

- GIVEN una policy con `mcp_scope: {groups: [Finance]}` de un plugin inert-safe
- WHEN se asocia a un consumer LLM
- THEN se acepta y la policy corre en ese consumer con el grupo inerte

#### Scenario: Consumer LLM con solo grupo y plugin que gatea por nombre

- GIVEN la misma policy con `slug: tool_allowlist`
- WHEN se asocia a un consumer LLM
- THEN 422, con el mensaje que nombra al plugin, no a la dimensión

### Requirement: Prune al borrar un registry

Al borrar un registry MUST eliminarse sus entradas de `registry_ids` y `tools` en las policies del gateway. Si el scope queda vacío MUST persistirse como `{}`, nunca `NULL`. En el data plane el prune MUST ser no-op.

#### Scenario: Varios registries

- GIVEN `registry_ids: [snowflake, jira]`
- WHEN se borra `jira`
- THEN queda `registry_ids: [snowflake]`

#### Scenario: Único registry

- GIVEN `tools: [{snowflake, run_query}]`
- WHEN se borra `snowflake`
- THEN persiste `{}` y la policy deja de hacer match
