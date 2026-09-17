# Especificación: mcp-policy-scope

## Purpose

Define `Policy.MCPScope *MCPScope` (`pkg/domain/policy`): a qué destinos (`registry_ids`, `tools`) y principales (`users`, `groups`, `except_users`, `except_groups`) aplica una policy en el plano MCP, cómo decide `Matches(target, principal)`, qué valida la Admin API y cómo se poda al borrar un registry. El plano LLM no lee este campo.

## Requirements

### Requirement: `nil` frente a scope vacío

`MCPScope == nil` MUST aplicar a todo el tráfico MCP del consumer (comportamiento actual). Un scope presente sin entradas MUST NOT hacer match con nada.

#### Scenario: Policy sin scope

- GIVEN una policy con `mcp_scope` ausente
- WHEN `Matches` se evalúa para cualquier `(registry, tool, principal)`
- THEN devuelve `true`

#### Scenario: Scope `{}`

- GIVEN una policy con `mcp_scope: {}`
- WHEN `Matches` se evalúa para cualquier destino
- THEN devuelve `false`

### Requirement: Destino AND principal; unión entre policies

Dentro de una policy, destino (`registry_ids` ∪ `tools`) y principal (`users` ∪ `groups`) MUST combinarse con AND; una dimensión vacía acepta cualquier valor. Entre policies MUST aplicarse la unión.

#### Scenario: DLP para Finanzas en Snowflake

- GIVEN `mcp_scope{registry_ids: [snowflake], groups: [Finanzas]}`
- WHEN Finanzas llama a `snowflake`
- THEN hace match; Finanzas en `jira` o Marketing en `snowflake` no

#### Scenario: Dos policies coinciden

- GIVEN una policy por `registry_ids: [snowflake]` y otra por `groups: [Finanzas]`
- WHEN Finanzas llama a `snowflake`
- THEN ambas entran en el plan

### Requirement: Identificación del principal

`users` MUST comparar contra `Principal.Subject` o `Principal.Email()` en minúsculas. `groups` MUST seguir la regla de `Grant.Allows` (`storeaccess/grant.go`): igualdad exacta tras `TrimSpace` contra `Principal.Groups()`. Un caller sin identidad de usuario MUST NOT hacer match con `users` ni `groups`.

#### Scenario: Email con distinta capitalización

- GIVEN `users: ["ana@acme.com"]` y token con `email: "Ana@Acme.com"`
- WHEN se evalúa el principal
- THEN hace match

#### Scenario: IdP sin `email`

- GIVEN `users: ["usr_123"]` y token con `sub: "usr_123"` sin `email`
- WHEN se evalúa el principal
- THEN hace match por `Subject`

#### Scenario: API key

- GIVEN `groups: [Finanzas]` y un caller con `AppSubject` sin claims
- WHEN se evalúa el principal
- THEN no hace match

### Requirement: Excepciones

Tras el match positivo, si `Subject`/`Email()` ∈ `except_users` o `Groups() ∩ except_groups ≠ ∅`, `Matches` MUST devolver `false`. Un caller sin identidad MUST NOT caer nunca en una excepción.

#### Scenario: Todos menos Finanzas

- GIVEN `tools: [{snowflake, run_query}], except_groups: [Finanzas]`
- WHEN Marketing llama a `run_query`
- THEN hace match; Finanzas no

#### Scenario: Caller sin identidad

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

Create/update MUST rechazar con 4xx: registries de otro gateway o no MCP; `tool`, `users`, `groups` vacíos o duplicados; scope sin entradas; un registry a la vez en `registry_ids` y `tools`. En update, `mcp_scope` omitido MUST conservar el valor y `null` MUST eliminarlo. El listado MUST aceptar `registry_id`. La respuesta MAY incluir `warnings` no bloqueantes.

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

### Requirement: `global` con scope; consumers LLM

Una policy `global: true` con scope MUST permitirse (alcanza el Store vía `data.StoreConsumer`). Asociar una policy con scope a un consumer LLM MUST rechazarse.

#### Scenario: Global con scope

- GIVEN `global: true, registry_ids: [snowflake]`
- WHEN se crea
- THEN se acepta y forma parte de `StoreConsumer`

#### Scenario: Consumer LLM

- GIVEN una policy con scope
- WHEN se asocia a un consumer LLM
- THEN 4xx

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
