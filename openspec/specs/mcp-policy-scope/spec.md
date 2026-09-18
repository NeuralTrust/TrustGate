# Especificación: mcp-policy-scope

## Purpose

Define `Policy.MCPScope *MCPScope` (`pkg/domain/policy`): a qué destinos (`registry_ids`, `tools`) y principales (`groups`, `except_groups`) aplica una policy en el plano MCP, cómo decide `Matches(target, principal)`, qué valida la Admin API y cómo se poda al borrar un registry. El plano LLM no lee este campo.

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

El principal MUST ser siempre un grupo: `users` y `except_users` no existen como dimensión y una request que los traiga MUST ser rechazada con 422. `groups` MUST seguir la regla de `Grant.Allows` (`storeaccess/grant.go`): igualdad exacta tras `TrimSpace` contra `Principal.Groups()`. Un caller sin grupos MUST NOT hacer match con `groups`, salvo que su principal sea inerte (ver «El principal es inerte para un caller por api-key»).

#### Scenario: Grupo del token

- GIVEN `groups: ["Finanzas"]` y token con `groups: ["Finanzas"]`
- WHEN se evalúa el principal
- THEN hace match

#### Scenario: Dimensión de usuario retirada

- GIVEN un `mcp_scope` con `users` o `except_users`
- WHEN se crea o actualiza la policy
- THEN 422, para que un scope no pierda su principal y se ensanche

#### Scenario: Token sin claim `groups`

- GIVEN `groups: [Finanzas]` y un token cuyo IdP no emite `groups`
- WHEN se evalúa el principal
- THEN no hace match: el principal sigue gateando

### Requirement: El principal es inerte para un caller por api-key

Cuando `Principal.Method == identity.MethodAPIKey`, la dimensión de principal MUST NOT gatear: `MatchesCaller` MUST devolver `true` aunque el scope nombre `groups` que el caller no tiene, y la policy MUST entrar en el plan. El destino MUST seguir gateando con normalidad.

La decisión MUST tomarse en la proyección del principal a `MCPCaller` (`callerOf`, `pkg/app/consumer/policy_plans.go`), nunca en el matcher de dominio, que recibe una proyección para no depender de `identity.Principal`.

La relajación MUST ser una allow-list de un método y MUST NOT ser una deny-list: solo `MethodAPIKey` vuelve inerte el principal. Un principal nulo, `MethodMTLS`, `MethodJWT` (el valor legado indiferenciado), `MethodExternalJWT` y un bearer cuyo IdP no emite `groups` MUST seguir gateando. «Sin grupos en el claim → inerte» MUST NOT implementarse: un IdP mal configurado desactivaría todos los controles de grupo del gateway.

La relajación MUST ser asimétrica: solo cambia la dirección allow-list (`groups`). La dirección deny-list (`except_groups`) MUST dar el mismo resultado que antes, porque un caller por api-key nunca llevó grupos y nunca cayó en la exclusión.

Al crear, actualizar o atachar una policy con `groups`, la Admin API MUST devolver un warning no bloqueante que **nombre** cada consumer MCP alcanzado que acepta una auth de tipo `api_key`: `policy narrows to groups but consumer <id> accepts api-key auth: group checks do not apply to those callers`. El warning MUST nombrar los consumers, MUST NOT contarlos.

#### Scenario: API key con `groups`

- GIVEN `mcp_scope{tools: [{snowflake, run_query}], groups: [Finanzas]}` y un caller con api-key del consumer, que corre como `app:<consumer_id>` sin claim `groups`
- WHEN llama a `run_query`
- THEN hace match y la policy corre; el mismo caller por token y fuera de Finanzas no hace match

#### Scenario: API key contra un destino que no casa

- GIVEN la misma policy y un caller con api-key
- WHEN llama a otra tool del mismo registry
- THEN no hace match: `SkipDestination`, porque el destino no se ablanda

#### Scenario: El método es una allow-list

- GIVEN `groups: [Finanzas]` y un caller sin Finanzas
- WHEN el principal es `nil`, `MethodMTLS`, `MethodJWT` o `MethodExternalJWT`
- THEN no hace match en ninguno de los cuatro casos: `SkipPrincipal`

#### Scenario: Warning de escritura con nombres

- GIVEN una policy con `groups` que alcanza un consumer MCP con una auth `api_key` habilitada
- WHEN se crea, se actualiza o se atacha
- THEN la respuesta trae el warning nombrando ese consumer; un consumer alcanzado sin auth `api_key` no aparece

### Requirement: Excepciones

Tras el match positivo, si `Groups() ∩ except_groups ≠ ∅`, `Matches` MUST devolver `false`. Un caller sin grupos MUST NOT caer nunca en una excepción.

#### Scenario: Todos menos Finanzas

- GIVEN `tools: [{snowflake, run_query}], except_groups: [Finanzas]`
- WHEN Marketing llama a `run_query`
- THEN hace match; Finanzas no

#### Scenario: Caller sin grupos

- GIVEN la misma policy y un caller con API key
- WHEN llama a `run_query`
- THEN hace match, igual que antes de la inercia: la dirección deny-list no cambia

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
