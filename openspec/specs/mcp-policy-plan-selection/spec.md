# Especificación: mcp-policy-plan-selection

## Purpose

Define cómo `DataFinder` precompila `PolicyPlans` por consumer, cómo `callTool` (`pkg/app/mcp/rpc_dispatcher.go`) resuelve el destino antes de ejecutar plugins (`Composer.Resolve`/`Invoke`, `PolicyPlans.PlanFor(registry, toolNativa, principal)` y su variante `Explain`, que añade la `ScopeDecision` descrita en `mcp-policy-scope-telemetry`), el orden de la cadena y el `RequestContext` que ven los plugins.

## Requirements

### Requirement: Plan base sin scope

Para un consumer **MCP**, `RoutableConsumer.PolicyPlan` MUST contener solo policies con `MCPScope == nil`. `tools/list`, prompts, resources y meta-tools `trustgate_*` MUST usar ese plan base. Sin policies con scope, `PlanFor` MUST devolver el plan base sin asignaciones.

Para un consumer **no-MCP** el plan lo define `policy-inert-scope`: `NewInertStagePlan(unscoped ∪ crossing)`, `MCPPlans = nil`, y `Policies` y `PolicyPlan` construidos del mismo conjunto. `PlanFor` no se usa en ese plano.

#### Scenario: Consumer no-MCP

- GIVEN un consumer LLM con policies sin scope y una de solo grupo inert-safe
- WHEN se carga
- THEN `PolicyPlan` incluye las dos y `MCPPlans` es `nil`

#### Scenario: Consumer sin policies con scope

- GIVEN un consumer con dos policies sin scope
- WHEN `PlanFor` se invoca
- THEN devuelve el mismo `*StagePlan` base

#### Scenario: Discovery ignora el scope

- GIVEN una policy con `registry_ids: [snowflake]`
- WHEN se ejecuta `tools/list`
- THEN `PreResponseDiscovery` corre con el plan base

### Requirement: Anulación por `slug` acotada; Store

`composePolicies` MUST aplicar la anulación por `slug` solo entre policies sin scope; las con scope MUST ser aditivas. Las globales con scope MUST llegar a `data.StoreConsumer`.

En un plano **inerte** esto se invierte por necesidad: la inercia colapsa los niveles que hacían aditivas a las policies con scope, así que allí MUST aplicarse la coalescencia por `slug` de `policy-inert-scope` (gana la sin scope; una sola colapsada corre; dos o más no corre ninguna). La aditividad MUST mantenerse intacta en el plano MCP.

#### Scenario: TrustGuard global con scope

- GIVEN X con `trustguard` sin scope y una `trustguard` global con `groups: [Finanzas]`
- WHEN Finanzas llama en X
- THEN ambas están en el plan

#### Scenario: Anulación clásica

- GIVEN `trustguard` global y del consumer, ambas sin scope
- WHEN se compone X
- THEN solo la del consumer entra

#### Scenario: Store

- GIVEN una global con `registry_ids: [snowflake]`
- WHEN el Store llama a `snowflake`
- THEN hace match en `StoreConsumer`

### Requirement: Orden de `callTool`

`callTool` MUST ejecutar: rate limit → meta-tools → `Resolve(name)` → `PlanFor` → `PreRequest` → `Invoke(target)` → `PreResponse`, con el MISMO plan en ambos stages. MUST haber un solo `compose()` y un solo `RunStage` por stage.

#### Scenario: Camino feliz

- GIVEN una tool resoluble y una policy con scope que hace match
- WHEN se llama
- THEN ambos stages reciben el mismo plan y el upstream se invoca una vez

#### Scenario: Bloqueo en `PreRequest`

- GIVEN una policy que deniega
- WHEN se llama
- THEN `Invoke` y `PreResponse` no corren; error `-32001`

### Requirement: Errores de resolución antes de plugins

Tool desconocida, denegada por toolkit o con consentimiento pendiente MUST responder antes de cualquier `RunStage`.

#### Scenario: Tool desconocida

- GIVEN un nombre inexistente
- WHEN se llama
- THEN `ErrToolNotFound` sin ejecutar plugins

#### Scenario: Consentimiento pendiente

- GIVEN un upstream que requiere consentimiento
- WHEN se llama a una de sus tools
- THEN `ConsentRequiredError` sin ejecutar plugins

### Requirement: Precedencia

Orden: `Priority` ascendente; a igual prioridad, especificidad descendente (tool > registry > consumer; con principal > sin); después `slug`, `id`. El agrupamiento `Parallel` MUST seguir formando batches por `priority` igual.

En un plano inerte la especificidad MUST aplanarse a 0 para toda entrada, de modo que el orden sea `priority → slug → id` (ver `policy-inert-scope`). `lessEntry` MUST NOT cambiar: el aplanado se hace al construir la cadena.

#### Scenario: Empate de prioridad

- GIVEN dos policies `priority: 10`, una por tool y otra por registry
- WHEN se construye el plan
- THEN la de tool precede

#### Scenario: Batch paralelo

- GIVEN dos policies `parallel: true`, `priority: 10`, distinta especificidad
- WHEN se agrupan
- THEN comparten batch; la especificidad solo ordena dentro

#### Scenario: Empate en el plano inerte

- GIVEN una policy sin scope y otra con `groups: [Finance]`, las dos `priority: 10`, en un consumer LLM
- WHEN se construye el plan
- THEN el orden es el mismo que tendrían las dos sin `mcp_scope`: la de grupo no adelanta a la otra

### Requirement: Filtro por principal opt-in

`groups`/`except_groups` MUST evaluarse solo si existen policies con dimensión principal para ese destino; si no, el camino MUST ser O(1) sin asignaciones.

#### Scenario: Solo destino

- GIVEN policies con scope únicamente por `registry_ids`
- WHEN se resuelve `PlanFor`
- THEN no se lee `Groups()` ni `Email()`

#### Scenario: Grupo sobre el registry

- GIVEN una policy con `groups` sobre `snowflake`
- WHEN se llama a `snowflake`
- THEN el plan se filtra por principal en esa request

### Requirement: `RequestContext` en MCP

Tras `Resolve`, el runner MUST rellenar `RequestContext.RegistryID`, `Metadata["mcp.tool"]` (nativo) y `Metadata["mcp.registry_name"]`. `Body.name` MUST seguir siendo el expuesto. Un plugin que reescriba `name` MUST NOT cambiar el destino. El fail-open de RUN-832 MUST mantenerse.

#### Scenario: Consumer federado

- GIVEN una llamada a `mcp_ab12_run_query_9f8e`
- WHEN corre `PreRequest`
- THEN `Body.name` es el expuesto y `Metadata["mcp.tool"]` es `run_query`

#### Scenario: Plugin reescribe `name`

- GIVEN un plugin que cambia `name`
- WHEN termina `PreRequest`
- THEN `Invoke` usa el target resuelto y se loguea un warning

#### Scenario: Error no bloqueante

- GIVEN `RunStage` devuelve un error que no es `PluginError`
- WHEN corre `PreRequest`
- THEN la llamada continúa y se loguea

### Requirement: Store multi-instancia

Un scope por `registry_ids` MUST hacer match con clones del Store cuando `Registry.InstanceOf` coincide con el id de estantería, además de por `Registry.ID`.

#### Scenario: Clon

- GIVEN `registry_ids: [shelf]` y un clon con `ID = install`, `InstanceOf = shelf`
- WHEN se llama a una tool del clon
- THEN hace match

#### Scenario: Registry corriente

- GIVEN un registry sin `InstanceOf`
- WHEN se evalúa
- THEN solo `Registry.ID` cuenta
