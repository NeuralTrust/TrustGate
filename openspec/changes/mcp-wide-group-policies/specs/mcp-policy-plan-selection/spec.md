# Delta para mcp-policy-plan-selection

Cambio `mcp-wide-group-policies` (RUN-1746). Las policies MCP-wide se componen en cada consumer MCP y en el Store igual que las globales. Las del Store pasan a ser las globales más las MCP-wide.

## MODIFIED Requirements

### Requirement: Anulación por `slug` acotada; Store

`composePolicies` MUST aplicar la anulación por `slug` solo entre policies sin scope; las con scope MUST ser aditivas. En un consumer MCP las policies gateway-wide —globales y MCP-wide— MUST componerse igual: primero las sin scope del consumer y después las gateway-wide sin scope cuyo `slug` no esté ya tomado. Las con scope del consumer van primero y se suman las gateway-wide con scope, deduplicadas por id. Una policy sin scope adjunta al consumer MUST anular a una MCP-wide sin scope del mismo `slug`, igual que anula a una global.

Las globales y las MCP-wide, con y sin scope, MUST llegar a `data.StoreConsumer`. El clon por usuario de un registry del Store MUST evaluarse con los mismos `MCPPlans` de `StoreConsumer`. Un scope de solo grupo no nombra destino, así que se evalúa contra el principal en cualquier registry del Store, clon incluido.

En un plano **inerte** esto se invierte por necesidad: la inercia colapsa los niveles que hacían aditivas a las policies con scope, así que allí MUST aplicarse la coalescencia por `slug` de `policy-inert-scope` (gana la sin scope; una sola colapsada corre; dos o más no corre ninguna). La aditividad MUST mantenerse intacta en el plano MCP. Las MCP-wide nunca llegan a un plano inerte (ver `policy-inert-scope`).

#### Scenario: TrustGuard global con scope

- GIVEN X con `trustguard` sin scope y una `trustguard` global con `groups: [Finanzas]`
- WHEN Finanzas llama en X
- THEN ambas están en el plan

#### Scenario: Anulación clásica

- GIVEN `trustguard` global y del consumer, ambas sin scope
- WHEN se compone X
- THEN solo la del consumer entra

#### Scenario: Anulación de una MCP-wide

- GIVEN los consumers MCP X e Y, una `trustguard` MCP-wide sin scope y otra `trustguard` sin scope adjunta solo a X
- WHEN se componen X, Y y el Store
- THEN en X solo corre la del consumer, y en Y y en el Store corre la MCP-wide

#### Scenario: Store

- GIVEN una global con `registry_ids: [snowflake]`
- WHEN el Store llama a `snowflake`
- THEN hace match en `StoreConsumer`

#### Scenario: MCP-wide por grupo en un clon del Store

- GIVEN una policy MCP-wide con `groups: [Finanzas]` y un clon del Store con `ID = install` e `InstanceOf = shelf`
- WHEN un miembro de Finanzas llama a una tool del clon
- THEN la policy está en el plan
- AND cuando llama alguien de Marketing, o un caller sin principal, no está
