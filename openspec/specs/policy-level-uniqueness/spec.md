# Especificación: policy-level-uniqueness

## Purpose

Define la unicidad por nivel: no puede haber dos policies **habilitadas** del mismo plugin corriendo en el mismo nivel de un gateway. Cubre el modelo de ocupación (`Level`, `OccupancySet`, `Overlaps` en `pkg/domain/policy`), la detección de conflicto por **solape**, el `apppolicy.LevelGuard` que se aplica en los cinco caminos de escritura, y el `409 conflict` que sale por HTTP.

Esta capability es independiente de `policy-inert-scope`: la unicidad se comprueba sobre los niveles **almacenados**, en todos los planos. La coalescencia de `policy-inert-scope` existe porque la inercia colapsa niveles que esta regla aceptó legítimamente.

## Requirements

### Requirement: Una policy ocupa el producto cartesiano de sus dimensiones

Una policy MUST NOT modelarse como ocupante de **un** nivel. Ocupa el producto cartesiano de sus dimensiones, con `∅` = "todos":

```
nivel = (consumer, group, destination)        con ∅ = "todos"
destination = registry_id | (registry_id, tool)   ← una dimensión con dos rangos, no dos:
                                                     MCPToolRef ya lleva su registry_id

occupancy(p) = { (p.gateway, p.slug, c, g, d)
                 | c ∈ (p.consumer_ids  ?: {∅})
                 , g ∈ (p.groups        ?: {∅})
                 , d ∈ (p.registry_ids ∪ p.tools ?: {∅}) }
```

`∅` MUST ser un valor explícito, no el cero de un UUID por accidente.

`except_groups` MUST NOT entrar en la clave: es una resta, no un nivel. Dos policies con el mismo `groups` y distinto `except_groups` chocan, y deben: las dos están en el nivel "grupo g1" y las dos correrían para un caller de g1 que no esté en ninguna de las dos exclusiones.

Una lápida (`mcp_scope: {}`) MUST ocupar **cero** niveles: no entra en un conflicto ni lo provoca.

#### Scenario: Producto cartesiano

- GIVEN una policy con `consumer_ids: [c1, c2]`, `registry_ids: [r1, r2]` y `groups: [g1]`
- WHEN se calcula `Occupancy`
- THEN ocupa exactamente **4** niveles

#### Scenario: `except_groups` no desempata

- GIVEN dos policies del mismo `slug` con `groups: [g1]`, una con `except_groups: [g2]` y la otra sin
- WHEN se comparan sus ocupaciones
- THEN se solapan: las dos están en el nivel `(∅, g1, ∅)`

#### Scenario: La lápida ocupa cero

- GIVEN una policy con `mcp_scope: {}`
- WHEN se calcula `Occupancy`
- THEN el conjunto es vacío

### Requirement: Conflicto por solape, no por igualdad exacta

Hay conflicto si `occupancy(p) ∩ occupancy(q) ≠ ∅` para el mismo `(gateway, slug)`. La comprobación MUST NOT ser una igualdad de niveles ni un hash normalizado del scope.

El caso que rompe de verdad es el solape parcial: `registry_ids: [a,b]` contra `registry_ids: [b,c]`. Para un `tools/call` sobre `b` las dos están en el plan, las dos corren, mismo plugin, dos configuraciones en el mismo nivel. Y es el caso **frecuente**, porque un operador añade un registry a una policy existente en vez de crear otra. Una regla de igualdad exacta sería una regla que falla precisamente en el único caso que importa.

Los candidatos MUST filtrarse antes por `(gateway, slug)`, que tiene índice (`policies_gateway_slug_idx`, migración `20260805140000`).

#### Scenario: Solape parcial

- GIVEN una policy con `registry_ids: [a, b]` y otra del mismo `slug` con `registry_ids: [b, c]`
- WHEN se comprueba el conflicto
- THEN hay conflicto: comparten el nivel `(∅, ∅, b)`

#### Scenario: Niveles disjuntos conviven

- GIVEN una policy con `groups: [finance]` y otra del mismo `slug` con `groups: [engineering]`, ambas en el consumer X
- WHEN se comprueba el conflicto
- THEN no hay conflicto: son configuración legítima y distinta

#### Scenario: Distinto plugin

- GIVEN dos policies de `slug` distinto en el mismo nivel
- WHEN se comprueba el conflicto
- THEN no hay conflicto: la clave incluye el `slug`

### Requirement: `LevelGuard` en los cinco caminos de escritura

`apppolicy.LevelGuard.Check(ctx, tx, p)` MUST llamarse desde los **cinco** caminos que ocupan un nivel:

| Camino | Por qué |
|---|---|
| `creator` | crea la ocupación |
| `updater` | cambia las dimensiones; **incluido el update que solo pone `enabled: true`** |
| `associator.AttachPolicy` | añade un consumer, es decir niveles nuevos |
| `promoter` / `scoper.SetGlobal` (`POST .../policies/{id}/global`) | mueve la policy al nivel `(∅,∅,∅)` |
| `duplicator` | copia la ocupación |

`DetachPolicy` y `UnsetGlobal` MUST NOT llevar guard: quitar un consumer o quitar `global` solo libera niveles.

El guard MUST hacer `SELECT … FOR UPDATE` sobre los candidatos `(gateway, slug)` en la **misma transacción**, la misma forma que ya usa `PruneRegistryReferencesTx`. Sin él, dos creates concurrentes del mismo nivel pasan los dos.

La comprobación MUST vivir en la capa app y MUST NOT delegarse a un índice único sobre `policies`: la ocupación es un conjunto por fila y los `consumer_id` viven en `consumer_policy`, una tabla que un índice sobre `policies` no alcanza.

#### Scenario: Crear en un nivel ocupado

- GIVEN una policy `trustguard` habilitada en el nivel `(X, ∅, ∅)`
- WHEN se crea otra `trustguard` en el mismo nivel
- THEN la escritura se rechaza con conflicto

#### Scenario: Promoción a `global`

- GIVEN una policy `trustguard` all-traffic ya existente
- WHEN se promueve otra `trustguard` con `POST .../policies/{id}/global`
- THEN la promoción se rechaza con conflicto, y reintentarla no lo arregla

#### Scenario: Detach nunca choca

- GIVEN una policy adjunta a varios consumers
- WHEN se hace `DetachPolicy`
- THEN nunca devuelve conflicto

#### Scenario: Concurrencia

- GIVEN dos escrituras concurrentes que ocuparían el mismo nivel
- WHEN las dos corren
- THEN una pasa y la otra devuelve conflicto

### Requirement: `enabled: false` no ocupa, pero habilitar sí pasa por el guard

Una policy deshabilitada MUST NOT contar como ocupante ni MUST provocar conflicto contra ella: la regla impide que dos plugins *corran* en el mismo nivel, y una policy deshabilitada no corre. El movimiento operativo normal —crear el reemplazo deshabilitado, revisarlo y hacer el cambio— MUST seguir siendo posible.

Habilitar MUST pasar por el guard, o la regla se esquiva creando deshabilitada y encendiendo después.

#### Scenario: Crear deshabilitada sobre un nivel ocupado

- GIVEN una policy `trustguard` habilitada en el nivel `(X, ∅, ∅)`
- WHEN se crea otra `trustguard` en el mismo nivel con `enabled: false`
- THEN se acepta

#### Scenario: Habilitarla después

- GIVEN esa misma policy deshabilitada
- WHEN se actualiza a `enabled: true`
- THEN se rechaza con conflicto

#### Scenario: No se cuenta contra una lápida

- GIVEN una policy con `mcp_scope: {}` del mismo `slug`
- WHEN se crea otra policy en cualquier nivel
- THEN la lápida no provoca conflicto

### Requirement: El conflicto sale como `409`

`ErrPolicyLevelConflict` MUST envolver `commonerrors.ErrConflict`, que `httpio` ya mapea a **409** con `"error": "conflict"`, junto a `ErrAlreadyExists` y `ErrHasDependents`. MUST NOT ser 422: la petición está bien formada; es el estado el que la rechaza.

El mensaje MUST nombrar la policy en conflicto y el nivel:

```
policy <id> ("<name>") already runs plugin <slug> at level consumer=<c|all> group=<g|all> resource=<r|all>
```

Los handlers de create, update y asociación, y el de promoción a `global`, MUST mapearlo sin un caso especial nuevo en `httpio`, y MUST declarar el 409 en `docs/openapi.json` (regenerado con `make openapi`, no editado a mano).

#### Scenario: 409 en create

- GIVEN un nivel ocupado
- WHEN se hace `POST /v1/gateways/{gw}/policies`
- THEN responde 409 con `"error": "conflict"` y el mensaje nombra la policy y el nivel

#### Scenario: 409 en attach

- GIVEN un nivel ocupado
- WHEN se hace `POST .../consumers/{id}/policies/{pid}`
- THEN responde 409, no 204 ni 422

#### Scenario: No es un fallo transitorio

- GIVEN un 409 de conflicto de nivel
- WHEN el cliente lo recibe
- THEN MUST tratarlo como conflicto y MUST NOT reintentarlo como si fuera un fallo de red

### Requirement: Los duplicados preexistentes no se rechazan retroactivamente

La regla MUST aplicarse solo en escritura. Los duplicados de nivel que ya existen en base de datos MUST NOT bloquear el despliegue ni reescribirse: el runtime los deja **sin ejecutar** en un plano inerte (tercer caso de la coalescencia de `policy-inert-scope`), y el único rastro es el warning que `dataFinder` loguea al cargar.

La auditoría que los cuenta MUST correrse antes del despliegue para **conocer el número**, no como puerta. El fundamento de esa decisión es la exposición de producción casi nula de TrustGate v2, y por tanto **caduca**:

> **Si la población de TrustGate v2 crece, esa auditoría vuelve a ser puerta de despliegue.** El argumento no es "los duplicados son inofensivos" — es "casi no hay". En cuanto deje de ser cierto, el razonamiento se cae y hay que releerlo, no heredarlo.

El coste aceptado MUST decirse sin suavizar: para un plugin bloqueante —una TrustGuard, un guardrail de prompt injection— un par de duplicados deja ese plano **sin guardrail ninguno**, no con uno de los dos.

#### Scenario: Duplicado preexistente

- GIVEN dos policies `trustguard` habilitadas que ya ocupan el mismo nivel antes del despliegue
- WHEN se despliega el cambio
- THEN ninguna de las dos se rechaza ni se modifica, y el conflicto solo aparece en el warning de carga

#### Scenario: La siguiente escritura sí choca

- GIVEN ese mismo par
- WHEN se edita cualquiera de las dos por un camino de escritura
- THEN el guard devuelve 409
