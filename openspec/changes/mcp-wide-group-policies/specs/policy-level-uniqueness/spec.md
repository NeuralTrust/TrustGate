# Delta para policy-level-uniqueness

Cambio `mcp-wide-group-policies` (RUN-1746). Una policy MCP-wide ocupa la misma celda que una global: consumer `∅` por los grupos y destinos de su scope. `SetMCPWide` pasa por el guard y `UnsetMCPWide` no. Además, la escritura que el guard autoriza tiene que aterrizar sobre la fila que el guard leyó: `Update` compara la ubicación y una promoción compara `updated_at`.

## MODIFIED Requirements

### Requirement: Una policy ocupa el producto cartesiano de sus dimensiones

Una policy MUST NOT modelarse como ocupante de **un** nivel. Ocupa el producto cartesiano de sus dimensiones, con `∅` = "todos":

```
nivel = (consumer, group, destination)        con ∅ = "todos"
destination = registry_id | (registry_id, tool)   ← una dimensión con dos rangos, no dos:
                                                     MCPToolRef ya lleva su registry_id

occupancy(p) = { (p.gateway, p.slug, c, g, d)
                 | c ∈ (gatewayWide(p) ? {∅} : p.consumer_ids ?: {∅})
                 , g ∈ (p.groups        ?: {∅})
                 , d ∈ (p.registry_ids ∪ p.tools ?: {∅}) }

gatewayWide(p) = p.global ∨ p.mcp_wide
```

`∅` MUST ser un valor explícito, no el cero de un UUID por accidente.

Una policy gateway-wide, global o MCP-wide, MUST ocupar la celda de consumer `∅` sean cuales sean sus enlaces: corre en todos los consumers de sus planos y la carga ignora sus enlaces. Una MCP-wide MUST ocupar esa misma celda aunque solo corra en el plano MCP. Así la ocupación sigue siendo función de la fila, y crear un consumer o cambiarle el tipo no necesita guard.

Un borrador —ni global, ni MCP-wide, y sin consumers (`Policy.Draft()`)— MUST ocupar **cero** niveles: no corre en ningún sitio. Por eso un duplicado, que nace borrador, no choca con su origen.

`except_groups` MUST NOT entrar en la clave: es una resta, no un nivel. Dos policies con el mismo `groups` y distinto `except_groups` chocan, y deben: las dos están en el nivel "grupo g1" y las dos correrían para un caller de g1 que no esté en ninguna de las dos exclusiones.

Una lápida (`mcp_scope: {}`) MUST ocupar **cero** niveles: no entra en un conflicto ni lo provoca.

#### Scenario: Producto cartesiano

- GIVEN una policy con `consumer_ids: [c1, c2]`, `registry_ids: [r1, r2]` y `groups: [g1]`
- WHEN se calcula `Occupancy`
- THEN ocupa exactamente **4** niveles

#### Scenario: MCP-wide ocupa la celda de la global

- GIVEN una policy `mcp_wide: true` con `groups: [Finanzas]`, enlazada además a `c1`
- WHEN se calcula `Occupancy`
- THEN ocupa exactamente `(∅, Finanzas, ∅)`: el enlace no cuenta

#### Scenario: Un borrador ocupa cero

- GIVEN una policy habilitada con `global: false`, `mcp_wide: false`, cero consumers y `groups: [Finanzas]`
- WHEN se calcula `Occupancy`
- THEN el conjunto es vacío

#### Scenario: `except_groups` no desempata

- GIVEN dos policies del mismo `slug` con `groups: [g1]`, una con `except_groups: [g2]` y la otra sin
- WHEN se comparan sus ocupaciones
- THEN se solapan: las dos están en el nivel `(∅, g1, ∅)`

#### Scenario: La lápida ocupa cero

- GIVEN una policy con `mcp_scope: {}`
- WHEN se calcula `Occupancy`
- THEN el conjunto es vacío

### Requirement: `LevelGuard` en los cinco caminos de escritura

`apppolicy.LevelGuard.Check(ctx, p, write)` MUST llamarse desde los **cinco** caminos que ocupan un nivel, con `p` tal como quedaría guardada:

| Camino | Por qué |
|---|---|
| `creator` | crea la ocupación |
| `updater` | cambia las dimensiones; **incluido el update que solo pone `enabled: true`** |
| `associator.AttachPolicy` | añade un consumer, es decir niveles nuevos |
| `scoper.SetGlobal` (`POST .../policies/{id}/global`) y `scoper.SetMCPWide` (`POST .../policies/{id}/mcp-wide`) | mueven la policy a la celda de consumer `∅` de su scope |
| `duplicator` | copia la ocupación |

`DetachPolicy`, `UnsetGlobal` y `UnsetMCPWide` MUST NOT llevar guard: quitar un consumer o quitar una ubicación solo libera niveles. Quitar un flag que no está puesto MUST responder la policy tal cual, sin escribir.

Pasar de una ubicación a la otra (`SetMCPWide` sobre una global, `SetGlobal` sobre una MCP-wide) MUST ser una sola escritura que limpia el otro flag, y MUST pasar por el guard **una sola vez**, con la policy ya en la ubicación nueva. La propia fila MUST quedar fuera de los ocupantes, así que el cambio no choca consigo mismo.

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

#### Scenario: Dos MCP-wide con grupos solapados

- GIVEN una `trustguard` MCP-wide habilitada con `groups: [Finanzas]`
- WHEN se promueve a MCP-wide otra `trustguard` con `groups: [Finanzas, Marketing]`
- THEN la promoción se rechaza con conflicto en el nivel `consumer=all group=Finanzas resource=all`, y no se escribe nada

#### Scenario: MCP-wide contra global

- GIVEN una `trustguard` global habilitada con `groups: [Finanzas]`
- WHEN se promueve a MCP-wide otra `trustguard` con `groups: [Finanzas]`
- THEN la promoción se rechaza con conflicto: las dos están en `(∅, Finanzas, ∅)`

#### Scenario: MCP-wide con grupos disjuntos conviven

- GIVEN una `trustguard` MCP-wide habilitada con `groups: [Finanzas]`
- WHEN se promueve a MCP-wide otra `trustguard` con `groups: [Marketing]`
- THEN la promoción se acepta

#### Scenario: El cambio de global a MCP-wide se comprueba una vez

- GIVEN una `trustguard` global y ninguna otra policy de ese plugin
- WHEN se hace `POST .../policies/{id}/mcp-wide`
- THEN el guard corre una vez, la policy no choca con su propia fila, y queda `mcp_wide: true` y `global: false`

#### Scenario: Quitar MCP-wide nunca choca

- GIVEN una policy MCP-wide y otra MCP-wide del mismo plugin en el mismo nivel, un duplicado preexistente
- WHEN se hace `DELETE .../policies/{id}/mcp-wide` sobre una de ellas
- THEN responde 200 sin pasar por el guard

#### Scenario: Quitar un flag que no está

- GIVEN una policy MCP-wide
- WHEN se hace `DELETE .../policies/{id}/global`
- THEN responde 200 con la policy sin cambios, y no se escribe nada

#### Scenario: Detach nunca choca

- GIVEN una policy adjunta a varios consumers
- WHEN se hace `DetachPolicy`
- THEN nunca devuelve conflicto

#### Scenario: Concurrencia

- GIVEN dos escrituras concurrentes que ocuparían el mismo nivel
- WHEN las dos corren
- THEN una pasa y la otra devuelve conflicto

### Requirement: El conflicto sale como `409`

`ErrPolicyLevelConflict` MUST envolver `commonerrors.ErrConflict`, que `httpio` ya mapea a **409** con `"error": "conflict"`, junto a `ErrAlreadyExists` y `ErrHasDependents`. MUST NOT ser 422: la petición está bien formada; es el estado el que la rechaza.

El mensaje MUST nombrar la policy en conflicto y el nivel, y MUST NOT cambiar con la ubicación MCP-wide, porque la consola lo reconoce por ese texto:

```
policy <id> ("<name>") already runs plugin <slug> at level consumer=<c|all> group=<g|all> resource=<r|all>
```

Los handlers de create, update y asociación, y los de promoción a `global` y a `mcp_wide`, MUST mapearlo sin un caso especial nuevo en `httpio`, y MUST declarar el 409 en `docs/openapi.json` (regenerado con `make openapi`, no editado a mano).

#### Scenario: 409 en create

- GIVEN un nivel ocupado
- WHEN se hace `POST /v1/gateways/{gw}/policies`
- THEN responde 409 con `"error": "conflict"` y el mensaje nombra la policy y el nivel

#### Scenario: 409 en attach

- GIVEN un nivel ocupado
- WHEN se hace `POST .../consumers/{id}/policies/{pid}`
- THEN responde 409, no 204 ni 422

#### Scenario: 409 en la promoción a MCP-wide

- GIVEN un nivel ocupado por una global o una MCP-wide del mismo plugin
- WHEN se hace `POST .../policies/{id}/mcp-wide`
- THEN responde 409 con `"error": "conflict"` y el mensaje contiene `already runs plugin`

#### Scenario: No es un fallo transitorio

- GIVEN un 409 de conflicto de nivel
- WHEN el cliente lo recibe
- THEN MUST tratarlo como conflicto y MUST NOT reintentarlo como si fuera un fallo de red

## ADDED Requirements

### Requirement: La escritura aterriza sobre la fila que el guard comprobó

El guard decide sobre la policy que el caller leyó. Esa lectura ocurre antes de tomar el lock, y cuando la policy no ocupa nada (deshabilitada, borrador, lápida) el guard no toma ninguno. La escritura que autoriza MUST aterrizar solo si la fila sigue siendo la que se leyó en lo que la decisión depende. Si no, MUST fallar con `ErrPlacementChanged`, que envuelve `ErrConflict` (409), sin escribir nada; el cliente recarga y reintenta. Si la fila ya no existe, MUST responder `ErrNotFound` (404), no 409.

- `Repository.Update` MUST NOT escribir `global` ni `mcp_wide`: MUST compararlos con los que leyó el caller. Una promoción o degradación confirmada entre la lectura y la escritura hace fallar el update.
- Una promoción (`SetGlobal` o `SetMCPWide` a `true`) MUST aterrizar solo mientras `updated_at` siga siendo el que se leyó. Sin esto, un `PUT {enabled: true}` confirmado después de que el scoper leyera la policy deshabilitada dejaría la promoción, que nadie comprobó, sobre una fila habilitada: dos globales habilitadas del mismo plugin sin 409.
- Toda escritura de la fila (`Update`, `SetGlobal`, `SetMCPWide` y la poda de registry) MUST mover `updated_at`. `SetGlobal`, `SetMCPWide` y la poda MUST dejarlo estrictamente por encima del anterior aunque el reloj no avance (`GREATEST(clock_timestamp(), updated_at + 1 µs)`). Así, de dos promociones decididas sobre la misma lectura solo aterriza la primera.
- Una degradación MUST NOT ser condicional: solo libera niveles, y un 409 en un `DELETE` por una edición ajena no protegería nada.
- `SetGlobal` y `SetMCPWide` MUST devolver la ubicación que la fila tiene tras escribir (`global`, `mcp_wide` y `updated_at`, con `RETURNING`), y la respuesta y la caché del scoper MUST salir de ella, no de la copia leída. Una degradación toca solo su flag, así que el otro puede haber cambiado desde la lectura.

#### Scenario: Promoción sobre una fila editada

- GIVEN una `trustguard` deshabilitada sin consumers y otra `trustguard` global habilitada
- AND el scoper ya leyó la primera para `POST .../policies/{id}/global`
- WHEN un `PUT {enabled: true}` sobre ella se confirma antes que la promoción
- THEN la promoción responde 409 (`ErrPlacementChanged`), y la policy queda habilitada y no global

#### Scenario: Update sobre una ubicación movida

- GIVEN un `PUT` que leyó la policy con `global: false`
- WHEN una promoción a global se confirma antes que el `PUT`
- THEN el `PUT` responde 409 y no escribe nada, y la promoción se mantiene

#### Scenario: Dos promociones sobre la misma lectura

- GIVEN `POST .../global` y `POST .../mcp-wide` concurrentes sobre la misma policy, decididos sobre la misma lectura
- WHEN los dos escriben
- THEN uno aterriza y el otro responde 409

#### Scenario: La degradación no es condicional

- GIVEN una policy global
- WHEN un `PUT` sobre ella se confirma entre la lectura y la escritura de `DELETE .../policies/{id}/global`
- THEN la degradación aterriza igual

#### Scenario: La respuesta es la fila escrita

- GIVEN una policy global que `DELETE .../policies/{id}/global` ya leyó
- WHEN un `POST .../policies/{id}/mcp-wide` se confirma antes que la degradación
- THEN la degradación aterriza y responde `global: false`, `mcp_wide: true` y el `updated_at` de la fila, que es también lo que queda en caché
