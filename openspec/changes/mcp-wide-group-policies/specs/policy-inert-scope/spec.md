# Delta para policy-inert-scope

Cambio `mcp-wide-group-policies` (RUN-1746). Añade una tercera ubicación, `mcp_wide`, junto a `global` y los enlaces a consumers. Una policy MCP-wide corre en todos los consumers MCP del gateway y en el Store, y nunca en un plano LLM o A2A. Un borrador pasa a ser la policy que no es global, ni MCP-wide, ni tiene consumers.

## MODIFIED Requirements

### Requirement: La inercia es por dimensión, no por scope entero

El enunciado central, tal como lo fija el producto:

> **La dimensión de consumer gatea siempre, en los dos planos. Grupo, registry y tool solo gatean en MCP; en LLM y A2A son inertes.**

Ninguna formulación por scope entero MUST sustituir a esta: la dimensión de consumer nunca es inerte, y el destino no es inerte sino imposible.

| Dimensión | Dónde vive | Gatea en… | Fuera de MCP | Por qué |
|---|---|---|---|---|
| **Consumer** | `global`, `mcp_wide` y `consumer_policy` — **no es parte de `mcp_scope`** | **siempre**: MCP, LLM y A2A | gatea igual | No es scope: es enrutado. `global` y los enlaces significan lo mismo en los tres planos; `mcp_wide` enruta solo a los consumers MCP y al Store, nunca a un consumer LLM o A2A |
| **Destino** (`registry_ids`, `tools`) | `mcp_scope` | consumer MCP | **no llega**: 422 en attach, filtrado en carga | En LLM no existe el binding `(registry, tool nativa)`, y aproximarlo por nombre sería incorrecto |
| **Principal** (`groups`) | `mcp_scope` | consumer MCP | **inerte**: llega y no gatea | Es lo que el producto pide |

`except_groups` MUST NOT tratarse como una dimensión aparte: es una resta sobre la de principal y sigue su misma suerte.

La dimensión de destino MUST describirse como **imposible** fuera de MCP, no como inerte: "inerte" describe algo que llega y no gatea, y ese es solo el caso del grupo.

> Nota de alcance: dentro del plano MCP la dimensión de principal también deja de gatear para un caller autenticado por api-key. Esa regla **no forma parte de esta capability**: la fija `mcp-policy-scope`, en «El principal es inerte para un caller por api-key». Una policy MCP-wide con `groups` la hereda tal cual en los consumers MCP que admiten api-key; el Store no las admite.

#### Scenario: El consumer gatea en los tres planos

- GIVEN una policy ni global ni MCP-wide, adjunta al consumer X y no adjunta al consumer Y
- WHEN X e Y son de tipo MCP, LLM o A2A, en cualquier combinación
- THEN la policy entra en la cadena de X y no en la de Y, sin depender del tipo

#### Scenario: MCP-wide enruta solo al plano MCP

- GIVEN una policy `mcp_wide: true` y los consumers X (MCP), Y (LLM) y Z (A2A) del mismo gateway
- WHEN se cargan los tres
- THEN la policy entra en la cadena de X y en la del Store, y no en la de Y ni en la de Z

#### Scenario: El grupo llega al plano LLM y no gatea

- GIVEN una policy con `mcp_scope: {groups: [Finance]}` adjunta a un consumer LLM
- WHEN el consumer recibe una petición de cualquier caller
- THEN la policy está en el plan y el grupo no filtra nada

#### Scenario: El destino no llega al plano LLM

- GIVEN una policy con `mcp_scope: {registry_ids: [snowflake]}`
- WHEN se intenta hacerla correr en un consumer LLM, por attach o por `global`
- THEN no corre: el attach responde 422 y la carga la deja fuera del plan no-MCP

### Requirement: Lo que no llega por falta de consumer no necesita filtro nuevo

Un borrador —una policy sin consumers, sin `global` y sin `mcp_wide` (`Policy.Draft()`)— MUST seguir sin correr en ningún plano, y eso MUST pasar por `loadPolicies` —no cae ni en un bucket gateway-wide (`everywhere`, `onMCP`) ni en `byConsumer`— sin ningún filtro añadido. `IsGlobal()` MUST seguir devolviendo `p.Global`: MUST NOT derivarse de `len(ConsumerIDs)` ni contar `mcp_wide`. La ubicación gateway-wide, global o MCP-wide, la dice `GatewayWide()`.

#### Scenario: Borrador abandonado

- GIVEN una policy con `global: false`, `mcp_wide: false`, cero consumers y `mcp_scope: {groups: [Finance]}`
- WHEN se cargan todos los consumers del gateway
- THEN no aparece en ningún plan, y no hay ningún filtro que lo consiga: es el reparto de `loadPolicies`

#### Scenario: Una policy MCP-wide no es un borrador

- GIVEN una policy con `global: false`, `mcp_wide: true`, cero consumers y `mcp_scope: {groups: [Finance]}`
- WHEN se cargan todos los consumers del gateway
- THEN `Draft()` es `false`, está en las `ScopedPolicies` de cada consumer MCP y del Store, y `IsGlobal()` sigue siendo `false`

## ADDED Requirements

### Requirement: MCP-wide nunca entra en una cadena LLM/A2A

Una policy con `mcp_wide: true` MUST NOT entrar en `Policies`, `PolicyPlan` ni `ScopedPolicies` de un consumer LLM o A2A, sea cual sea su scope y su plugin. No llega por `everywhere`, que solo lleva las globales, ni por enlaces: no los tiene (`policy-mcp-wide-placement`), y la carga ignoraría los de una fila anterior igual que ignora los de una global. Por tanto `inertPolicies` y `coalesceInert` MUST NOT verla: no hay inercia ni coalescencia para ella. Eso la distingue de una global de solo grupo, que sí cruza con el grupo inerte.

`loadPolicies` MUST repartir por ubicación:

| Bucket | Contenido | Lo leen |
|---|---|---|
| `everywhere` | las globales | consumers LLM y A2A |
| `onMCP` | las globales y las MCP-wide, en el orden del repositorio | consumers MCP y `data.StoreConsumer` |
| `byConsumer` | los enlaces de las que no son ni globales ni MCP-wide | el consumer enlazado |

Un consumer MCP MUST componer `onMCP` exactamente como hoy compone las globales: `composePolicies` para las sin scope y `mergeScoped` para las con scope, con la misma precedencia.

#### Scenario: Solo grupo e inert-safe

- GIVEN una policy `mcp_wide: true` con `groups: [Finance]` de un plugin inert-safe, enlazada además a un consumer LLM y a uno A2A
- AND una policy `global: true` con `groups: [Finance]` de otro plugin inert-safe
- WHEN se cargan el consumer LLM y el A2A
- THEN la MCP-wide no está en su `Policies`, ni en su `PolicyPlan`, ni en sus `ScopedPolicies`
- AND la global sí está en su plan, con el grupo inerte

#### Scenario: Con destino

- GIVEN una policy `mcp_wide: true` con `registry_ids: [snowflake]`
- WHEN se cargan un consumer LLM y un consumer MCP
- THEN no está en el plan del consumer LLM y está en las `ScopedPolicies` del consumer MCP

#### Scenario: Sin scope

- GIVEN una policy `mcp_wide: true` con `mcp_scope: null`
- WHEN se cargan un consumer LLM y un consumer MCP
- THEN no está en el plan del consumer LLM y está en el plan base del consumer MCP y del Store
