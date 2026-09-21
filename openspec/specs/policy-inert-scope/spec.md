# Especificación: policy-inert-scope

## Purpose

Define qué dimensiones de `Policy.MCPScope` gatean en cada plano y cuáles llegan y no gatean. El scope **no es una unidad**: son dimensiones con destinos distintos. Cubre el predicado único `MCPScope.CrossesPlanes()` (`pkg/domain/policy`), aplicado en escritura (`associator.validatePolicyScope`) y en carga (`dataFinder.partitionScoped`); la lápida `{}`; el opt-in de plugin `ScopeInertSafe`; la coalescencia por `slug` en el plano inerte; y el aplanado de la especificidad. Sustituye a la promesa de `mcp-policy-scope` de que el plano LLM nunca lee este campo: la dimensión de principal sí llega, y no gatea.

El nombre es **inert** y no `fail open`: `fail open` ya significa en TrustGate que un **error de plugin** deja pasar la petición (`Consumer.FailMode()`, RUN-832), en los mismos ficheros que toca este cambio. Una dimensión es *inerte* cuando sigue almacenada y visible en la API pero no gatea.

## Requirements

### Requirement: La inercia es por dimensión, no por scope entero

El enunciado central, tal como lo fija el producto:

> **La dimensión de consumer gatea siempre, en los dos planos. Grupo, registry y tool solo gatean en MCP; en LLM y A2A son inertes.**

Ninguna formulación por scope entero MUST sustituir a esta: la dimensión de consumer nunca es inerte, y el destino no es inerte sino imposible.

| Dimensión | Dónde vive | Gatea en… | Fuera de MCP | Por qué |
|---|---|---|---|---|
| **Consumer** | `global` + `consumer_policy` — **no es parte de `mcp_scope`** | **siempre**: MCP, LLM y A2A | gatea igual | No es scope: es enrutado. Existe y significa lo mismo en los tres planos |
| **Destino** (`registry_ids`, `tools`) | `mcp_scope` | consumer MCP | **no llega**: 422 en attach, filtrado en carga | En LLM no existe el binding `(registry, tool nativa)`, y aproximarlo por nombre sería incorrecto |
| **Principal** (`groups`) | `mcp_scope` | consumer MCP | **inerte**: llega y no gatea | Es lo que el producto pide |

`except_groups` MUST NOT tratarse como una dimensión aparte: es una resta sobre la de principal y sigue su misma suerte.

La dimensión de destino MUST describirse como **imposible** fuera de MCP, no como inerte: "inerte" describe algo que llega y no gatea, y ese es solo el caso del grupo.

> Nota de alcance: dentro del plano MCP la dimensión de principal también deja de gatear para un caller autenticado por api-key (Regla 5 del diseño). Ese requisito **no forma parte de esta capability** y sigue pendiente del visto bueno de producto; hasta entonces `mcp-policy-scope` describe el comportamiento vigente (un caller sin grupos no hace match con `groups`).

#### Scenario: El consumer gatea en los tres planos

- GIVEN una policy adjunta al consumer X y no adjunta al consumer Y
- WHEN X e Y son de tipo MCP, LLM o A2A, en cualquier combinación
- THEN la policy entra en la cadena de X y no en la de Y, sin depender del tipo

#### Scenario: El grupo llega al plano LLM y no gatea

- GIVEN una policy con `mcp_scope: {groups: [Finance]}` adjunta a un consumer LLM
- WHEN el consumer recibe una petición de cualquier caller
- THEN la policy está en el plan y el grupo no filtra nada

#### Scenario: El destino no llega al plano LLM

- GIVEN una policy con `mcp_scope: {registry_ids: [snowflake]}`
- WHEN se intenta hacerla correr en un consumer LLM, por attach o por `global`
- THEN no corre: el attach responde 422 y la carga la deja fuera del plan no-MCP

### Requirement: `CrossesPlanes()` es el predicado único, en escritura y en carga

`MCPScope.CrossesPlanes()` MUST devolver `s != nil && !s.IsEmpty() && !s.HasDestination()`: solo cruza el scope que narra exclusivamente por principal. Una lápida no cruza nada.

`associator.validatePolicyScope` y `dataFinder.partitionScoped` MUST llamar al mismo predicado, sin repetir la condición. Si los dos discrepasen, la carga MUST ganar: el guard de escritura es un 422 temprano con buen mensaje, no la barrera. Un attach que la partición luego descarta deja al operador con un 204 y una policy que no corre.

#### Scenario: Los seis valores del predicado

- GIVEN los scopes `nil`, `{}`, `{groups}`, `{except_groups}`, `{registry_ids}` y `{groups + registry_ids}`
- WHEN se evalúa `CrossesPlanes()`
- THEN devuelve `false`, `false`, `true`, `true`, `false` y `false` respectivamente

#### Scenario: Escritura y carga no divergen

- GIVEN un scope que `CrossesPlanes()` acepta y un plugin inert-safe
- WHEN se adjunta a un consumer LLM
- THEN el attach se acepta **y** la policy entra en el plan no-MCP de ese consumer

### Requirement: Cuatro buckets en la partición

`partitionScoped` MUST repartir en cuatro buckets, no en dos:

| Bucket | Scope | Destino |
|---|---|---|
| `unscoped` | `nil` | todos los planes |
| `crossing` | solo principal (`CrossesPlanes()`) | plan MCP **y** plan no-MCP |
| `mcpOnly` | con destino | solo el plan MCP |
| `dormant` | `{}` | ningún plan |

En la rama MCP el comportamiento MUST ser idéntico al actual. En la rama no-MCP el plan MUST construirse como `unscoped ∪ coalesce(unscoped, filter(crossing, inertSafe))`, con `MCPPlans = nil`.

#### Scenario: Una policy por bucket

- GIVEN cuatro policies con scope `nil`, `{groups: [g]}`, `{registry_ids: [r]}` y `{}`
- WHEN se carga un consumer MCP y un consumer LLM del mismo gateway
- THEN el plan MCP lleva las tres primeras y el plan LLM lleva la primera y la segunda

#### Scenario: La lápida no cae en ningún bucket ejecutable

- GIVEN una policy con `mcp_scope: {}`
- WHEN se carga cualquier consumer
- THEN no aparece ni en el plan MCP ni en el inerte

### Requirement: El destino no cruza tampoco por `global`

Una policy `global: true` con `registry_ids` o `tools` MUST seguir permitida y MUST seguir siendo solo-MCP. La promoción a `global` MUST NOT ser una puerta de atrás al plano no-MCP: no pasa por `validatePolicyScope`, pero cae en el bucket `mcpOnly` de la carga, que es la barrera real. No hace falta código nuevo para la promoción.

Una policy `global: true` con scope de **solo grupo** MUST alcanzar todo el tráfico LLM y A2A del gateway, con el grupo inerte. Es la única fila de comportamiento que cambia sin que nadie edite la policy.

#### Scenario: Global con destino

- GIVEN una policy `global: true` con `registry_ids: [snowflake]`
- WHEN se carga un consumer LLM del gateway
- THEN la policy no está en su plan

#### Scenario: Global con solo grupo

- GIVEN una policy `global: true` con `groups: [Finance]` de un plugin inert-safe
- WHEN se carga un consumer LLM del gateway
- THEN la policy está en su plan y el grupo no filtra

### Requirement: `{}` es una lápida, no un filtro vacío

Un `mcp_scope` presente y sin entradas (`IsEmpty()`) MUST dejar la policy fuera de **todos** los planes, MCP y no-MCP. MUST NOT tratarse como "mapping que no se puede resolver aquí", porque eso la despertaría en LLM.

Los tres estados MUST ser: `nil` = sin scope, corre en todos los planos; presente con entradas = gatea donde toque; presente vacío = lápida, no corre en ninguno.

Una lápida MUST ocupar cero niveles (ver `policy-level-uniqueness`): nunca entra en un conflicto ni lo provoca.

La Admin API MUST avisar con `policy has an empty mcp_scope and runs nowhere; set mcp_scope to null to run it everywhere`.

#### Scenario: Lápida por borrado de registry

- GIVEN `PruneRegistry` escribe `&MCPScope{}` al borrar el último registry que un scope nombraba
- WHEN el consumer es de tipo LLM
- THEN la policy sigue sin correr: la lápida no se ensancha a todo el consumer

#### Scenario: Lápida fabricada por la migración

- GIVEN una fila reseteada a `'{}'` por `20260917120000_drop_policy_mcp_scope_users` (su único principal eran usuarios)
- WHEN se despliega este cambio
- THEN la policy sigue dormida en los tres planos, no despierta en LLM

#### Scenario: Reanimar una lápida

- GIVEN una policy con `mcp_scope: {}`
- WHEN se actualiza con `{"mcp_scope": null}`
- THEN vuelve a correr en todos los planos como una policy sin scope

### Requirement: Opt-in por plugin — `ScopeInertSafe`, default deny

Una policy con scope de **solo grupo** MUST entrar en un plan no-MCP solo si su plugin declara `ScopeInertSafe() bool { return true }`. Un descriptor que no implementa la interfaz MUST tratarse como `false`: ningún plugin se vuelve transversal por descuido.

El criterio MUST ser: **¿el plugin gatea por nombre de tool o de registry — lee `Metadata["mcp.tool"]`, `mcp.registry_id`, o lleva nombres de tool en su config? Entonces `false`.** La razón es del producto:

> *"en LLM se ignora por completo el Mapping MCP ya que en una request LLM no vamos a saber si una tool pertenece a un MCP server y hacer match por nombre puede ser incorrecto"*

La decisión MUST tomarse en tiempo de carga (plan-time), no en el hot path: un plugin que se olvidara de mirar un flag por petición fallaría abierto.

`associator.validatePolicyScope` MUST tener dos motivos de 422, con mensajes distinguibles: destino presente sobre un consumer no-MCP, o plugin que gatea por nombre.

#### Scenario: Descriptor sin la interfaz

- GIVEN un `PluginDescriptor` que no implementa `ScopeInertSafe`
- WHEN se filtra el bucket `crossing`
- THEN la policy queda fuera del plan no-MCP

#### Scenario: El deny-all que el guard de destino no para

- GIVEN una policy `tool_allowlist` con `deny_tools: ["*"]` y `mcp_scope: {except_groups: [Finance]}` adjunta a un consumer LLM
- WHEN se construye el plan no-MCP
- THEN la policy queda fuera, porque `tool_allowlist` no es inert-safe
- AND sin esta regla el deny-all se aplicaría a **todas** las function calls del consumer, ya que el principal es inerte y "para todos menos Finanzas" pasa a ser "para todos"

#### Scenario: El mismo plugin en MCP

- GIVEN la misma policy `tool_allowlist` adjunta a un consumer MCP
- WHEN se construye el plan MCP
- THEN la policy entra con normalidad: en MCP el binding existe y el scope gatea

### Requirement: Coalescencia por `slug` en el plano inerte

La unicidad de nivel se comprueba sobre los niveles **almacenados**; la inercia los **colapsa**. Dos policies del mismo `slug` con `groups` distintos son dos niveles legítimos en MCP y caen al mismo nivel en un plano inerte. La resolución MUST hacerse en carga, MUST ser permanente —no un puente para datos viejos— y MUST seguir estos tres casos **en este orden**:

| Situación en el plano inerte | Resolución |
|---|---|
| Hay una policy **sin scope** del mismo `slug` | Corre la sin scope; las colapsadas se descartan. Warning |
| No hay sin scope y colapsa **exactamente una** | Corre |
| No hay sin scope y colapsan **dos o más** | **No corre ninguna**, y `dataFinder` loguea un warning nombrándolas todas |

El tercer caso MUST documentarse con su coste: para un plugin bloqueante, no ejecutar ninguna deja ese plano **sin guardrail**. Se acepta porque ejecutar una cualquiera de dos configuraciones contradictorias es peor.

El warning existente `consumer <id> already runs plugin <slug> without scope` MUST pasar a describir el **primer** caso.

#### Scenario: Gana la policy sin scope

- GIVEN un `trustguard` sin scope y un `trustguard` con `groups: [Finance]`, ambos en el consumer LLM X
- WHEN se construye el plan de X
- THEN corre solo el sin scope, y hay warning

#### Scenario: Una sola colapsada corre

- GIVEN solo un `trustguard` con `groups: [Finance]` en el consumer LLM X
- WHEN se construye el plan de X
- THEN corre: es el requisito de producto

#### Scenario: Dos colapsadas no corren

- GIVEN un `trustguard` con `groups: [finance]` y otro con `groups: [engineering]`, los dos en el consumer LLM X y sin un `trustguard` sin scope
- WHEN se construye el plan de X
- THEN no corre ninguna de las dos y el warning las nombra a las dos

### Requirement: La especificidad se aplana fuera de MCP

En un plano inerte toda entrada MUST puntuar `specificity: 0`. `buildStageChain` MUST aceptar `flatSpecificity bool` y `NewInertStagePlan` MUST pasarlo a `true`. `lessEntry` MUST NOT tocarse.

Sin aplanar, un scope de solo grupo puntúa `1` (`rank(destino) 0 × 2 + bit(principal) 1`) contra el `0` de una policy sin scope, y el orden descendente por especificidad la pone por delante de sus pares del mismo `priority`, cambiando quién es el primer escritor del batch. Aplanado, el orden inerte MUST ser `priority → slug → id`, idéntico al de hoy.

#### Scenario: El aplanado preserva el orden

- GIVEN dos policies del mismo `priority`, una sin scope y otra con `groups: [Finance]`
- WHEN se construye el plan con `NewInertStagePlan`
- THEN el orden es idéntico al de las mismas policies con `MCPScope = nil`

#### Scenario: Sin aplanado se cuela

- GIVEN el mismo par
- WHEN se construye el plan sin `flatSpecificity`
- THEN la policy con grupo precede a la sin scope, que es lo que el invariante prohíbe

### Requirement: `Policies` y `PolicyPlan` son el mismo conjunto en un consumer no-MCP

`stageInput` y el forwarder leen **tanto** `rc.Policies` **como** `rc.PolicyPlan`; `Policies` es el fallback cuando `Plan` es `nil`. Para un consumer no-MCP los dos MUST construirse del mismo conjunto, o el fallback ejecuta un chain distinto del plan.

#### Scenario: Fallback coherente

- GIVEN un consumer LLM con policies sin scope y una de solo grupo inert-safe
- WHEN se compara `rc.Policies` con el contenido de `rc.PolicyPlan`
- THEN contienen exactamente el mismo conjunto de policies

### Requirement: El invariante de edición del scope

> **Editar el `mcp_scope` de una policy MUST NOT cambiar el comportamiento de un plano no-MCP salvo añadiendo o quitando esa policy entera.** Ni reordenar, ni duplicar, ni resucitar, ni cambiar lo que un plugin decide.

Las lápidas (no resucitar), el opt-in de plugin (no cambiar lo que un plugin decide), la coalescencia (no duplicar) y la especificidad aplanada (no reordenar) MUST leerse como las cuatro caras de este invariante.

#### Scenario: El plan difiere solo en la entrada editada

- GIVEN el plan de un consumer LLM con una policy sin `mcp_scope`
- WHEN a esa policy se le añade `groups: [Finance]`
- THEN la secuencia completa de slugs del plan es la misma, salvo la presencia o ausencia de esa entrada

### Requirement: Lo que no llega por falta de consumer no necesita filtro nuevo

Una policy sin consumers y sin `global` MUST seguir sin correr en ningún plano, y eso MUST pasar por `loadPolicies` —no cae ni en `globals` ni en `byConsumer`— sin ningún filtro añadido. `IsGlobal()` MUST seguir devolviendo `p.Global` y MUST NOT derivarse de `len(ConsumerIDs)`.

#### Scenario: Borrador abandonado

- GIVEN una policy con `global: false`, cero consumers y `mcp_scope: {groups: [Finance]}`
- WHEN se cargan todos los consumers del gateway
- THEN no aparece en ningún plan, y no hay ningún filtro que lo consiga: es el reparto de `loadPolicies`
