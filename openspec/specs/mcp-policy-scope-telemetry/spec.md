# Especificación: mcp-policy-scope-telemetry

## Purpose

Da visibilidad a las policies que NO corrieron por scope en una `tools/call`. Hoy la telemetría (`pkg/app/metrics/builder.go`, `PolicyEntry`) solo registra plugins ejecutados, así que "¿por qué no me bloqueó?" se depura a ciegas. `PolicyPlans` expone dos entradas: `PlanFor` (solo el plan, cero asignaciones) y `Explain` (plan + `ScopeDecision`). El dispatcher llama a `Explain` únicamente cuando hay span activo, estampa la `ScopeDecision` en el span MCP y esta se emite en el metadata MCP del evento de request.

## Requirements

### Requirement: Estructura de `ScopeDecision`

`ScopeDecision` MUST contener `Evaluated int` (policies con scope consideradas para el consumer), `Matched []PolicyRef` (las que entraron en el plan) y `Skipped []SkippedPolicy{ID, Name, Reason}` con `Reason ∈ {destination, principal, except}`. Las policies sin scope MUST NOT aparecer en `Matched` ni en `Skipped`.

#### Scenario: Tres policies con scope

- GIVEN una por `registry_ids: [jira]`, una por `groups: [Finanzas]` y una por `tools: [{snowflake, run_query}]`
- WHEN Marketing llama a `snowflake/run_query`
- THEN `Evaluated = 3`, `Matched` contiene la de tool, `Skipped` contiene `jira` con `destination` y `Finanzas` con `principal`

#### Scenario: Excluida por excepción

- GIVEN una policy con `except_groups: [Finanzas]`
- WHEN Finanzas llama a una tool cubierta
- THEN aparece en `Skipped` con `Reason = except`

#### Scenario: Sin policies con scope

- GIVEN un consumer solo con policies sin scope
- WHEN se llama a una tool
- THEN `Evaluated = 0` y `Matched`/`Skipped` están vacíos

### Requirement: Cálculo solo con span activo

`ScopeDecision` MUST construirse únicamente cuando `trace.SpanFromContext(ctx) != nil`: el dispatcher MUST llamar a `PlanFor` sin span y a `Explain` con span. `PlanFor` MUST NOT asignar memoria para la decisión, y `Explain` MUST devolver exactamente el mismo plan que `PlanFor` para los mismos argumentos.

#### Scenario: Sin span

- GIVEN un contexto sin span MCP
- WHEN el dispatcher invoca `PlanFor`
- THEN el plan es el mismo que devolvería `Explain` y no se construye `ScopeDecision`

#### Scenario: Con span

- GIVEN un contexto con span MCP activo
- WHEN el dispatcher invoca `Explain`
- THEN se construye `ScopeDecision` a partir de las listas precompiladas y el plan coincide con el de `PlanFor`

### Requirement: Estampado en el span

El dispatcher MUST estampar la decisión con `Span.SetMCPPolicyScope(...)` en el mismo punto en que se anota el upstream (`SetMCPUpstream`), antes de `PreRequest`.

#### Scenario: Llamada con plugins

- GIVEN una `tools/call` con span y policies con scope
- WHEN termina la request
- THEN el span MCP lleva la `ScopeDecision` junto al upstream resuelto

#### Scenario: Bloqueo antes de resolver

- GIVEN una tool desconocida
- WHEN falla `Resolve`
- THEN el span no lleva `ScopeDecision` (no hubo `PlanFor` ni `Explain`)

### Requirement: Emisión en el evento MCP

El builder de eventos MUST emitir la decisión dentro del metadata MCP del evento de request. `PolicyEntry` MUST seguir listando solo plugins ejecutados; una policy en `Skipped` MUST NOT aparecer en la cadena de policies.

#### Scenario: Policy descartada

- GIVEN una policy en `Skipped` con `Reason = principal`
- WHEN se construye el evento
- THEN aparece en el metadata MCP y no en `policies[]`

#### Scenario: Doble TrustGuard (G3)

- GIVEN `trustguard` del consumer sin scope y `trustguard` global con scope que hace match
- WHEN se construye el evento
- THEN `policies[]` lista dos entradas `trustguard` y el metadata MCP muestra la global en `Matched`

### Requirement: Alcance limitado a `tools/call`

`ScopeDecision` MUST emitirse solo en `tools/call` resueltas contra un upstream. `tools/list`, prompts, resources y meta-tools `trustgate_*` MUST NOT llevar `ScopeDecision`.

#### Scenario: Discovery

- GIVEN una `tools/list` con span activo
- WHEN se construye el evento
- THEN el metadata MCP no incluye `ScopeDecision`

#### Scenario: Meta-tool

- GIVEN una llamada a `trustgate_connect_*`
- WHEN se construye el evento
- THEN no hay `ScopeDecision`
