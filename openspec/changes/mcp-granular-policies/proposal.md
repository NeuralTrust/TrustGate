---
linear: RUN-1597
type: feat
changelog: "Add mcp_scope to policies so MCP policies apply per registry, tool, user or group, with a tool_allowlist deny primitive and scope-decision telemetry."
---

# Proposal: Policies MCP granulares (RUN-1597)

## Intent

Una policy MCP corre hoy para **todo** el tráfico del consumer, y `callTool` resuelve registry y tool después de `PreRequest`. Hace falta acotar policies a registry, tool, usuario o grupo del token ("DLP para Finanzas en Snowflake", "solo Finanzas puede `run_query`") con cero trabajo del plugin cuando no aplica, sin tocar el plano LLM.

## Scope

### In Scope

- Campo `mcp_scope` (destino: `registry_ids`, `tools`; principal: `users`, `groups`, `except_*`), migración additiva, Admin API con `warnings` y filtro `registry_id`.
- `PolicyPlans` precompilados en `DataFinder`, plan base sin scope (Store incluido), desempate por especificidad.
- Reorden de `callTool` con `Resolve`/`Invoke`.
- `tool_allowlist` en MCP (denegación, `-32001`); `ScopeDecision` en span y evento.
- Tres PRs encadenados sobre `develop`: dominio + API; DataFinder + plan; hot path MCP.

### Out of Scope

- Plano LLM, roles, claim `roles`.
- UI de Policies y clave de grupo estable en `app` (G2); endpoint de tools por registry.
- Ocultar tools denegadas en `tools/list`; entidad nueva para el mapping.

## Capabilities

### New Capabilities

- `mcp-policy-scope`: `MCPScope`, `Matches` (destino AND principal, `except_*`, `nil` vs vacío), validación, prune al borrar registry.
- `mcp-policy-plan-selection`: `PolicyPlans`, orden `Priority` → especificidad → `slug` → `id`, anulación por `slug` solo sin scope, split `Resolve`/`Invoke`.
- `mcp-tool-allowlist`: `ProtocolMCP` sobre la tool nativa de `Metadata["mcp.tool"]`.
- `mcp-policy-scope-telemetry`: `ScopeDecision{Evaluated, Matched, Skipped{Reason}}` solo con span activo.

### Modified Capabilities

- None.

## Approach

Approach 1 de la exploración: rate limit → meta-tools → `composer.Resolve(name)` (un `compose()` cacheado) → `MCPPlans.PlanFor(registry, toolNativa, principal)` → `PreRequest` → `composer.Invoke(target)` → `PreResponse`.

- Match: `nil` → todo el consumer; destino (`registry_ids` o `(registry, tool)`) AND principal (`Subject`/`Email()` ∈ `users` o `Groups() ∩ groups`), luego `except_*`; unión entre policies.
- Orden: `Priority` asc; empate: tool > registry > consumer, con principal > sin; `slug`, `id`.
- Coste: índices por registry y `(registry, tool)`; filtro por principal solo si existen policies con `users`/`groups` para ese destino.
- Denegar: `tool_allowlist deny_tools: ["*"]` + `tools: [run_query]` + `except_groups: [Finanzas]`.
- G3: aditivo por diseño; Admin API devuelve `warnings` no bloqueantes.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `pkg/domain/policy/{policy,mcp_scope,errors,repository}.go` | New/Modified | `MCPScope`, `Matches`, prune |
| `pkg/infra/database/migrations/`, `pkg/infra/repository/policy/repository.go` | New/Modified | `mcp_scope JSONB NULL`; scan, filtro |
| `pkg/runtimeconfig/snapshot/adapters/policy_repository.go`, `pkg/infra/configsnapshot/codec_test.go` | Modified | prune no-op; round-trip |
| `pkg/app/policy/{creator,updater,validate}.go`, `pkg/app/consumer/associator.go` | Modified | validar registries MCP; rechazar en consumer LLM |
| `pkg/app/consumer/{consumer_data,data_finder,policy_plans}.go`, `pkg/app/plugins/{chain,plan}.go` | New/Modified | planes, índices, `specificity` |
| `pkg/app/mcp/{composer,rpc_dispatcher,plugin_runner}.go` (+ `mocks/`) | Modified | `Resolve`/`Invoke`; `RequestContext` con `RegistryID`, tool, principal |
| `pkg/domain/registry/registry.go`, `pkg/app/store/scoper.go`, `pkg/container/modules/registry.go` | Modified | `InstanceOf`; `WithDeleteHook` |
| `pkg/api/handler/http/policy/{request,response}/`, `docs/openapi.json` | Modified | `mcp_scope`, `warnings` |
| `pkg/infra/plugins/toolallowlist/{plugin,config}.go` | Modified | `ProtocolMCP` |
| `pkg/infra/trace/span.go`, `pkg/app/metrics/builder.go`, `pkg/infra/metrics/events` | Modified | `SetMCPPolicyScope` |
| `tests/functional/mcp_plugin_chain_test.go` + unit | New/Modified | dos upstreams, TrustGuard stub |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Scope por nombre expuesto (hash `naming.go`) | High | Clave `(registry_id, tool nativa)` |
| Anulación por `slug` apaga la TrustGuard global | High | Policies con scope fuera de `composePolicies` |
| Prune deja `NULL` y ensancha la policy | Med | Prune escribe `{}` |
| IdP sin `email` nunca matchea | Med | Comparar `sub` y email |
| Store multi-instancia sin match | Med | `InstanceOf` en clones |
| Data plane antiguo ejecuta consumer-wide | Med | Data plane antes que control plane |
| `acts_for_users` sin grupos; rename de grupo (G2) | Med | Documentar en UI; `DirectoryGroup.id` |
| `groupBatches` por request; orden de errores (`rpc_dispatcher_test.go:296`) | Low | Opt-in + benchmark; ajustar test |

## Rollback Plan

- Migración additiva: revertible sin pérdida; el data plane ignora el campo desconocido.
- PR1 y PR2 sin efecto en runtime: revertibles aislados.
- PR3: revertir el reorden de `callTool` devuelve el plan consumer-wide; limpiar `mcp_scope` neutraliza la feature sin desplegar.

## Dependencies

- `app`: UI Application → Registry → Tool; clave `DirectoryGroup.id` (revisar `MAX_BRIDGE_GROUPS`).
- Admin API: `GET .../registries/{id}/tools` para el selector (no bloquea).
- `multi-agent-tests`: `.env.dev` + `ENV_FILE` (G5) antes de PR3.
- Despliegue: data plane antes que control plane.

## Success Criteria

- [ ] `mcp_scope` se crea, actualiza, lista (filtro `registry_id`) y viaja en el snapshot; inválido → 4xx.
- [ ] Policy con `registry_ids`/`tools` solo corre en ese destino, también en consumers federados.
- [ ] Policy con `groups`/`users` solo corre para el principal que matchea (`sub` o email); `except_*` excluye.
- [ ] Policy `global` con scope alcanza el Store multi-instancia; plano LLM intacto.
- [ ] Sin policies con scope, `PlanFor` devuelve el plan base sin asignaciones.
- [ ] `tool_allowlist deny *` en MCP responde `-32001` sin llamar al upstream.
- [ ] Borrar un registry poda a `{}`; Admin API emite `warnings` ante doble plugin.
- [ ] Span y evento MCP incluyen `ScopeDecision` con `Skipped{Reason}`.
- [ ] `mcp_plugin_chain_test.go` cubre registry, tool, grupo, usuario y excepción; `-race` limpio.
