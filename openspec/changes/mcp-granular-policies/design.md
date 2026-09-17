# Design: Policies MCP granulares (RUN-1597)

Specs: `mcp-policy-scope`, `mcp-policy-plan-selection`, `mcp-tool-allowlist`, `mcp-policy-scope-telemetry`. Exploración: `openspec/changes/mcp-granular-policies/exploration.md` (decisiones cerradas y gaps G1–G5). `docs/internal/*` está en `.gitignore` (`.gitignore:57`), así que la exploración se versiona dentro de la carpeta del change y no bajo `docs/internal/`.

## Technical Approach

Un único campo estructurado `mcp_scope` en la policy (dominio + JSONB) viaja en el snapshot como parte del blob JSON de `Policy` (`pkg/infra/configsnapshot/codec.go:88,156`), sin tocar el proto. `DataFinder` particiona las policies en *sin scope* (el plan que ya existe, `RoutableConsumer.PolicyPlan`, que sigue siendo lo único que ve el plano LLM en `pkg/app/proxy/forwarder.go:160-161`) y *con scope*, y precompila `PolicyPlans` con índices por registry y por `(registry, tool nativa)`. En el hot path, `callTool` resuelve el binding antes de los plugins (`Composer.Resolve`), pide el plan al índice (`PlanFor`) y ejecuta `PreRequest` → `Invoke` → `PreResponse` con ese plan. El filtro por principal es opt-in: solo cuesta cuando existen policies con `users`/`groups`/`except_*` para ese destino. `tool_allowlist` gana `ProtocolMCP` y se convierte en la primitiva de denegación; `ScopeDecision` deja rastro de lo que no corrió, solo con span activo.

## Architecture Decisions

| Decisión | Elegido | Alternativas descartadas | Razón |
|---|---|---|---|
| Persistencia del scope | Columna `mcp_scope JSONB NULL` tipada por `policy.MCPScope`, misma fila (`policies`) | `metadata map[string]string` con clave reservada; tablas junction `policy_registry` / `policy_principal` | Sin entidad ni tabla nueva (objetivo de la reunión); el hot path necesita el struct tipado igualmente; una junction rompería el blob único del snapshot y obligaría a tocar el proto y el compilador (`pkg/app/configsnapshot/compiler.go:276`). El metadata string exige parsear JSON sin tipo y no permite validar registries en Admin API. |
| Binding antes de plugins | Split `Composer.CallTool` → `Resolve(name)` + `Invoke(target)`; `callTool` pasa a rate limit → meta-tools → `Resolve` → `PlanFor` → `PreRequest` → `Invoke` → `PreResponse` | Dos `RunStage` por stage (sin scope antes de `compose`, con scope después) | `compose()` ya está cacheado (`discovery.go:154-225`), así que resolver primero cuesta un `TTLMap.Get` por registry. Dos fases rompen el orden por `Priority` entre policies y duplican el fail-open. El binding se fija antes de que un body writer pueda reescribir `name` (`plugin_runner.go:172-175`). |
| Plan por request | `PolicyPlans` precompilados en `DataFinder`: `base` + `byRegistry[R].static` + `byTool[(R,T)].static`, cada uno un `*StagePlan` completo; listas `principal` aparte por clave de destino | Re-ejecutar `NewStagePlan`/`groupBatches` en cada `tools/call` | Una policy con scope de destino y sin principal es estática por config: se precompila una vez en `load` (`data_finder.go:101-145`). `groupBatches` solo corre por request cuando hay policies con principal para ese destino y alguna hace match (`StagePlan.Union`). |
| Precedencia | `Priority` asc (hoy) → `specificity` desc → `slug` → `id`, en el comparador de `groupBatches` (`plan.go:128-137`) | Especificidad como orden primario | Mantiene el agrupamiento `Parallel` por `priority` igual y la semántica del plano LLM; solo decide el primer escritor dentro de un batch (`executor.go:249-297`). `specificity` = rango destino (`tool`=2 > `registry`=1 > `consumer`=0) ×2 + bit principal. |
| Clave de usuario | `users` compara con `Principal.Subject` **o** `Principal.Email()` (email en minúsculas) | Solo email | Access ya usa `sub` (`storeaccess`); un IdP sin `email` nunca haría match. Mismo matcher exacto tras `TrimSpace` que `Grant.Allows` (`grant.go:148-172`). |
| Anulación por `slug` | Solo entre policies sin scope; las policies con scope quedan fuera de `composePolicies` (`data_finder.go:293-316`) y son aditivas | Aplicar la anulación a todas | Una TrustGuard con scope a una tool apagaría la TrustGuard global del consumer. Coste: doble ejecución posible (G3), cubierta con `warnings` y con `ScopeDecision`. |
| Prune al borrar registry | Segundo `registryrepo.WithDeleteHook` (`pkg/container/modules/registry.go:66`) → `policyrepo.PruneRegistryReferencesTx`; deja `&MCPScope{}` (`{}`), nunca `NULL` | Dejar la referencia colgando; `NULL` | `{}` no hace match con nada (misma distinción `nil` vs vacío que el toolkit); `NULL` ensancharía la policy a todo el consumer en silencio. Sigue el patrón de `Consumer.PruneRegistry` (`registry_prune.go:29-39`) y va en la misma transacción. |
| Store multi-instancia | `Registry.InstanceOf ids.RegistryID` que `instanceRegistry` (`scoper.go:272-285`) rellena con el `ID` del shelf; `PlanFor` indexa por `InstanceOf` si está presente | Indexar por `MCPTarget.Code` | Un scope `registry_ids: [shelf]` alcanza todas las instancias; `configuredRegistry` conserva el `ID` y no cambia. Campo `omitempty`, viaja en snapshot sin coste. |
| Denegación (G1) | `tool_allowlist` declara `ProtocolMCP`; en MCP lee `Request.Metadata["mcp.tool"]` (tool nativa) y responde `StopUpstream` 403 → `-32001` cuando `keepTool` falla; `except_users`/`except_groups` en el scope | Plugin `mcp_deny` nuevo; denegar desde el propio matcher | Reutiliza catálogo, schema y `keepTool` (`toolallowlist/plugin.go:262-275`). "Solo Finanzas puede `run_query`" = `deny_tools: ["*"]` + `tools: [run_query]` + `except_groups: [Finanzas]`. El scope selecciona, no autoriza. |
| Telemetría (G4) | `PolicyPlans.Explain` devuelve `ScopeDecision` solo cuando el dispatcher ve `trace.SpanFromContext(ctx) != nil`; `Span.SetMCPPolicyScope` junto a `SetMCPUpstream` (`composer.go:133-147`); el builder lo copia a `events.MCP.PolicyScope` | Añadir `PolicyEntry` con `skipped` a `PolicyChain` | `PolicyChain` es "lo que corrió" (`builder.go:183-238`); mezclar descartadas rompe `PoliciesMs`. Sin span, `PlanFor` no asigna nada. |
| Admin API `warnings` (G3) | `apppolicy.Warner.Overlaps(ctx, p)` calcula `"consumer <id> already runs plugin <slug> without scope"`; create/update devuelven `warnings` en el `PolicyResponse`; attach responde `200 {"warnings":[…]}` en vez de `204` solo cuando hay avisos | Bloquear la creación | Dos configuraciones del mismo plugin pueden ser intencionadas (`direction`, collector distinto). No bloqueante. |
| Update tri-estado | DTO con `MCPScope json.RawMessage`; `UpdateInput.MCPScope MCPScopePatch{Set bool; Value *MCPScope}`: omitido → no tocar; `null` → borrar scope; objeto → reemplazar | `*MCPScope` como el resto de campos de `UpdateInput` | Un puntero no distingue omitido de `null`, y "quitar el scope" es una operación real. |
| Validación de vacío | Estructural en `Policy.Validate()` (dups, ids nil, `tool` vacío, registry en ambos); "al menos una entrada" solo en `creator`/`updater` cuando el scope llega en el input | Todo en `Validate()` | Una policy podada a `{}` debe poder renombrarse (`updater.go:114`) sin fallar. |
| Prune fuera del puerto de dominio | `PruneRegistryReferencesTx` es método del `*policyrepo.Repository` concreto, como `deps.Consumers.PruneRegistryReferencesTx` | Añadirlo a `policy.Repository` | Evita un no-op en el adaptador de snapshot (`policy_repository.go`) y mantiene `pgx.Tx` fuera del dominio. |

## Data Flow

Hot path `tools/call` (PR3):

    callTool(params)
      │ checkRateLimit ─────────────► RPCError -32004/-32005
      │ meta-tools (connections / inventory / store) ──► cortocircuito
      ▼
    composer.Resolve(ctx, rc, name)          ── un compose() (TTLMap hit) ──► ResolvedTool{Registry, Tool(nativa), Exposed}
      │ ErrToolNotFound | ToolNotPermittedError | ConsentRequiredError | ErrUpstreamUnavailable
      ▼
    span := trace.SpanFromContext(ctx)
    plan := rc.MCPPlans.PlanFor(reg, tool, principal)          (span == nil, cero asignaciones)
    plan, decision := rc.MCPPlans.Explain(reg, tool, principal) (span != nil) → span.SetMCPPolicyScope(decision)
      ▼
    plugins.PreRequest(ctx, rc, ToolCall{Exposed, Registry, NativeTool, Arguments, Plan})
      │ RequestContext{RegistryID, MCP:true, Body:{name: exposed, arguments}, Metadata{"mcp.tool","mcp.registry_id","mcp.exposed_tool"}}
      │ block → RPCError -32001 (tool_allowlist deny incluido) ; Result → respuesta del plugin
      ▼
    composer.Invoke(ctx, rc, target, arguments)   ── annotateUpstream + invokeUpstream ──► result
      ▼
    plugins.PreResponse(ctx, rc, call, result)     ── mismo plan ──► result | masked | RPCError

Carga de configuración (PR2, `dataFinder.load`):

    policyRepo.ListByGateway ──► loadPolicies
      │  globals / byConsumer  →  partitionScoped(): unscoped | scoped
      ▼
    por consumer:
      unscoped := composePolicies(globalsUnscoped, consumerUnscoped)   ← anulación por slug (solo aquí)
      scoped   := dedupByID(consumerScoped ∪ globalsScoped)            ← aditivas
      PolicyPlan := NewStagePlan(unscoped)                             ← plano LLM y discovery, sin cambios
      MCPPlans   := buildPolicyPlans(unscoped, scoped):
            base                    = PolicyPlan
            byRegistry[R].static    = NewStagePlan(unscoped ∪ scopedStatic{R ∈ registry_ids})
            byTool[(R,T)].static    = NewStagePlan(unscoped ∪ scopedStatic{R} ∪ scopedStatic{(R,T) ∈ tools})
            anyDest/byRegistry/byTool .principal = [scopedEntry{scope, plan precompilado, ref}]
    StoreConsumer: Policies = globalsUnscoped; PolicyPlan = base; MCPPlans = buildPolicyPlans(globalsUnscoped, globalsScoped)

## Interfaces / Contracts

Dominio (`pkg/domain/policy/mcp_scope.go`):

```go
type MCPToolRef struct {
    RegistryID ids.RegistryID `json:"registry_id"`
    Tool       string         `json:"tool"` // nombre nativo del upstream
}

type MCPScope struct {
    RegistryIDs  []ids.RegistryID `json:"registry_ids,omitempty"`
    Tools        []MCPToolRef     `json:"tools,omitempty"`
    Users        []string         `json:"users,omitempty"`  // sub o email (email normalizado a minúsculas)
    Groups       []string         `json:"groups,omitempty"`
    ExceptUsers  []string         `json:"except_users,omitempty"`
    ExceptGroups []string         `json:"except_groups,omitempty"`
}

// Policy gana: MCPScope *MCPScope `json:"mcp_scope,omitempty"`  (nil = todo el consumer; {} = nada)

type MCPTarget struct {
    RegistryID ids.RegistryID
    Tool       string
}

// MCPCaller es la vista del principal que lee el matcher; el app layer la construye una vez por request.
type MCPCaller struct {
    Subject string
    Email   string   // ya en minúsculas
    Groups  []string
}

type SkipReason string
const (
    SkipDestination SkipReason = "destination"
    SkipPrincipal   SkipReason = "principal"
    SkipExcept      SkipReason = "except"
)

func (s *MCPScope) IsEmpty() bool        // no nil y sin ninguna entrada
func (s *MCPScope) HasDestination() bool // RegistryIDs o Tools
func (s *MCPScope) HasPrincipal() bool   // Users, Groups, ExceptUsers o ExceptGroups
func (s *MCPScope) Specificity() uint8   // destino: tools=2, registry=1, ninguno=0; ×2 + bit principal
func (s *MCPScope) MatchesTarget(t MCPTarget) bool
func (s *MCPScope) MatchesCaller(c MCPCaller) (ok bool, why SkipReason)
func (s *MCPScope) Matches(t MCPTarget, c MCPCaller) (bool, SkipReason) // nil → true; destino AND principal, luego except_*
func (s *MCPScope) Validate() error      // ErrInvalidMCPScope: dups, ids nil, tool vacío, registry en registry_ids y tools
func (s *MCPScope) Normalize()           // TrimSpace; emails a minúsculas
func (p *Policy) PruneRegistry(id ids.RegistryID) bool // quita id de RegistryIDs/Tools; deja &MCPScope{} si queda vacío
```

Persistencia (`pkg/infra/database/migrations/20260916120000_add_policy_mcp_scope.go`, `pkg/infra/repository/policy/repository.go`):

```sql
ALTER TABLE policies ADD COLUMN IF NOT EXISTS mcp_scope JSONB NULL;   -- Down: DROP COLUMN IF EXISTS mcp_scope
-- select/insert/update añaden p.mcp_scope; NULL → MCPScope nil; '{}' → &MCPScope{}
-- filtro ListFilter.RegistryID:
--   AND ($N::uuid IS NULL
--        OR p.mcp_scope->'registry_ids' ? $N::text
--        OR p.mcp_scope->'tools' @> jsonb_build_array(jsonb_build_object('registry_id', $N::text)))
-- prune (hook, misma tx que DELETE registries):
--   SELECT id, mcp_scope FROM policies WHERE gateway_id=$1 AND mcp_scope IS NOT NULL
--     AND (mcp_scope->'registry_ids' ? $2 OR mcp_scope->'tools' @> jsonb_build_array(jsonb_build_object('registry_id',$2))) FOR UPDATE;
--   UPDATE policies SET mcp_scope=$2, updated_at=now() WHERE id=$1;
```

```go
// pkg/infra/repository/policy/registry_prune.go — misma firma que registryrepo.DeleteHook
func (r *Repository) PruneRegistryReferencesTx(ctx context.Context, tx pgx.Tx, gatewayID ids.GatewayID, registryID ids.RegistryID) (registrydomain.PruneReport, error)
// registrydomain.PruneReport gana Policies []PolicyPrune{PolicyID ids.PolicyID; Emptied bool}; Merge lo acumula.
// registrydomain.Registry gana InstanceOf ids.RegistryID `json:"instance_of,omitempty"`; ScopeKey() devuelve InstanceOf o ID.
```

App policy (`pkg/app/policy`): `CreateInput.MCPScope *domain.MCPScope`; `UpdateInput.MCPScope MCPScopePatch`; `validateMCPScope(ctx, registryRepo, gatewayID, scope)` comprueba `FindByIDs` del mismo gateway, `IsMCP()` y que el plugin declare `ProtocolMCP`; `Warner.Overlaps(ctx, p) ([]string, error)`. `associator.validatePolicyProtocol` rechaza `MCPScope != nil` en consumer `TypeLLM` (`domain.ErrPolicyProtocolMismatch`).

Admin API (`pkg/api/handler/http/policy/{request,response}`):

```jsonc
// POST /v1/gateways/{gw}/policies   (PUT igual; "mcp_scope": null en PUT borra el scope; omitido no toca)
{ "name": "DLP Finanzas Snowflake", "slug": "trustguard", "enabled": true, "priority": 0,
  "settings": {...},
  "mcp_scope": { "registry_ids": ["<uuid>"], "tools": [{"registry_id": "<uuid>", "tool": "run_query"}],
                 "users": ["sub-or-email"], "groups": ["<group-key>"],
                 "except_users": [], "except_groups": ["Finanzas"] } }
// 201 / 200 → PolicyResponse + "mcp_scope": {...} (ausente cuando nil, {} cuando podado) + "warnings": ["consumer <id> already runs plugin trustguard without scope"]
// GET /v1/gateways/{gw}/policies?registry_id=<uuid>  → policies cuyo scope nombra ese registry
// POST .../consumers/{id}/policies/{pid}  → 204, o 200 {"warnings":[…]} cuando hay solapes
// 400 ErrInvalidMCPScope: registry de otro gateway / no MCP, tool vacía, duplicados, scope sin entradas, plugin sin ProtocolMCP
```

Planes (`pkg/app/consumer/policy_plans.go`, `pkg/app/plugins/{plan,chain}.go`):

```go
type PolicyRef struct{ ID, Name, Slug string }
type SkippedPolicy struct{ PolicyRef; Reason policydomain.SkipReason }
type ScopeDecision struct {
    Evaluated int             // policies CON scope consideradas para el consumer (las sin scope no cuentan)
    Matched   []PolicyRef     // con scope y que entraron en el plan
    Skipped   []SkippedPolicy // con scope y descartadas, con la razón (destination | principal | except)
}

type scopedEntry struct {
    ref   PolicyRef
    scope *policydomain.MCPScope
    plan  *appplugins.StagePlan // precompilado, una policy
}
type destPlans struct {
    static    *appplugins.StagePlan // base ∪ estáticas de este destino
    principal []scopedEntry
}
type PolicyPlans struct {
    base       *appplugins.StagePlan
    anyDest    []scopedEntry                       // scope con principal y sin destino
    byRegistry map[ids.RegistryID]*destPlans
    byTool     map[policydomain.MCPTarget]*destPlans
    scoped     []scopedEntry                       // todas, solo para Explain
}

func BuildPolicyPlans(reg appplugins.Registry, unscoped, scoped []*policydomain.Policy, logger *slog.Logger) *PolicyPlans
// PlanFor: nil receiver → nil (el executor cae a in.Policies como hoy). Sin principal-scoped para el destino: 2 lookups, 0 asignaciones.
func (p *PolicyPlans) PlanFor(reg *registrydomain.Registry, nativeTool string, principal *identity.Principal) *appplugins.StagePlan
func (p *PolicyPlans) Explain(reg *registrydomain.Registry, nativeTool string, principal *identity.Principal) (*appplugins.StagePlan, ScopeDecision)

// RoutableConsumer gana MCPPlans *PolicyPlans; PolicyPlan sigue siendo el plan sin scope.

// pkg/app/plugins
type chainEntry struct { /* ... */ specificity uint8 } // NewStagePlan lo rellena desde pol.MCPScope.Specificity()
// groupBatches: priority asc → specificity desc → slug → id
func (p *StagePlan) Union(extra ...*StagePlan) *StagePlan // concatena byStage y reagrupa; no vuelve al Registry
```

Hot path MCP (`pkg/app/mcp`):

```go
type ResolvedTool struct {
    Registry *registrydomain.Registry
    Tool     Tool   // nativa
    Exposed  string
}
type Composer interface {
    ListTools(...); ListResources(...); ListResourceTemplates(...); ReadResource(...); ListPrompts(...); GetPrompt(...); ToolInventory(...)
    Resolve(ctx context.Context, rc *appconsumer.RoutableConsumer, name string) (*ResolvedTool, error)
    Invoke(ctx context.Context, rc *appconsumer.RoutableConsumer, target *ResolvedTool, arguments json.RawMessage) (json.RawMessage, error)
} // CallTool desaparece del puerto; mocks regenerados con mockery

type ToolCall struct {
    Exposed    string
    Registry   *registrydomain.Registry
    NativeTool string
    Arguments  json.RawMessage
    Plan       *appplugins.StagePlan
}
func (r *PluginRunner) PreRequest(ctx context.Context, rc *appconsumer.RoutableConsumer, call ToolCall) (*StageResult, error)
func (r *PluginRunner) PreResponse(ctx context.Context, rc *appconsumer.RoutableConsumer, call ToolCall, result json.RawMessage) (*StageResult, error)
// buildRequestContext: RegistryID = reg.ID; Body = {name: exposed, arguments}; Metadata:
//   infracontext.MetadataMCPTool = "mcp.tool" (nativa), MetadataMCPRegistryID = "mcp.registry_id", MetadataMCPExposedTool = "mcp.exposed_tool"

// pkg/infra/trace/span.go
type MCPPolicyScope struct{ Evaluated int; Matched []string; Skipped []MCPSkippedPolicy } // MCPSkippedPolicy{ID, Name, Reason string}
func (s *Span) SetMCPPolicyScope(scope MCPPolicyScope)      // MCPAttrs.PolicyScope *MCPPolicyScope
// events.MCP gana PolicyScope *events.MCPPolicyScope `json:"policy_scope,omitempty"`; foldMCPSpans lo copia.
```

`tool_allowlist` en MCP: `SupportedProtocols` → `{LLM, MCP}`; `Execute` bifurca en `in.Request.MCP`: tool nativa de `Metadata[MetadataMCPTool]`; ausente → `okResult`; `keepTool` falso y `Blocks(mode)` → `newRejectResult(403, errToolDenied, [tool])` (→ `-32001` vía `blockToRPCError`); observe → `SetDecision`. `on_empty_after_filter` no aplica en MCP.

## Complejidad y latencia

- `Resolve` = el `compose()` que hoy hace `CallTool` (`composer.go:107-129`): un `TTLMap.Get` por registry con caché caliente más `resolveNames` O(bindings). Las calls bloqueadas pasan a pagarlo (solo CPU); las permitidas no cambian: un `compose()` por call, como hoy.
- `PlanFor`: `byTool` lookup, `byRegistry` lookup, tres `len()` → O(1) y cero asignaciones cuando no hay policies con principal para el destino (caso por defecto y caso "sin `mcp_scope`", en el que devuelve `base`).
- Con principal-scoped: `MatchesCaller` es O(|groups|·|scope.groups|) con `groups` ≤ `MAX_BRIDGE_GROUPS`; solo si alguna hace match se paga `Union` → `groupBatches` por stage, O(n log n) con n = policies del consumer (decenas). Sin match, devuelve el plan estático.
- `Explain` asigna `Matched`/`Skipped` a partir de `scoped` precompilado; nunca corre sin span.
- Un solo `RunStage` por stage, como hoy.

## File Changes

PR1 — dominio + persistencia + Admin API (sin efecto en runtime):

| File | Action | Description |
|---|---|---|
| `pkg/domain/policy/mcp_scope.go` (+`_test.go`) | Create | `MCPScope`, `MCPToolRef`, `MCPTarget`, `MCPCaller`, `Matches`, `Validate`, `Normalize`, `Specificity`, `PruneRegistry` |
| `pkg/domain/policy/policy.go`, `errors.go` | Modify | Campo `MCPScope`; `Rehydrate`; `Validate` llama `MCPScope.Validate`; `ErrInvalidMCPScope` |
| `pkg/domain/registry/registry.go`, `prune_report.go` | Modify | `InstanceOf`, `ScopeKey()`; `PolicyPrune` en `PruneReport` |
| `pkg/infra/database/migrations/20260916120000_add_policy_mcp_scope.go` | Create | `ALTER TABLE policies ADD COLUMN mcp_scope JSONB NULL` |
| `pkg/infra/repository/policy/repository.go`, `registry_prune.go` | Modify/Create | columna en select/insert/update/scan; filtro `RegistryID`; `PruneRegistryReferencesTx` |
| `pkg/domain/policy/repository.go` | Modify | `ListFilter.RegistryID` |
| `pkg/app/policy/{creator,updater,validate,warnings}.go` | Modify/Create | inputs, `MCPScopePatch`, `validateMCPScope`, `Warner` |
| `pkg/app/consumer/associator.go` | Modify | rechazar scope en consumer LLM |
| `pkg/app/store/scoper.go` | Modify | `instanceRegistry` rellena `InstanceOf` |
| `pkg/container/modules/{policy,registry}.go` | Modify | deps de creator/updater (registry repo, warner); `WithDeleteHook(deps.Policies.PruneRegistryReferencesTx)`; proveer `*policyrepo.Repository` concreto |
| `pkg/api/handler/http/policy/request/{create,update}_policy_request.go`, `response/policy_response.go`, `{create,update,list}_policy_handler.go`, `consumer/association_handler.go` | Modify | `mcp_scope`, `warnings`, `registry_id` |
| `pkg/infra/configsnapshot/codec_test.go` | Modify | round-trip de `mcp_scope` (nil / `{}` / completo) |
| `docs/openapi.json`, `docs/swagger.*` | Modify | `make openapi` |

PR2 — DataFinder + plan (sin efecto en runtime: el dispatcher sigue usando `PolicyPlan`):

| File | Action | Description |
|---|---|---|
| `pkg/app/consumer/policy_plans.go` (+`_test.go`) | Create | `PolicyPlans`, `BuildPolicyPlans`, `PlanFor`, `Explain`, `ScopeDecision` |
| `pkg/app/consumer/data_finder.go`, `consumer_data.go` | Modify | `partitionScoped`, `composePolicies` solo sin scope, `MCPPlans` en consumers y `StoreConsumer` |
| `pkg/app/plugins/chain.go`, `plan.go` (+`plan_test.go`) | Modify | `specificity`, comparador de `groupBatches`, `Union` |

PR3 — hot path MCP:

| File | Action | Description |
|---|---|---|
| `pkg/app/mcp/composer.go`, `mocks/mcp_composer_mock.go` | Modify | `Resolve`/`Invoke`; quitar `CallTool`; `go generate` |
| `pkg/app/mcp/rpc_dispatcher.go` | Modify | reorden de `callTool`, `PlanFor`/`Explain`, `SetMCPPolicyScope` |
| `pkg/app/mcp/plugin_runner.go` | Modify | `ToolCall`, firmas, `RegistryID` + metadata `mcp.*` |
| `pkg/infra/context/request_context.go` | Modify | constantes `MetadataMCP*` |
| `pkg/infra/plugins/toolallowlist/{plugin,config}.go`, `pkg/container/modules/plugins_test.go` | Modify | `ProtocolMCP`, rama MCP, `errToolDenied` |
| `pkg/infra/trace/span.go`, `pkg/infra/metrics/events/event.go`, `pkg/app/metrics/builder.go` | Modify | `MCPPolicyScope` en span y evento |
| `pkg/api/handler/http/mcp/rpc_dispatcher_test.go`, `rpc_dispatcher_span_test.go`, `mcp_handler_test.go`, `mcp_handler_unreachable_test.go`, `pkg/api/middleware/mcp_pipeline_integration_test.go`, `pkg/app/mcp/{composer,plugin_runner,mcp_audit_regression,naming}_test.go` | Modify | expectativas `Resolve`/`Invoke` en lugar de `CallTool` |
| `tests/functional/mcp_plugin_chain_test.go` | Modify | dos upstreams, casos por registry/tool/grupo/usuario/excepción, `tool_allowlist deny *` |

## Testing Strategy

| Layer | What to Test | Approach |
|---|---|---|
| Unit `pkg/domain/policy` | `Matches` (nil, `{}`, destino AND principal, `sub` vs email minúsculas, `except_*` con y sin identidad), `Validate`, `PruneRegistry` deja `{}`, `Specificity` | Table-driven, `t.Parallel()` |
| Unit `pkg/app/plugins` | Orden `priority → specificity → slug → id` dentro de un batch; `Union` reagrupa y respeta caps de capacidad | Extender `plan_test.go` |
| Unit `pkg/app/consumer` | `partitionScoped`; anulación por `slug` solo sin scope; `PlanFor` devuelve `base` sin scoped; `byTool` > `byRegistry`; `InstanceOf`; principal-scoped opt-in; `Explain` con `Skipped{Reason}`; `StoreConsumer` con globales con scope | `data_finder_test.go`, `policy_plans_test.go` con mocks existentes |
| Unit `pkg/app/policy`, handlers | `validateMCPScope` (otro gateway, LLM, plugin sin MCP, vacío); tri-estado en update; `warnings`; filtro `registry_id` | mocks mockery de `registrydomain.Repository` |
| Unit `pkg/app/mcp` | `callTool` nuevo orden: `Resolve` antes de `PreRequest`; blocked → `Invoke` no llamado; errores de `Resolve` antes de plugins; `RequestContext.Metadata["mcp.tool"]` nativa | `TestRPCGateway_ToolsCall_PreRequestBlock_SkipsUpstream` (`rpc_dispatcher_test.go:296`) añade `composer.EXPECT().Resolve(...)` y asserta `AssertNotCalled("Invoke")`; `mcpRoutableConsumer()` sin `MCPPlans` sigue cayendo a `in.Policies` |
| Unit `toolallowlist` | Rama MCP: deny `*`, allow por patrón, observe no bloquea, metadata ausente → ok | `plugin_test.go` |
| Unit telemetría | `SetMCPPolicyScope` → `events.MCP.PolicyScope`; sin span, `PlanFor` no asigna (`testing.AllocsPerRun == 0`) | `builder_test.go`, `policy_plans_test.go` |
| Integration repo (`//go:build integration`) | insert/update/scan `NULL`/`{}`/completo; filtro `registry_id`; prune en misma tx que `DELETE registries` | `tests/repositories` |
| Snapshot | round-trip codec con `mcp_scope` | `codec_test.go` |
| Contract | `docs/openapi.json` incluye `mcp_scope` en `CreatePolicyRequest`/`UpdatePolicyRequest`/`PolicyResponse` y `warnings` | `docs/openapi_test.go` (patrón `TestRegistryListOpenAPIDocumentsFlatAndGroupedShapes`) |
| Functional | Dos upstreams stub + TrustGuard stub: policy por registry solo dispara en su upstream (también federado con nombres hash); por tool; por grupo; por usuario (`sub` y email); `except_groups`; `tool_allowlist deny *` → `-32001` sin llamar al upstream; sin scope, comportamiento actual | `tests/functional/mcp_plugin_chain_test.go` con `-race` |
| Benchmark | `BenchmarkCallTool` sin scope vs con scope estático vs con principal-scoped | `pkg/app/mcp`, caché caliente, composer stub |

## Migration / Rollout

- Migración additiva (`ADD COLUMN ... NULL`), `Down` con `DROP COLUMN`; sin backfill.
- El snapshot lleva `mcp_scope` dentro del JSON de `Policy`; el proto no cambia. Un data plane antiguo ignora el campo y ejecuta la policy consumer-wide: **desplegar data plane antes que control plane**, y no crear policies con scope hasta terminar.
- PR1 y PR2 no cambian el runtime (`callTool` sigue con `PolicyPlan`); revertibles aislados.
- PR3: revertir devuelve el plan consumer-wide. Sin desplegar, limpiar `mcp_scope` (`PUT ... {"mcp_scope": null}`) neutraliza la feature.
- Snapshot `Version` cambia con el contenido (`codec.go:70-73`), así que un scope nuevo invalida la caché de `DataFinder` por la vía habitual.

## Open Questions

- [ ] Timestamp definitivo de la migración (`20260916120000_add_policy_mcp_scope` como propuesta; ajustar al día del merge de PR1).
- [ ] ¿Cap de policies con principal por destino (p. ej. 32) para acotar `Union` por request, o basta con el benchmark?
- [ ] Presupuesto de 400 líneas: PR1 (dominio + repo + API + wiring + tests) y PR3 (17 sitios de test con `CallTool`) probablemente lo superan. `sdd-tasks` decide si PR1 se parte en 1a (dominio + migración + repo) / 1b (app + API + prune) y PR3 en 3a (hot path) / 3b (`tool_allowlist` + telemetría), o si se acepta `size:exception`.
- [ ] `attach` devolviendo `200` con cuerpo solo cuando hay `warnings` frente a `204` siempre: confirmar con la UI antes de fijar el contrato.
