# Verification Report: Policies MCP granulares (RUN-1597)

**Change**: `mcp-granular-policies`
**Linear**: RUN-1597
**Mode**: openspec · Standard (sin Strict TDD: no hay `openspec/config.yaml` ni runner TDD)
**Rama / worktree**: `feat/run-1597-mcp-policy-scope` · `/Users/edu/Neuraltrust/TrustGate-run-1597` (árbol sucio, sin commits; 10 slices aplicados)
**Fecha**: 2026-09-17
**Artefactos contrastados**: `proposal.md` (Success Criteria = contrato), `design.md`, `tasks.md`, `exploration.md`, `openspec/specs/{mcp-policy-scope,mcp-policy-plan-selection,mcp-tool-allowlist,mcp-policy-scope-telemetry}/spec.md`

## Veredicto

**PASS WITH WARNINGS**. Los 9 Success Criteria tienen evidencia de ejecución; 7 PASS y 2 PARTIAL por el mismo hueco: el match **positivo** de `groups`/`users` (y la exención por `except_groups`) solo está probado en unitarios, porque la suite funcional no dispone de un helper que emita un bearer MCP con claim `groups` (`t.Skip` en `tests/functional/mcp_policy_scope_test.go:255`). Ninguna suite falla; `-race` limpio en unitarios y en la funcional completa.

## Completeness

| Métrica | Valor |
|---|---|
| Tareas totales (`tasks.md`) | 66 |
| Completas antes de esta fase | 63 |
| Incompletas antes de esta fase | 3 (2.8, 4.7, 11.4: gates que requerían Postgres y esta verificación) |
| Completas tras esta fase | 66 (2.8 y 4.7 cerradas con la ejecución local contra Postgres; 11.4 con este informe) |

## Gates (build, lint, tests)

| Gate | Resultado | Evidencia |
|---|---|---|
| `make test-race` | ✅ 152 paquetes `ok`, 0 `FAIL`, 0 `SKIP` | `/tmp/claude-501/test-race.log` |
| `make lint` | ✅ 0 issues | ejecución del orquestador |
| `gofmt -l pkg tests docs` | ✅ vacío | ídem |
| `go vet ./...` · `go vet -tags functional ./tests/functional/...` | ✅ | ídem |
| `go test ./docs/...` (contrato OpenAPI) | ✅ `TestPolicyOpenAPIDocumentsMCPScopeAndWarnings` PASS | ídem + re-ejecución del verificador |
| Repositorios (integración, Postgres local `trustgate_repo_test`) | ✅ 6 paquetes `ok`; `TestRepository_MCPScope_RoundTrip`, `_MCPScope_UpdateTransitions`, `_List_FilterByRegistryID`, `_DeleteRegistry_PrunesMCPScopeInSameTx` PASS | `/tmp/claude-501/repo-tests.log` |
| Funcional, subconjunto policy/MCP | ✅ `ok tests/functional 18.216s`; 1 SKIP | `/tmp/claude-501/func-mcp-policy.log` (el fichero solo conserva la línea `ok` del paquete; los veredictos por test los aportó la ejecución verbosa del orquestador; el SKIP está en el código, `mcp_policy_scope_test.go:255`) |
| Funcional COMPLETA `go test -tags functional -race -count=1 -p 1 ./tests/functional/...` | ✅ `exit=0`; `tests/functional 32.318s` + 6 paquetes `repositories/*` `ok` | `/tmp/claude-501/func-full.log` |
| Re-ejecución dirigida del verificador (`go test -count=1 -v -run <nuevos>` en 16 paquetes) | ✅ 16 `ok`; 102 tests de nivel superior / 229 con subtests, 0 FAIL, 0 SKIP | `scratchpad/targeted-unit.log` |
| `BenchmarkRPCDispatcher_CallTool` (`-benchmem`, 300 ms) | `no_scope` 1379 ns/op · 38 allocs · `static_scope` 1309 ns/op · 38 allocs · `principal_scoped` 2485 ns/op · 72 allocs (1,9× < 2× → sin cap `maxPrincipalScopedPerDest`, conforme a 9.4) | ejecución del verificador |
| Cobertura | ➖ no medida (sin umbral en config) | — |

## Success Criteria (proposal.md)

| # | Criterio | Veredicto | Evidencia |
|---|---|---|---|
| 1 | `mcp_scope` se crea, actualiza, lista (filtro `registry_id`) y viaja en el snapshot; inválido → 4xx | ✅ PASS | Funcionales `TestCreatePolicy_WithMCPScope_EchoesStoredScope`, `TestCreatePolicy_WithoutMCPScope_OmitsField`, `TestCreatePolicy_MCPScopeRejections` (9 subtests, 422), `TestCreatePolicy_MCPScopeNotAnObjectRejected`, `TestUpdatePolicy_MCPScopeTriState`, `TestListPolicies_FilterByRegistryID` (en `registry_ids`, en `tools`, desconocido → vacío, no-uuid → 400); repo `TestRepository_MCPScope_RoundTrip`, `_UpdateTransitions`, `_List_FilterByRegistryID`; snapshot `TestCodecRoundTripsPolicyMCPScope` (nil / `{}` / completo). Logs: func-full, repo-tests, targeted-unit |
| 2 | Policy con `registry_ids`/`tools` solo corre en ese destino, también en consumers federados | ✅ PASS | Funcionales `TestMCPPolicyScope_FederatedSurfaceKeepsNativeNamesForScopes`, `_ToolScopedTrustGuardGuardsOnlyThatTool`, `_RegistryScopedPolicyCoversEveryToolOfThatRegistry` (dos upstreams, nombres `mcp_<hash>_…`, `GuardHits` del stub TrustGuard); unit `TestPolicyPlans_ToolBeatsRegistryBeatsBase`, `TestMCPScope_MatchesTarget/exposed federated name does not match` |
| 3 | Policy con `groups`/`users` solo corre para el principal que matchea (`sub` o email); `except_*` excluye | ⚠️ PARTIAL | Unit: `TestMCPScope_MatchesCaller` (email con mayúsculas, `sub` sin email, API key nunca matchea, `everyone but Finanzas` ×3), `TestPolicyPlans_PrincipalScopedPoliciesAreFilteredByTheCaller`, `_ExceptionsExcludeTheCallerAndSpareIdentitylessCallers`, `TestPlanFor_PrincipalScopeUnionsMatchingPolicy`. Funcional: solo el lado negativo con API key (`TestMCPPolicyScope_PrincipalScopedPoliciesAgainstAPIKeyCallers`: `group and user scopes stay dormant` PASS, `except_groups denies a caller outside the group` PASS); `except_groups exempts a member of the group` **SKIP** (`mcp_policy_scope_test.go:255`: ningún helper emite un bearer MCP con `groups`; `oauthIDPStub` descarta la clave de firma). El match positivo end-to-end con token real no está probado |
| 4 | Policy `global` con scope alcanza el Store multi-instancia; plano LLM intacto | ✅ PASS | Store: `TestDataFinder_FindByGateway_StoreConsumerPlansFromScopedGlobals`, `_StoreConsumerPartitionsGlobalPolicies`, `TestPolicyPlans_InstanceOfResolvesToTheShelfKey`, `TestScoperExposesOneRegistryPerInstance` (`InstanceOf` = shelf, `scoper_test.go:163`), `scoper_governance_test.go:89,110`, `TestRegistry_ScopeKey`. LLM: `TestDataFinder_FindByGateway_ScopedPoliciesStayOutOfThePolicyPlan`, `_BuildsMCPPlansOnlyForMCPConsumers`, `TestAssociator_AttachPolicy_ScopeRequiresMCPConsumer`, funcional `TestAttachPolicy_ScopedPolicyOnLLMConsumerRejected` (422); `pkg/app/proxy/` fuera del diff; rama LLM de `tool_allowlist` intacta (`TestPlugin_Execute`). Nota: la evidencia del Store es unitaria; no hay funcional que llame al Store con una global con scope |
| 5 | Sin policies con scope, `PlanFor` devuelve el plan base sin asignaciones | ✅ PASS | `TestPolicyPlans_WithoutScopedReturnsTheBasePlan` (mismo puntero), `_PlanForAllocatesNothingWithoutPrincipalScopedPolicies` (`testing.AllocsPerRun(1000) == 0` en hit por tool, por registry y base con principal con `groups`), `TestPlanFor_WithoutPrincipalScopeAllocatesNothing`, `TestRPCGateway_ToolsCall_WithoutMCPPlansRunsTheConsumerPlan`; bench `no_scope` = `static_scope` en allocs |
| 6 | `tool_allowlist deny *` en MCP responde `-32001` sin llamar al upstream | ✅ PASS | Funcional `TestMCPPolicyScope_ToolAllowlistDenyAllScopedToOneTool` (HTTP 200, `-32001`, `callCount() == 0`), `_ToolAllowlistObserveNeverBlocks`; unit `TestPlugin_ExecuteMCP/deny everything refuses the call`, `TestRPCGateway_ToolsCall_PreRequestBlock_SkipsUpstream` (`AssertNotCalled Invoke`) |
| 7 | Borrar un registry poda a `{}`; Admin API emite `warnings` ante doble plugin | ✅ PASS | Repo `TestRepository_DeleteRegistry_PrunesMCPScopeInSameTx`; unit `TestPolicy_PruneRegistry` (`several registries`, `single registry in tools leaves {}`, `last destination drops principal too`); funcionales `TestPolicyGlobalWithMCPScope_WarnsAboutUnscopedTrustGuard` (201 → `/global` 200 con `warnings` → `?registry_id=`), `TestAttachPolicy_ScopedPolicyWarnsOnUnscopedOverlap` (204 limpio / 200 con `warnings`); unit `TestWarner_*` (7) |
| 8 | Span y evento MCP incluyen `ScopeDecision` con `Skipped{Reason}` | ✅ PASS | `TestRPCGateway_ToolsCall_StampsTheScopeDecisionOnTheSpan`, `_StampsAnEmptyDecisionWhenNothingIsScoped`, `TestRPCGateway_Dispatch_NoScopeDecisionOutsideResolvedToolCalls` (sin planes, `Resolve` falla, discovery, meta-tool), `TestBuilder_MCPCopiesPolicyScopeAndKeepsSkippedOutOfTheChain`, `_MCPDoubleTrustGuardListsBothAndTheGlobalInMatched`, `_MCPDiscoveryCarriesNoPolicyScope`, `TestEvent_MarshalMCPPolicyScope`, `TestSpan_SetMCPPolicyScopeRoundTripsACopy`, `TestPolicyPlans_Explain*` (5) |
| 9 | `mcp_plugin_chain_test.go` cubre registry, tool, grupo, usuario y excepción; `-race` limpio | ⚠️ PARTIAL | La cobertura vive en el fichero hermano `tests/functional/mcp_policy_scope_test.go` (8 tests, mismo `setupMCPPluginChainTwoUpstreams`); los 4 `TestMCPPluginChain_*` originales siguen verdes. Registry ✅, tool ✅, excepción ✅ (lado denegado), grupo/usuario solo como "quedan dormidas" para API key; la exención positiva del miembro del grupo está en SKIP. `-race`: funcional completa con `-race` `exit=0`; `make test-race` 152 `ok` |

## Matriz de cumplimiento de specs

Estados: ✅ COMPLIANT (test cubre el escenario y pasó) · ⚠️ PARTIAL (test pasa pero cubre solo parte) · ❌ UNTESTED / FAILING.

### `mcp-policy-scope`

| Requirement | Scenario | Evidencia | Estado |
|---|---|---|---|
| `nil` frente a scope vacío | Policy sin scope | `TestMCPScope_Matches/nil scope applies to everything` | ✅ |
| | Scope `{}` | `TestMCPScope_Matches/empty scope matches nothing`; `TestPolicy_PruneRegistry/single registry in tools leaves {}` | ✅ |
| Destino AND principal; unión | DLP Finanzas en Snowflake | `TestMCPScope_Matches/{DLP Finanzas on snowflake, Finanzas on jira, Marketing on snowflake}` | ✅ |
| | Dos policies coinciden | `TestPolicyPlans_UnionOfStaticAndPrincipalScopedPolicies`, `TestPlanFor_PrincipalScopeUnionsMatchingPolicy` | ✅ |
| Identificación del principal | Email con distinta capitalización | `TestMCPScope_MatchesCaller/email with different case`; `TestPolicyPlans_PrincipalScopedPoliciesAreFilteredByTheCaller` | ✅ |
| | IdP sin `email` | `TestMCPScope_MatchesCaller/subject without email` | ✅ |
| | API key | `TestMCPScope_MatchesCaller/{api key never matches groups, api key never matches users}`; funcional `…AgainstAPIKeyCallers/group and user scopes stay dormant` | ✅ |
| Excepciones | Todos menos Finanzas | `TestMCPScope_MatchesCaller/everyone but Finanzas: {Marketing, Finanzas}`; `TestPolicyPlans_ExceptionsExcludeTheCallerAndSpareIdentitylessCallers` (unit). Funcional: exención del miembro en SKIP | ⚠️ (unit ✅, funcional SKIP) |
| | Caller sin identidad | `TestMCPScope_MatchesCaller/everyone but Finanzas: api key`; funcional `…/except_groups denies a caller outside the group` | ✅ |
| Tools por `(registry_id, nativo)` | Consumer federado | `TestMCPScope_MatchesTarget/exposed federated name does not match`; funcional `TestMCPPolicyScope_FederatedSurfaceKeepsNativeNamesForScopes` | ✅ |
| | `expose_as` | Sin test específico. Ruta de código: `Resolve` devuelve `b.tool` nativa (`composer.go`), `callTool` pasa `NativeTool: target.Tool.Name` (`rpc_dispatcher.go`), `targetOf` compara sobre ella (`policy_plans.go`); el caso federado prueba la misma ruta expuesto≠nativo | ⚠️ |
| Validación en la Admin API | Registry de otro gateway | `TestCreatePolicy_MCPScopeRejections`, `TestCreator_Create_RejectsInvalidMCPScope`, `TestUpdater_Update_RejectsScopeWithForeignRegistry` | ✅ |
| | Registry en ambas listas | `TestMCPScope_Validate_Rejects/registry in both lists`; `TestCreatePolicy_MCPScopeRejections` | ✅ |
| | Update omitido frente a `null` | `TestUpdatePolicy_MCPScopeTriState`; `TestUpdater_Update_{OmittedScopeKeepsExistingScope, OmittedScopeKeepsPrunedScope, NullScopeClearsIt, ScopeValueReplacesAfterValidation, RejectsEmptyScopeValue}`; `TestUpdatePolicyRequest_ToMCPScope_TriState` | ✅ |
| | Filtro y aviso | `TestPolicyGlobalWithMCPScope_WarnsAboutUnscopedTrustGuard`; `TestListPolicies_FilterByRegistryID`; `TestWarner_Overlaps_GlobalUnscopedWarnsEveryReachedConsumer` | ✅ |
| `global` con scope; consumers LLM | Global con scope | `TestPolicyGlobalWithMCPScope_…`; `TestDataFinder_FindByGateway_StoreConsumerPlansFromScopedGlobals` | ✅ |
| | Consumer LLM | `TestAttachPolicy_ScopedPolicyOnLLMConsumerRejected` (422); `TestAssociator_AttachPolicy_ScopeRequiresMCPConsumer` | ✅ |
| Prune al borrar un registry | Varios registries | `TestPolicy_PruneRegistry/several registries` | ✅ |
| | Único registry | `TestPolicy_PruneRegistry/single registry in tools leaves {}`; `TestRepository_DeleteRegistry_PrunesMCPScopeInSameTx` | ✅ |
| | Data plane no-op (MUST de la Requirement) | Estático: `PruneRegistryReferencesTx` es método del `*policyrepo.Repository`, fuera del puerto `policy.Repository`; `git diff --stat pkg/runtimeconfig/` vacío | ✅ (estático) |

### `mcp-policy-plan-selection`

| Requirement | Scenario | Evidencia | Estado |
|---|---|---|---|
| Plan base sin scope | Consumer sin policies con scope | `TestPolicyPlans_WithoutScopedReturnsTheBasePlan` | ✅ |
| | Discovery ignora el scope | `TestDataFinder_FindByGateway_ScopedPoliciesStayOutOfThePolicyPlan`; `TestRPCGateway_Dispatch_NoScopeDecisionOutsideResolvedToolCalls/discovery`; `TestBuilder_MCPDiscoveryCarriesNoPolicyScope` | ✅ |
| Anulación por `slug` acotada; Store | TrustGuard global con scope | `TestDataFinder_FindByGateway_SlugOverrideOnlyAmongUnscopedPolicies` | ✅ |
| | Anulación clásica | `TestDataFinder_FindByGateway_ComposesGlobalAndConsumerPolicies` | ✅ |
| | Store | `TestDataFinder_FindByGateway_StoreConsumerPlansFromScopedGlobals`, `_StoreConsumerPartitionsGlobalPolicies` | ✅ |
| Orden de `callTool` | Camino feliz | `TestRPCGateway_ToolsCall_SamePlanBothStages`; funcional `TestMCPPolicyScope_ListToolsOncePerRegistryWithinTTL` (un `compose()`), `_UnscopedPolicyKeepsConsumerWideBehaviour` | ✅ |
| | Bloqueo en `PreRequest` | `TestRPCGateway_ToolsCall_PreRequestBlock_SkipsUpstream` (`Resolve` esperado, `Invoke` no llamado); funcional `TestMCPPluginChain_PreRequestEnforceBlockSkipsUpstream` | ✅ |
| Errores de resolución antes de plugins | Tool desconocida | `TestRPCGateway_ToolsCall_ResolveErrorSkipsPlugins`; `TestComposer_Resolve_UnknownToolStaysNotFound` | ✅ |
| | Consentimiento pendiente | `TestRPCGateway_ToolsCall_ResolveErrorSkipsPlugins`; `TestComposer_Resolve_{UnknownToolSurfacesPendingConsent, DeniedBeatsPendingConsent}` | ✅ |
| Precedencia | Empate de prioridad | `TestStagePlan_EqualPriorityOrdersBySpecificityDesc`, `_PriorityStillBeatsSpecificity`, `_EqualSpecificityFallsBackToSlugThenID`; `TestMCPScope_Specificity` | ✅ |
| | Batch paralelo | `TestStagePlan_ParallelBatchGroupsByPriorityOnly` | ✅ |
| Filtro por principal opt-in | Solo destino | `TestPolicyPlans_PlanForAllocatesNothingWithoutPrincipalScopedPolicies` (0 allocs con principal que lleva `groups`) | ✅ |
| | Grupo sobre el registry | `TestPolicyPlans_PrincipalScopedPoliciesAreFilteredByTheCaller` | ✅ |
| `RequestContext` en MCP | Consumer federado | `TestPluginRunner_ResolvedCall_CarriesNativeBinding`, `TestRPCGateway_ToolsCall_PluginsSeeTheResolvedBinding`, `TestPlugin_ExecuteMCP/federated consumer is judged on the native name` | ✅ |
| | Plugin reescribe `name` | `TestRPCGateway_ToolsCall_RewrittenNameDoesNotReroute` asegura que `Invoke` usa el target resuelto y viajan los argumentos reescritos; el warning existe (`plugin_runner.go:190`) pero el test no lo aserta | ⚠️ |
| | Error no bloqueante | `TestRPCGateway_ToolsCall_NonBlockExecutorErrorFailsOpen`; funcional `TestMCPPluginChain_GuardErrorFailsOpen` | ✅ |
| Store multi-instancia | Clon | `TestPolicyPlans_InstanceOfResolvesToTheShelfKey`; `TestScoperExposesOneRegistryPerInstance`; `scoper_governance_test.go:89` | ✅ |
| | Registry corriente | `TestRegistry_ScopeKey`; `scoper_governance_test.go:110`; `TestRegistry_InstanceOfNeverSerialises` | ✅ |

### `mcp-tool-allowlist`

| Requirement | Scenario | Evidencia | Estado |
|---|---|---|---|
| Soporte de `ProtocolMCP` | Asociar a un consumer MCP | `TestNewPluginRegistry_SupportedProtocolsMatrix` (`{LLM, MCP}`); funcional `TestMCPPolicyScope_ToolAllowlistDenyAllScopedToOneTool` (attach aceptado) | ✅ |
| | Config inválida | `TestPlugin_ValidateConfig` (sin cambios) | ✅ |
| Tool nativa desde `Metadata["mcp.tool"]` | Consumer federado | `TestPlugin_ExecuteMCP/federated consumer is judged on the native name` | ✅ |
| | Sin metadato | `TestPlugin_ExecuteMCP/{missing native tool metadata is a no-op, no metadata map at all is a no-op}` | ✅ |
| Semántica allow/deny | Allow por prefijo | `TestPlugin_ExecuteMCP/allow by prefix {permits a match, refuses a non-match}` | ✅ |
| | Deny gana | `TestPlugin_ExecuteMCP/deny wins over allow` | ✅ |
| | Denegar todo | `TestPlugin_ExecuteMCP/deny everything refuses the call` | ✅ |
| Denegación en MCP | Enforce | Funcional `…ToolAllowlistDenyAllScopedToOneTool` (`-32001`, HTTP 200, upstream 0 llamadas) | ✅ |
| | Observe | `TestPlugin_ExecuteMCP/observe records the denial without blocking`; funcional `…ToolAllowlistObserveNeverBlocks` | ✅ |
| | `on_empty_after_filter` no aplica (MUST NOT) | `TestPlugin_ExecuteMCP/on_empty_after_filter has no effect on MCP` | ✅ |
| Patrón "solo el grupo X" | Finanzas permitido | Unit `TestPolicyPlans_ExceptionsExcludeTheCallerAndSpareIdentitylessCallers`, `TestMCPScope_MatchesCaller/everyone but Finanzas: Finanzas`. Funcional `…/except_groups exempts a member of the group` **SKIP** | ⚠️ |
| | Marketing denegado | Unit `…/everyone but Finanzas: Marketing`; funcional `…/except_groups denies a caller outside the group` (`-32001`) | ✅ |
| Plano LLM sin cambios | Petición LLM con tools | `TestPlugin_Execute/{openai allow-only keeps matches, openai deny-only removes matches, …}` | ✅ |
| | Lista vacía tras filtrar | `TestPlugin_Execute/empty after filter rejects with no_tools_allowed body` | ✅ |

### `mcp-policy-scope-telemetry`

| Requirement | Scenario | Evidencia | Estado |
|---|---|---|---|
| Estructura de `ScopeDecision` | Tres policies con scope | `TestPolicyPlans_ExplainListsMatchedAndSkippedWithReasons` | ✅ |
| | Excluida por excepción | `TestPolicyPlans_ExplainReportsExceptionsAndDormantScopes` | ✅ |
| | Sin policies con scope | `TestPolicyPlans_ExplainWithoutScopedPoliciesIsEmpty`; `TestRPCGateway_ToolsCall_StampsAnEmptyDecisionWhenNothingIsScoped` | ✅ |
| Cálculo solo con span activo | Sin span | `TestPolicyPlans_ExplainReturnsThePlanForPlan` (mismo plan); `_PlanForAllocatesNothingWithoutPrincipalScopedPolicies`; los tests de `rpc_dispatcher_scope_test.go` corren sin span (rama `span == nil` → `PlanFor`) | ✅ |
| | Con span | `TestRPCGateway_ToolsCall_StampsTheScopeDecisionOnTheSpan`; `TestPolicyPlans_ExplainAllocatesOnlyForTheDecision` | ✅ |
| Estampado en el span | Llamada con plugins | `TestRPCGateway_ToolsCall_StampsTheScopeDecisionOnTheSpan` | ✅ |
| | Bloqueo antes de resolver | `TestRPCGateway_Dispatch_NoScopeDecisionOutsideResolvedToolCalls/resolve fails` | ✅ |
| Emisión en el evento MCP | Policy descartada | `TestBuilder_MCPCopiesPolicyScopeAndKeepsSkippedOutOfTheChain`; `TestEvent_MarshalMCPPolicyScope`, `TestEvent_MCPOmitsPolicyScopeWhenAbsent` | ✅ |
| | Doble TrustGuard (G3) | `TestBuilder_MCPDoubleTrustGuardListsBothAndTheGlobalInMatched` | ✅ |
| Alcance limitado a `tools/call` | Discovery | `…NoScopeDecisionOutsideResolvedToolCalls/discovery`; `TestBuilder_MCPDiscoveryCarriesNoPolicyScope` | ✅ |
| | Meta-tool | `…NoScopeDecisionOutsideResolvedToolCalls/meta-tool` (`trustgate_list_tools`) | ✅ |

**Resumen**: 61 escenarios · 58 ✅ COMPLIANT · 3 ⚠️ PARTIAL (`expose_as`, "Plugin reescribe `name`" [warning no asertado], "Finanzas permitido" [funcional en SKIP]) · 0 ❌.

## Correctness (evidencia estática)

| Requisito | Estado | Nota |
|---|---|---|
| `MCPScope` + `Matches` (`pkg/domain/policy/mcp_scope.go`) | ✅ Implementado | `Matches`: `nil` → true; `{}` o destino fallido → `SkipDestination`; principal → `SkipPrincipal`; exclusión → `SkipExcept`. `Validate` no exige entradas (renombrar `{}`); "≥1 entrada" en `validateMCPScope` (`pkg/app/policy/validate.go:66`) |
| Persistencia (`repository.go`, `registry_prune.go`, migración `20260916120000`) | ✅ | `NULL` ↔ nil, `'{}'` ↔ `&MCPScope{}`; filtro `?` / `@>` con parámetro `text`; `SELECT … FOR UPDATE` + `UPDATE` en la tx del `DELETE registries` vía segundo `WithDeleteHook` |
| `PolicyPlans` (`policy_plans.go`) | ✅ | `base` / `byRegistry[R].static` / `byTool[(R,T)].static` precompilados; `principal` por destino; `anyDest`; `PlanFor` O(1) sin asignaciones si no hay principal-scoped; `Explain` desde `scoped` |
| `callTool` reordenado (`rpc_dispatcher.go`) | ✅ | rate limit → meta-tools → `Resolve` → `planFor` (`PlanFor` sin span / `Explain` + `SetMCPPolicyScope` con span) → `PreRequest` → `Invoke(target)` → `PreResponse` con la misma `ToolCall` |
| `RequestContext` MCP (`plugin_runner.go`) | ✅ | `RegistryID`, `mcp.tool`, `mcp.registry_id`, `mcp.registry_name`, `mcp.exposed_tool`; `Body.name` = expuesto; `Plan == nil` → `rc.PolicyPlan` |
| `tool_allowlist` MCP (`toolallowlist/plugin.go`) | ✅ | Solo `StagePreRequest`; metadato ausente → `okResult`; deny → `newRejectResult(403, tool_denied)` → `-32001`; observe → `SetDecision` |
| Telemetría (`span.go`, `event.go`, `builder.go`) | ✅ | `MCPPolicyScope{Evaluated, Matched []string, Skipped}`; copia defensiva en el span; `events.MCP.PolicyScope json:"policy_scope,omitempty"` |
| Admin API | ✅ | `mcp_scope` create/update/list; `warnings` en create/update/`global`; attach 204 / 200 `{"warnings"}`; OpenAPI regenerado y contrastado por test |

## Coherence (design.md) y desviaciones detectadas

| Decisión del diseño | ¿Seguida? | Nota |
|---|---|---|
| Columna `mcp_scope JSONB NULL` tipada, sin tabla nueva | ✅ | Tal cual |
| Split `Resolve`/`Invoke`, `CallTool` eliminado del puerto | ✅ | Mock regenerado (mockery v2.53.7, misma versión pinada en `go.mod:126`); los 30 sitios de test migrados |
| `PolicyPlans` precompilados; `Explain`/`PlanFor` | ✅ | Como §Interfaces. Añadido `RoutableConsumer.ScopedPolicies` (no estaba en el diseño; informativo) |
| Precedencia `Priority → specificity → slug → id`; `Union` | ✅ | `lessEntry` compartido por `buildStageChain`, `NewStagePlan` y `groupBatches` |
| `users` = `Subject` o `Email()` minúsculas; `groups` regla `Grant.Allows` | ✅ | `Normalize` solo pasa a minúsculas entradas con `@` |
| Anulación por `slug` solo sin scope | ✅ | `partitionScoped` + `mergeScoped` (dedupe por id) |
| Prune deja `{}`; fuera del puerto de dominio | ✅ | Adaptador de snapshot intacto |
| `InstanceOf` `json:"instance_of,omitempty"` en el snapshot | ⚠️ Desviación | Implementado `json:"-"` y rellenado también en `configuredRegistry` (decisión del maintainer en 2a, `tasks.md` 5.4). Correcto: el scoper construye la vista por request en el data plane, así que el snapshot no lo necesita. `TestRegistry_InstanceOfNeverSerialises` lo fija |
| Admin API `400 ErrInvalidMCPScope` | ⚠️ Desviación | Es **422 `validation_failed`** (mapeo del repo para `ErrValidation`); `?registry_id=` no-uuid → 400 `invalid_query`. Cumple el "4xx" de la spec; OpenAPI, docs y funcionales están alineados con 422 |
| `MCPScopePatch{Set, Value}` tri-estado | ✅ | DTO `json.RawMessage` + `parseMCPScopePatch`; el `request` no importa `app` |
| `PreRequest(ctx, rc, ToolCall)` | ✅ | En 3a convivió `PreRequestCall`; 3b dejó las firmas del diseño |
| `Matched` con ids | ✅ (según diseño) | `trace.MCPPolicyScope.Matched []string` = ids; `Skipped` lleva id+name. Consecuencia: el consumidor del evento debe resolver id → nombre para `matched` |
| `scoped` "todas, solo para Explain" | ✅ con matiz | Incluye las `{}` habilitadas (aparecen como `Skipped/destination` y cuentan en `Evaluated`); `tasks.md` 6.1 dice que "se descartan al construir" (se descartan de los planes, no de `scoped`). El comentario del código es el correcto |
| Metadata `mcp.tool` / `mcp.registry_id` / `mcp.exposed_tool` | ✅ + extra | Añadido `mcp.registry_name` porque la spec lo exige (§RequestContext); el diseño no lo listaba |
| Attach `204` o `200 {"warnings"}` | ✅ | Open Question del diseño sigue **abierta**: falta confirmar el contrato con `app` |
| `Warner` calculado en create/update | ✅ con matiz | Lo invocan los handlers tras la escritura (no `Creator`/`Updater`); fallo del Warner → `slog` y respuesta sin `warnings`. Además `POST /global` devuelve `warnings` (no previsto en el diseño, necesario para el escenario "trustguard global con scope") |
| Rechazo de scope en consumer LLM en `validatePolicyProtocol` | ⚠️ Más estricto | Guard separado `validatePolicyScope` con `ErrPolicyScopeRequiresMCP` (envuelve `ErrPolicyProtocolMismatch`); rechaza en cualquier `Type != TypeMCP` (A2A incluido) y también `{}` |
| Telemetría "solo con span" | ✅ | `policy_scope` va en el JSON del evento; **no** se aplana a atributo OTLP (documentado en `docs/telemetry/otlp-metadata-contract.md`) |
| Cap `maxPrincipalScopedPerDest` (Open Question) | ✅ Cerrada | Bench 1,9× en allocs (< 2×): no se añade cap |
| Timestamp de migración (Open Question) | ✅ Cerrada | `20260916120000_add_policy_mcp_scope` |

## Issues

**CRITICAL**: ninguno.

**WARNING**

1. **Escenario funcional en SKIP** (`tests/functional/mcp_policy_scope_test.go:255`): la exención positiva de `except_groups` (y, por extensión, el match positivo de `groups`/`users` end-to-end) no se prueba con un token real porque `oauthIDPStub` descarta la clave de firma y no hay helper que emita un bearer MCP con `groups`. Cubierto solo en unitarios (SC 3 y SC 9 PARTIAL). Follow-up: helper de token en la suite funcional.
2. **Duplicar una policy podada a `{}` falla con 422**: `Duplicator` clona el scope (`cloneMCPScope`, `duplicator.go`) → `Creator` → `validateMCPScope` rechaza `IsEmpty()` (`validate.go:66`, "scope has no entries"). `TestDuplicator_CopiesMCPScope` solo cubre un scope completo. Decidir: mapear `{}` → `nil` al duplicar (ojo: ensancharía la copia a todo el consumer), copiar `{}` saltando la regla, o documentar el 422.
3. **`policy_scope` no viaja como atributo OTLP**: solo en el JSON del evento (`events.MCP.PolicyScope`). Sinks OTLP-only no ven la decisión. Documentado como "not flattened yet".
4. **Orden de despliegue**: un data plane antiguo ignora `mcp_scope` y ejecuta la policy consumer-wide (el snapshot lleva el campo dentro del JSON de `Policy`). Data plane antes que control plane; no crear policies con scope hasta terminar. Documentado en `docs/mcp-policy-scope.md` §Rollout; riesgo operativo, no de código.
5. **Contrato de attach (`204` / `200 {"warnings"}`) sin confirmar con `app`** (Open Question del diseño). Cambio de una línea si la UI prefiere `200` siempre.
6. **Ruido en `Explain` por policies `{}`**: una policy podada y habilitada aparece en `Skipped/destination` en cada `tools/call` y cuenta en `Evaluated` hasta que se le dé destino o se deshabilite. Es coherente con "la policy queda dormida", pero conviene que la UI lo muestre.
7. **Test `RewrittenNameDoesNotReroute` no aserta el warning** exigido por la spec ("se loguea un warning"); el log existe en `plugin_runner.go:190`.

**SUGGESTION**

- Añadir un test unitario o funcional con toolkit `expose_as` + scope por tool (escenario `expose_as` de `mcp-policy-scope`), hoy cubierto solo por la ruta de código y el caso federado.
- Funcional del Store con una global con scope (`registry_ids: [shelf]`) contra una instancia clonada; hoy la evidencia es unitaria.
- Alinear la nota de `tasks.md` 6.1 ("se descartan … los scopes `{}`") con el comportamiento real (se conservan en `scoped` para `Explain`).
- `make gen-mocks` en CI para confirmar diff limpio de los mocks (la versión pinada v2.53.7 coincide con la cabecera de los mocks generados; no se ha ejecutado aquí).

## Riesgos abiertos (proposal.md / exploration.md G1–G5)

| Riesgo | Estado |
|---|---|
| Scope por nombre expuesto (hash `naming.go`) | Mitigado: clave `(registry_id, tool nativa)`; funcional federado PASS |
| Anulación por `slug` apaga la TrustGuard global | Mitigado: scoped fuera de `composePolicies`; `TestDataFinder_…SlugOverrideOnlyAmongUnscopedPolicies` |
| Prune deja `NULL` | Mitigado: `{}`; test de repo en la misma tx |
| IdP sin `email` | Mitigado: `sub` o email |
| Store multi-instancia sin match | Mitigado: `InstanceOf`/`ScopeKey` (unit) |
| Data plane antiguo ejecuta consumer-wide | Abierto (operativo): orden de despliegue documentado |
| G2 clave de grupo por nombre / `acts_for_users` sin grupos | Fuera de este cambio; documentado en `docs/mcp-policy-scope.md` |
| G3 doble ejecución | Mitigado: `warnings` + `ScopeDecision`; no bloqueante |
| G5 validación en dev (`multi-agent-tests` `.env.dev`) | Fuera de este cambio; la E2E apunta a prod |
| Coste `groupBatches` por request | Medido: `principal_scoped` 2485 ns / 72 allocs vs 1309 ns / 38 allocs; sin cap |

## Presupuesto de revisión (realidad frente a `tasks.md`)

| Medida | Valor |
|---|---|
| `git diff --shortstat` (ficheros ya trackeados) | **78 files changed, 4454 insertions(+), 382 deletions(-)** |
| Ficheros nuevos sin trackear | **26**: 17 de código/docs (**3.778 líneas**) + 9 de `openspec/` (specs y artefactos del change; no son código) |
| Generados | `docs/openapi.json`, `docs/swagger.{json,yaml}`, `docs/docs.go`, `mocks/mcp_composer_mock.go`: 854 ins / 75 del; `mocks/policy_warner_mock.go` nuevo: 159 líneas → ≈1.013 líneas generadas |
| Tests | 33 `_test.go` modificados: 2.706 ins / 166 del; 9 `_test.go` nuevos: 2.363 líneas → ≈5.069 líneas de test |
| Total aproximado (código + tests + generados + docs, sin `openspec/`) | ≈8.230 líneas añadidas, ≈380 borradas |
| Previsión de `tasks.md` | ≈3.000 a mano + ≈430 generadas |

La previsión se queda muy corta sobre todo en tests (≈5.000 frente a los "≈3.000 a mano" que incluían tests) y en generados (≈1.000 frente a 430: el mock del `Composer` con expecter y el OpenAPI pesan más). El código productivo a mano (≈2.150 líneas) sí está en el orden previsto. La `size:exception` aceptada por el maintainer sigue siendo la vía; la revisión commit a commit según la tabla de slices de `tasks.md` es imprescindible con este volumen.

## Ready to open PR

**Sí**, con `size:exception` y dejando constancia en el cuerpo del PR de:

1. El escenario funcional en SKIP (exención positiva de `except_groups`) y su follow-up (helper de bearer MCP con `groups`).
2. El 422 (no 400) para `ErrInvalidMCPScope` y el contrato de attach `204`/`200 {"warnings"}` pendiente de confirmar con `app`.
3. El comportamiento al duplicar una policy podada a `{}` (422) hasta decidir el mapeo.
4. El orden de despliegue (data plane antes que control plane) y que `policy_scope` no se aplana aún a atributo OTLP.

No queda ninguna tarea de código pendiente; los gates locales (unit `-race`, lint, vet, OpenAPI, repositorios contra Postgres, funcional completa `-race`) están verdes.
