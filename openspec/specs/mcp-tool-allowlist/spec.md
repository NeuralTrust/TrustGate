# Especificación: mcp-tool-allowlist

## Purpose

Extiende el plugin `tool_allowlist` (`pkg/infra/plugins/toolallowlist`) al plano MCP. Hoy solo soporta `ProtocolLLM` y filtra la lista `tools` de una petición LLM; en MCP decide sobre la tool nativa de una `tools/call` leída de `Request.Metadata["mcp.tool"]` y, combinado con `mcp_scope`, es el primitivo de denegación ("solo Finanzas puede `run_query`").

## Requirements

### Requirement: Soporte de `ProtocolMCP`

`SupportedProtocols()` MUST incluir `ProtocolMCP` además de `ProtocolLLM`. La asociación a consumers MCP MUST aceptarse; catálogo, schema y `ValidateConfig` MUST ser los mismos en ambos protocolos.

#### Scenario: Asociar a un consumer MCP

- GIVEN una policy `tool_allowlist` con `deny_tools: ["*"]`
- WHEN se asocia a un consumer MCP
- THEN la asociación se acepta

#### Scenario: Config inválida

- GIVEN `settings` sin `allow_tools` ni `deny_tools`
- WHEN se valida
- THEN se rechaza igual que hoy

### Requirement: Tool nativa desde `Metadata["mcp.tool"]`

En MCP el plugin MUST evaluar el nombre nativo de `Request.Metadata["mcp.tool"]`, nunca `Body.name`. Si el metadato falta MUST comportarse como no-op (`okResult`).

#### Scenario: Consumer federado

- GIVEN `Body.name = mcp_ab12_run_query_9f8e` y `Metadata["mcp.tool"] = run_query`
- WHEN corre `PreRequest` con `deny_tools: [run_query]`
- THEN la llamada se deniega

#### Scenario: Sin metadato

- GIVEN un `RequestContext` MCP sin `Metadata["mcp.tool"]` (por ejemplo discovery)
- WHEN corre el plugin
- THEN devuelve OK sin bloquear ni reescribir

### Requirement: Semántica `allow_tools` / `deny_tools`

Con `allow_tools` no vacío la tool MUST coincidir con algún patrón; cualquier coincidencia en `deny_tools` MUST denegar; deny MUST ganar a allow. Los patrones MUST usar la misma semántica glob que en LLM (`path.Match` con `/` escapado).

#### Scenario: Allow por prefijo

- GIVEN `allow_tools: ["run_*"]`
- WHEN se llama a `run_query`
- THEN se permite
- AND `delete_table` se deniega

#### Scenario: Deny gana

- GIVEN `allow_tools: ["run_query"]` y `deny_tools: ["run_query"]`
- WHEN se llama a `run_query`
- THEN se deniega

#### Scenario: Denegar todo

- GIVEN `deny_tools: ["*"]`
- WHEN se llama a cualquier tool
- THEN se deniega

### Requirement: Denegación en MCP

Una tool denegada en modo `enforce` MUST devolver `StopUpstream` y el dispatcher MUST responder un error JSON-RPC `-32001` sin invocar el upstream; el estado HTTP MUST ser 200, como toda denegación de policy en el plano MCP (`httpStatusForRPCError`, `pkg/api/handler/http/mcp/mcp_handler.go:397-399`; un no-2xx rompe la sesión MCP del cliente). En MCP MUST NOT aplicarse `on_empty_after_filter` (una `tools/call` es binaria). En modo `observe` la llamada MUST continuar y el evento MUST registrar la decisión.

#### Scenario: Enforce

- GIVEN `deny_tools: ["*"]`, `mode: enforce`
- WHEN se llama a `run_query`
- THEN la respuesta es `-32001`, el upstream no recibe la llamada y el evento marca `rejected`

#### Scenario: Observe

- GIVEN la misma policy con `mode: observe`
- WHEN se llama a `run_query`
- THEN la llamada llega al upstream y el evento registra la decisión sin bloquear

### Requirement: Patrón "solo el grupo X"

Combinado con `mcp_scope`, `deny_tools: ["*"]` + `tools: [{registry, tool}]` + `except_groups: [X]` MUST denegar la tool a todos salvo a X.

#### Scenario: Finanzas permitido

- GIVEN esa policy sobre `run_query` con `except_groups: [Finanzas]`
- WHEN Finanzas llama a `run_query`
- THEN la policy no entra en el plan y la llamada prosigue

#### Scenario: Marketing denegado

- GIVEN la misma policy
- WHEN Marketing llama a `run_query`
- THEN responde `-32001`

### Requirement: Plano LLM sin cambios

El comportamiento en `ProtocolLLM` MUST ser idéntico al actual: filtrado de `tools` del body, `on_empty_after_filter`, detección de claves ambiguas.

#### Scenario: Petición LLM con tools

- GIVEN una petición OpenAI con dos tools y `allow_tools` que acepta una
- WHEN corre el plugin
- THEN el body se reescribe con la tool permitida, como hoy

#### Scenario: Lista vacía tras filtrar

- GIVEN `on_empty_after_filter: reject`
- WHEN ninguna tool pasa
- THEN responde 403 como hoy
