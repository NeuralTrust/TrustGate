# Especificación: mcp-registry-tool-discovery

## Purpose

Define `GET /v1/gateways/{gw}/registries/{id}/tools` (`ListRegistryToolsHandler` sobre `appmcp.Introspector`) como la fuente del catálogo de tools que la consola usa para construir `mcp_scope.tools[]`. El endpoint ya existe; esta capability fija los nombres que devuelve, el **409** para un registry que no se puede introspeccionar sin un principal, y el **502** cuando el upstream responde pero `tools/list` falla —que hoy sale como 500—. El cacheo queda explícitamente fuera.

## Requirements

### Requirement: Nombres nativos, sin prefijo ni alias

La respuesta MUST llevar el nombre **nativo** que el upstream declara, tal cual: el introspector MUST NOT pasar por `resolveNames`. Ese es exactamente el valor que `mcp_scope.tools[].tool` almacena, así que un nombre expuesto (`mcp_<hash>_…`) o un alias `expose_as` haría que el scope escrito desde la consola no casara nunca.

Cada tool MUST pasarse tal como el servidor la declaró (nombre más lo que exponga, por ejemplo `description` e `inputSchema`). Una lista vacía MUST serializarse como `[]`, no como `null`.

#### Scenario: Registry federado

- GIVEN un registry cuyas tools se exponen como `mcp_ab12cd34_run_query_9f8e7d6c`
- WHEN se pide el listado
- THEN la respuesta trae `run_query`

#### Scenario: Toolkit con `expose_as`

- GIVEN un toolkit que expone `run_query` como `consulta`
- WHEN se pide el listado
- THEN la respuesta trae `run_query`, que es la clave que el scope guarda

#### Scenario: Sin tools

- GIVEN un servidor MCP que no declara ninguna tool
- WHEN se pide el listado
- THEN responde 200 con `{"tools": []}`

### Requirement: `409` para un registry que no se introspecciona

`ErrRegistryNotIntrospectable` MUST devolverse cuando `perPrincipalAuth(reg) || reg.MCPTarget.HasURLVariables()`, y el handler MUST mapearlo a **409**. MUST NOT ser 422: la petición está bien formada; es el registry el que no admite una introspección sin principal.

Un registry per-principal no tiene un catálogo único: depende de quién pregunte. Un target con variables de URL ni siquiera tiene una URL que marcar. En los dos casos el cliente MUST poder distinguir "aquí no hay catálogo, escribe el nombre a mano" de "el upstream falló, reintenta".

#### Scenario: Auth per-principal

- GIVEN un registry con modo de auth per-principal (por ejemplo `passthrough`)
- WHEN se pide el listado
- THEN responde 409

#### Scenario: Variables de URL

- GIVEN un registry cuyo `MCPTarget` lleva variables en la URL
- WHEN se pide el listado
- THEN responde 409

#### Scenario: Los dos a la vez

- GIVEN un registry que cumple los dos predicados
- WHEN se pide el listado
- THEN responde 409 una sola vez, con el mismo error

### Requirement: `502` cuando el upstream falla, también en `tools/list`

El introspector MUST envolver con `ErrUpstreamUnavailable` **tanto** el fallo de `Connect` **como** el de `ListTools`. Hoy envuelve el primero y devuelve `up.ListTools(ctx)` crudo, así que con el upstream accesible y `tools/list` fallando `errors.Is(err, ErrUpstreamUnavailable)` es falso en el handler y sale **500 en vez de 502**.

#### Scenario: Upstream inalcanzable

- GIVEN un registry cuyo servidor MCP no acepta la conexión
- WHEN se pide el listado
- THEN responde 502

#### Scenario: `tools/list` falla con la conexión abierta

- GIVEN un servidor MCP que acepta la conexión y devuelve error en `tools/list`
- WHEN se pide el listado
- THEN responde 502, no 500

### Requirement: Registry inexistente, de otro gateway o no MCP

Un `id` que no existe o que pertenece a otro gateway MUST responder **404**. Un registry que existe pero no es MCP MUST responder con el error de "no es un registry MCP", nunca con un 200 vacío que el cliente leería como "este servidor no tiene tools".

#### Scenario: Registry de otro gateway

- GIVEN un `registry_id` válido de otro gateway
- WHEN se pide el listado
- THEN responde 404

#### Scenario: Registry no MCP

- GIVEN un registry que no es MCP
- WHEN se pide el listado
- THEN responde con error, no con `{"tools": []}`

### Requirement: Síncrono y sin cachear

El endpoint MUST resolverse de forma síncrona contra el upstream. MUST NOT cachearse en el `TTLMap` `mcp_tools` mientras no exista el 409.

El motivo es **de seguridad, no de rendimiento**: para un registry per-principal la clave de caché tendría que incluir el principal; si no, el catálogo de un tenant se sirve a otro. El 409 es precisamente el que declara "este registry no se introspecciona sin principal", así que cachear antes de tenerlo es abrir la fuga. Un cacheo posterior MUST usar la clave `(gateway, registry, principal?)`.

Tampoco MUST hacerse prefetch del catálogo de todos los registries al abrir un panel: son N conexiones de las que la mayoría no se despliegan nunca.

#### Scenario: Dos llamadas seguidas

- GIVEN dos peticiones consecutivas al mismo registry
- WHEN se sirven
- THEN las dos consultan el upstream

### Requirement: Contrato declarado en OpenAPI

`docs/openapi.json` y `docs/swagger.*` MUST declarar **409** y **502** en este endpoint, regenerados con `make openapi` y no editados a mano.

#### Scenario: Spec regenerada

- GIVEN el handler anotado con los códigos nuevos
- WHEN se corre `make openapi`
- THEN la spec declara 200, 400, 401, 404, 409 y 502, y `docs/openapi_test.go` pasa
