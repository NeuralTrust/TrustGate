# Asociación auth ↔ consumer (reglas duras)

| Tipo consumer | routing_mode | Nº auths | Tipos de auth permitidos |
|---|---|---|---|
| LLM / A2A | inline | varios | `api_key`, `oauth2`, `idp`, `mtls` |
| MCP | inline | varios | `api_key`, `oauth2`, `mtls` (❌ `idp`) |
| LLM / A2A | role_based | máx. 1 | `oauth2` o `idp` |
| MCP | role_based | máx. 1 | solo `oauth2` |

## Reglas asociadas

- Los auths se gestionan **solo** por los endpoints de attach/detach (no se setean al crear/actualizar el consumer).
- El auth debe pertenecer al **mismo gateway** que el consumer.
- `role_based` ⇒ máx. 1 auth y de tipo identity-provider (`oauth2`/`idp`).
- `MCP` ⇒ nunca `idp`.
- La intersección `MCP` + `role_based` ⇒ **solo `oauth2`**.

> El backend rechaza estas violaciones con un error de conflicto (HTTP 409).
