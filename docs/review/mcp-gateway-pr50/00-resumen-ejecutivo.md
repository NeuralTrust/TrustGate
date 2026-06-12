# Revisión arquitectónica PR #50 (`feat/mcp_gateway`) — Resumen ejecutivo

> Revisión de los 171 archivos de la PR contra las reglas del proyecto: SOLID, Clean Code y
> Arquitectura Hexagonal (`handlers → app → domain ← infra`).
>
> El análisis está dividido en fases que siguen el plan épico de la PR
> (`docs/design/trustgate-mcp-gateway-epic-plan.md`):
>
> | Documento | Fase | Ámbito |
> |---|---|---|
> | [01-fase-1-inbound-auth.md](01-fase-1-inbound-auth.md) | Fase 1 | Validación de credenciales inbound: `infra/auth/{oidc,introspection,mtls}`, `middleware/auth_chain`, `domain/identity` |
> | [02-fase-2-mcp-dataplane.md](02-fase-2-mcp-dataplane.md) | Fase 2 | Dataplane MCP: `app/mcp` (composer, session, introspector), `infra/mcp/client`, `mcp_handler`, toolkit |
> | [03-fase-3-oauth.md](03-fase-3-oauth.md) | Fase 3 | OAuth 2.1 RS/AS: `app/oauth`, `infra/oauth`, handlers OAuth, `oauth_challenge` |
> | [04-fase-4-sts-vault.md](04-fase-4-sts-vault.md) | Fase 4 | STS y federación de credenciales: `app/identity/sts`, `app/mcp/credentials`, `domain/vault`, `infra/crypto` |
> | [05-transversal.md](05-transversal.md) | Transversal | Domain, container/DI, convenciones, deuda preexistente y plan de remediación |
> | [06-cobertura.md](06-cobertura.md) | Cobertura | Matriz de los 171 archivos de la PR y quién revisó cada uno |
> | [07-tests.md](07-tests.md) | Tests | Auditoría de la suite de tests, mocks y helpers |
> | [08-fase-6-server-lifecycle.md](08-fase-6-server-lifecycle.md) | Fase 6 | Ciclo de vida HTTP (`pkg/server`), arranque del plano MCP (`main` → `server_mcp` → listener) y deps del router |

## Veredicto general

La PR es funcionalmente sólida (buena cobertura de tests, errores sentinel, validación rica en
`MCPTarget`/`Toolkit`, stores OAuth en Redis multi-réplica), pero **rompe sistemáticamente la
dirección de dependencias hexagonal en el eje MCP** y concentra infraestructura dentro de
`pkg/app`. Los tres problemas estructurales son:

### 1. `pkg/app/mcp` es en gran parte infraestructura (el "pifostio" del composer)

- `composer.go` (640 líneas) mezcla **4 interfaces** en un archivo (`Upstream`, `Dialer`,
  `DialerFunc`, `Composer`) y al menos 3 responsabilidades: federación/selección de toolkit
  (lógica de dominio), caching TTL (infra) y construcción de targets/credenciales (infra).
- `session.go` es un **pool de conexiones** con mutex, fingerprint SHA-256 y eviction TTL:
  infraestructura pura viviendo en `app`.
- Toda la API pública de `app/mcp` (incluido el puerto `Composer`) está tipada con
  `pkg/infra/mcp/client.Tool/Target/...`: **infra define el contrato y app lo consume**,
  exactamente la inversión de dependencias al revés.

### 2. `pkg/app/oauth` y `pkg/app/identity/sts` contienen adaptadores HTTP y crypto

`dcr.go`, `provider.go`, `metadata.go`, `proxy.go` y `exchanger.go` hacen llamadas HTTP reales
(discovery RFC 8414/9728, DCR RFC 7591, token endpoints); `signer.go` y `proxy.go` hacen crypto
(RSA, JWT, PKCE, SHA-256). Nada de eso es orquestación de casos de uso: son adaptadores driven
que deberían vivir en `pkg/infra/{oauth,identity}` detrás de puertos.

### 3. La capa HTTP no es fina en el eje MCP

`mcp_handler.go` (370 líneas) implementa un servidor JSON-RPC completo (dispatch, handshake
`initialize`, mapeo de errores multinivel, autorización por consumer duplicada de
`proxy_handler.go`) e importa `pkg/infra/mcp/client`. `list_registry_tools_handler.go` y
`jwks_handler.go` también dependen de tipos concretos.

## Recuento de hallazgos

| Fase | Alta | Media | Baja |
|---|---|---|---|
| Fase 1 — Inbound auth | 6 | 9 | 8 |
| Fase 2 — Dataplane MCP | 9 | 8 | 8 |
| Fase 3 — OAuth | 10 | 26 | 16 |
| Fase 4 — STS / Vault | 7 | 14 | 12 |
| Transversal / Domain | 4 | 13 | 14 |
| Fase 6 — Server lifecycle | 0 | 4 | 5 |
| Tests | 3 | 4 | 7 |
| **Total** | **~39** | **~78** | **~70** |

## Hotfixes previos al refactor (bugs funcionales/seguridad, independientes de la arquitectura)

| ID | Qué | Por qué urge |
|---|---|---|
| T-04 | `consumer.Rehydrate` descarta `Toolkit`/`FailMode` | Fail-open de autorización: un consumer MCP rehidratado expone TODAS las tools/prompts/resources |
| T-03 | `registry.Rehydrate` descarta `Type`/`MCPTarget` | Entidad corrupta/coerción a LLM en la API pública de rehidratación |
| F4-18 | `tokenEndpointFor` asume convención Okta para todo IdP no-Entra | El exchange STS falla en silencio con Auth0, Keycloak, etc. |
| F4-19 | Cache de tokens del `Exchanger` sin purga ni límite | Fuga de memoria por réplica en multi-tenant |
| F1-04 | Cache de introspection nunca borra entradas expiradas | Fuga de memoria |
| F1-13 / F1-09 / TST-03 | XFCC aceptado de cualquier peer + fail-open del path scope (consagrado por test) | Decisión de seguridad sin documentar; potencial spoofing/degradación de aislamiento |
| F4-15 | Secretos de `mcp_target` en JSONB plano (vs vault cifrado) | Datos sensibles en claro en BD |
| OPS-3 / F4-17 | `STS_SIGNING_KEY` vacío con `replicas: 2` en prod | JWKS inconsistente entre réplicas: validación intermitente |

## Las 10 acciones de mayor impacto (orden sugerido)

1. **Invertir el eje MCP**: definir tipos `Tool/Prompt/Resource/Target` y puertos
   (`Dialer`, `Upstream`) en `app/mcp` (o `domain/mcp`) y hacer que `infra/mcp/client`
   los implemente y mapee desde el SDK. Elimina los imports `app → infra` y
   `handler → infra` de golpe. (Fase 2)
2. **Trocear `composer.go`**: separar selección de toolkit (dominio puro, testeable sin mocks),
   federación con cache (servicio app con puerto de cache) y construcción de
   target/credenciales (junto a `credentials.go`). Una interfaz por archivo. (Fase 2)
3. **Mover `session.go` (cachedDialer) a `pkg/infra/mcp`**: es un connection pool. (Fase 2)
4. **Adelgazar `mcp_handler.go`**: extraer el dispatch JSON-RPC y el mapeo de errores a
   `app/mcp`; compartir la autorización por consumer con `proxy_handler.go`. (Fase 2)
5. **Extraer adaptadores HTTP de `app/oauth`**: `UpstreamRegistrar` (DCR), `ProviderClient`,
   `metadataService` (fetch), `idpTokenCall` → `pkg/infra/oauth`, unificando el cliente de
   token OAuth que hoy está triplicado. (Fase 3)
6. **Mover `sts.Signer` a `pkg/infra/identity`** detrás de un puerto `TokenSigner`;
   el handler JWKS deja de depender de `*sts.Signer` concreto. (Fase 4)
7. **Subir los puertos de validación de `middleware/auth_chain.go` a `app/auth`** y unificar
   el audience-matching (hoy OIDC e introspection se comportan distinto). (Fase 1)
8. **Arreglar la fuga de memoria del cache de introspection** (las entradas expiradas nunca
   se borran) y poner poda/TTL en los caches de JWKS y discovery. (Fase 1)
9. **Completar el dominio**: `Rehydrate` de registry/consumer sin soporte MCP/toolkit,
   invariantes type-aware del Consumer MCP, sacar `PrincipalFromContext` de domain. (Transversal)
10. **Convenciones**: una interfaz por archivo, `//go:generate mockery` en todos los puertos
    nuevos, constructores que devuelven interfaz, DTOs `request/` con `Validate()` en OAuth/MCP.
    (Transversal)
11. **Consolidar `pkg/server`**: `BaseServer` implementa `Server`, `plane_*.go` con stacks de
    middleware y factories de plano; `modules/server_*` solo wrap-up dig; `MCPRouterDeps`.
    (Fase 6)

## Qué está bien y conviene conservar

- Stores OAuth sobre Redis con `GETDEL` atómico: correcto para multi-réplica.
- `vault.Repository`: puerto en domain, mapeo `pgx.ErrNoRows → ErrNotFound`, cifrado at-rest.
- Validación de invariantes en `MCPTarget`, `Toolkit` y `Gateway.Domain`.
- `server_mcp.go` (composition root del plano MCP) limpio, solo ensambla.
- El orden anti-downgrade del `auth_chain` (mTLS → Bearer → API key) y el scoping por path.
- Sesiones MCP process-local: decisión documentada y permitida por la spec Streamable HTTP.
