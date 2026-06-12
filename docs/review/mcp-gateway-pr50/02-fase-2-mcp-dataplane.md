# Fase 2 — Dataplane MCP (composer, sesiones, handler JSON-RPC)

Ámbito: `pkg/app/mcp/{composer,session,introspector,errors}.go`, `pkg/infra/mcp/client/*`,
`pkg/api/handler/http/mcp/mcp_handler.go`, `pkg/domain/consumer/toolkit.go`,
`pkg/domain/registry/mcp_target.go`, `pkg/app/consumer/path_resolver.go`,
`pkg/api/handler/http/registry/list_registry_tools_handler.go`, `pkg/container/modules/mcp.go`.

Esta fase concentra el problema estructural de la PR: **infra define el contrato del eje MCP
y app/handlers lo consumen**, y el paquete `app/mcp` mezcla dominio, aplicación e
infraestructura en los mismos archivos.

## Hallazgos de severidad alta

### F2-01 · `app/mcp` importa `pkg/infra/mcp/client` y `pkg/infra/cache` — DIP / Hexagonal

`composer.go` (líneas 21–22), `credentials.go` (16), `session.go` (13) e `introspector.go` (9)
importan infra. Peor: el propio puerto `Composer` y las interfaces `Upstream`/`Dialer` están
tipadas con `mcpclient.Tool`, `mcpclient.Target`, `mcpclient.Prompt`… Es decir, el contrato de
la capa de aplicación lo dicta el adaptador. Cualquier cambio del SDK MCP se propaga a app,
handlers y tests.

**Refactor**: definir en `app/mcp` (o `domain/mcp`) los tipos `Tool`, `Prompt`, `Resource`,
`ResourceTemplate`, `Target` y los puertos `Dialer`/`Upstream`; `infra/mcp/client` los
implementa y mapea desde el SDK (los type-aliases de `protocol.go` pasan a ser structs propios).
Esto resuelve a la vez F2-06, F2-07 y los imports de handlers (F2-08).

### F2-02 · `composer.go`: 4 interfaces y 3 responsabilidades en 640 líneas — SRP / ISP / Clean Code

Un solo archivo contiene:

- **Interfaces**: `Upstream` (10 métodos), `Dialer`, `DialerFunc` y `Composer` (7 métodos).
  Regla del proyecto: una interfaz (caso de uso) por archivo.
- **Lógica de dominio pura**: `selectTools`, `selectPrompts`, `resolveNames`,
  `resolveExposedNames`, `sanitizeName` — aplican el `Toolkit` (domain) y resuelven colisiones.
  No necesitan contexto, red ni cache: son funciones de dominio testeables en aislamiento.
- **Orquestación con infraestructura**: `discoverCached` construye claves de cache con
  formato de timestamp, usa `cache.TTLMap` (tipo concreto de infra) y hace type-assertions
  `cached.([]T)` no tipadas.
- **Construcción de credenciales/targets**: `target`, `targetFor`, `perPrincipalAuth`,
  `Target()` — pertenecen al eje de credenciales (Fase 4), no a la composición.

**Refactor sugerido** (estructura objetivo):

```
pkg/domain/mcp/            # o pkg/domain/consumer si se prefiere no crear contexto
  selection.go             # selectTools/selectPrompts sobre tipos de dominio
  naming.go                # resolveExposedNames, sanitizeName
pkg/app/mcp/
  composer.go              # interfaz Composer + orquestación (sin cache concreto)
  dialer.go                # puertos Dialer/Upstream (tipos propios)
  discovery.go             # discoverCached contra un puerto DiscoveryCache
  target_builder.go        # target/targetFor/perPrincipalAuth junto a credentials
pkg/infra/mcp/
  client/                  # adaptador SDK (mapea a tipos de app)
  session_cache.go         # cachedDialer (hoy app/mcp/session.go)
```

### F2-03 · `session.go` es un connection pool en la capa de aplicación — Hexagonal

`cachedDialer` gestiona ciclo de vida de conexiones: mutex, mapa de sesiones,
fingerprint SHA-256 de headers (`crypto/sha256` en app), eviction por TTL de 30 min, retry
de operaciones sobre sesión muerta. Es un adaptador de infraestructura de manual; su único
vínculo con el caso de uso es implementar `Dialer`.

**Refactor**: mover a `pkg/infra/mcp/session_cache.go` implementando el puerto `Dialer` de app.
El diseño interno (pin key + fingerprint, retry-once, sesiones process-local) está bien y se
conserva tal cual.

### F2-04 · `mcp_handler.go` es un servidor de protocolo, no un handler fino — SRP / Hexagonal

370 líneas que incluyen: dispatch JSON-RPC de 10 métodos (`switch req.Method`), negociación de
`protocolVersion` y `capabilities` en `initialize`, detección de notificaciones, construcción
de `connect_url` para consent, y traducción de errores multinivel (`writeComposerError`,
~259–303, conoce `ConsentRequiredError`, `sts.ErrInteractionRequired`, códigos JSON-RPC…).
La regla del proyecto es: parsear, validar DTO, llamar a app, mapear errores.

**Refactor**: `app/mcp.RPCGateway` con `Handle(ctx, principal, rc, raw []byte) ([]byte, error)`
que encapsule dispatch + mapeo a `RPCError`; el handler queda en parseo del body, resolución
del consumer (ver F2-05) y escritura de la respuesta.

### F2-05 · Autorización por consumer duplicada del proxy — DRY

`resolveMCPConsumer`/`hasAuth` (~341–370) duplican casi línea a línea
`resolveConsumer`/`consumerHasAuth` de `proxy_handler.go` (~158–202): match de path, check de
tipo, validación de `AuthIDs`.

**Refactor**: middleware de autorización por consumer o servicio `app/consumer.AccessChecker`
compartido por ambos planos.

### F2-06 · `infra/mcp/client`: type-aliases del SDK como contrato público — DIP

`protocol.go` (~24–29) re-exporta los tipos del SDK MCP con alias. Cualquier consumidor
(app, handlers, tests) queda acoplado transitivamente al SDK.

**Refactor**: parte de F2-01 — structs propios + mappers en el adaptador.

### F2-07 · Errores con semántica de aplicación definidos en infra — Hexagonal

`mcpclient.ErrUnreachable` y `ErrNotSupported` gobiernan decisiones de app (fail_mode,
fallback de `ReadResource`), pero los define infra. `IsRPCError` (utilidad de app) también
vive allí.

**Refactor**: mover los sentinels a `app/mcp/errors.go`; infra envuelve los errores del SDK.

### F2-08 · Handlers que importan `pkg/infra/mcp/client` — DIP

- `mcp_handler.go` (línea 21) para `Tool/Resource/Prompt/RPCError`.
- `list_registry_tools_handler.go` (línea 9): la response expone `[]mcpclient.Tool` crudo,
  mientras el resto del admin API mapea a DTOs de `response/`.

**Refactor**: con F2-01 resuelto, los handlers consumen tipos de app; añadir
`registry/response/mcp_tool_response.go`.

### F2-09 · El container registra el cliente MCP como tipo concreto — DIP

`container/modules/mcp.go` (~27–33) registra `mcpclient.New` devolviendo `*Client` y
`NewCachedDialer` recibe el concreto.

**Refactor**: registrar factories que devuelvan los puertos de app.

## Hallazgos de severidad media

| ID | Archivo | Hallazgo | Refactor |
|---|---|---|---|
| F2-10 | `composer.go` ~451–480 | `discoverCached`: cache key artesanal (`kind:id:updated_at` con formato de fecha) + type-assertion genérica silenciosa; si falla el cast se relanza el fetch sin log | Puerto `DiscoveryCache` tipado; log en cast fallido (como hace `path_resolver.cached`) |
| F2-11 | `composer.go` ~26–37 | `Upstream` con 10 métodos es interfaz gorda (ISP); `Introspector` solo necesita `ListTools` + `Close` | Trocear (p.ej. `ToolLister`, `ResourceReader`, `PromptGetter`) o aceptar y documentar; mínimo: separar a `dialer.go` |
| F2-12 | `composer.go`, `introspector.go` | `Dialer`, `Upstream` e `Introspector` sin `//go:generate mockery` (solo `Composer` lo tiene) | Añadir directivas |
| F2-13 | `domain/consumer/toolkit.go` | Toolkit (reglas de exposición de superficies MCP) vive en el bounded context `consumer`; el composer reimplementa la *aplicación* de esas reglas en app | Valorar `domain/mcp` con `Toolkit`; al mover `selectTools/selectPrompts` a domain, la política queda junto al dato |
| F2-14 | `app/consumer/path_resolver.go` (14) | Mismo patrón `app → infra/cache` (preexistente en todo el repo, ver doc transversal); el resolver en sí está bien diseñado | Cubierto por la deuda transversal T-01 |
| F2-15 | `mcp_handler.go` ~94–100, 174–241 | Structs `rpcRequest`, `callToolParams`… inline con validación manual (`params.Name == ""`); sin `request/` + `Validate()` | Carpeta `mcp/request/` siguiendo la convención del admin API |
| F2-16 | `mcp_handler.go` ~287–290 | Mezcla de canales de error: `sts.ErrInteractionRequired` → HTTP 401, resto → JSON-RPC error con HTTP 200; intencional (OAuth challenge) pero frágil y sin documentar | Centralizar la decisión en el `RPCGateway` de app y documentar el contrato |
| F2-17 | `infra/mcp/client/client.go` ~73–77 | `headerRoundTripper` usa `http.DefaultTransport` global: sin TLS/timeouts configurables ni inyección | Inyectar `http.RoundTripper` o clonar el transport |

## Hallazgos de severidad baja

- `composer.go`: `federate` y `discoverCached` reciben `c *composer` como primer parámetro en
  vez de ser métodos (consecuencia de usar genéricos); convención rara pero funcional.
- Magic numbers: `sessionIdleTTL=30m` (session.go), `defaultTimeout=30s`, `clientVersion="1.0"`
  (client.go), versiones de protocolo MCP en el handler.
- `mcp_handler.go` normaliza `nil → []` igual que `list_registry_tools_handler`: hacerlo una vez
  en app.
- `errors.go` de `app/mcp` está bien (sentinels encadenados a `commonerrors`), pero
  `ErrNoPrincipal`/`ErrAudienceMismatch`/`ConsentRequiredError` están en `credentials.go` en
  lugar de `errors.go`.
- Eviction de sesiones solo se dispara en `lookup` (sin reaper de fondo); aceptable con tráfico,
  documentarlo.
- `mcp_handler.go`: un body JSON-RPC batch (array) responde `parse error`, pero
  `supportedProtocolVersions` anuncia 2024-11-05 y 2025-03-26, revisiones que aún permitían
  batches (2025-06-18 los retiró); o se rechazan esas revisiones o se responde el error
  apropiado (`invalid request` con detalle).
- El "desacoplamiento" de F2-06 es nominal: al ser alias (`Tool = sdk.Tool`), cualquier breaking
  change del SDK se propaga a app y handlers sin capa de absorción — refuerza la prioridad de
  PR-A.

## Qué está bien

- La lógica de composición en sí (toolkit, wildcard, `expose_as`, colisiones con prefijo de
  registry y sufijos numéricos) es correcta y está bien testeada; el problema es **dónde** vive.
- `cachedDialer`: pin key por (gateway, consumer, registry [, principal]) + fingerprint de
  credenciales evita cruzar sesiones entre usuarios; retry-once distingue bien errores de
  transporte de errores JSON-RPC.
- Sesiones process-local: decisión consciente, documentada y conforme a la spec Streamable HTTP.
- `domain/registry/mcp_target.go`: validación exhaustiva (modos de auth, URL, guardrails de
  passthrough, registration auto/manual).
