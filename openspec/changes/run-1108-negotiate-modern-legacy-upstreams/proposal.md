# Proposal: Negociar upstreams MCP modernos y legacy

## Goal

Permitir a TrustGate conectar upstreams MCP 2026-07-28 y legacy, con `auto` por defecto y overrides estrictos.

## Non-goals

- Añadir UI.
- Reenviar identidad/metadata inbound, inferir capacidades o reintentar `tools/call`.
- Soportar eras distintas bajo un origen; requieren override u origen separado.

## Scope

- Añadir `protocol_mode: auto|modern|legacy` a modelo, API y round-trip JSONB/snapshot, sin migración ni cambio proto.
- Introducir en infra un router dual: upstream moderno stateless; legacy conserva `ClientSession`, caché por origen/URL canónicos + `ProtocolMode` + `PinKey` + fingerprint de credencial, TTL 30m y refresh solo de lecturas.
- En `auto`, `server/discover` exitoso o HTTP 400 con `-32020/-32021/-32022` clasifica moderno; `-32022` reintenta una vez con versión común. Un 400 vacío, malformado o no reconocido habilita legacy. Auth, 404/405/429, 5xx, red y timeout no clasifican ni degradan.
- Hacer overrides estrictos, sin probe/fallback.
- Usar origen `scheme+host+effective port`; rechazar userinfo, redirects y sobrescritura de headers reservados.
- Mantener caché por proceso y singleflight, sin TTL: `legacy`, `modern+version` o `modern-incompatible`; nunca capacidades/credenciales. Invalidar una vez ante contradicción protocolaria segura.
- Usar identidad `trustgate`, versión de `pkg/version` y capacidades mínimas/vacías.
- Con RUN-1103, `server/discover` northbound no dispara probes southbound.

## Capabilities

### New Capabilities

- `mcp-upstream-protocol-negotiation`: clasificación estricta, overrides, caché por origen y ejecución dual-era.

### Modified Capabilities

None.

## Approach and PR Slices

1. Contrato: dominio, API, snapshot y tests de round-trip/validación.
2. HTTP/probe: transporte compartido, seguridad de origen/headers y clasificación estricta.
3. Legacy: bump atómico a SDK v1.7.0, supresión HTTP local y acotada de `server/discover`, ownership correcto del body y paridad de sesión/caché.
4. Modern: adaptador stateless y sus invariantes wire.
5. Coordinación: caché de era, singleflight, router, composición, compatibilidad RUN-1103 y tests funcionales dual-era.

Cada slice será autónomo, reversible y PR apilada bajo 400 líneas cuando sea viable.

## Affected Areas

- `pkg/domain/registry`, `pkg/app/mcp`: contrato y target.
- `pkg/api/handler/http/registry`: entrada/salida administrativa.
- `pkg/infra/mcp/client`: negociación, transportes y cachés.
- `pkg/app/configsnapshot`, `pkg/runtimeconfig/snapshot`: propagación del override.
- Tests unitarios/race y `tests/functional/mcp_e2e_test.go`.

## Observabilidad mínima

Registrar origen no sensible, modo, era/fuente, resultado y latencia; nunca headers, credenciales, body ni metadata.

## Risks and Mitigations

- Clasificación falsa: matriz HTTP/JSON-RPC cerrada y tests tabulares.
- Contención o carreras: singleflight por origen y `go test -race`.
- Servidores mixtos por origen: contrato explícito, override u origen separado.
- Acoplamiento al SDK: encapsular el wire moderno en infra.

## Rollback Plan

Revertir slices en orden inverso; mientras tanto, fijar registries afectados a `legacy`. No hay migración que deshacer.

## Acceptance Criteria

- [ ] `auto` cumple la matriz y no degrada ante errores no clasificables.
- [ ] Overrides evitan probes/fallback y sobreviven API, JSONB y snapshot.
- [ ] Cachés no contienen secretos y la concurrencia pasa race.
- [ ] Ambas eras conservan la semántica de retry existente.
- [ ] Redirects, headers reservados y metadata inbound quedan bloqueados.
- [ ] No hay bloqueantes; listo para `sdd-spec`.
