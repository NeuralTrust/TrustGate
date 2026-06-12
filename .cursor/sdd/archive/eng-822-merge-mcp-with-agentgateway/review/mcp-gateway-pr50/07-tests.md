# Tests y mocks — auditoría de la suite de la PR

Ámbito: todos los `*_test.go` nuevos/modificados de la PR, `mocks/` generados, helpers de
test y disciplina mockery. Auditoría realizada por subagente Fable 5 (F5-C, ver
`06-cobertura.md`).

**Valoración global: notable alto.** Los tests apuntan a invariantes de seguridad reales
(aislamiento por principal, PKCE, state single-use, anti-downgrade de credenciales,
confused deputy), no a happy paths. Higiene buena: `httptest` siempre con
`t.Cleanup`/`defer Close`, sin sleeps, sin red real, errores comprobados con
`errors.Is`/`errors.As` contra sentinels en app/domain. Los problemas grandes están en lo
que **no** está testeado y en la disciplina de mocks.

## Hallazgos de severidad alta

### TST-01 · El handler MCP del data plane no tiene ningún test

`pkg/api/handler/http/mcp/mcp_handler.go` (370 líneas, nuevo) es el punto de entrada del
producto: dispatch JSON-RPC y mapeo de errores de aplicación a respuestas de protocolo
(`writeComposerError`, ~259–303). El flujo "consent requerido → cómo se materializa en la
respuesta MCP" es el corazón de la federación de credenciales y solo está probado a nivel
de servicio (`ConsentRequiredError` se construye bien), nunca a nivel de protocolo. Lo
mismo aplica a la fachada AS HTTP completa: `authorize_handler.go`, `callback_handler.go`,
`token_handler.go`, `jwks_handler.go` (solo el servicio `AuthProxy` está testeado).

**Recomendación**: test de handler con `fiber.App` + composer/proxy stub cubriendo al
menos: initialize, tools/list, tools/call OK, `ConsentRequiredError` → respuesta esperada,
`ErrNoPrincipal` → 401 con challenge.

### TST-02 · Persistencia del vault y stores OAuth sin test

`pkg/infra/repository/vault/repository.go` (151 líneas) y
`pkg/infra/oauth/{connect_store,store}.go` (191 líneas) no tienen test. El repositorio del
vault es donde se aplica `crypto.Cipher` para el cifrado at-rest; `cipher_test.go` prueba
el cifrador en aislamiento, pero **nadie verifica que el repositorio cifra antes de
escribir** — una regresión que guardara `AccessToken` en claro pasaría la suite entera.
Los stores Redis llevan los TTL de tickets/states/codes que garantizan el single-use real
en producción (los `memFlowStore`/`memConnectStore` de los tests reimplementan esa
semántica a mano).

**Recomendación**: test del repo vault (sqlite/miniredis o el mecanismo del repo) con
round-trip + assert de que el valor persistido ≠ claro.

### TST-03 · Un test consagra el fail-open de la cadena de autenticación

`auth_chain_test.go` ~287–302 (`TestChain_PathFirst_LookupErrorFallsBackUnrestricted`):
si el resolver de paths falla (DB caída), el test **exige** volver al modo "unrestricted" —
cualquier token válido de cualquier IdP configurado se acepta sin la restricción path-first
que `TestChain_PathFirst_UnattachedCredentialRejected` defiende como propiedad de
aislamiento entre tenants. Es el mismo fail-open señalado en F1-09: si es decisión
deliberada (disponibilidad sobre aislamiento) necesita comentario justificativo y
aprobación de seguridad; si no, el test está consagrando un bug de degradación. Contrasta
con el propio diseño de la PR: ante fallo, el consumer MCP defaultea a `FailModeClosed`.

## Hallazgos de severidad media

### TST-04 · Disciplina de mocks: generados sin uso, declarados sin generar, fakes a mano

- `app/mcp/mocks/mcp_composer_mock.go` (460 líneas) y
  `app/consumer/mocks/path_resolver_mock.go` (97 líneas) se añaden pero **no los importa
  nadie**: peso muerto (o se usan en el test del handler que falta — TST-01 — o se borran).
- Directivas `//go:generate mockery` sin mock generado: `CredentialResolver`
  (`credentials.go:43`), `Exchanger` (`exchanger.go:42`), `ConnectService`
  (`connect.go:76`). Directiva y artefacto deben ir juntos (ídem F4-23 para vault).
- Los tests de `app/mcp` y `app/oauth` usan fakes a mano (`stubExchanger`, `stubConnect`,
  `memVault`, `fakeChainer`…). Los fakes con estado están justificados; los stubs de
  retorno fijo deberían ser mockery `--with-expecter` como en `guard_test.go`.
- Dos versiones de mockery (v2.53.5 y v2.53.6) y dos estilos de directiva (pelada vs
  `go run …@v2.53.5` pineada). Unificar en el estilo pineado.

### TST-05 · Validadores de infra: cualquier error cuenta como "rechazo"

En `oidc/validator_test.go` (~115–157, 185–197), `introspection/validator_test.go`
(~79–114) y `mtls/validator_test.go` (~85–122) los caminos negativos solo comprueban
`err != nil`. `TestValidator_RejectsWrongIssuer` pasaría igual si el validador fallara por
no alcanzar el JWKS. `ErrKeyNotFound` existe y no se usa en ningún assert.

**Recomendación**: sentinels (`ErrIssuerMismatch`, `ErrInactiveToken`…) + `errors.Is`.

### TST-06 · Huecos de cobertura concretos por área

- **Composer**: sin test del sufijo numérico de `resolveExposedNames` (`github_search_2`,
  composer.go ~556–579), de `sanitizeName` con espacios/Unicode, de la inyección del header
  en modo `static` vía `Target()` (~630–640; `credentials_test.go:288` solo verifica
  ausencia de error), del **pin de sesión por principal** (`targetFor` ~604–615; que dos
  usuarios con auth `forwarded` no compartan `PinKey` es la propiedad hermana del
  fingerprint que sí prueba `session_test.go:136`), ni del hit de caché de
  `discoverCached`.
- **CredentialResolver**: falta `aud` como array (`hasAudience` ~183–195, solo string),
  el error desconocido del vault (~127–129) y, sobre todo, que el refresh exitoso
  **persiste** en vault y rota el refresh token (~145–152): si `Upsert` dejara de llamarse
  el test seguiría verde re-refrescando contra el IdP en cada llamada.
- **CachedDialer**: sin test de eviction por idle TTL (~113–116), de la carrera de
  `connectAndStore` (~89–93, `errgroup` + `-race`), ni del fallo de re-connect en
  `refresh` (~219–224).
- **AuthProxy**: faltan `unsupported_grant_type` (proxy.go:342), `invalid_client` por
  client_id desconocido en Authorize (189) y mismatch en Exchange (361), y expiración de
  `pendingTTL`/`codeTTL`.
- **ConnectService**: `Disconnect` de provider no vinculado; `Callback` con state caducado
  o ticket borrado a mitad de flujo.
- **OIDC/JWKS**: `jwks.go` sin test propio — rotación de claves (refetch on unknown kid),
  rate-limit `minRefresh` (~62–66), claves EC/Ed25519 (~143–169). El validador tampoco
  prueba `aud` array ni `nbf` futuro.
- **Introspección**: sin assert de `SetBasicAuth` (validator.go:118), endpoint 500/JSON
  malformado, `exp` pasado. Las variables `calls` (~81, 91, 104) se declaran y nunca se
  assertan.
- **mTLS**: sin certificado caducado, cadena con intermedia, ni XFCC multi-elemento
  separado por comas (formato real de Envoy).
- **Cipher**: falta el invariante de no-determinismo (dos `Encrypt` del mismo claro →
  ciphertexts distintos, nonce fresco) y `Decrypt` de entrada no-base64.
- **oauth_challenge**: solo el `resource_metadata` raíz; la variante path-scoped
  (`/.well-known/oauth-protected-resource/*`) sin probar.
- **Sin test alguno**: `app/mcp/introspector.go`, `app/catalog/mcp_servers.go`,
  `app/oauth/dcr.go` directo (247 líneas, solo de refilón vía
  `TestConnectService_AutoRegistrationFlow`), `infra/auth/oidc/discovery.go` (solo happy
  path indirecto).

### TST-07 · Duplicación de helpers entre paquetes

| Helper | Paquetes |
|---|---|
| `fakeCredentialFinder` | `app/oauth`, `handler/http/oauth`, `api/middleware` (+ `stubCredentials` en `sts`) |
| `oauth2Auth(...)` (3 firmas distintas) | los mismos tres paquetes |
| `unsignedJWT` | `app/oauth/proxy_test.go:443` y `middleware/auth_chain_test.go:67` |
| vault en memoria | `memVault` (`app/mcp`) y `memVaultRepo` (`app/oauth`), casi idénticos |
| `fakePathResolver` | `app/oauth/proxy_test.go:304` y `middleware/auth_chain_test.go:193` |
| servidor MCP real del SDK | `upstreamStub` (`app/mcp/session_test.go`) y `newUpstream` (`infra/mcp/client/client_test.go`) |

Ya existe el patrón `pkg/infra/cache/cachetest`: crear `authtest`/`oauthtest` análogo
(fixtures de `Auth`, IdP falso con metadata+token, vault en memoria). El IdP falso está
triplicado (`fakeIdP`, `fakeIdPWithToken`, `fakeSpecUpstream`) con variaciones ligeras.

## Hallazgos de severidad baja

- `t.Parallel` ausente en todo `infra/auth/{oidc,introspection,mtls}` y
  `auth_chain_test.go`, mientras el resto de la PR lo usa sistemáticamente.
- `composer_test.go:15` y `path_resolver_test.go:16` importan `pkg/infra/cache`
  (`NewTTLMapManager`): la causa raíz es de producción (tipo concreto en el constructor,
  ver F2-01/T-01), no del test. `session_test.go` es de facto un test de integración (SDK
  MCP real) viviendo en `pkg/app`; encajaría mejor junto al cliente en `pkg/infra/mcp`.
- `errorIs` en `exchanger_test.go:228` es un alias literal de `errors.Is` — eliminar.
- El test de `tokenEndpointFor` (`exchanger_test.go:205`) consagra la convención solo-Okta
  (ver F4-18): si se admite OIDC genérico, el contrato del test cambia.
- Asserts posicionales frágiles en `TestComposer_ListPrompts_MergesAndPrefixesCollisions`
  y similares (dependen del orden de iteración; hoy determinista): `ElementsMatch`.
- `pages_test.go` acopla al texto del template; aceptable (clava la regresión ZgotmplZ),
  pero comentar que el assert del JS es deliberado.
- `fakeSpecUpstream` escribe `*registrations`/`*tokenForm` sin mutex desde goroutines del
  servidor HTTP (`connect_test.go:226–266`); sin carrera real hoy, pero frágil —
  `memFlowStore` sí usa mutex; unificar (ídem `gotForm` en `credentials_test.go:229` y
  `exchanger_test.go:90`).

## Checklist de flujos críticos

| Flujo | ¿Testeado? |
|---|---|
| Refresh de credenciales forwarded | Sí (refresh OK, fallo de RefreshAuth → consent, sin refresh token → consent). Falta assert de persistencia/rotación post-refresh |
| `fail_mode` | Sí, open y closed + default closed en dominio. Falta fail_mode en `ReadResource` (composer.go:218) |
| Colisiones de nombres | Sí para auto-prefijo y alias duplicados. Falta sufijo `_2` y colisión alias-explícito vs auto-prefijo |
| Challenge OAuth | Sí a nivel middleware (3 casos). Falta el extremo a extremo handler MCP → 401 → challenge (TST-01) |
| Aislamiento multi-tenant / por principal | Muy bien cubierto (cache key STS, vault por sub, fingerprint de sesión, path-first). El agujero es el fail-open de TST-03 |

## Veredicto

Se aprobaría la parte de tests de servicios y dominio con cambios menores, pero antes del
merge se pediría: (1) tests del handler MCP y de la fachada AS HTTP, (2) test de cifrado
at-rest en el repo del vault, (3) decisión explícita y documentada sobre el fail-open de
`auth_chain`, y (4) limpieza de mocks (generados sin uso + directivas sin generar).
