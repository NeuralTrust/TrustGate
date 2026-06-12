# Fase 3 — OAuth 2.1 Resource Server + Authorization Server

Ámbito: `pkg/app/oauth/{connect,dcr,metadata,provider,proxy}.go`, `pkg/infra/oauth/*`,
`pkg/api/handler/http/oauth/*`, `pkg/api/middleware/oauth_challenge.go`,
`pkg/server/router/mcp_router.go`.

El patrón dominante de esta fase: **los archivos de `pkg/app/oauth` no importan `pkg/infra`
(cumplen la regla "en superficie"), pero contienen la infraestructura dentro**: clientes HTTP,
discovery, DCR, PKCE, parsing de JWT. La regla hexagonal no es "no importar infra" sino
"app solo orquesta a través de puertos".

## Hallazgos de severidad alta

### F3-01 · `dcr.go` es íntegramente un adaptador HTTP — Hexagonal / SRP

`UpstreamRegistrar` (~54–240): `http.Client` propio, discovery RFC 9728/8414, POST de Dynamic
Client Registration RFC 7591, cache TTL en memoria y persistencia vía `ClientStore`. Cero
orquestación de caso de uso.

**Refactor**: mover a `pkg/infra/oauth/dcr_registrar.go`; puerto `UpstreamRegistrar`
(`Discover`, `EnsureClient`) + tipos `AuthServerMetadata`/`RegisteredClient` en
`pkg/domain/oauth` (o app).

### F3-02 · `provider.go` es un cliente HTTP OAuth completo — Hexagonal

`ProviderClient` (~24–137): authorize URL, intercambio de code, refresh — todo con llamadas de
red. Además es un struct exportado sin interfaz ni mockery, y `app/mcp/credentialResolver`
depende de `*ProviderClient` concreto (DIP).

**Refactor**: puerto `ThirdPartyOAuthClient` (en domain/app) + implementación en
`pkg/infra/oauth/provider_client.go`.

### F3-03 · `metadata.go` y `proxy.go` hacen fetch HTTP a IdPs — Hexagonal

- `metadataService` (~80–99, 196–243): `*http.Client`, `fetchJSON`, cache de metadata.
- `authProxy.idpTokenCall` (~413–443): POST al token endpoint del IdP.
- Agravante (DIP): `NewAuthProxy` **construye internamente** un `metadataService` propio en
  lugar de recibir el puerto inyectado (~162–168).

**Refactor**: `pkg/infra/oauth/{metadata_client,idp_token_client}.go`; inyectar interfaces.

### F3-04 · Cliente de token OAuth triplicado — DRY

`provider.tokenCall`, `proxy.idpTokenCall` y `sts/exchanger.idpTokenCall` (Fase 4) son
prácticamente el mismo código: POST form-urlencoded, límite `1<<20`, parsing de
`access_token/expires_in`, manejo de error no-2xx.

**Refactor**: un único `pkg/infra/oauth/token_client.go` reutilizado por los tres flujos.

### F3-05 · Crypto y parsing JWT en app — Hexagonal

`proxy.go`: `s256`, `randomToken` (PKCE, `crypto/rand`+SHA-256, ~579–590) y
`subjectFromToken` con `jwt.ParseUnverified` (~316–333).

**Refactor**: PKCE a `pkg/infra/oauth/pkce` (o `pkg/common`); extracción de subject a
`infra/auth/jwt` detrás de un puerto.

### F3-06 · `proxy.go`: 590 líneas, 3+ interfaces y 6 responsabilidades — SRP / ISP / Clean Code

Un archivo contiene `FlowStore`, `ConsentChainer`, `AuthProxy` (interfaces), los DTOs de
authorize/token, el flujo authorize, el callback, el exchange, el refresh, la resolución de IdP
por resource y los helpers de redirect. Mismo anti-patrón que `composer.go` en Fase 2.

**Refactor**: un archivo por interfaz (`flow_store.go`, `consent_chainer.go`, `auth_proxy.go`)
y por sub-flujo (`authorize.go`, `callback.go`, `token_exchange.go`). Añadir
`//go:generate mockery` a las tres interfaces (hoy ninguna lo tiene).

### F3-07 · `ConnectService` viola ISP — ISP

`connect.go` (~76–96): una sola interfaz agrupa página de consent, start, callback, disconnect,
refresh de auth, creación de tickets y chaining OAuth. Los consumidores usan subconjuntos
disjuntos (el `credentialResolver` solo necesita `CreateTicket` + `RefreshAuth`; los handlers
solo Page/Start/Callback).

**Refactor**: trocear en `TicketCreator`, `ConsentStarter`, `ConsentCompleter`, `AuthRefresher`…

### F3-08 · Puertos de persistencia OAuth definidos en app y "estado de flujo" sin dominio — Hexagonal

`ConnectStore`, `ClientStore`, `FlowStore` están en app (aceptable como puerto driven de app),
pero los tipos que persisten (`ConnectTicket`, `ConnectState`, `PendingAuthorization`,
`CodeGrant`) son estado de negocio del flujo OAuth modelado como structs anémicos de app.

**Refactor**: mover los tipos de estado a `pkg/domain/oauth` como value objects; los stores
quedan como puertos sobre tipos de dominio.

### F3-09 · Handler JWKS acoplado a `*sts.Signer` concreto — DIP

`jwks_handler.go` (12–28) inyecta la implementación concreta del signer.

**Refactor**: interfaz `JWKSProvider` en app; ver Fase 4 (F4-01).

### F3-10 · Resolución "auth OAuth2 por resource" duplicada — DRY

`metadata.resourceAuths` (~117–145) y `proxy.authForResource/resourceAuth/singleOAuth2Auth`
(~445–551) duplican el mismo algoritmo (paths.Match + filtro de auths OAuth2).

**Refactor**: un `OAuth2AuthResolver` compartido en `app/auth`.

## Hallazgos de severidad media

| ID | Archivo | Hallazgo | Refactor |
|---|---|---|---|
| F3-11 | `connect.go` ~100–115 | Dependencias concretas `*ProviderClient` y `*UpstreamRegistrar` en el servicio | Inyectar los puertos de F3-01/F3-02 |
| F3-12 | `connect.go` ~49–74 | `ConnectPage`/`ProviderStatus` son view-models de presentación en app | Mover a `handler/http/oauth/response/` o presenter |
| F3-13 | `metadata.go` ~65–76 | `MetadataService` sin mockery; DTOs RFC 9728/7591 (`ProtectedResourceMetadata`, `RegisterRequest/Response`) en app | Directiva mockery; DTOs a `request/`/`response/` |
| F3-14 | `infra/oauth/connect_store.go` ~34 + `container/modules/mcp.go` ~60–68 | `NewConnectStore` devuelve `*ConnectStore`; el container registra el concreto y lo convierte a mano a las dos interfaces | Constructores que devuelven interfaz; providers DI directos |
| F3-15 | handlers `authorize`/`token`/`register`/`connect` | DTOs ensamblados inline desde query/form sin carpeta `request/` ni `Validate()` (la validación vive en app) | `oauth/request/*.go` con `Validate()` |
| F3-16 | `token_handler.go` ~56–71 | `writeOAuthError` (helper RFC 6749 compartido por 3 handlers) definido dentro del handler de token | `oauth/errors.go` del paquete handler |
| F3-17 | `connect_handler.go` ~113–121 | `pageError` solo mapea 2 errores; el default devuelve `err` crudo (500 sin formato ni log estructurado) | Mapear conocidos + default consistente |
| F3-18 | `callback_handler.go` ~40–47 | Decisión deep-link vs 302 (UX) en el handler | `Callback` devuelve `RedirectResult{URL, Kind}` |
| F3-19 | `oauth_challenge.go` ~24–25 | `resource_metadata` del 401 apunta siempre al root, no al path del virtual MCP (el diseño contempla metadata por consumer); además path well-known hardcoded | Construir desde `c.Path()`; constante compartida en `app/oauth` |
| F3-20 | `pages.go` ~18–152 | ~130 líneas de HTML+CSS inline; rutas `/oauth/connect/` hardcoded en el template sin reutilizar las constantes del handler | `embed.FS` con templates; base paths en el view-model |
| F3-21 | `proxy.go` ~36–37 | `pendingTTL`/`codeTTL` declarados y **no usados** (infra tiene los suyos): código muerto/duplicación | Eliminar de app; fuente única |
| F3-22 | `infra/oauth/{store,connect_store}.go` | Patrón JSON+Redis (`set/save/take`) duplicado entre ambos stores | Helper interno común |
| F3-23 | `catalog/list_mcp_servers_handler.go` ~18–32 | La response embebe `[]domain.MCPServer` directo (los providers sí mapean a DTO) | `catalog/response/mcp_server_response.go` |
| F3-24 | `register_handler.go`, `authorization_server_handler.go`, `list_registry_tools_handler.go` | Mapeo de errores ad hoc e inconsistente con `helpers.WriteError` | Helper común de mapeo OAuth |
| F3-25 | `dcr.go` ~56–99 | Mezcla discovery + cache + DCR + persistencia en un struct | Separar al mover a infra (F3-01) |
| F3-26 | `connect.go` ~161–199 | Selección de "providers forwarded sin vincular" mezclada con la orquestación del ticket | Extraer selector reutilizable |
| F3-27 | `infra/oauth/{store,connect_store}.go` | "Not found" modelado como `nil, nil` en `TakePending`, `TakeCode`, `GetTicket`, `TakeConnect`, `GetClient` — contrato implícito distinto al del resto de repos (`domain.ErrNotFound`), propenso a nil-deref en los llamadores y no documentado en los puertos de app | Sentinel `appoauth.ErrStateNotFound` (o documentar `nil, nil` en la interfaz del puerto) |
| F3-28 | `token_handler.go` ~67–69 | `ErrNoAuthorizationServer`/`ErrAmbiguousAuthorizationServer` → HTTP **404** con body `{"error":"invalid_request"}`: RFC 6749 asocia `invalid_request` a 400; un 404 con error-body OAuth confunde a los clientes | Devolver 400 `invalid_request`, o 404 sin body OAuth |
| F3-29 | `proxy.go` ~276–289, ~366 | **Seguridad**: el token completo del IdP (incluido el refresh token corporativo) se persiste en el `CodeGrant` (Redis, en claro) y se entrega tal cual al cliente MCP en `Exchange` | Cifrar el payload en el adaptador Redis, o guardar referencia al vault en lugar del token |
| F3-30 | `proxy.go` ~285 + `connect.go` ~153 | La resume URL (que contiene el authorization code de un solo uso) se persiste dentro del `ConnectTicket` en Redis durante el detour de consentimiento: el code queda en reposo mientras viva el ticket (15 min) | Parquear solo `state` y reconstruir, o acortar el TTL del ticket con resume |
| F3-31 | `connect.go` ~158 | El ticket de consentimiento (credencial sustituta del Bearer) viaja como query param `?ticket=`: filtrable por access logs, Referer e historial | Fragment, POST o cookie de sesión corta |
| F3-32 | `connect.go` ~188–199 | Cualquier error de `vault.Find` (p. ej. DB caída) se interpreta como "no vinculado": re-consentimientos espurios que enmascaran fallos de infra | Distinguir `ErrNotFound` de errores de infraestructura y propagar estos últimos |
| F3-33 | `dcr.go` ~170 | El error de `GetClient` se descarta: ante fallo transitorio del store se re-registra un cliente DCR nuevo en el upstream (churn de client_ids, cliente anterior huérfano) | Propagar el error; solo re-registrar ante not-found |
| F3-34 | `dcr.go` ~60–61, `metadata.go` ~85–92 | Los caches in-memory de discovery (`map` + mutex) nunca purgan entradas expiradas; las URLs upstream las definen los tenants → crecimiento sin límite por réplica | Cache con TTL/evicción (o Redis, como el resto del estado del paquete) |
| F3-35 | `metadata.go` ~174–193 | `RegisterClient` devuelve el client_id del **primer** auth con `ClientID` sin considerar el resource ni orden determinista: con varios IdPs el DCR entrega un cliente arbitrario | Aceptar el resource indicator y resolver con el mismo resolutor de F3-10 |
| F3-36 | `proxy.go` ~167 | `NewAuthProxy` construye `&metadataService{...}` a mano (struct literal, saltándose el constructor): dependencia de tipo concreto interno y **segunda** cache de AS-metadata paralela a la del container (doble fetch del mismo documento) | Inyectar un `ASMetadataResolver` compartido |

## Hallazgos de severidad baja

- Magic numbers repetidos: timeouts 10/15 s, `io.LimitReader(…, 1<<20)`, TTLs
  (`discoveryTTL=1h`, `asMetadataTTL=1h`, `ticketTTL=15m`, `connectTTL=10m`).
- `client_name` DCR hardcoded `"TrustGate MCP Gateway"`.
- Workaround específico de GitHub (`Accept: application/json`) en el cliente genérico.
- `pages.go`: timeout JS `2500` ms sin constante; mapa `knownSchemeApps` crecerá sin config.
- Router: mezcla de constantes de path entre `appoauth.CallbackPath` y `oauthhttp.*Path`;
  ruta `/+/connect` sin constante exportada.
- `Callback` devuelve `ticketID` también en error parcial (intencional para UI); unificar en un
  `CallbackResult`.
- `errors.New`/`fmt.Errorf`/`oauthErr` mezclados; faltan sentinels de dominio para
  consent/refresh.
- `proxy.go` ~360–362: la verificación de `client_id` en `exchangeCode` se omite si cualquiera
  de los dos es vacío (binding de cliente débil; PKCE mitiga).
- `proxy.go` ~311: se loguea el `sub` del usuario (PII) a nivel INFO.
- `proxy.go` ~319–333: `subjectFromToken` asume access token JWT; con IdPs de token opaco el
  chaining se omite con un Warn (usar id_token o userinfo como fallback).
- `proxy.go` ~490–504: rama de compatibilidad "pendings sin AuthID" muerta tras el primer
  deploy (TTL 10 min); eliminar tras el release.
- `dcr.go` ~205: el error de `json.Unmarshal` se colapsa en "registration response has no
  client_id", perdiendo la causa real.
- `provider.go` ~126: si el status ≠ 200 sin campos `error`, el mensaje queda
  `"token exchange failed (): "` y se pierde el status code.
- `dcr.go` ~86–99: check-then-act sin singleflight (thundering herd de discovery concurrente).

## Qué está bien

- `infra/oauth/store.go`: implementa `appoauth.FlowStore` con `GETDEL` atómico — multi-réplica
  correcto y documentado.
- Handlers `authorize`, `token`, `callback`, `protected_resource`, `authorization_server`:
  finos, una llamada a app, sin imports de infra.
- `pages.go` usa `html/template` con auto-escape y `template.URL` para los deep links.
- El router MCP solo enruta; el 405 para GET/DELETE antes del middleware de auth evita loops de
  re-autenticación.
