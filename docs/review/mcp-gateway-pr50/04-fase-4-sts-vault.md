# Fase 4 — STS y federación de credenciales downstream

Ámbito: `pkg/app/identity/sts/{signer,exchanger}.go`, `pkg/app/mcp/credentials.go`,
`pkg/domain/vault/credential.go`, `pkg/infra/repository/vault/repository.go`,
`pkg/infra/crypto/cipher.go`.

## Hallazgos de severidad alta

### F4-01 · `sts/signer.go` es infraestructura criptográfica en app — Hexagonal / DIP

El archivo completo (125 líneas): parsing/generación de claves RSA, firma JWT RS256,
construcción del JWKS, `crypto/rand`. Además `Signer` es un struct exportado, `NewSigner`
devuelve `(*Signer, error)` (no interfaz, sin mockery) y el handler JWKS depende del concreto
(ver F3-09).

**Refactor**: puerto `TokenSigner` (con `Mint(claims)` y `JWKS()`) en `pkg/domain/identity`
o `pkg/app/identity`; implementación en `pkg/infra/identity/sts/signer.go`. La generación de
clave efímera de desarrollo (~39–46) se decide en el wiring (`container/modules`), no dentro
del signer.

### F4-02 · `sts/exchanger.go` llama por HTTP al IdP — Hexagonal

`idpTokenCall` (~203–244): POST al token endpoint (Entra OBO / RFC 8693) con `http.Client`.
Es la tercera copia del cliente de token (ver F3-04). También `tokenEndpointFor` (~192–201),
heurística de URLs Entra vs Okta, es conocimiento de integración.

**Refactor**: puerto `TokenExchanger`/`IdPTokenClient`; implementación compartida en
`pkg/infra/oauth/token_client.go`; el `Exchanger` de app queda en orquestación + cache.

### F4-03 · `credentialResolver` depende de concretos y de tipos de infra — DIP

`app/mcp/credentials.go`: depende de `*appoauth.ProviderClient` (struct concreto, F3-02) y
escribe sobre `*mcpclient.Target` (tipo de infra, F2-01). El resto de dependencias
(`sts.Exchanger`, `vault.Repository`, `ConnectService`) sí son puertos.

**Refactor**: se resuelve al combinar F2-01 (Target en app) y F3-02 (puerto del provider).

### F4-04 · `forwarded()` orquesta el ciclo de vida completo del token en un método — SRP

`credentials.go` ~116–156: lookup en vault, detección de expiración, resolución del cliente
OAuth efectivo, refresh contra el provider, upsert en vault y fallback a consent — todo en un
método con 4 salidas distintas a `consentRequired`. La lógica de "dame una credencial fresca o
dime que hace falta consent" es un caso de uso en sí mismo.

**Refactor**: extraer `VaultedCredentialProvider` (app) con
`FreshCredential(ctx, gateway, principal, provider) (*vault.Credential, error)`; el resolver
solo decide el modo y setea el header.

### F4-05 · Tercer matcher de audience — DRY / Consistencia

`credentials.hasAudience` (~175–197) reimplementa el matching de `aud` (string, `[]any`,
`[]string`) ya implementado de dos formas distintas en los validators de Fase 1 (F1-03).
Tres implementaciones, tres semánticas potencialmente divergentes para el guardrail
anti-confused-deputy.

**Refactor**: `identity.AudienceMatches` único en domain; `Principal` puede exponer
`HasAudience(expected string) bool`.

### F4-18 · `tokenEndpointFor` adivina el token endpoint por heurística — BUG funcional

`exchanger.go` ~195–201: si el issuer no es `login.microsoftonline.com`, asume la convención
Okta (`{issuer}/v1/token`). Auth0 usa `/oauth/token`, Keycloak
`/protocol/openid-connect/token`, etc.: el exchange STS **falla con cualquier IdP que no sea
Entra u Okta**, silenciosamente y en producción. Además duplica el discovery RFC 8414 que ya
existe por triplicado (`metadata.go`, `dcr.go`, `infra/auth/oidc/discovery.go`).

**Refactor**: resolver `token_endpoint` vía el discovery compartido de infra (cacheado).

### F4-19 · Cache de tokens del exchanger crece sin límite — BUG (fuga de memoria)

`exchanger.go` ~54–104: `cache map[string]*Token` con clave por (principal × target) nunca
purga entradas expiradas ni de principals inactivos: en multi-tenant crece sin límite por
réplica (es la fuga grave del eje OAuth/STS; las de discovery — F3-34 — están acotadas por
config). El check-then-act además permite exchanges duplicados concurrentes, y el puerto
`Exchanger` expone `cacheKey string` como parámetro (detalle de implementación delegando el
aislamiento cross-user al llamador, cuando el propio comentario admite que una colisión de
clave es escalada de privilegios).

**Refactor**: puerto `TokenCache` (Redis con TTL = exp del token, o `cache.TTLMap` tras
puerto); derivar la clave internamente de `principal.Subject` + target.

## Hallazgos de severidad media

| ID | Archivo | Hallazgo | Refactor |
|---|---|---|---|
| F4-06 | `exchanger.go` ~54–104 | Cache de tokens in-memory (`map[string]*Token` + mutex) dentro del servicio de app | Puerto `TokenCache` (o `cache.TTLMap` vía puerto); app orquesta |
| F4-07 | `exchanger.go` ~31–36, ~108–129 | `Token` y la construcción de claims de delegación (`jwt.MapClaims`) definidos en app; el token STS es un concepto de dominio | `domain/identity/token.go` + factoría `NewDelegationClaims(principal, cfg)` |
| F4-08 | `domain/vault/credential.go` ~59 | `ids.New` (UUIDv4) mientras el resto de agregados usan `ids.NewV7` | `ids.NewV7[ids.VaultKind]()` |
| F4-09 | `domain/vault/credential.go` ~82–91 | Repo fuera de convención: `Upsert`, `Find(gw, principal, provider)`, `ListByPrincipal` | `FindByPrincipalAndProvider`; valorar `Create/Update` explícitos |
| F4-10 | `domain/vault/credential.go` | Sin `Rehydrate`: el repo de infra reconstruye `Credential` con struct literal post-descifrado | Añadir `Rehydrate(...)` que no regenere ID/timestamps |
| F4-11 | `infra/crypto/cipher.go` ~17–36 | Sin puerto: `vault.Repository` y el grafo DI dependen de `*crypto.Cipher` concreto | Puerto `Encrypter` (`Encrypt/Decrypt`) en domain/vault o app |
| F4-12 | `credentials.go` ~166–171 | `setAuthorization` escribe el header `"Authorization"` a mano: detalle de transporte en app | Con F2-01, `Target` de app puede exponer `WithBearer(token)` |
| F4-13 | `credentials.go` ~19–37 | `ErrNoPrincipal`, `ErrAudienceMismatch`, `ConsentRequiredError` definidos fuera de `errors.go` del paquete | Consolidar en `app/mcp/errors.go` |
| F4-14 | `infra/repository/vault/repository.go` ~54 | Regla "preservar refresh_token si el nuevo viene vacío" implementada en SQL | Resolverla en la entidad/servicio de dominio; el repo persiste estado ya decidido |
| F4-15 | `infra/repository/registry/repository.go` (`marshalMCPTarget`) | **Secretos en claro en DB**: `mcp_target` se persiste como JSONB incluyendo `auth.value` (credencial estática) y `auth.client_secret`, mientras los tokens del vault sí van cifrados con AES-GCM — tratamiento incoherente de secretos at rest dentro de la misma feature | Cifrar `Value`/`ClientSecret` con el mismo cipher antes de persistir (como hace vault), o documentar la excepción y su mitigación |
| F4-16 | `infra/crypto/cipher.go` ~27 + `config.go` | La KEK del vault se deriva de `SERVER_SECRET_KEY` (que además firma los JWT admin) sin key-id ni versión en el ciphertext: rotar el secret invalida **todos** los tokens vault sin camino de re-cifrado, y el doble uso viola separación de claves | Variable dedicada (`VAULT_ENCRYPTION_KEY`), prefijo de versión en el ciphertext (`v1:...`) y soporte de clave anterior para re-cifrado perezoso |
| F4-17 | `sts/signer.go` + `k8s/overlays/prod` | Con `STS_SIGNING_KEY` vacío cada réplica genera una clave RSA efímera distinta; prod corre 2 réplicas, así que el JWKS servido por una réplica no valida los tokens firmados por la otra (fallos intermitentes en upstreams que validan contra `/.well-known/jwks.json`). El fallback solo emite un Warn — y nada si `logger == nil` | Exigir `STS_SIGNING_KEY` cuando `replicas > 1` (fail-fast en arranque) y fijarla en el SecretProviderClass de prod |
| F4-20 | `sts/signer.go` ~120–124 | `randomJTI` ignora el error de `rand.Read`: ante fallo de entropía emite un `jti` de ceros en silencio (inconsistente con `randomToken` de proxy.go, que sí falla) | Propagar el error desde `MintClaims` |
| F4-21 | `sts/exchanger.go` ~226–244 | A diferencia de `provider.tokenCall`, no valida `AccessToken != ""` en una respuesta 200: un IdP que responda 200 sin token hace cachear un `Token` vacío durante todo el TTL | Validar y unificar con el cliente de token compartido (F3-04) |
| F4-22 | `domain/vault/credential.go` ~17–20 | `ErrInvalidCredential`/`ErrNotFound` son `errors.New` planos: el resto de dominios envuelven `commonerrors.ErrValidation`/`ErrNotFound` (lo que el mapeo HTTP usa para 400/404); cuando se cablee un handler de vault sus errores caerán en 500 | Envolver los sentinels de `commonerrors` como hace `gateway/errors.go` |
| F4-23 | `domain/vault/credential.go` ~81 | `//go:generate mockery` declarado pero `pkg/domain/vault/mocks/` **no existe**: la generación no se ejecutó (auth/gateway/consumer sí regeneraron) | `go generate ./pkg/domain/vault/...` |

## Hallazgos de severidad baja

- `vaultRefreshSkew=60s` (`credentials.go`) y `refreshSkew=30s` (`exchanger.go`): el mismo
  concepto con dos valores distintos y sin config.
- `defaultTokenTTL=5m` compartido implícitamente entre `signer.go` y `exchanger.mint`.
- Salt del cipher hardcoded (`"agentgateway-vault:"`); aceptable pero merece constante
  documentada.
- `PrincipalSub` como string plano en `vault.Credential` duplica `identity.Principal.Subject`
  sin value object compartido.
- `exchanger.go` ~230–232: `invalid_grant` se mapea siempre a `ErrInteractionRequired` (401);
  un error de configuración del exchange se disfraza de "re-autentícate".
- `exchanger.mint` ~111–119: estampa `aud` aunque `cfg.Audience` esté vacío y copia los scopes
  inbound al token downstream sin filtrar por target (sobre-alcance).
- `signer.MintClaims` ~54–62 muta el map `claims` del llamador (side effect no documentado).
- `NewCredential` toma 8 parámetros posicionales con 6 strings contiguos: transponer dos
  compila y es bug silencioso; la convención del repo es `New(CreateParams)`.
- `domain/vault/credential.go`: el doc afirma "stored encrypted at rest" — el adaptador de
  infra de esta misma PR sí cifra (AES-GCM), pero el contrato del puerto no lo exige; un
  segundo implementador podría persistir en claro sin violar la interfaz. Reformular como
  requisito del contrato.
- Migración `20260609200000`: el `Down` no restaura los `NOT NULL` de `provider`/`auth`
  (drift de esquema en rollback). `expires_at` nullable casa con el scan de infra
  (`*time.Time`), pero la entidad usa `time.Time` plano — decidir puntero o
  `NOT NULL DEFAULT 'epoch'`.

## Qué está bien

- `vault.Repository` (infra) es el adaptador mejor alineado de la PR: puerto en domain,
  `pgx.ErrNoRows → domain.ErrNotFound`, cifrado at-rest obligatorio, migración con
  UNIQUE `(gateway_id, principal_sub, provider)` y CASCADE coherentes.
- `domain/vault.NewCredential` con validación + sentinels + `Expired(skew)`.
- El cache key del exchange (`subject|registry|gateway`) garantiza aislamiento por principal —
  diseño de seguridad correcto, solo mal ubicado el cache.
- `credentialResolver.Apply` con switch por modo es legible y los guardrails
  (audience en passthrough, consent en forwarded) están bien pensados.
