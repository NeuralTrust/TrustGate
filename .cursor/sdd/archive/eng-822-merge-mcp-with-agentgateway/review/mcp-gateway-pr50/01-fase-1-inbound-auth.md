# Fase 1 — Validación de credenciales inbound

Ámbito: `pkg/infra/auth/{oidc,introspection,mtls}`, `pkg/api/middleware/{auth_chain,auth}.go`,
`pkg/domain/identity/principal.go`, `pkg/domain/auth/*`.

## Hallazgos de severidad alta

### F1-01 · Los puertos de validación viven en el middleware, no en app — DIP / Hexagonal

`auth_chain.go` define `JWTValidator`, `IntrospectionValidator` y `MTLSValidator` en
`pkg/api/middleware`. La capa API es un adaptador driving: no debería ser la dueña de los
contratos que implementa infra. Hoy el grafo es `infra → (duck typing) → middleware`, en lugar
de `infra → app ← middleware`.

**Refactor**: mover las tres interfaces a `pkg/app/auth` (p. ej. `TokenValidator`,
`CertificateValidator`) con `//go:generate mockery`; los constructores de
`infra/auth/{oidc,introspection,mtls}` pasan a devolver esas interfaces.

### F1-02 · Política de identidad multi-IdP dentro de `infra/auth/oidc/validator.go` — Hexagonal / SRP

Líneas ~45–157: además de verificar la firma (responsabilidad legítima de infra), el validator
decide reglas de negocio de identidad: `subjectOf` prefiere el claim `oid` de Entra,
`extractScopes` normaliza scopes multi-IdP y `anyMatch` aplica la equivalencia
`api://{guid}` ↔ GUID pelado. Eso es política, no plumbing.

**Refactor**: extraer un `ClaimsNormalizer`/`AudienceMatcher` a `pkg/domain/identity`
(donde ya vive `HasScopes` con lógica Entra) y dejar el validator de infra solo con
verificación criptográfica + delegación.

### F1-03 · Audience-matching inconsistente entre mecanismos — LSP / Consistencia

`oidc.anyMatch` acepta la equivalencia Entra `api://...`; `introspection.audMatch` no.
El mismo token puede pasar por un mecanismo y fallar por otro: las implementaciones del
"mismo" contrato no son sustituibles.

**Refactor**: un único helper `identity.AudienceMatches(have, want []string) bool` en domain,
usado por ambos validators (y por `app/mcp/credentials.hasAudience`, que es la tercera
implementación del mismo concepto — ver Fase 4).

### F1-04 · Fuga de memoria en el cache de introspection — Concurrencia

`infra/auth/introspection/validator.go` ~52–143: el `map[string]cacheEntry` solo *ignora*
las entradas expiradas al leer; nunca las borra. En un proceso long-running con muchos tokens
distintos crece sin límite.

**Refactor**: borrar al leer entradas expiradas y/o reusar `cache.TTLMap` (que ya tiene reaper).
Lo mismo aplica, con menor riesgo (acotado por nº de IdPs), a los caches de
`oidc/jwks.go` y `oidc/discovery.go`, que tampoco podan.

### F1-05 · El middleware importa infra para parsear XFCC — DIP

`auth_chain.go` usa `mtls.HeaderXFCC` y `mtls.CertFromXFCC` de `pkg/infra/auth/mtls`.
El parsing del header `x-forwarded-client-cert` es un detalle del adaptador.

**Refactor**: exponer un puerto `ClientCertificateExtractor` en app (o mover el parsing al
propio middleware si se considera HTTP puro); infra implementa.

### F1-13 · XFCC aceptado de cualquier origen — Seguridad

`auth_chain.go` ~211–223 (`clientCertificate`): si no hay TLS directo, acepta el header
`X-Forwarded-Client-Cert` de **cualquier** peer, sin verificar que la petición venga del edge
proxy de confianza. XFCC solo transporta el certificado público — la prueba de posesión de la
clave privada la hizo el edge al terminar TLS. Un cliente que llegue directo al pod (red
interna, port-forward, ruta mal configurada) puede presentar el certificado público de otra
identidad (los certs públicos no son secretos) y autenticarse como ella.

**Refactor**: aceptar XFCC solo cuando la conexión venga de peers de confianza (lista de
CIDRs/identidad mTLS interna) o tras un flag de configuración explícito
(`TRUST_XFCC_FROM=<cidr>`), desactivado por defecto.

## Hallazgos de severidad media

| ID | Archivo | Hallazgo | Refactor |
|---|---|---|---|
| F1-06 | `domain/identity/principal.go` ~83–95 | `WithPrincipal`/`PrincipalFromContext` acoplan domain a `context.Context` como bus request-scoped; patrón de middleware, no de dominio | Mover los helpers de contexto a `pkg/app/identity` o `pkg/api/middleware`; en domain quedan `Principal` + `HasScopes` |
| F1-07 | `domain/identity/principal.go` ~23–30 | `Principal` se construye con struct literal, sin factoría ni invariantes (`Subject` vacío pasa) | `NewPrincipal(subject string, method Method) (*Principal, error)` + sentinel `ErrInvalidPrincipal` |
| F1-08 | `middleware/auth.go` | `apiKeyIdentityResolver` no rellena `Principal` en el contexto, pero `chainIdentityResolver` sí: implementaciones de `IdentityResolver` inconsistentes (LSP) | Construir `Principal{Method: MethodAPIKey}` también en el resolver simple, o retirar ese resolver |
| F1-09 | `middleware/auth_chain.go` ~106–110 | Si `paths.Match` falla, el scope queda `nil` (sin restricción): fail-open silencioso en error de infraestructura | Fail-closed en producción o, como mínimo, métrica + alerta documentada |
| F1-10 | `domain/auth/repository.go` ~24–26 | `FindEnabledByTypes` lista auths cross-gateway: amplía el repo de agregado con una query global | Puerto de lectura separado (`AuthCredentialIndex`) o `FindByCriteria` |
| F1-11 | `infra/auth/oidc/validator.go` ~38 y todos los validators | Constructores devuelven `*Validator` concreto, no la interfaz del puerto | Devolver la interfaz una vez los puertos estén en `app/auth` |
| F1-12 | `domain/identity/principal.go` ~36–81 | Conocimiento vendor-specific (matching de scopes Entra `api://…/leaf`) embebido en el dominio genérico | Extraer `ScopeMatcher` o subpaquete `identity/oauth` |
| F1-14 | `infra/auth/mtls/validator.go` ~47–52 | `cert.Verify` sin pool de `Intermediates`: cadenas con CA intermedia no validan aunque la raíz esté en `ca_cert`; `CertFromXFCC` además solo extrae el leaf | Construir `Intermediates` desde la cadena presentada (elementos `Chain=` de XFCC / `PeerCertificates[1:]`) o documentar que solo se soportan certs emitidos directamente por la raíz |
| F1-15 | `middleware/auth.go` ~32–40 | `NewAPIKeyIdentityResolver` ya no se cablea en el container (`modules/api.go` lo sustituyó por el chain resolver): es código muerto en producción, solo lo usa su propio test | Eliminarlo (su lógica vive en `chainIdentityResolver.resolveAPIKey`) |

## Hallazgos de severidad baja

- `clockSkew=60s`, algoritmos por defecto, `jwksTTL=1h`, `minRefresh=30s`, `discoveryTTL=1h`,
  `fallbackTTL=1m`, `maxTTL=5m`: magic numbers repartidos por los validators; llevarlos a config.
- `contains`/`anyContained` duplicados entre `mtls` y `oidc`.
- Ventana de doble fetch JWKS entre unlock/re-lock (aceptable; `singleflight` opcional).
- Literal `"Bearer "` duplicado entre `auth_chain.go` y `admin_auth.go`.
- `auth_chain.go` ~250 líneas con 4 mecanismos: extraíble a `auth_chain_{mtls,bearer}.go`.
- `domain/identity` sin `errors.go` de sentinels.
- TTL efectivo del cache de introspection (revocación acotada a 1 min) sin documentar en app.
- `introspection/validator.go` ~133–140: la rama de TTL deja en `fallbackTTL` (1 min) los
  tokens con exp entre 1 y 5 min — conservador pero ilegible; reescribir como
  `ttl = clamp(until, fallbackTTL, maxTTL)`.
- Los maps de `jwks.go` (`sets`) y `discovery.go` (`entries`) nunca podan URLs/issuers
  retirados (fuga lenta acotada por nº de IdPs configurados históricamente).

## Qué está bien

- Orden anti-downgrade mTLS → Bearer → API key, con scoping por path para multi-tenant.
- `domain/auth.ConflictsWith` y la validación de issuer OIDC como invariantes de configuración.
- Los validators usan tipos de `domain/auth` para la config (dirección correcta).
