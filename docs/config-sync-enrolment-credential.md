# Config-sync — credencial de enrolamiento del data plane

Spec del **contrato de la credencial** que el data plane presenta al control plane
en el transporte config-sync (gRPC). Es la fuente de verdad para la verificación
(control plane OSS) y la emisión (DataCore / script de instalación).

> Linear: RUN-910 (sub-issue de RUN-905). Afecta por igual a **TrustGate** y
> **TrustGuard** (mismo mecanismo de pull config).

## Contexto

Hoy el data plane se autentica con un **bearer token compartido**
(`CONFIG_SYNC_TOKEN`) que el control plane compara en tiempo constante contra el
digest del token actual/anterior. Ese token **no lleva identidad**: el control
plane sirve un único snapshot global a cualquier data plane autenticado.

Para el modo **híbrido** (control plane = SaaS de NeuralTrust, data plane alojado
por el cliente) la credencial debe **portar identidad de forma no falsificable**,
de modo que el control plane sepa a qué partición (`scope`, que en la capa
propietaria mapea a `tenant_id`) pertenece el data plane y le devuelva **solo su
configuración**.

Principio rector: **el `scope`/`tenant_id` efectivo nunca lo declara el cliente**;
sale de algo que solo el emisor puede producir (una firma) o de una fila del
emisor (lookup). La seguridad **no** depende de que el `scope` sea secreto.

## El data plane no cambia

El data plane manda un bearer opaco: copia `CONFIG_SYNC_TOKEN` en
`authorization: Bearer <token>` sin interpretarlo. Le da igual si es un JWT firmado
o un secreto aleatorio. **El método de validación lo decide el control plane**
(`CONFIG_SYNC_AUTH_MODE`, ver RUN-907). Esta spec define el formato del token que
el emisor produce y el verificador acepta.

## Modo recomendado: JWT firmado

### Algoritmo de firma

- **EdDSA (Ed25519)** como opción por defecto (claves cortas, firma rápida,
  sin parámetros ambiguos). Alternativas aceptables: `ES256` o `RS256`.
- El verificador mantiene una **allowlist de `alg`** y **rechaza `none`** y
  cualquier `alg` fuera de la lista (defensa frente a *algorithm confusion*).
- La clave se identifica por **`kid`** en la cabecera JWT para permitir rotación.

### Claims

| Claim | Obligatorio | Descripción |
|---|:---:|---|
| `iss` | ✅ | Emisor. DataCore/CP en híbrido. Verificado contra `CONFIG_SYNC_JWT_ISSUER`. |
| `aud` | ✅ | Audiencia fija del transporte config-sync. Verificado contra `CONFIG_SYNC_JWT_AUDIENCE`. |
| `scope` | ✅ | Clave de partición **opaca** para el OSS. La capa propietaria la interpreta como `tenant_id`. Nombre único y estable. |
| `exp` | ✅ | Expiración. Obliga a renovación/rotación. |
| `iat` | ✅ | Emisión. |
| `nbf` | ⬜ | *Not before* (si aplica). |
| `jti` | ✅ | Identificador único del token, para revocación / anti-replay. |
| `gateway_scope` | ⬜ | Restringe a un subconjunto de gateways dentro del `scope` (lista de gateway IDs). Vacío/ausente = todos los del `scope`. |
| `sub` / `instance` | ⬜ | Identificador del deployment/DP (informativo; no es control de acceso). |

> El OSS extrae únicamente `scope` (string opaca) y valida `iss`/`aud`/`exp`/`nbf`
> + firma. **La palabra "tenant" no aparece en el OSS**; el mapeo
> `scope → tenant_id` vive en la capa propietaria (RUN-909).

### Ejemplo (payload)

```json
{
  "iss": "datacore",
  "aud": "trustgate-config-sync",
  "scope": "org_7f3a9c2e-1b4d-4e8a-9c11-2d5f6a7b8c90",
  "gateway_scope": [],
  "iat": 1751980800,
  "nbf": 1751980800,
  "exp": 1752585600,
  "jti": "b0f1c2d3-e4a5-6789-90ab-cdef01234567"
}
```

## Alternativa: token opaco con lookup

Cuando se prefiere no depender de verificación de firma en el hot path (o para el
modo `shared` sin identidad), el token puede ser opaco:

- Formato `"<key_id>.<secret>"`.
- El verificador busca `key_id` en su almacén → `{ hash(secret), scope, estado }`.
- Compara `secret` en **tiempo constante** contra el hash almacenado.
- El `scope` **no viaja en el token**; se deriva de la fila del emisor.

Ventaja: revocación inmediata (marcar `estado=revocado`). Coste: un lookup por
conexión (mitigable con caché corta). El `scope` sigue siendo server-authoritative.

## Rotación de claves

- Cada credencial firmada indica su `kid`. El verificador mantiene un **conjunto
  de claves activas** (`kid → public key`).
- Al rotar, se publica la nueva pública **antes** de emitir con ella y se retira la
  vieja **después** de que caduquen los tokens que la usaban (solapamiento sin
  ventana de fallo). Es el equivalente firmado de
  `CONFIG_SYNC_TOKEN` + `CONFIG_SYNC_TOKEN_PREVIOUS`.
- Para el modo opaco, rotación = emitir nuevo `key_id` y marcar el viejo como
  `deprecado` hasta expirar.

## Revocación

- **Por `jti`/`kid`**: lista de revocados consultada por el verificador (o TTL
  corto que fuerza refresco). Necesario para *offboarding* de un cliente.
- **Kill-switch** por `scope`: invalidar todas las credenciales de un `scope`.
- Para el modo opaco, revocar = `estado=revocado` en el almacén.

## Bootstrap vs long-lived

Patrón alineado con `ENROLMENT_TOKEN` del subsistema de residencia
(DataAgent/DataBridge):

1. En el alta del gateway self-hosted, el emisor entrega un **token de
   enrolamiento** (vida corta, de un solo uso).
2. En el primer dial, el data plane **canjea** ese token por una **credencial de
   larga duración** (JWT con `exp` razonable + rotación).
3. El token de enrolamiento se **invalida** tras el canje, para no dejar vivo el
   secreto de alta.

> Nota: el canje requiere un endpoint de emisión en el control plane/DataCore
> (fuera del alcance OSS; ver RUN-911). Para self-hosted 100% no aplica: el
> `CONFIG_SYNC_TOKEN` es un secreto compartido sin identidad generado por el script
> de instalación, y el control plane corre en modo `shared` (`scope` vacío →
> snapshot global).

## Variables de entorno relacionadas (verificación, RUN-907)

```
CONFIG_SYNC_AUTH_MODE      = shared | signed     # default: shared
CONFIG_SYNC_JWT_PUBLIC_KEY = <PEM>               # o CONFIG_SYNC_JWT_JWKS_URL
CONFIG_SYNC_JWT_ISSUER     = <iss esperado>
CONFIG_SYNC_JWT_AUDIENCE   = <aud esperado>
```

En modo `signed`, un token no-JWT, con firma inválida, `alg:none`, `exp` vencido o
`iss`/`aud` incorrectos se **rechaza sin fallback** a `shared` (fail-closed).

## Requisitos de seguridad

- El `scope`/`tenant_id` **nunca** se toma de un campo auto-declarado no firmado.
- `alg` en allowlist; `none` prohibido.
- `exp` obligatorio; `jti` para revocación/anti-replay.
- Un token por deployment (radio de explosión = una partición).
- No loguear tokens.
- El control primario es la firma/lookup, no el secreto del `scope`
  (asúmelo conocido por el atacante).

## Referencias

- `RUN-905` — diseño general (config-sync multi-tenant).
- `RUN-907` — `CONFIG_SYNC_AUTH_MODE` + verificación JWT (consumidor de esta spec).
- `RUN-909` — capa propietaria (`scope → tenant_id`).
- `RUN-911` — emisión de credencial + evento data-plane-online (DataCore).
- `pkg/infra/configsync/grpc/{interceptor,credentials}.go` — auth actual.
- `pkg/config/config.go` — `ConfigSyncConfig`, `STS_ISSUER`/`STS_SIGNING_KEY`.
