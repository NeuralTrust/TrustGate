# Cobertura de la revisión — los 171 ficheros de la PR #50

Matriz de auditoría: cada fichero de `git diff --name-status develop...HEAD`, quién lo revisó
(lectura completa para ficheros nuevos, diff + contexto para modificados) y el hallazgo
principal si lo hay. Los IDs de hallazgo remiten a los docs de fase (`01`–`05`) y al de
tests (`07`).

Leyenda de revisor: **F5** = revisión directa con Fable 5 (este análisis); **F5-A** = auditor
Fable 5 de OAuth/STS; **F5-B** = auditor Fable 5 de dominio; **F5-C** = auditor Fable 5 de tests.

## 1. Operaciones y configuración (30 ficheros)

| Fichero | Est. | Revisor | Notas |
|---|---|---|---|
| `.env.example` | M | F5 | Documenta `SERVER_SECRET_KEY` con doble uso (JWT admin + KEK vault) → ver OPS-2 |
| `cmd/agentgateway/main.go` | M | F5 | Tercer server `mcp` con el mismo patrón que admin/proxy. Sin issues |
| `docker-compose.api.yaml` | M | F5 | Servicio `mcp` puerto 8082. Sin issues |
| `docs/design/consumer-identity-federation-spec.md` | M | F5 | Doc. Sin issues |
| `docs/design/trustgate-mcp-gateway-epic-plan.md` | M | F5 | Doc (consolidación de fases). Sin issues |
| `docs/design/trustgate-mcp-gateway-phase{1..5}-*.md` (5) | D | F5 | Borrados, contenido consolidado en el epic plan |
| `docs/postman/mcp-gateway.postman_collection.json` | A | F5 | Colección Postman (2.617 líneas), no código |
| `go.mod` / `go.sum` | M | F5 | Añade `modelcontextprotocol/go-sdk v1.6.1` y transitvas. Sin issues |
| `k8s/base/deployment/agentgateway-mcp.yaml` | A | F5 | **OPS-1**: anti-affinity con `key: app` que ningún pod tiene → no-op (bug heredado del proxy) |
| `k8s/base/healthcheckpolicy/agentgateway-healthchecks.yaml` | M | F5 | HealthCheckPolicy GKE para el service mcp. Sin issues |
| `k8s/base/horizontalpodautoscaler/agentgateway-mcp.yaml` | A | F5 | HPA por CPU, comentado en kustomization (no activo). Coherente con proxy |
| `k8s/base/httproute/agentgateway-routes.yaml` | M | F5 | Ruta `agentgateway-mcp.*`. Sin issues |
| `k8s/base/kustomization.yaml` | M | F5 | Alta de recursos mcp. Sin issues |
| `k8s/base/poddisruptionbudget/agentgateway-mcp.yaml` | A | F5 | **OPS-4**: selector exige `app.kubernetes.io/name` que el pod template no declara (heredado del PDB del proxy); verificar que kustomize lo inyecte |
| `k8s/base/service/agentgateway-mcp.yaml` | A | F5 | ClusterIP 8082. Sin issues |
| `k8s/overlays/dev/config.env` | M | F5 | `SERVER_MCP_PORT`. Sin issues |
| `k8s/overlays/dev/patches/{httproute,pdb,replicas,resources}-patch.yaml` (4) | M | F5 | Réplicas 1, PDB 0, recursos reducidos. Coherente |
| `k8s/overlays/prod/config.env` | M | F5 | **OPS-3**: prod corre 2 réplicas y no fija `STS_SIGNING_KEY` en config (debe ir en el secret CSI); si queda vacío, cada réplica genera clave RSA efímera distinta y el JWKS publicado no valida los tokens de la otra réplica |
| `k8s/overlays/prod/patches/{httproute,pdb,replicas,resources}-patch.yaml` (4) | M | F5 | Réplicas 2, PDB 1. Coherente |

## 2. Handlers HTTP y middleware (36 ficheros)

| Fichero | Est. | Revisor | Notas |
|---|---|---|---|
| `pkg/api/handler/http/catalog/list_mcp_servers_handler.go` | A | F5 | Devuelve entidades `domain.MCPServer` directamente como response (sin DTO); patrón distinto al resto de handlers. Baja |
| `pkg/api/handler/http/consumer/create_consumer_handler.go` | M | F5 | Añade `FailMode`. **API-1**: `create` no acepta `toolkit` (solo `update`); asimetría en la API admin |
| `pkg/api/handler/http/consumer/request/create_consumer_request.go` | M | F5 | Define `ToolkitEntryRequest`/`parseToolkit` pero el struct de create no tiene campo `Toolkit` (ver API-1). `ToFailMode` sin validar el enum a nivel DTO (lo valida domain) |
| `pkg/api/handler/http/consumer/request/update_consumer_request.go` | M | F5 | Sin issues |
| `pkg/api/handler/http/consumer/response/consumer_response.go` | M | F5 | Sin issues |
| `pkg/api/handler/http/consumer/update_consumer_handler.go` | M | F5 | Sin issues |
| `pkg/api/handler/http/gateway/*.go` (5) | M | F5 | `Domain` en create/update/response. Sin issues propios (ver APP-2 sobre la factoría) |
| `pkg/api/handler/http/mcp/mcp_handler.go` | A | F5 | **F2-01/F2-02** (ya documentado): servidor JSON-RPC completo en un handler; importa `infra/mcp/client`. Nuevo matiz: bodies batch (array JSON) responden `parse error`, incoherente con las revisiones 2024-11-05/2025-03-26 anunciadas que sí permitían batch (baja) |
| `pkg/api/handler/http/oauth/authorization_server_handler.go` | A | F5 | Fino y limpio. Sin issues |
| `pkg/api/handler/http/oauth/authorize_handler.go` | A | F5 | Sin issues |
| `pkg/api/handler/http/oauth/callback_handler.go` | A | F5 | Sin issues (interstitial deep-link justificado) |
| `pkg/api/handler/http/oauth/connect_handler.go` | A | F5 | Sin issues |
| `pkg/api/handler/http/oauth/jwks_handler.go` | A | F5 | Depende del tipo concreto `*sts.Signer` (no interfaz). Media — ver F4 |
| `pkg/api/handler/http/oauth/pages.go` | A | F5 | 226 líneas de CSS/HTML embebido en strings Go; preferible `//go:embed` con ficheros `.gohtml`. Baja |
| `pkg/api/handler/http/oauth/protected_resource_handler.go` | A | F5 | Sin issues |
| `pkg/api/handler/http/oauth/register_handler.go` | A | F5 | Sin issues |
| `pkg/api/handler/http/oauth/token_handler.go` | A | F5 | **API-2**: `ErrNoAuthorizationServer` → HTTP 404 con body `{"error":"invalid_request"}`; RFC 6749 pide 400 para invalid_request. Baja |
| `pkg/api/handler/http/oauth/{connect_handler,handlers,pages}_test.go` (3) | A | F5-C | Ver informe de tests |
| `pkg/api/handler/http/registry/create_registry_handler.go` | M | F5 | Sin issues |
| `pkg/api/handler/http/registry/list_registry_tools_handler.go` | A | F5 | **F2-03** (ya documentado): expone `mcpclient.Tool` (infra) en la response |
| `pkg/api/handler/http/registry/request/*.go` (2) | M | F5 | `MCPAuthRequest`: struct-unión plano de 16 campos para 4 modos; refleja el domain pero con cohesión baja. Baja |
| `pkg/api/handler/http/registry/response/registry_response.go` | M | F5 | `secret.Mask` aplicado a `Value`/`ClientSecret` — correcto |
| `pkg/api/handler/http/registry/update_registry_handler.go` | M | F5 | Sin issues |
| `pkg/api/middleware/access_log.go` | M | F5 | Corrección correcta: deriva el status del error antes de que el error handler lo escriba |
| `pkg/api/middleware/auth.go` | M | F5 | **API-3**: `NewAPIKeyIdentityResolver` queda muerto en producción (el DI ya solo cablea el chain resolver); solo lo usa su propio test. Eliminar o documentar |
| `pkg/api/middleware/auth_chain.go` | A | F5 | **F1-XFCC (ALTA, nuevo)**: `clientCertificate()` acepta `X-Forwarded-Client-Cert` de cualquier origen sin verificar que el peer sea el edge proxy de confianza; XFCC solo transporta el cert público, la posesión de la clave privada la verificó el edge — un cliente directo puede presentar el cert público de otra identidad y autenticarse. Restringir XFCC a redes/peers de confianza o desactivarlo por config. Además fail-open documentado en `pathScope` (ya reportado) |
| `pkg/api/middleware/auth_chain_test.go` | A | F5-C | Ver informe de tests |
| `pkg/api/middleware/oauth_challenge.go` | A | F5 | Limpio. Sin issues |
| `pkg/api/middleware/oauth_challenge_test.go` | A | F5-C | Ver informe de tests |
| `pkg/server/server.go` | A | F6 | `BaseServer` sin `Run`/`Shutdown`; comentario de paquete no menciona MCP. Ver [08-fase-6-server-lifecycle.md](08-fase-6-server-lifecycle.md) (F6-01, F6-04) |
| `pkg/server/http_server.go` | A | F6 | Wrapper `httpServer` redundante si `BaseServer` implementa `Server`. Ver F6-01 |
| `pkg/server/router/admin_router.go` | M | F5 | Ruta `/:id/tools` + catálogo MCP. Sin issues |
| `pkg/server/router/mcp_router.go` | A | F5 + F6 | 12 parámetros posicionales → `MCPRouterDeps` (F6-02). El 405 pre-auth está justificado y comentado |

## 3. Capa app (33 ficheros)

| Fichero | Est. | Revisor | Notas |
|---|---|---|---|
| `pkg/app/auth/creator.go` / `updater.go` | M | F5 | Llaman al guard antes de persistir. Sin issues propios |
| `pkg/app/auth/credential_finder.go` | A | F5 | Importa `infra/cache` (deuda T-01 ya documentada). Cache de candidatos correcto |
| `pkg/app/auth/guard.go` | A | F5 | **APP-1**: TOCTOU — dos creates concurrentes pueden pasar `ensureNoOAuth2Conflict` y persistir ambos (no hay unique constraint en DB que lo respalde). Baja/Media |
| `pkg/app/auth/guard_test.go` / `updater_test.go` | A/M | F5 + F5-C | Buenos casos de equivalencia de audiences |
| `pkg/app/catalog/mcp_servers.go` | A | F5 (sesión previa) | Catálogo estático. Sin issues relevantes |
| `pkg/app/consumer/consumer_data.go` | M | F5 (sesión previa) | Ya documentado en F2 |
| `pkg/app/consumer/creator.go` / `updater.go` | M | F5 | `validateRegistryRefsAssociated` cubre toolkit — correcto |
| `pkg/app/consumer/path_resolver.go` (+test, +mock) | A | F5 (sesión previa) + F5-C | Ya documentado en F1 |
| `pkg/app/gateway/creator.go` | M | F5 | **APP-2**: `Domain` se asigna a mano tras la factoría y se llama `Validate()` manual; rompe el patrón `New(CreateParams)` del proyecto. Media/Baja |
| `pkg/app/gateway/updater.go` (+tests gateway) | M | F5 + F5-C | Sin issues propios |
| `pkg/app/identity/sts/exchanger.go` / `signer.go` (+tests) | A | F5-A + F5-C | Ver informe F5-A (fase 4) |
| `pkg/app/mcp/composer.go`, `credentials.go`, `session.go`, `introspector.go`, `errors.go` (+tests, +mock) | A | F5 (sesión previa, lectura completa) + F5-C | Núcleo del problema — fase 2 |
| `pkg/app/oauth/connect.go`, `dcr.go`, `metadata.go`, `provider.go`, `proxy.go` (+tests) | A | F5-A + F5-C | Ver informe F5-A (fase 3) |
| `pkg/app/registry/creator.go` | M | F5 | Branch `NewMCPRegistry`/`NewRegistry` — correcto |
| `pkg/app/registry/updater.go` | M | F5 | **APP-3**: muta el parámetro de entrada (`in.MCPTarget.Normalize()` / `ResolveSecretsFrom`) antes de asignarlo; efecto colateral sobre el input. Baja |

## 4. Dominio (26 ficheros)

| Fichero | Est. | Revisor | Notas |
|---|---|---|---|
| `pkg/domain/auth/{config,errors,repository,auth_test}.go` + mock | M | F5-B | Ver informe F5-B |
| `pkg/domain/catalog/mcp_server.go` | A | F5-B | Ver informe F5-B |
| `pkg/domain/consumer/{consumer,errors,repository}.go` + `toolkit.go` (+test) + mock | M/A | F5-B | Ver informe F5-B |
| `pkg/domain/gateway/{gateway,errors,repository,gateway_test}.go` + mock | M | F5-B | Ver informe F5-B |
| `pkg/domain/identity/principal.go` (+test) | A | F5-B | Ver informe F5-B (lógica de transporte en domain ya documentada en T-02) |
| `pkg/domain/ids/ids.go` | M | F5-B | Ver informe F5-B |
| `pkg/domain/registry/{registry,errors}.go` + `mcp_target.go` (+test) | M/A | F5-B | Ver informe F5-B |
| `pkg/domain/vault/credential.go` (+test) | A | F5-B | Ver informe F5-B |
| `pkg/infra/database/migrations/2026*.go` (3) | A | F5-B | Ver informe F5-B |

## 5. Infraestructura (21 ficheros)

| Fichero | Est. | Revisor | Notas |
|---|---|---|---|
| `pkg/infra/auth/introspection/validator.go` | A | F5 | Fuga de memoria confirmada (sin eviction; ya documentado F1). Nuevo: la lógica de TTL deja en `fallbackTTL` (1 min) los tokens con exp entre 1 y 5 min — conservador pero confuso; reescribir como `min(maxTTL, max(until, 0))`. Baja |
| `pkg/infra/auth/mtls/validator.go` | A | F5 | **F1-MTLS (nuevo, media)**: `cert.Verify` sin pool de `Intermediates` — cadenas con CA intermedia no validan aunque la raíz esté configurada; `CertFromXFCC` solo extrae el leaf. Documentar o soportar cadenas |
| `pkg/infra/auth/oidc/validator.go` | A | F5 | Lógica de política (`anyMatch` api://-equivalencia, `subjectOf` con `oid`) en infra, ya documentado F1. Resto correcto |
| `pkg/infra/auth/oidc/jwks.go` / `discovery.go` | A | F5 | Maps `sets`/`entries` crecen sin poda por URL/issuer retirado (fuga lenta acotada por nº de IdPs). Baja |
| `pkg/infra/auth/*/validator_test.go` (3) | A | F5-C | Ver informe de tests |
| `pkg/infra/cache/subscriber/invalidate_gateway_data_event_subscriber.go` (+test) | M | F5 | `Clear()` total de auth y paths en cualquier evento de gateway — coarse pero justificado en comentario. Sin issues |
| `pkg/infra/cache/ttlmap_manager.go` | M | F5 | Nuevos nombres/TTLs centralizados — correcto (los TTLs duplicados muertos están en `app/oauth/proxy.go`, ya documentado F3) |
| `pkg/infra/crypto/cipher.go` (+test) | A | F5 + F5-C | **F4-KEY (nuevo, media)**: KEK derivada de `SERVER_SECRET_KEY` sin key-id ni versionado en el ciphertext → rotar el secret invalida todos los tokens del vault sin camino de re-cifrado. Además el mismo secret firma los JWT admin (doble uso). `Encrypt("")→""` silencioso: baja |
| `pkg/infra/mcp/client/client.go` / `protocol.go` (+test) | A | F5 + F5-C | **F2-ALIAS (matiz nuevo)**: los "tipos propios" son alias (`Tool = sdk.Tool`), así que el desacoplamiento del SDK es nominal: toda la API pública de app/handlers queda atada a los tipos del SDK. Refuerza F2-01. `headerRoundTripper` usa `http.DefaultTransport` compartido (sin TLS config por target). Media |
| `pkg/infra/oauth/store.go` / `connect_store.go` | A | F5 | **F3-NIL (nuevo, media)**: "not found" se modela como `nil, nil` (`TakePending`, `GetTicket`, `GetClient`, …) en vez de error sentinel como hace el resto de repos (`domain.ErrNotFound`); patrón propenso a nil-deref en los llamadores y contrato implícito no documentado en los puertos |
| `pkg/infra/repository/auth/repository.go` | M | F5 | `FindEnabledByTypes` correcto (parametrizado, `ANY($1)`) |
| `pkg/infra/repository/consumer/repository.go` | M | F5 | `failMode()` re-aplica el default de dominio en infra (duplicación de regla). Baja |
| `pkg/infra/repository/gateway/repository.go` | M | F5 | `FindByDomain` correcto |
| `pkg/infra/repository/registry/repository.go` | M | F5 | **F4-SECRETS (nuevo, alta)**: `mcp_target` se persiste como JSONB en claro incluyendo `auth.value` (header estático) y `auth.client_secret`, mientras los tokens del vault sí van cifrados con AES-GCM — tratamiento incoherente de secretos at rest en la misma feature. Cifrar estos campos con el mismo cipher (o documentar la excepción) |
| `pkg/infra/repository/vault/repository.go` | A | F5 | `Upsert` pisa `updated_at` con `time.Now()` en infra (el timestamp debería fijarlo domain/app). Baja. Cifrado correcto, `refresh_token` preservado en upsert si llega vacío — bien |

## 6. Wiring (9 ficheros)

| Fichero | Est. | Revisor | Notas |
|---|---|---|---|
| `pkg/config/config.go` | M | F5 | Ver OPS-2/OPS-3. `STS_ISSUER` default `trustgate` razonable |
| `pkg/container/modules/api.go` | M | F5 | **W-1 (media)**: el chain resolver sustituye al de API key en *todos* los planos (el proxy LLM ahora también corre mTLS/JWT/introspection con lookup de path por request); intencional pero conviene confirmar el coste en el hot path del proxy. **W-2 (media)**: `oidc.NewValidator(nil)`, `NewAuthProxy(..., nil, ...)`, `NewMetadataService(..., nil)` — cada componente crea su propio `http.Client`; inyectar uno compartido con timeouts/proxy/TLS centralizados |
| `pkg/container/modules/auth.go`, `cache.go`, `catalog.go`, `consumer.go`, `modules.go`, `server_admin.go` | M | F5 | Altas de providers correctas. Sin issues |
| `pkg/container/modules/mcp.go` | A | F5 | Refleja las dependencias concretas ya documentadas (F3/F4): `*appoauth.ProviderClient`, `*sts.Signer`, `*appoauth.UpstreamRegistrar` se inyectan como tipos concretos, no puertos |
| `pkg/container/modules/server_mcp.go` | A | F5 + F6 | Patrón idéntico a server_proxy; ensamblaje de plano debería vivir en `pkg/server/plane_mcp.go` (F6-09). Ver [08-fase-6-server-lifecycle.md](08-fase-6-server-lifecycle.md) |

## Conclusión de cobertura

171/171 ficheros revisados: 117 directamente con Fable 5 en esta pasada (más los 8 de
`pkg/app/mcp` + consumer data/path resolver leídos completos en la pasada anterior), y 54
delegados a tres auditores Fable 5 (OAuth/STS, dominio, tests) cuyos informes están fusionados
en los docs de fase. Los hallazgos nuevos de esta segunda pasada (no presentes en la primera
versión de los docs) están marcados como **nuevo** arriba y volcados en su doc de fase.

Informes de los auditores integrados:

- **F5-A (OAuth/STS)** → fusionado en `03-fase-3-oauth.md` y `04-fase-4-sts-vault.md`
  (incluye F4-18 token endpoint Okta-only y F4-19 fuga del cache del exchanger).
- **F5-B (dominio)** → fusionado en `04-fase-4-sts-vault.md` (vault) y `05-transversal.md`
  (T-03/T-04 escalados a **Alta**, T-23..T-29 nuevos).
- **F5-C (tests)** → documento propio [07-tests.md](07-tests.md) (TST-01..TST-07).
- **F6 (server lifecycle)** → [08-fase-6-server-lifecycle.md](08-fase-6-server-lifecycle.md)
  (F6-01..F6-08; refactor de `pkg/server` y deps del router MCP, posterior al plan épico).
