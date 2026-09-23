# Tasks: Preservar imágenes al convertir chat OpenAI → Anthropic (ENG-1608)

Spec: `chat-image-content` (`spec.md`). Diseño: `design.md` (autoritativo). Linear: [ENG-1608](https://linear.app/neuraltrust/issue/ENG-1608/preserve-image-content-when-converting-openai-format-chat-requests-to). Worktree hermano `/Users/edu/Neuraltrust/TrustGate-eng1608`, rama `fix/eng-1608-preserve-image-content-openai-to-anthropic` desde `origin/develop` (`0b99b40d`); `develop` está protegida, nunca se commitea ahí. Cada fase es **un commit de unidad de trabajo** (skill `work-unit-commits`) que compila y pasa `go test -race` por sí solo, con sus propios tests.

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ≈1.010: ≈325 de producción (+305 / −20) + ≈685 de tests. Sin ficheros generados (no cambian mocks, proto ni OpenAPI) |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | 5 PRs encadenados (stacked), uno por fase: ≈200 / ≈200 / ≈210 / ≈240 / ≈170 líneas (ver tabla) |
| Delivery strategy | ask-on-risk |
| Chain strategy | single-pr size:exception (aprobado por Edu 2026-09-23) |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: single-pr size:exception
400-line budget risk: High

**Por qué High aunque la producción cabe:** el presupuesto cuenta `additions + deletions` del PR entero, tests incluidos. La producción (≈325) cabe en 400; con tests el PR único mide ≈1.010, 2,5× el presupuesto.

**Opciones (decide Edu antes de aplicar):**

1. **Recomendada: 5 PRs stacked** (`chained-pr`, estrategia Stacked PRs). Cada fase deja `develop` verde y sin regresiones, y se revierte sola:
   - La Fase 1 no tiene efecto en runtime.
   - La 2 arregla ya las reescrituras mismo-formato OpenAI de los plugins.
   - La 3 arregla OpenAI → Anthropic directo.
   - La 4 arregla Bedrock, que es el caso ISDIN.
   - La 5 solo añade tests.
   
   Ninguna pieza supera ≈250 líneas. Coste: 5 rondas de revisión para un bug High, y el caso ISDIN no llega hasta la 4.
2. **Alternativa: PR único con `size:exception`** y 5 commits de unidad de trabajo, como en `mcp-granular-policies`. Justificación: la producción (≈325) cabe en el presupuesto, el exceso es solo de tests, y la revisión va commit a commit. Es la vía más rápida para cerrar ENG-1608.
3. Descartada: 2 PRs (Fases 1–3 y Fases 4–5). Miden ≈610 y ≈410, así que los dos siguen por encima de 400 sin evitar la excepción.

Si se elige la 1, cada PR apunta a la rama de la fase anterior y se retarguea a `develop` al fusionar la previa. Si se elige la 2, la tabla de abajo es la guía de revisión y el cuerpo del PR lleva `size:exception` con esta justificación. En ambos casos el orden es 1 → 2 → 3 → 4 → 5.

### Suggested Work Units

| Orden | Fase | Commit | Objetivo | Líneas (prod / test) | Verificación | Sin regresión porque… |
|---|---|---|---|---|---|---|
| 1 | `canonical` | `fix(adapter): add CanonicalImage and image helpers` | `CanonicalImage`, `CanonicalMessage.Images`, `image.go` (`ErrUnsupportedContent`, parseo `data:`, media types, `isHTTPImageURL`) | ≈88 / ≈110 | `go test -race ./pkg/infra/providers/adapter/...`, `make lint` | ningún decoder rellena `Images`; `omitempty` |
| 2 | `openai` | `fix(adapter): keep image_url parts in OpenAI chat completions` | decode/encode `image_url`; `contentToString` delega en `decodeOpenAIContent` | ≈90 / ≈110 | `go test -race ./pkg/infra/providers/adapter/...` | sin imágenes, `content` sigue siendo string; los encoders Anthropic/Bedrock aún ignoran `Images` (igual que hoy) |
| 3 | `anthropic` | `fix(adapter): carry image blocks through Anthropic messages` | encode/decode bloque `image`; `ErrUnsupportedContent` → `ErrInvalidRequestPayload` en `provider.go` | ≈62 / ≈150 | `go test -race ./pkg/infra/providers/adapter/... ./pkg/app/proxy/...` | primer emisor del sentinel y su mapeo a 400 en el mismo commit; sin imágenes el wire no cambia |
| 4 | `bedrock` | `fix(bedrock): send image blocks to Converse` | `ConverseImageBlock`, encode/decode en `BedrockAdapter`, `sdkImage` en `converse.go` | ≈87 / ≈150 | `go test -race ./pkg/infra/providers/... ./pkg/app/proxy/...` | sin imágenes, un único bloque `text` como hoy |
| 5 | `regression` | `test(adapter): cover image content across formats` | `TestAdaptRequest_Images`, `TestAdaptRequest_ImageRegression`, functional con stub Anthropic | 0 / ≈170 | `make test-race`, `make test-functional` | solo tests |

Total ≈325 de producción + ≈685 de tests. Las cifras salen de la tabla File Changes del diseño: los tests cross-format de `adapter_test.go` (+130) se reparten entre las Fases 2–4 (casos propios de cada formato) y la 5 (tabla cruzada y regresión con/sin imagen).

**Cambio respecto a la partición sugerida:** el mapeo a 400 de `provider.go` pasa de la Fase 1 a la 3. En la Fase 1 ningún encoder emite todavía `ErrUnsupportedContent`, y `provider_invoker_test.go` usa el registry real de adapters, así que la línea no se podría probar en su propio commit. La Fase 3 incluye el primer emisor (Anthropic con `ftp://`) y su test de invoker; la 4 le añade el caso Bedrock + `https`.

## Fase 1 — Commit 1 · `canonical`

- [x] 1.1 `pkg/infra/providers/adapter/canonical.go` (`:43-48`): tipo `CanonicalImage{MediaType, Data, URL, Detail}` y campo `CanonicalMessage.Images []CanonicalImage json:"images,omitempty"`, tal cual en design §Interfaces. Doc comments solo en lo exportado (`go-comments.mdc`). [chat-image-content §Imágenes en el modelo canónico]
- [x] 1.2 Crear `pkg/infra/providers/adapter/image.go` con:
  - `var ErrUnsupportedContent = errors.New("unsupported content")`.
  - `normalizeImageMediaType` (`TrimSpace`, minúsculas, `image/jpg` → `image/jpeg`).
  - `supportedImageMediaType` (jpeg | png | gif | webp). *Eliminado en la revisión final (ver "Revisión final"): Anthropic y Bedrock validan el media type ellos mismos.*
  - `parseImageURL(raw, detail)`: `data:<mt>[;params];base64,<d>` → `{MediaType, Data, Detail}`; cualquier otra cosa, también una `data:` sin `;base64`, → `{URL: raw, Detail}`.
  - `(CanonicalImage).dataURI()`.
  - `isHTTPImageURL` (`url.Parse`, esquema `http`/`https`, `Host != ""`).
  
  [§Decode OpenAI Chat Completions]
- [x] 1.3 Crear `pkg/infra/providers/adapter/image_test.go`, table-driven con `t.Parallel()` y testify:
  - `parseImageURL`: png; `image/jpg` → jpeg; mayúsculas; `;charset=…;base64`; sin `;base64` → `URL`; vacía; https con `detail`.
  - Round-trip `dataURI(parseImageURL(x)) == x` para las URIs bien formadas.
  - `isHTTPImageURL`: http y https → true; ftp, `file://`, sin host, `data:` → false.
  - `supportedImageMediaType`: los 4 tipos y tiff.
  
  El linter `unused` corre con `tests: true` (`.golangci.yml`), así que estos tests cuentan como uso de los helpers.
- [x] 1.4 Gate: `make fmt`, `make lint`, `go test -race ./pkg/infra/providers/adapter/...`, `clean-comments` sobre los `.go` tocados.

## Fase 2 — Commit 2 · `openai`

- [x] 2.1 `pkg/infra/providers/adapter/openai_completions_adapter.go`: tipos `openaiContentPart{Type, Text, ImageURL json.RawMessage}` y `openaiImageURL{URL, Detail}`. `image_url` puede venir como objeto o como string.
- [x] 2.2 `pkg/infra/providers/adapter/openai_adapter.go` (`:140-162`): `decodeOpenAIContent(raw) (string, []CanonicalImage)`. El texto conserva la semántica actual de `contentToString`: partes `text` unidas con `\n`, string tal cual. Una parte `image_url` sin URL se ignora. `contentToString` pasa a devolver solo el texto de `decodeOpenAIContent`, así que sus otros llamadores (Anthropic `:258/:309/:845/:889`, Cohere, Responses) no cambian.
- [x] 2.3 Decode (`openai_completions_adapter.go:257-276`): los mensajes `user` usan `decodeOpenAIContent` y rellenan `Images`. En `system`/`developer` las imágenes se ignoran como hoy. [§Decode OpenAI]
- [x] 2.4 Encode (`:331-341`): `encodeOpenAIContent(m)`.
  - Sin `Images` → `stringToContent(m.Content)`, byte a byte lo de hoy.
  - Con `Images` → array con una parte `image_url` por imagen (`dataURI()`, `detail` si existe) y después una parte `text` si `Content != ""`.
  - Solo en la rama de mensaje ordinario: ni `tool` ni assistant con `tool_calls`.
  - Nunca falla. [§Encode OpenAI, §Orden de bloques]
- [x] 2.5 `openai_completions_adapter_test.go`:
  - `TestDecodeCompletionsRequest_Images`: data URI, URL + `detail`, `image_url` string, `data:` mal formada → `URL` sin error, imagen en `system` ignorada, varios textos + imagen → `Content` unido.
  - `TestEncodeCompletionsRequest_Images`: orden imágenes → texto, solo imagen sin parte `text`, sin imágenes → `content` string.
  - Round-trip OpenAI → OpenAI de un plugin: decode, editar `Messages[i].Content`, encode. La `image_url` sale intacta y el texto una sola vez. [§Plugin reescribe el texto de un mensaje con imagen]
- [x] 2.6 Los tests actuales de `openai_adapter_test.go` / `adapter_test.go` sobre `contentToString` siguen verdes sin tocarlos (criterio "texto y múltiples bloques de texto no cambia").
- [x] 2.7 Gate: `make fmt`, `make lint`, `go test -race ./pkg/infra/providers/adapter/... ./pkg/infra/plugins/...` (los plugins mismo-formato dependen del round-trip), `clean-comments`.

## Fase 3 — Commit 3 · `anthropic`

- [x] 3.1 `pkg/infra/providers/adapter/anthropic_adapter.go` (`:83-94`): tipo `anthropicImageSource{Type, MediaType, Data, URL}` y campo `anthropicContentBlock.Source *anthropicImageSource json:"source,omitempty"`.
  *Sustituido en la revisión final (R.1): `Source` es `json.RawMessage` y solo se deserializa a `anthropicImageSource` en `case "image"`.*
- [x] 3.2 Decode (`decodeAnthropicMessageContent`, `:246-315`): en mensajes `user`, un bloque `image` con `source.type = base64` produce `{MediaType normalizado, Data}` y uno con `url` produce `{URL}`. `file` y el resto se ignoran como hoy. Un mensaje que solo tiene imágenes produce un `CanonicalMessage` con `Content: ""`. [§Decode Anthropic Messages]
- [x] 3.3 Encode: `anthropicImageBlock(img)` y `anthropicUserContent(m)` en la rama ordinaria de `EncodeRequest` (`:441-444`).
  - Sin imágenes → `stringToContent`, igual que hoy.
  - Con imágenes → bloques `image` y después `text` si no está vacío.
  - `Data` exige un media type soportado; si no, `unsupported content: image media type is not supported`.
  - `URL` exige `isHTTPImageURL`; si no, `unsupported content: image must be a base64 data URI or an http(s) URL`.
  - Los errores envuelven `ErrUnsupportedContent` con `%w` y no incluyen la URL ni los datos. `Detail` se descarta. [§Encode Anthropic Messages]
  *Sustituido en la revisión final (R.3, R.4, R.7): una sola `anthropicMessageContent`; solo se rechaza una URL no `http(s)` (el media type no se valida, tiff pasa) con `*UnsupportedContentError` y razón neutra.*
- [x] 3.4 `pkg/app/proxy/provider.go` (`:332`): `if adapter.IsRequestDecodeError(err) || errors.Is(err, adapter.ErrUnsupportedContent)` → `ErrInvalidRequestPayload` (versión final en R.4: `errors.As` + `%w: %w`). Ya es terminal en `classifyOutcome` y ya da 400 en `proxy_handler.go:461-463`. [§Error de cliente, nunca 502 ni descarte]
- [x] 3.5 `anthropic_adapter_test.go`:
  - `TestAnthropicEncodeRequest_Images`: base64; url; tiff → `ErrorIs(ErrUnsupportedContent)`; `ftp://` y `data:` mal formada → `ErrorIs`; solo imagen sin bloque `text`; el mensaje de error no contiene la URL ni el base64.
  - `TestDecodeAnthropicMessageContent_Images`: base64, url, `file` ignorado, solo imagen produce mensaje.
  *Sustituido en la revisión final (R.3, R.4): tiff pasa sin error; ftp y `data:` mal formada → `ErrorAs(*UnsupportedContentError)` sin URL, datos ni "anthropic" en el mensaje.*
- [x] 3.6 `adapter_test.go`, casos propios de esta fase sobre `testRegistry()`:
  - OpenAI → Anthropic con data URI y con URL.
  - Anthropic → OpenAI con webp: `image_url.url = "data:image/webp;base64,…"`.
  - Intercalado `[text A, image X, text B, image Y]` → `[image X, image Y, text "A\nB"]`.
  
  `TestAdaptRequest_OpenAIToAnthropic` (`:347`) sigue verde sin tocarlo.
- [x] 3.7 `pkg/app/proxy/provider_invoker_test.go`: `TestProviderInvoke_UnsupportedImageIsInvalidPayload`. Target Anthropic con imagen `ftp://…` → `assert.ErrorIs(err, ErrInvalidRequestPayload)` y el cliente mock no se llama (patrón de `TestProviderInvoke_ImagesInvalidMethod`, `provider_images_test.go:87`). Table-driven, para que la Fase 4 solo tenga que añadir una fila.
- [x] 3.8 Gate: `make fmt`, `make lint`, `go test -race ./pkg/infra/providers/adapter/... ./pkg/app/proxy/...`, `clean-comments`.

## Fase 4 — Commit 4 · `bedrock`

- [x] 4.1 `pkg/infra/providers/adapter/bedrock_adapter.go` (`:48-53`): tipos exportados `ConverseImageBlock{Format, Source}` y `ConverseImageSource{Bytes []byte json:"bytes,omitempty"}`, y campo `ConverseContentBlock.Image *ConverseImageBlock json:"image,omitempty"`. Doc comments porque son exportados.
- [x] 4.2 `converseImageFormat(mediaType) (string, bool)` y `converseImageFromCanonical(img)`. Casos que devuelven error:
  - `URL` presente → `unsupported content: bedrock accepts images only as base64 data URIs`.
  - Media type no soportado → mismo texto que en Anthropic.
  - `base64.StdEncoding.DecodeString` falla → `unsupported content: image data is not valid base64`.
  
  Todos envuelven `ErrUnsupportedContent`. [§Bedrock Converse]
  *Sustituido en la revisión final (R.3, R.4): `image/<x>` → `x` sin allowlist (tiff pasa); errores `*UnsupportedContentError` con razones neutras: URL, media type vacío o no `image/*`, base64 inválido.*
- [x] 4.3 `converseMessageFromCanonical` (`:415-444`) pasa a devolver `(ConverseMessage, error)` y emite las imágenes antes del bloque `text`. `EncodeRequest` (`:381-398`, llamador en `:393`) propaga el error. Hay que buscar con grep otros llamadores y ajustarlos.
- [x] 4.4 Decode (`converseMessageToCanonical`, `:314-347`): bloque `image` con `source.bytes` → `{MediaType: "image/<format>", Data: base64.StdEncoding.EncodeToString(bytes)}`. Sin bytes (`s3Location`) se ignora como hoy.
- [x] 4.5 `pkg/infra/providers/bedrock/converse.go` (`:195-216`): caso `b.Image != nil` en `sdkContentBlock`. `sdkImage(img)` devuelve `&bedrockTypes.ContentBlockMemberImage{Value: ImageBlock{Format: ImageFormat(img.Format), Source: &ImageSourceMemberBytes{Value: img.Source.Bytes}}}`, o `nil` si `len(Bytes) == 0`.
- [x] 4.6 `bedrock_adapter_test.go`:
  - `TestBedrock_EncodeRequest_Images`, con el helper `decodeConverse`: formato por cada media type, bytes decodificados, imagen antes del texto; URL, `image/tiff` y `data:image/png;base64,@@@` → `ErrorIs(ErrUnsupportedContent)`; el mensaje no contiene la URL ni los datos.
  - `TestBedrock_DecodeRequest_Image`.
  
  `TestAdaptRequest_OpenAIToBedrock` (`adapter_test.go:550`) sigue verde sin tocarlo.
- [x] 4.7 `pkg/infra/providers/bedrock/converse_test.go`: `TestDecodeConverseBody_Image` junto a `TestDecodeConverseBody` (`:42`). Espera `ContentBlockMemberImage{Format: jpeg}` con los bytes esperados, antes del texto; una imagen sin bytes se descarta. [§OpenAI data URI → Bedrock (caso ISDIN)]
- [x] 4.8 `provider_invoker_test.go`: nueva fila en la tabla de 3.7. Target Bedrock + `https://…` → `ErrInvalidRequestPayload`, sin llamada al cliente. [§URL hacia Bedrock]
- [x] 4.9 Gate: `make fmt`, `make lint`, `go test -race ./pkg/infra/providers/... ./pkg/app/proxy/...`, `clean-comments`.

## Fase 5 — Commit 5 · `regression`

- [x] 5.1 `adapter_test.go`: extend `TestAdaptRequest_Images` with rows (ya existe desde la Fase 3, table-driven sobre `testRegistry()`) hasta completar la tabla cruzada:
  - OpenAI → Anthropic (data URI, URL).
  - OpenAI → Bedrock (data URI).
  - OpenAI → Bedrock con URL → error.
  - OpenAI → OpenRouter: conserva `image_url` + `detail`. Es cross-format, así que valida el encode OpenAI compartido con Groq y Mistral.
  - Anthropic → OpenAI (data URI).
  - Anthropic → Bedrock.
- [x] 5.2 `adapter_test.go`: `TestAdaptRequest_ImageRegression`. La misma petición OpenAI, con `system`, `max_tokens`, `tools` y texto de usuario, se adapta con y sin una parte `image_url` hacia Anthropic y hacia Bedrock, y se comparan los bodies:
  - Solo la versión con imagen lleva el bloque de imagen en el primer turno de usuario.
  - Tras quitar ese bloque, el resto del body es igual en ambas (`assert.JSONEq`).
  - Sin imagen, `content` es string en Anthropic y un único `text` en Converse.
  
  Es el sustituto a nivel de body de la comparación de `prompt_tokens`: si la imagen llega al wire, el upstream la tokeniza. [§Regresión con y sin imagen; AC 3 de Linear]
- [x] 5.3 `tests/functional/payload_normalization_test.go` (`//go:build functional`): stub `newAnthropicUpstream` sobre `fakeUpstream`, que devuelve una respuesta Messages mínima con `usage`, y el test `TestPayloadNormalization_ImageContent` con un backend Anthropic hecho con `anthropicFilesBackendPayload` (`files_provider_test.go:266`) apuntando al stub. Casos:
  1. Con imagen: `up.LastBody()` contiene `"type":"image"` y `"media_type":"image/png"`.
  2. Sin imagen: `content` string como hoy.
  3. `ftp://` → 400 con `error = "invalid_request"` y `up.Hits() == 0`.
  
  La ruta del proxy debe coincidir con el nombre del consumer (AGENTS.md §Functional proxy routes). [§400 extremo a extremo]
  
  **Desviación aplicada:** el cliente Anthropic de chat (`pkg/infra/providers/anthropic/client.go`, `messagesURL`) ignora `provider_options.base_url`, así que un stub Anthropic nunca recibe la petición. Los casos 1 y 2 van por `/v1/messages` hacia un stub OpenAI (`newJSONUpstream`): la imagen llega como `image_url` `data:` URI, y sin imagen `content` es string. El caso 3 usa un backend Anthropic real (sin llamada de red porque el encoder rechaza antes) y comprueba 400 `invalid_request`, `unsupported content` y que el stub no recibe nada.
- [x] 5.4 Gate: `make test-race`, `go vet -tags functional ./tests/functional/...`, `make test-functional` (Postgres + Redis locales), `clean-comments`.

## Revisión final (fixups sobre las fases 3 y 4, y commit nuevo de semanticcache)

- [x] R.1 Anthropic: `anthropicContentBlock.Source` pasa a `json.RawMessage` y solo se deserializa en `case "image"` (un `search_result` con `source` string rompía el array y se perdían los `tool_result`). Test `[tool_result, search_result{source:"https://…"}, text]`. (fixup Fase 3)
- [x] R.2 Anthropic decode: los mensajes `tool` salen antes del mensaje `user` del mismo turno (también para texto + `tool_result`, que antes salía en un orden que OpenAI rechaza). (fixup Fase 3)
- [x] R.3 Sin allowlist de media types: Anthropic solo rechaza URLs no `http(s)`; Bedrock mapea `image/<x>` → `x` y solo rechaza URL, media type vacío o no `image/`, y base64 inválido. `supportedImageMediaType` eliminado. tiff pasa en ambos. (fixups Fases 3 y 4)
- [x] R.4 `*UnsupportedContentError{Reason}` exportado en `image.go` (su `Is` casa con `ErrUnsupportedContent`), con razones neutras respecto al proveedor. `prepare` usa `errors.As` y `fmt.Errorf("%w: %w", ErrInvalidRequestPayload, contentErr)` (sin el prefijo `adapter request encode (<fmt>)`), con log debug de la cadena completa; `RequestDecodeError` también con `%w: %w`. Tests: el mensaje no contiene URL, `adapter` ni el nombre del backend. (fixups Fases 3, 4 y 5)
- [x] R.5 Converse nativo con `bytes` no base64: antes el error de `decodeConverseBody` era plano (retryable → fallback → 502). Ahora es `*adapter.RequestDecodeError` y `clientRequestError` en `Invoke`/`InvokeStream` lo convierte en `ErrInvalidRequestPayload` (400 terminal). Infra no importa `pkg/app`. (fixup Fase 4)
- [x] R.6 `fix(semanticcache): bypass cache for turns with images`: si el último turno de usuario (el de la clave) tiene `Images`, no hay lookup ni store (`SkipReason = "images_present"`). Test `TestPlugin_ImagesBypassCache`. (commit nuevo)
- [x] R.7 `anthropicMessageContent` y `anthropicUserContent` fusionadas. (fixup Fase 3)

## Fase 6 — Verificación final (no es commit; evidencia en el PR y en ENG-1608)

- [ ] 6.1 En el worktree: `make fmt`, `make lint` (0 issues), `go test -race ./pkg/...`, y `make test-functional` si Postgres + Redis están disponibles en local. Si no lo están, basta `go vet -tags functional ./tests/functional/...` y se anota en el PR que no se pudo ejecutar. `git diff --stat origin/develop` para contrastar las líneas reales con el forecast. `.cursor/` no entra en el PR.
- [ ] 6.2 Live check fuera del repo, en `/Users/edu/Neuraltrust/multi-agent-tests`. No bloquea el PR; sí bloquea cerrar ENG-1608.
  - **Entorno.** Levantar en local el gateway de esta rama (admin `:8080`, proxy `:8081`). Antes de lanzar nada, confirmar que `.env` apunta a local (`TG_ADMIN_URL=http://localhost:8080/api/v1`, `TG_PROXY_URL=http://localhost:8081`). Por defecto el `.env` de ese repo apunta al gateway de prod, donde este fix no está desplegado.
  - **Configuración.** Crear vía Admin API dos registries y consumers: Anthropic directo (con `ANTHROPIC_API_KEY`) y Bedrock (con credenciales `AWS_*`, modelo `eu.anthropic.claude-sonnet-4-5-20250929-v1:0`).
  - **Petición.** Para cada upstream, enviar `/v1/chat/completions` dos veces, con y sin una parte `image_url` `data:image/png;base64,…` (una imagen pequeña con contenido reconocible), con el mismo texto y `max_tokens`.
  - **Resultado esperado.** `prompt_tokens` con imagen sensiblemente mayor que sin ella (el baseline del cliente eran 28), y la respuesta describe la imagen en vez de `NO_IMAGE`.
  - **Negativo en Bedrock.** Una imagen `https://…` hacia Bedrock → 400 `invalid_request`.
  - **Evidencia.** Guardar los `usage` en el PR y en un comentario de ENG-1608. [AC 1 de Linear]
- [ ] 6.3 Decidir si se añade un e2e permanente en `multi-agent-tests`, por ejemplo en `src/e2e/tests/` o como celda de `make matrix-tg`, con imagen para anthropic y bedrock. Si se añade, va en **un PR aparte en ese repo**, citando ENG-1608, y se fusiona después del despliegue a dev. Si no, se deja constancia en el ticket con el motivo, por ejemplo el coste en tokens por ejecución.
- [ ] 6.4 Marcar `[x]` aquí al fusionar cada commit o PR y, al final, ejecutar `sdd-verify` contra los requisitos de `spec.md`.

## QA checklist (Linear ENG-1608)

| Acceptance criterion (Linear) | Cómo se verifica | Tareas |
|---|---|---|
| Una imagen enviada vía `/v1/chat/completions` a un modelo Anthropic hace que `prompt_tokens` refleje la imagen y el modelo responda sobre el contenido visual | Unit: el body a Anthropic y a Converse lleva el bloque `image` y el SDK recibe `ContentBlockMemberImage`. Functional: Anthropic ingress → stub OpenAI recibe `image_url` (no hay stub Anthropic: el cliente de chat ignora `base_url`). Live: `prompt_tokens` sube con imagen y el modelo describe la imagen, contra Anthropic directo y Bedrock `eu.anthropic.claude-sonnet-4-5-20250929-v1:0` | 3.3, 3.6, 4.3, 4.5, 4.7, 5.3, 6.2 |
| El comportamiento actual con texto y múltiples bloques de texto en `/v1/chat/completions` no cambia | Sin imágenes, el body de salida es byte a byte el actual (`content` string, un único `text` en Converse). Los tests actuales `TestAdaptRequest_OpenAIToAnthropic` / `_OpenAIToBedrock` y los de `contentToString` pasan sin tocarlos. Caso functional sin imagen | 2.4, 2.6, 3.6, 4.6, 5.2, 5.3 |
| Test de regresión que compare tokens con/sin imagen en la ruta OpenAI → Anthropic | `TestAdaptRequest_ImageRegression` compara los bodies con y sin imagen hacia Anthropic y Bedrock: solo difiere el bloque de imagen. La comparación real de `prompt_tokens` es el live check, y opcionalmente un e2e permanente en `multi-agent-tests` | 5.2, 6.2, 6.3 |
| (Diseño) Lo que el destino no puede representar da 400, nunca 502 ni descarte silencioso | Invoker: `ErrInvalidRequestPayload` + `ErrUnsupportedContent` sin llamada al upstream, mensaje sin nombre de backend; `RequestDecodeError` del cliente Converse nativo → 400. Functional: `ftp://` → 400 y `Hits() == 0`. Live: `https` hacia Bedrock → 400 | 3.4, 3.7, 4.8, 5.3, 6.2, R.4, R.5 |
| (Diseño) Las reescrituras mismo-formato de los plugins no borran la imagen | Round-trip OpenAI → OpenAI con `Content` editado; `go test -race ./pkg/infra/plugins/...` | 2.5, 2.7 |

## Fuera de este cambio (seguimiento, no son tareas)

- Gemini, Cohere y OpenAI Responses siguen descartando `Images`.
- El cliente de chat de Anthropic (`pkg/infra/providers/anthropic/client.go`, `messagesURL`) ignora `provider_options.base_url`; solo Files lo respeta. Impide un functional OpenAI → stub Anthropic.
- `promptcompression/safety.go`: sigue saltando los bodies con `image_url`.
- `semanticcache`: hoy se hace bypass con imágenes (R.6); incluirlas en la clave y en el embedding queda pendiente.
- `semanticcache`: la clave sigue ignorando las imágenes (y el bypass no se activa) para Responses, Gemini, Cohere y el fallback genérico `ExtractUserInputGeneric`, porque sus decoders no producen `Images`.
- Imágenes en `tool_result`, Anthropic `source.type = file`, Converse `s3Location`, documentos y audio.
- Changelog: `prompt_tokens` sube para clientes que ya enviaban imágenes, y Bedrock con URL `http(s)` pasa a 400.
- Si ISDIN necesita el fix en prod antes del ciclo normal: rama desde `main` y back-merge a `develop`. Nunca promoción `develop` → `main`.
- Linear: crear los tickets de seguimiento anteriores, y sub-issues por fase si se eligen PRs encadenados (`sdd-linear-sync`).
