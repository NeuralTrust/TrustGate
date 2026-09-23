---
linear: ENG-1608
type: fix
changelog: "Preserve image content parts when a chat request crosses formats (OpenAI ↔ Anthropic ↔ Bedrock Converse); unsupported image sources now return 400 instead of being dropped."
---

# Proposal: Preservar imágenes al convertir chat OpenAI → Anthropic (ENG-1608)

## Intent

`/v1/chat/completions` (formato OpenAI) pierde las partes `image_url` cuando el upstream es Anthropic o Bedrock. El cliente (ISDIN) usaba `eu.anthropic.claude-sonnet-4-5-20250929-v1:0` (inference profile de Bedrock → Converse): `prompt_tokens` idéntico con y sin imagen, y el modelo responde `NO_IMAGE`. Un segundo bloque de texto sí sube los tokens, así que el problema son las imágenes.

Causa raíz: `CanonicalMessage.Content` es un `string` (`pkg/infra/providers/adapter/canonical.go:43-48`). `contentToString` (`openai_adapter.go:140-162`) se queda solo con el texto de las partes, y ningún encoder puede emitir lo que el modelo canónico no tiene. La misma pérdida afecta a:

- Anthropic → OpenAI y cualquier reescritura mismo-formato de `/v1/messages` (`decodeAnthropicMessageContent`, `anthropic_adapter.go:246-315`, descarta bloques `image`).
- Reescrituras mismo-formato OpenAI hechas por plugins (regexreplace, trustguard rewrite, googlemodelarmor, bedrockguardrail, toolallowlist, pertoolratelimit, toolinjection): decode → editar `Content` → encode aplana el array de partes a string y borra la imagen, **incluso con upstream OpenAI**.
- Converse nativo: `sdkContentBlock` (`pkg/infra/providers/bedrock/converse.go:195-216`) devuelve `nil` para bloques desconocidos, así que una imagen Converse nunca llega al SDK.

## Scope

### In Scope

- Modelo canónico: `CanonicalMessage.Images []CanonicalImage` (media type + base64, o URL; `detail` opcional). `Content` sigue siendo el texto unido, así que los plugins siguen editando `Content` sin cambios.
- OpenAI Chat Completions: decode (`data:` URI → media type + base64; resto → URL) y encode (partes `image_url` antes del texto). Cubre OpenAI mismo-formato vía plugins y OpenAI ↔ Groq / OpenRouter / Mistral, que comparten `encodeCompletionsRequest`.
- Anthropic Messages: encode (`source.type` `base64` / `url`) y decode (bloques `image` → canónico).
- Bedrock Converse: tipo wire `ConverseImageBlock`, encode/decode en `BedrockAdapter` y mapeo al SDK (`ContentBlockMemberImage` + `ImageSourceMemberBytes`). El `format` es la `x` de un media type `image/<x>`; lo valida Bedrock.
- Error explícito para lo que el destino no puede representar: sentinel `adapter.ErrUnsupportedContent`, mapeado a `ErrInvalidRequestPayload` → HTTP 400. El gateway nunca descarga una URL (SSRF) y nunca descarta en silencio.
- `semanticcache`: bypass de lookup y store cuando el turno de usuario que da la clave lleva imágenes (la clave es solo texto y colisionaría). Meter las imágenes en la clave queda como seguimiento.
- Tests: unit table-driven en `adapter`, `bedrock`, `app/proxy` y `semanticcache`; functional Anthropic ingress → stub OpenAI y 400 hacia backend Anthropic (el cliente de chat de Anthropic ignora `base_url`, así que no hay stub Anthropic).

### Out of Scope

- Gemini, Cohere y OpenAI Responses (siguen descartando imágenes como hoy) → ticket de seguimiento.
- Ampliar la allowlist de `promptcompression/safety.go` (hoy salta los bodies con `image_url`; sigue igual).
- Imágenes dentro de `tool_result` (Anthropic y Converse), fuentes `file` de Anthropic y `s3Location` de Converse.
- Documentos / PDF / audio (`input_audio`, `file`).
- Incluir las imágenes en la clave (y el embedding) de `semanticcache` → ticket de seguimiento; aquí solo se hace bypass.
- Conservar el orden exacto de texto e imágenes intercalados.

## Capabilities

### New Capabilities

- `chat-image-content`: imágenes de usuario como parte tipada del modelo canónico, conservadas entre OpenAI Chat Completions, Anthropic Messages y Bedrock Converse, con rechazo explícito (400) de las fuentes que el destino no admite.

### Modified Capabilities

- None.

## Approach

Partes de imagen tipadas junto al texto. Cada decoder separa el texto (unido con `\n`, igual que hoy) de las imágenes; cada encoder emite primero las imágenes y después un único bloque de texto, que es el orden que recomienda Anthropic. Sin imágenes, el wire de salida es byte a byte el actual: `content` string en OpenAI y Anthropic, un bloque `text` en Converse.

Validación solo donde hay que traducir: el decoder OpenAI nunca falla (una `data:` URI que no se puede parsear se guarda tal cual en `URL`, y OpenAI la reemite sin pérdida). Anthropic solo rechaza URLs que no son `http(s)` (media type y base64 los valida Anthropic). Bedrock rechaza una URL, un media type vacío o que no es `image/*`, y un base64 inválido. Lo demás lo valida el upstream. Los rechazos locales devuelven `*UnsupportedContentError` (satisface `errors.Is(err, ErrUnsupportedContent)`), con un mensaje que no nombra al backend.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `pkg/infra/providers/adapter/canonical.go` | Modified | `CanonicalImage`, `CanonicalMessage.Images` |
| `pkg/infra/providers/adapter/image.go` (+`_test.go`) | New | `ErrUnsupportedContent`, `UnsupportedContentError`, parseo de `data:` URI |
| `pkg/infra/providers/adapter/openai_completions_adapter.go` | Modified | decode/encode de partes `image_url` |
| `pkg/infra/providers/adapter/anthropic_adapter.go` | Modified | bloque `image` en decode/encode |
| `pkg/infra/providers/adapter/bedrock_adapter.go` | Modified | `ConverseImageBlock`, decode/encode |
| `pkg/infra/providers/bedrock/converse.go` | Modified | `ContentBlockMemberImage` en `sdkContentBlock` |
| `pkg/app/proxy/provider.go` | Modified | `ErrUnsupportedContent` → `ErrInvalidRequestPayload` (400) |
| `tests/functional/payload_normalization_test.go` | Modified | OpenAI → Anthropic stub con y sin imagen; 400 |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Peticiones que hoy "funcionan" (la imagen se descartaba) pasan a 400 en Bedrock con URL `http(s)` | Med | Es la decisión acordada: mejor 400 claro que una respuesta falsa. El mensaje indica enviar la imagen como `data:` URI base64 |
| `prompt_tokens` sube para clientes que ya enviaban imágenes | High | Es el comportamiento correcto; mencionarlo en el changelog |
| Base64 grande copiado varias veces en memoria (canónico, `[]byte` Converse, re-encode JSON) | Low | Solo en cross-format; el límite de body del gateway ya acota el tamaño |
| Plugins que fallan al re-encode y hacen passthrough | Low | En mismo-formato los decoders solo producen imágenes que el encoder del mismo formato acepta; no se abre ningún camino fail-open nuevo |
| Mistral recibe `image_url` en forma objeto | Low | Mistral acepta `{"url": …}`; hoy la imagen se perdía |
| Orden intercalado texto/imagen no se conserva | Low | Documentado; el texto sigue unido en un bloque como hoy |
