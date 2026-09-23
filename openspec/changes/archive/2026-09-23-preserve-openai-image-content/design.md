# Design: Preservar imágenes al convertir chat OpenAI → Anthropic (ENG-1608)

Spec: `chat-image-content` (`openspec/changes/preserve-openai-image-content/spec.md`). Linear: ENG-1608. No hay `exploration.md`: los hallazgos de la exploración vienen en el brief del orquestador y están verificados contra `origin/develop` (`0b99b40d`).

## Technical Approach

`CanonicalMessage` gana `Images []CanonicalImage` junto al `Content` string que ya existe. Los decoders de OpenAI Chat Completions, Anthropic Messages y Bedrock Converse separan el texto de las imágenes. El texto se sigue uniendo con `\n` como hoy, así que los siete plugins que editan `Messages[i].Content` no cambian. Los encoders de esos tres formatos emiten primero las imágenes y después un único bloque de texto. Sin imágenes, el wire de salida es exactamente el de hoy.

La validación vive en el encoder de destino, que es quien sabe qué puede representar:

- OpenAI lo acepta todo y reemite sin pérdida.
- Anthropic acepta cualquier base64 (el media type y los datos los valida Anthropic) y URLs `http(s)`.
- Bedrock acepta solo base64 válido con un media type `image/<x>` (el formato `x` lo valida Bedrock).

Lo demás devuelve un `*adapter.UnsupportedContentError{Reason}`, que satisface `errors.Is(err, adapter.ErrUnsupportedContent)` y cuyo `Reason` no nombra al proveedor. `providerInvoker.prepare` lo extrae con `errors.As` y devuelve `fmt.Errorf("%w: %w", ErrInvalidRequestPayload, contentErr)`, que ya es terminal y ya se mapea a 400. El SDK de Bedrock recibe `ContentBlockMemberImage` con los bytes.

## Architecture Decisions

| Decisión | Elegido | Alternativas descartadas | Razón |
|---|---|---|---|
| Representación canónica | `Images []CanonicalImage` al lado de `Content string` (decisión del orquestador) | `Content []CanonicalPart` ordenado; `RawContent json.RawMessage` con el JSON original | Un array de partes rompe los 7 plugins (`regexreplace`, trustguard rewrite, `googlemodelarmor`, `bedrockguardrail`, `toolallowlist`, `pertoolratelimit`, `toolinjection`) y todos los adapters, y se sale del presupuesto de 400 líneas. Con `RawContent`, cada encoder tendría que conocer todos los formatos de origen, y la edición de `Content` por un plugin divergiría del raw. Coste aceptado: se pierde el intercalado texto/imagen. |
| Orden de bloques | Imágenes primero, después un único bloque `text` | Texto primero; conservar el intercalado | Es el orden que recomienda Anthropic para visión. Conservar el intercalado exige la opción de partes ordenadas, que ya está descartada. |
| Forma de `CanonicalImage` | `{MediaType, Data}` (base64 sin decodificar) o `{URL}`, más `Detail` | Guardar `[]byte` ya decodificado; guardar siempre la URI original | Base64 como string evita decodificar en Anthropic y OpenAI (el upstream valida) y hace que el round-trip OpenAI sea exacto (`data:` + `MediaType` + `;base64,` + `Data`). `Detail` cuesta un campo y hace que OpenAI → OpenAI no pierda nada; Anthropic y Bedrock lo descartan. Al re-encodificar en OpenAI, el media type de la `data:` URI sale normalizado (minúsculas, `image/jpg` → `image/jpeg`) y se descartan parámetros extra como `;charset`; OpenAI acepta esa forma normalizada. |
| Dónde se valida | En el encoder de destino; el decoder OpenAI nunca falla (una `data:` URI mal formada se guarda tal cual en `URL`) | Validar en el decode (incluido el base64) | Validar en el decode rompería la reescritura mismo-formato de OpenAI: el plugin haría passthrough y se saltaría, por ejemplo, la redacción de `regexreplace`. Además decodificaría el base64 de más en el camino a Anthropic. Con este reparto, y sin allowlists de media type, los decoders de Anthropic y Converse solo producen imágenes que su propio encoder acepta, salvo una imagen Anthropic nativa con `url` no `http(s)`; el encoder es el único punto de rechazo y el upstream la rechazaría igualmente (ver Error Handling). |
| Validación en Anthropic | Solo URL `http`/`https` con host; media type y base64 sin validar | Allowlist local de media types {jpeg, png, gif, webp} (primera versión) | La allowlist abría un camino de fallo nuevo en la reescritura mismo-formato de un plugin (un `image/tiff` nativo hacía que el plugin cayera a passthrough). Anthropic valida media type y base64 y su 400 ya se propaga. El único borde que queda es una imagen Anthropic nativa con `source.type = url` no `http(s)`, que Anthropic también rechazaría. |
| URL `http(s)` hacia Bedrock | `*UnsupportedContentError` → 400 con el texto "image URLs are not supported by the target; send inline base64 image data" | Descargar la URL y pasarla a base64; descartarla con un warning | Descargarla abre un SSRF y añade latencia y tamaño sin límite. Descartarla es justo el bug de este ticket. |
| Base64 en el wire Converse | `ConverseImageSource.Bytes []byte` (`encoding/json` lo serializa como base64 estándar); el encoder decodifica `Data` con `base64.StdEncoding` para validarlo | `Bytes string` y decodificar en `converse.go` | Un base64 inválido falla en el adapter (sale como 400) y no en el cliente SDK (saldría como 502). `converse.go` recibe los bytes ya decodificados por `json.Unmarshal` y no hace base64 a mano. El wire JSON coincide con el de Converse REST (blobs en base64). |
| Mapeo de media type a formato Converse | `image/<x>` → `x` para cualquier `x` no vacío (Bedrock valida el formato); `image/jpg` se normaliza a `image/jpeg` al decodificar. Se rechaza solo URL, media type vacío o que no empieza por `image/`, y base64 inválido | Allowlist {png, jpeg, gif, webp}; deducirlo de los magic bytes | Igual que en Anthropic: sin allowlist no hay caminos de fallo nuevos en mismo-formato. Los magic bytes son más código y no son necesarios. |
| Superficie del error | `*adapter.UnsupportedContentError{Reason}` (su `Is` casa con el sentinel `ErrUnsupportedContent`); en `prepare` (`provider.go`) `errors.As` lo extrae y se devuelve `fmt.Errorf("%w: %w", ErrInvalidRequestPayload, contentErr)`; la cadena completa va a `slog` debug. `RequestDecodeError` también se envuelve con `%w: %w` (el texto no cambia) | Solo el sentinel con `%w: %s` (primera versión); mapear en `mapProxyError` del handler | Con `%w: %s` el sentinel se perdía y el mensaje llevaba `adapter request encode (bedrock)`, que revela el backend al cliente. Extraer el error tipado da `errors.Is` para los dos sentinels y un mensaje neutro. Mapear en el handler dejaría el error como `OutcomeRetryable` en `classifyOutcome` (`classify.go:131-139`), así que haría fallback a otro backend y acabaría en 502. `ErrInvalidRequestPayload` ya es terminal y ya da 400 (`proxy_handler.go:461-463`). |
| Cuerpo de error | El contrato actual de `writeProxyError`: `{"error":"invalid_request","message":…}` para OpenAI y el sobre adaptado para Anthropic (`NeedsAdaptedError`) | Un sobre nuevo al estilo OpenAI (`{"error":{"type":…}}`) | Es el mismo contrato que un `RequestDecodeError` hoy. Cambiarlo no entra en el ticket. |
| Contenido del mensaje de error | Sin la URL, los datos, el media type ni el nombre del backend | Hacer eco de la URL o del media type | Una `data:` URI puede ocupar megas, la URL puede llevar tokens firmados y el media type lo controla el cliente. El nombre del backend es detalle interno del enrutado. |
| Imágenes fuera del turno de usuario | Solo se decodifican en mensajes `user` (OpenAI, Anthropic y Converse); los encoders emiten `Images` solo en mensajes `user` (no en `tool`, ni en assistant) | Soportar imágenes en `tool_result` | Ni OpenAI ni Anthropic aceptan imágenes en mensajes assistant. `tool_result` con imagen queda fuera del alcance. |
| Orden de tool results en el decode | Anthropic y Converse emiten los mensajes `tool` antes del mensaje `user` del mismo turno | Mantener `user` primero (lo que hacía Anthropic antes) | OpenAI exige `assistant(tool_calls) → tool → user`. El orden anterior de Anthropic ya era inválido para texto + `tool_result`; el arreglo también cambia esos turnos, y es intencionado. Converse ya lo hacía así. |
| `anthropicContentBlock.Source` | `json.RawMessage`, y solo dentro de `case "image"` se deserializa a `anthropicImageSource` | `*anthropicImageSource` (primera versión) | Otros bloques también tienen `source` y no siempre es un objeto (`search_result` lo lleva como string). Con el puntero tipado fallaba el `Unmarshal` de todo el array y el decode caía a `contentToString`, perdiendo los `tool_result`. |
| Semantic cache | Si el último turno de usuario (el que da la clave) tiene `Images`, el plugin no consulta ni guarda (`SkipReason = "images_present"`) | Meter un hash de las imágenes en la clave | La clave es solo texto; con imágenes fluyendo, el mismo texto con otra imagen devolvería una respuesta ajena. Saltarse la caché es lo seguro y lo mínimo; incluir las imágenes en la clave y en el embedding queda como seguimiento. |
| Converse `s3Location` y Anthropic `source.type = file` | Se ignoran como hoy (el wire no los modela) | Modelarlos | Fuera del alcance. No es una regresión: hoy también se pierden. |

## Data Flow

Caso ISDIN, `/v1/chat/completions` → Bedrock (Claude Sonnet 4.5, inference profile):

    forwarder → providerInvoker.prepare (provider.go:300)
      │ crossFormat(openai → bedrock)
      ▼
    Registry.AdaptRequest (registry.go:149)
      │ OpenAIAdapter.DecodeRequest → decodeCompletionsRequest
      │    decodeOpenAIContent(m.Content) → ("¿Qué ves?", [{MediaType:"image/jpeg", Data:"/9j/…"}])
      ▼
    CanonicalMessage{Role:"user", Content:"¿Qué ves?", Images:[…]}
      │ BedrockAdapter.EncodeRequest → converseMessageFromCanonical
      │    converseImageFromCanonical: URL? → *UnsupportedContentError
      │                                media type sin "image/<x>"? → *UnsupportedContentError
      │                                base64.StdEncoding.DecodeString falla → *UnsupportedContentError
      ▼
    {"messages":[{"role":"user","content":[{"image":{"format":"jpeg","source":{"bytes":"/9j/…"}}},{"text":"¿Qué ves?"}]}]}
      │ bedrock client → decodeConverseBody (converse.go:47) → sdkContentBlock → sdkImage
      ▼
    bedrockTypes.ContentBlockMemberImage{Format: jpeg, Source: &ImageSourceMemberBytes{Value: raw}}

    Error:  AdaptRequest → "adapter request encode (bedrock): %w" ─► prepare:
            errors.As(*UnsupportedContentError) → fmt.Errorf("%w: %w", ErrInvalidRequestPayload, contentErr)
            (slog debug con la cadena completa; el cliente no ve el prefijo del adapter)
            ─► classifyOutcome = Terminal ─► mapProxyError = 400 invalid_request

Converse nativo (mismo formato, sin adaptación):

    bedrock client → decodeConverseBody → json.Unmarshal falla (p. ej. bytes no base64)
      ─► &adapter.RequestDecodeError{Format: bedrock} ─► Invoke/InvokeStream: clientRequestError
      ─► fmt.Errorf("%w: %w", ErrInvalidRequestPayload, decodeErr) ─► Terminal ─► 400

Reescritura mismo-formato por plugin (OpenAI → OpenAI, Anthropic → Anthropic, Converse → Converse):

    DecodeRequestFor(body, fmt) → plugin edita Messages[i].Content → adapter(fmt).EncodeRequest
      Images viaja intacto en el struct; el encoder del mismo formato lo reemite. Como Anthropic y Converse ya no tienen allowlist de media types, el único fallo posible en mismo-formato es una URL Anthropic no http(s), que el upstream también rechazaría

## File Changes

| File | Action | Description | ± líneas |
|---|---|---|---|
| `pkg/infra/providers/adapter/canonical.go` | Modify | `CanonicalImage` (doc comments) y `CanonicalMessage.Images` (`:43-48`) | +18 |
| `pkg/infra/providers/adapter/image.go` | Create | `ErrUnsupportedContent`, `UnsupportedContentError`, `parseImageURL`, `(CanonicalImage).dataURI`, `normalizeImageMediaType`, `isHTTPImageURL` | +70 |
| `pkg/infra/providers/adapter/openai_adapter.go` | Modify | `contentToString` (`:140-162`) delega en `decodeOpenAIContent` y devuelve solo el texto (los otros llamadores no cambian) | +30 / −18 |
| `pkg/infra/providers/adapter/openai_completions_adapter.go` | Modify | tipos `openaiContentPart` / `openaiImageURL`; decode (`:257-276`) usa `decodeOpenAIContent`; encode (`:331-341`) usa `encodeOpenAIContent` | +40 |
| `pkg/infra/providers/adapter/anthropic_adapter.go` | Modify | `anthropicImageSource`, `anthropicContentBlock.Source json.RawMessage` (`:83-94`); rama `image` y orden tool-primero en `decodeAnthropicMessageContent`; `anthropicMessageContent` en la rama ordinaria de `EncodeRequest` | +60 |
| `pkg/infra/providers/adapter/bedrock_adapter.go` | Modify | `ConverseImageBlock`, `ConverseImageSource`, `ConverseContentBlock.Image` (`:48-53`); `converseMessageToCanonical` (`:314-347`) recoge imágenes; `converseMessageFromCanonical` (`:415-444`) pasa a devolver `error`; `EncodeRequest` (`:381-398`) lo propaga; `converseImageFromCanonical`, `converseImageFormat` | +65 |
| `pkg/infra/providers/bedrock/converse.go` | Modify | caso `b.Image != nil` en `sdkContentBlock`; `sdkImage`; el fallo de `json.Unmarshal` en `decodeConverseBody` devuelve `*adapter.RequestDecodeError` | +22 |
| `pkg/app/proxy/provider.go` | Modify | `errors.As(*UnsupportedContentError)` en `prepare` con `%w: %w`; `clientRequestError` en `Invoke`/`InvokeStream` | +25 / −2 |
| `pkg/infra/plugins/semanticcache/plugin.go` | Modify | `extractUserInput` informa si el turno de la clave lleva imágenes; bypass de lookup y store | +25 |
| **Subtotal producción** | | | **≈ +305 / −20** |
| `pkg/infra/providers/adapter/image_test.go` | Create | `parseImageURL`, `dataURI`, `isHTTPImageURL`, media types (table-driven) | +110 |
| `pkg/infra/providers/adapter/openai_completions_adapter_test.go` | Modify | decode (data URI, URL + detail, string `image_url`, mal formada, system ignorada); encode (partes, sin imágenes → string) | +90 |
| `pkg/infra/providers/adapter/anthropic_adapter_test.go` | Modify | encode base64/url/errores; decode base64/url/`file` ignorado/solo imagen | +90 |
| `pkg/infra/providers/adapter/bedrock_adapter_test.go` | Modify | encode con `decodeConverse`, formatos (tiff pasa), URL/media type vacío/base64 → error; decode `image` | +90 |
| `pkg/infra/providers/adapter/adapter_test.go` | Modify | `TestAdaptRequest_Images` table-driven cross-format + regresión con/sin imagen | +130 |
| `pkg/infra/providers/bedrock/converse_test.go` | Modify | `TestDecodeConverseBody_Image`; bloque vacío ignorado | +45 |
| `pkg/app/proxy/provider_invoker_test.go` | Modify | Bedrock + URL → `ErrInvalidRequestPayload` y el cliente no se llama | +40 |
| `tests/functional/payload_normalization_test.go` | Modify | Anthropic ingress → stub OpenAI con/sin imagen; `ftp://` hacia backend Anthropic → 400 sin hits | +90 |
| **Subtotal tests** | | | **≈ +685** |

Previsión: unas 325 líneas cambiadas de producción, por debajo de las 400, y unas 685 de tests. Un solo PR. `sdd-tasks` decide si hace falta `size:exception` por los tests o si el functional se separa en un segundo PR encadenado.

## Interfaces / Contracts

`pkg/infra/providers/adapter/canonical.go`:

```go
// CanonicalImage is one image attached to a message. Exactly one of Data or
// URL is set; Data is standard base64 and requires MediaType.
type CanonicalImage struct {
    MediaType string `json:"media_type,omitempty"`
    Data      string `json:"data,omitempty"`
    URL       string `json:"url,omitempty"`
    Detail    string `json:"detail,omitempty"`
}

type CanonicalMessage struct {
    Role       string              `json:"role"`
    Content    string              `json:"content"`
    Images     []CanonicalImage    `json:"images,omitempty"`
    ToolCalls  []CanonicalToolCall `json:"tool_calls,omitempty"`
    ToolCallID string              `json:"tool_call_id,omitempty"`
}
```

`pkg/infra/providers/adapter/image.go`:

```go
// ErrUnsupportedContent reports request content the target format cannot carry.
var ErrUnsupportedContent = errors.New("unsupported content")

func parseImageURL(raw, detail string) CanonicalImage // "data:<mt>;base64,<d>" → {MediaType, Data}; otherwise {URL: raw}
func (img CanonicalImage) dataURI() string            // Data → "data:<mt>;base64,<d>"; otherwise URL
func normalizeImageMediaType(mt string) string        // lower + TrimSpace; image/jpg → image/jpeg
func isHTTPImageURL(raw string) bool                  // url.Parse; scheme http|https; Host != ""
```

OpenAI (`openai_completions_adapter.go` / `openai_adapter.go`):

```go
type openaiContentPart struct {
    Type     string          `json:"type"`
    Text     string          `json:"text,omitempty"`
    ImageURL json.RawMessage `json:"image_url,omitempty"` // object {url, detail} or bare string
}

type openaiImageURL struct {
    URL    string `json:"url"`
    Detail string `json:"detail,omitempty"`
}

func decodeOpenAIContent(raw json.RawMessage) (string, []CanonicalImage) // text keeps contentToString semantics
func encodeOpenAIContent(m CanonicalMessage) json.RawMessage             // no images → stringToContent(m.Content)
```

Anthropic (`anthropic_adapter.go`):

```go
type anthropicImageSource struct {
    Type      string `json:"type"` // base64 | url
    MediaType string `json:"media_type,omitempty"`
    Data      string `json:"data,omitempty"`
    URL       string `json:"url,omitempty"`
}
// anthropicContentBlock gains: Source json.RawMessage `json:"source,omitempty"`
// (decoded into anthropicImageSource only for type "image")

func anthropicImageToCanonical(raw json.RawMessage) (CanonicalImage, bool)
func anthropicImageBlock(img CanonicalImage) (anthropicContentBlock, error)
func anthropicMessageContent(m CanonicalMessage) (json.RawMessage, error) // role != user or no images → stringToContent(m.Content)
```

Bedrock (`bedrock_adapter.go`, wire exportado porque lo consume `pkg/infra/providers/bedrock`):

```go
// ConverseImageBlock is an inline image; Bedrock takes bytes only, never URLs.
type ConverseImageBlock struct {
    Format string              `json:"format"`
    Source ConverseImageSource `json:"source"`
}

// ConverseImageSource carries the raw image; encoding/json renders it as base64.
type ConverseImageSource struct {
    Bytes []byte `json:"bytes,omitempty"`
}
// ConverseContentBlock gains: Image *ConverseImageBlock `json:"image,omitempty"`

func converseMessageFromCanonical(m CanonicalMessage) (ConverseMessage, error)
func converseImageFromCanonical(img CanonicalImage) (*ConverseImageBlock, error)
func converseImageFormat(mediaType string) (string, bool) // "image/<x>" → x, x != ""
```

Error tipado (`image.go`):

```go
// UnsupportedContentError is the ErrUnsupportedContent a request encoder
// returns. Reason is client-facing, so it names neither the target provider nor
// the offending URL or data.
type UnsupportedContentError struct {
    Reason string
}
func (e *UnsupportedContentError) Error() string        // "unsupported content: " + Reason
func (e *UnsupportedContentError) Is(target error) bool // target == ErrUnsupportedContent
```

SDK (`pkg/infra/providers/bedrock/converse.go`):

```go
func sdkImage(img *adapter.ConverseImageBlock) bedrockTypes.ContentBlock
// &bedrockTypes.ContentBlockMemberImage{Value: bedrockTypes.ImageBlock{
//     Format: bedrockTypes.ImageFormat(img.Format),
//     Source: &bedrockTypes.ImageSourceMemberBytes{Value: img.Source.Bytes}}}
// len(Bytes) == 0 → nil (se descarta, igual que hoy un bloque desconocido o s3Location)
```

App (`pkg/app/proxy/provider.go`, `prepare`):

```go
var contentErr *adapter.UnsupportedContentError
if errors.As(err, &contentErr) {
    p.logger.Debug("request content not representable in target format", slog.String("error", err.Error()))
    return nil, fmt.Errorf("%w: %w", ErrInvalidRequestPayload, contentErr)
}
if adapter.IsRequestDecodeError(err) {
    return nil, fmt.Errorf("%w: %w", ErrInvalidRequestPayload, err)
}
```

Y en `Invoke`/`InvokeStream`, para el body que decodifica el propio cliente en mismo-formato:

```go
func clientRequestError(err error) error // *adapter.RequestDecodeError → fmt.Errorf("%w: %w", ErrInvalidRequestPayload, decodeErr)
```

Mensajes de error (`*UnsupportedContentError`, neutros respecto al proveedor, sin URL, datos ni media type):

| Encoder | Condición | Texto |
|---|---|---|
| Anthropic | URL que no es `http(s)` (incluida una `data:` mal formada) | `unsupported content: image must be inline base64 data or an http(s) URL` |
| Bedrock | `URL` presente | `unsupported content: image URLs are not supported by the target; send inline base64 image data` |
| Bedrock | media type vacío o que no empieza por `image/` | `unsupported content: image media type is missing or not an image/* type` |
| Bedrock | base64 inválido | `unsupported content: image data is not valid base64` |

## Error Handling

- Decoders: nunca fallan por imágenes. Una parte `image_url` sin URL se ignora.
- Los decoders de Anthropic y Converse conservan las imágenes tal cual (cualquier media type; en Anthropic también una `url` no `http(s)`). Media type y base64 los valida el upstream. El encoder es el único punto de rechazo local (400), y solo en mismo-formato Anthropic con `url` no `http(s)` puede fallar una reescritura de plugin: el plugin hace passthrough de una petición que Anthropic rechazaría igualmente.
- Encoders: devuelven el primer `*UnsupportedContentError` que encuentran. `AdaptRequest` lo envuelve (`adapter request encode (%s): %w`, `registry.go:172-174`); `prepare` lo extrae con `errors.As` y lo reenvuelve en `ErrInvalidRequestPayload` sin ese prefijo: 400, terminal, sin fallback ni llamada al upstream.
- `UnsupportedContentError` es terminal: en un pool mixto (Bedrock primario, OpenAI de fallback) una imagen con URL `http(s)` da 400 aunque el fallback pudiera servirla. Es intencionado y determinista: el resultado no depende de qué miembro del pool se elija.
- Plugins mismo-formato: si un encode fallara, el plugin hace passthrough como con cualquier error hoy (por ejemplo `regexreplace/plugin.go:104-107`). Sin allowlists de media type, el único caso es una imagen Anthropic nativa con `url` no `http(s)`, que Anthropic también rechazaría.
- `converse.go`: un bloque de imagen sin bytes se descarta (igual que hoy). Los bytes ya llegan validados por el adapter en cross-format. En Converse nativo, un `bytes` que no es base64 hace fallar `json.Unmarshal` en `decodeConverseBody`; antes de este cambio el bloque `image` no existía en el wire y se ignoraba, después era un error plano (retryable → fallback → 502). Ahora se devuelve `*adapter.RequestDecodeError`, que `clientRequestError` convierte en `ErrInvalidRequestPayload` (400 terminal). La dirección de dependencias se respeta: infra solo usa el tipo del paquete `adapter`, y el mapeo a `ErrInvalidRequestPayload` vive en `pkg/app/proxy`.

## Testing Strategy

| Layer | What to Test | Approach |
|---|---|---|
| Unit `adapter/image_test.go` | `parseImageURL` (png, `image/jpg`→jpeg, mayúsculas, parámetros `;charset=…;base64`, sin `;base64`, vacía, https); `dataURI` round-trip; `isHTTPImageURL` (http, https, ftp, `file://`, sin host, `data:`) | Table-driven con `t.Parallel()`, testify `assert`/`require` |
| Unit OpenAI | `TestDecodeCompletionsRequest_Images`: data URI, URL + `detail`, `image_url` string, mal formada → `URL`, imagen en system ignorada, multi-texto + imagen → `Content` unido; `TestEncodeCompletionsRequest_Images`: partes en orden, sin imágenes → `content` string | Table-driven |
| Unit Anthropic | `TestAnthropicEncodeRequest_Images`: base64, url, tiff pasa sin error, ftp y `data:` mal formada → `ErrorAs(*UnsupportedContentError)` sin URL/datos/"anthropic" en el mensaje, solo imagen sin bloque `text`; `TestDecodeAnthropicMessageContent_Images`: base64, url, `file` ignorado, solo imagen produce mensaje, tool_result antes de imagen y de texto, `search_result` con `source` string no pierde el tool_result, url no http(s) se conserva | Table-driven |
| Unit Bedrock adapter | `TestBedrock_EncodeRequest_Images`: formato por media type (incluido tiff), bytes decodificados, imagen antes del texto (helper `decodeConverse`); URL / media type vacío / no `image/` / base64 inválido → `ErrorAs`, texto esperado y sin "bedrock"; tool result + imagen + texto en un único turno user; `TestBedrock_DecodeRequest_Image` (incluido tool-primero) | Table-driven, en `bedrock_adapter_test.go` |
| Unit cross-format | `TestAdaptRequest_Images` en `adapter_test.go`: OpenAI→Anthropic (data URI, URL), OpenAI→Bedrock (data URI), OpenAI→Bedrock URL → error, OpenAI→OpenRouter (es cross-format, así que valida el round-trip OpenAI) conserva `image_url` + `detail`, Anthropic→OpenAI data URI. `TestAdaptRequest_ImageRegression`: misma petición con y sin imagen hacia Anthropic y Bedrock; solo cambia el bloque de imagen. Los tests actuales `TestAdaptRequest_OpenAIToAnthropic` (`:347`) y `TestAdaptRequest_OpenAIToBedrock` (`:550`) siguen verdes sin tocarlos | Table-driven sobre `testRegistry()` |
| Unit SDK | `TestDecodeConverseBody_Image` en `converse_test.go`: `ContentBlockMemberImage{Format: jpeg}` con los bytes esperados, antes del texto; imagen sin bytes → descartada. `TestDecodeConverseBody_InvalidImageBytesIsARequestDecodeError` | Junto a `TestDecodeConverseBody` (`:42`) |
| Unit app | `TestProviderInvoke_UnsupportedImageIsInvalidPayload`: Anthropic + `ftp` (buffered y stream) y Bedrock + `https` → `ErrorIs` de `ErrInvalidRequestPayload` y de `ErrUnsupportedContent`, mensaje sin URL, nombre del backend ni "adapter", cliente mock sin llamadas. `TestProviderInvoke_ClientDecodeErrorIsInvalidPayload`: el cliente devuelve `RequestDecodeError` → `ErrInvalidRequestPayload` (buffered y stream) | Patrón de `TestProviderInvoke_ImagesInvalidMethod` (`provider_images_test.go:87`) |
| Unit plugin | `TestPlugin_ImagesBypassCache` en `semanticcache/plugin_test.go`: texto + imagen y turno solo-imagen tras un texto cacheado → MISS, sin embedding, sin store | Table-driven |
| Functional | `TestPayloadNormalization_ImageContent` (`//go:build functional`). (1) `/v1/messages` con bloque `image` hacia un stub OpenAI (`newJSONUpstream`): el upstream recibe `image_url` con la `data:` URI y el texto. (2) Sin imagen: `content` string. (3) `/v1/chat/completions` con `ftp://` hacia un backend Anthropic → 400 `invalid_request` con `unsupported content`, sin URL, `adapter`, `anthropic` ni `bedrock` en el cuerpo, y `up.Hits() == 0`. No hay stub Anthropic: el cliente de chat de Anthropic (`anthropic/client.go`, `messagesURL`) ignora `provider_options.base_url`, así que un stub nunca recibiría la petición; el caso 3 no llega a la red porque el encoder rechaza antes | `tests/functional/payload_normalization_test.go`; reutiliza `anthropicFilesBackendPayload` (`files_provider_test.go:266`) |
| Live (fuera del repo) | Con y sin imagen, `prompt_tokens` sube y el modelo describe la imagen, contra upstream Anthropic directo y contra Bedrock (`eu.anthropic.claude-sonnet-4-5-20250929-v1:0`) | Repo `multi-agent-tests` contra un gateway levantado en local. Su `.env` apunta a prod por defecto, así que hay que cambiarlo a la URL local antes de lanzarlo. No bloquea el PR; sí bloquea cerrar ENG-1608 |

Comando de verificación: `make test-race` y `make test-functional`.

## Migration / Rollout

- Sin migración, flag ni cambio de configuración. `CanonicalMessage.Images` es `omitempty`.
- Cambio de comportamiento visible: las peticiones con imágenes hacia Anthropic/Bedrock suben de `prompt_tokens`, y Bedrock con URL `http(s)` pasa de responder "sin imagen" a 400. Va en el changelog.
- Revertir el PR devuelve el descarte silencioso; no deja estado.

## Open Questions

- None. Resueltas desde el código:
  - Superficie del error: `ErrInvalidRequestPayload` ya es terminal y da 400, así que basta con una línea en `provider.go:332`.
  - `detail`: se conserva en OpenAI con un campo, sin coste.
  - Base64 en Converse: `[]byte` en el wire, validado en el adapter.
  - Fail-open de plugins: el único camino nuevo es una imagen Anthropic nativa con `url` no `http(s)` (el upstream también la rechaza).
- Seguimientos (fuera de este PR, para crear en Linear):
  - Gemini / Cohere / OpenAI Responses siguen descartando `Images`.
  - Converse `s3Location` y Anthropic `source.type = file` siguen ignorándose.
  - El cliente de chat de Anthropic ignora `provider_options.base_url` (`anthropic/client.go`, `messagesURL`); solo Files lo respeta.
  - `promptcompression/safety.go`.
  - Clave de `semanticcache` con imágenes (hoy se hace bypass; incluirlas en la clave y en el embedding).
  - Imágenes en `tool_result`.
