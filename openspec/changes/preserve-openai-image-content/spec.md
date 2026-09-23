# Especificación: chat-image-content

## Purpose

Las imágenes que un cliente adjunta a un mensaje de usuario MUST llegar al modelo cuando la petición de chat cruza formatos entre OpenAI Chat Completions, Anthropic Messages y Bedrock Converse, y MUST sobrevivir a las reescrituras mismo-formato que hacen los plugins. Si el destino no puede representar una imagen, el gateway MUST rechazar la petición con 400 en vez de descartarla en silencio. Gemini, Cohere y OpenAI Responses quedan fuera (siguen descartando imágenes, como hoy).

## Requirements

### Requirement: Imágenes en el modelo canónico

`CanonicalMessage` MUST llevar las imágenes en `Images []CanonicalImage`, separadas del texto. `Content` MUST seguir siendo el texto de las partes unido con `\n`, igual que hoy, de modo que un plugin que edita `Content` no duplica ni pierde texto. Cada `CanonicalImage` MUST tener exactamente una fuente: `Data` (base64 con `MediaType`) o `URL`.

#### Scenario: Plugin reescribe el texto de un mensaje con imagen

- GIVEN un mensaje de usuario OpenAI con partes `[text "mi email es a@b.c", image_url data:image/png;base64,AAAA]`
- WHEN un plugin decodifica, sustituye el email en `Messages[i].Content` y re-encodifica en OpenAI
- THEN el body resultante contiene la parte `image_url` con la misma `data:` URI
- AND el texto aparece una sola vez, ya reescrito

#### Scenario: Solo texto, sin cambios

- GIVEN un mensaje con `content` string o con varias partes `text` y ninguna imagen
- WHEN se adapta a cualquier destino soportado
- THEN el body de salida es el mismo que antes de este cambio (texto unido con `\n`, `content` string en OpenAI y Anthropic, un único bloque `text` en Converse)

### Requirement: Decode OpenAI Chat Completions

Una parte `{"type":"image_url","image_url":{"url":…,"detail":…}}` (o `image_url` como string) MUST producir una `CanonicalImage`. Una `data:<media type>;base64,<data>` URI MUST separarse en `MediaType` (en minúsculas; `image/jpg` normalizado a `image/jpeg`) y `Data`. Cualquier otro valor, incluida una `data:` URI mal formada, MUST guardarse sin tocar en `URL`. `detail` MUST guardarse en `Detail`. El decode MUST NOT fallar por culpa de una imagen. Las imágenes en mensajes `system`/`developer` MUST ignorarse, como hoy.

#### Scenario: data URI

- GIVEN `image_url.url = "data:image/png;base64,iVBORw0KGgo="`
- WHEN se decodifica
- THEN `Images[0] = {MediaType: "image/png", Data: "iVBORw0KGgo="}`

#### Scenario: URL http(s)

- GIVEN `image_url.url = "https://example.com/cat.jpg"` y `detail = "low"`
- WHEN se decodifica
- THEN `Images[0] = {URL: "https://example.com/cat.jpg", Detail: "low"}`

#### Scenario: data URI mal formada

- GIVEN `image_url.url = "data:image/png,rawbytes"` (sin `;base64`)
- WHEN se decodifica
- THEN no hay error y `Images[0].URL` es la cadena original

### Requirement: Encode OpenAI Chat Completions

Un mensaje con `Images` MUST encodificarse con `content` como array: primero una parte `image_url` por imagen (`data:` URI reconstruida desde `MediaType`/`Data`, o `URL` tal cual; `detail` si existe), luego una parte `text` si `Content` no está vacío. Sin imágenes, `content` MUST seguir siendo string. El encode OpenAI MUST NOT fallar por culpa de una imagen.

#### Scenario: Round-trip OpenAI → OpenAI

- GIVEN un body OpenAI con una parte `image_url` y una `text`
- WHEN se decodifica y se vuelve a encodificar en OpenAI (plugin mismo-formato, o destino Groq / OpenRouter)
- THEN el body contiene la parte `image_url` con la misma URL y el mismo `detail`

#### Scenario: Anthropic → OpenAI

- GIVEN un bloque Anthropic `image` con `source {type: base64, media_type: image/webp, data: "UklGR…"}`
- WHEN se adapta a OpenAI
- THEN el mensaje contiene `image_url.url = "data:image/webp;base64,UklGR…"`

### Requirement: Encode Anthropic Messages

Un mensaje de usuario con `Images` MUST encodificarse como array de bloques: primero un bloque `image` por imagen y después un bloque `text` si `Content` no está vacío. Las imágenes `Data` MUST emitirse como `source {type: "base64", media_type, data}` sin validar el media type ni el base64 (los valida Anthropic, y su 400 se propaga). Las imágenes `URL` MUST emitirse como `source {type: "url", url}` solo si el esquema es `http` o `https`; si no, el encoder MUST devolver un `*UnsupportedContentError` (que satisface `errors.Is(err, ErrUnsupportedContent)`). Los mensajes que no son `user` MUST NOT llevar imágenes. `Detail` MUST descartarse (Anthropic no tiene equivalente).

#### Scenario: OpenAI data URI → Anthropic

- GIVEN un mensaje OpenAI con `data:image/png;base64,AAAA` y el texto `"¿Qué hay en la imagen?"`
- WHEN se adapta a Anthropic
- THEN `messages[0].content = [{type: image, source: {type: base64, media_type: image/png, data: AAAA}}, {type: text, text: "¿Qué hay en la imagen?"}]`

#### Scenario: OpenAI URL → Anthropic

- GIVEN `image_url.url = "https://example.com/cat.jpg"`
- WHEN se adapta a Anthropic
- THEN el bloque `image` lleva `source {type: url, url: "https://example.com/cat.jpg"}`
- AND el gateway no hace ninguna petición a esa URL

#### Scenario: Media type que valida Anthropic

- GIVEN `data:image/tiff;base64,AAAA`
- WHEN se adapta a Anthropic
- THEN el bloque sale como `source {type: base64, media_type: image/tiff, data: AAAA}` sin error local

#### Scenario: Esquema no soportado

- GIVEN `image_url.url = "ftp://example.com/a.png"` o una `data:` URI mal formada
- WHEN se adapta a Anthropic
- THEN `AdaptRequest` devuelve un error con `errors.Is(err, ErrUnsupportedContent)`

### Requirement: Decode Anthropic Messages

Un bloque `image` de un mensaje `user` MUST producir una `CanonicalImage`: `source.type = base64` → `{MediaType (normalizado), Data}`; `source.type = url` → `{URL}`, tal cual aunque no sea `http(s)` (el encoder la rechaza). Otros tipos de `source` (`file`) MUST ignorarse, como hoy. Un mensaje de usuario que solo tiene imágenes MUST producir un mensaje canónico (con `Content` vacío). Un campo `source` que no es un objeto en otro tipo de bloque (por ejemplo `search_result`) MUST NOT impedir decodificar el resto de bloques del mensaje. Las imágenes de mensajes `assistant` MUST ignorarse.

#### Scenario: Otro bloque con source string

- GIVEN un mensaje `user` con `[tool_result t1, search_result{source: "https://…"}, text "gracias"]`
- WHEN se decodifica
- THEN se obtiene el mensaje `tool` de `t1` y después el mensaje `user` con `"gracias"`

#### Scenario: Solo imagen

- GIVEN un mensaje `user` con un único bloque `image` base64
- WHEN se decodifica
- THEN hay un `CanonicalMessage{Role: "user", Content: "", Images: [1]}`

### Requirement: Orden de tool results en el decode

Al decodificar un turno de usuario que mezcla `tool_result` con texto o imágenes (Anthropic `tool_result`, Converse `toolResult`), los mensajes `tool` MUST ir antes que el mensaje `user`, para que un destino OpenAI reciba `assistant(tool_calls) → tool → user`. En Anthropic esto también cambia el orden de los turnos texto + `tool_result` que ya existían (antes salía `user` primero, un orden que OpenAI rechaza).

#### Scenario: tool_result con texto

- GIVEN un mensaje Anthropic `user` con `[text "y ahora?", tool_result t1]`
- WHEN se decodifica
- THEN los mensajes canónicos son `[tool t1, user "y ahora?"]`

#### Scenario: tool_result con imagen

- GIVEN un mensaje `user` con `[tool_result t1, image]` (Anthropic o Converse)
- WHEN se decodifica
- THEN los mensajes canónicos son `[tool t1, user {Images: [1]}]`

### Requirement: Bedrock Converse

El encoder Converse MUST emitir `{"image": {"format": <fmt>, "source": {"bytes": <base64>}}}` antes del bloque `text`, solo en mensajes `user`, con `format` = lo que sigue a `image/` en el media type (`image/png` → `png`, `image/tiff` → `tiff`; Bedrock valida el formato). MUST devolver un `*UnsupportedContentError` cuando la imagen es una `URL` (de cualquier esquema), cuando el media type está vacío o no empieza por `image/`, o cuando `Data` no es base64 estándar válido. El decoder Converse MUST convertir cada bloque `image` con `source.bytes` de un turno `user` en `{MediaType: "image/<format>", Data}`; un bloque sin bytes (`s3Location`) se ignora. El cliente SDK MUST mapear el bloque wire a `bedrockTypes.ContentBlockMemberImage` con `ImageSourceMemberBytes`. En una petición Converse nativa, un body que el cliente no puede decodificar (por ejemplo `bytes` que no es base64) MUST dar 400 terminal, no 502.

#### Scenario: OpenAI data URI → Bedrock (caso ISDIN)

- GIVEN una petición `/v1/chat/completions` con `data:image/jpeg;base64,/9j/4AAQ` hacia `eu.anthropic.claude-sonnet-4-5-20250929-v1:0` en Bedrock
- WHEN se adapta a Converse y se traduce al SDK
- THEN el primer bloque del turno de usuario es `ContentBlockMemberImage{Format: jpeg, Source: ImageSourceMemberBytes{Value: <bytes decodificados>}}`
- AND el segundo es el bloque de texto

#### Scenario: URL hacia Bedrock

- GIVEN `image_url.url = "https://example.com/cat.jpg"` hacia un backend Bedrock
- WHEN se adapta
- THEN `AdaptRequest` devuelve un error con `errors.Is(err, ErrUnsupportedContent)`
- AND el mensaje de error pide enviar la imagen como base64 inline y no incluye la URL, los datos ni el nombre del proveedor

#### Scenario: Base64 inválido

- GIVEN `data:image/png;base64,@@@`
- WHEN se adapta a Bedrock
- THEN `AdaptRequest` devuelve un error con `errors.Is(err, ErrUnsupportedContent)`

### Requirement: Error de cliente, nunca 502 ni descarte

Un `*UnsupportedContentError` que sale de la adaptación de la petición MUST convertirse en `providerInvoker.prepare` en `fmt.Errorf("%w: %w", ErrInvalidRequestPayload, contentErr)`, de modo que `errors.Is` funciona para los dos sentinels y el mensaje no lleva el prefijo `adapter request encode (<formato>)`. La cadena completa se registra con `slog` a nivel debug. MUST llegar al cliente como HTTP 400 con el cuerpo de error del gateway para el formato de entrada (el mismo contrato que `RequestDecodeError` hoy, que también se envuelve con `%w: %w`). El upstream MUST NOT recibir la petición. El outcome MUST ser terminal (sin fallback), igual que `ErrInvalidRequestPayload` hoy. El mensaje MUST NOT contener datos base64, la URL de la imagen, el media type ni el nombre del backend.

#### Scenario: 400 extremo a extremo

- GIVEN un consumer con backend Anthropic y una imagen `ftp://…`
- WHEN el cliente llama a `/v1/chat/completions`
- THEN la respuesta es 400 con `error = "invalid_request"` y un mensaje con `unsupported content`
- AND el mensaje no contiene la URL, `adapter`, `anthropic` ni `bedrock`
- AND el upstream stub no recibe ninguna petición

### Requirement: Orden de bloques

Los encoders MUST emitir todas las imágenes de un mensaje antes de su bloque de texto. El orden relativo entre imágenes MUST conservarse. El intercalado original texto/imagen MUST NOT conservarse (limitación documentada).

#### Scenario: Intercalado

- GIVEN partes OpenAI `[text A, image X, text B, image Y]`
- WHEN se adapta a Anthropic
- THEN el contenido es `[image X, image Y, text "A\nB"]`

### Requirement: Regresión con y sin imagen

MUST existir un test que adapte la misma petición OpenAI con y sin imagen hacia Anthropic y hacia Bedrock y verifique que solo la versión con imagen lleva el bloque de imagen, y que el resto de la petición coincide.

#### Scenario: Comparación

- GIVEN dos peticiones OpenAI iguales salvo por una parte `image_url`
- WHEN ambas se adaptan a Anthropic (y a Bedrock)
- THEN solo la versión con imagen tiene un bloque de imagen en el primer turno de usuario
- AND el texto de ese turno, `system`, `max_tokens` y `tools` coinciden en ambas

### Requirement: Semantic cache y turnos con imágenes

El plugin `semantic_cache` usa como clave solo el texto del último turno de usuario. Si ese turno lleva `Images`, el plugin MUST saltarse tanto la consulta como el almacenamiento (exacto y semántico), con `SkipReason = "images_present"`, para no servir la respuesta de otra imagen con el mismo texto.

#### Scenario: Mismo texto, otra imagen

- GIVEN una entrada en caché para el texto `"hello world"`
- WHEN llega `"hello world"` con una imagen, o un turno solo-imagen después de ese texto
- THEN la respuesta es MISS, no se calcula embedding y no se guarda nada
