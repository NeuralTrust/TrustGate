# Especificación de mcp-upstream-protocol-negotiation

## Requisitos

### Requirement: Modo de protocolo

`protocol_mode` MUST ser `auto|modern|legacy`, predeterminar `auto` y persistir en modelo, API, JSONB y snapshot.

#### Scenario: Validación y round-trip
- GIVEN un registro sin modo o permitido
- WHEN atraviesa API, JSONB y snapshot
- THEN aplica `auto` o conserva el valor; otro recibe API 400 o invalida modelo/snapshot, sin guardar.

### Requirement: Origen

El origen MUST ser esquema+host normalizado+puerto efectivo y SHALL tener una era; userinfo MUST rechazarse.

#### Scenario: Origen compartido
- GIVEN URLs equivalentes o eras distintas bajo un origen
- WHEN se clasifican
- THEN comparten decisión; contradicción persistente exige override u otro origen.

### Requirement: Probe automático

`auto` MUST probar `server/discover`. Éxito o 400 JSON-RPC `-32020|-32021|-32022` SHALL clasificar moderno; `-32022` MUST negociar versión y reintentar una vez.

#### Scenario: Clasificación moderna
- GIVEN éxito o 400 moderno reconocido
- WHEN finaliza el probe
- THEN cachea `modern+version`; retry incompatible cachea `modern-incompatible` y falla sin legacy.

#### Scenario: Confirmación de versión negociada
- GIVEN un 400 `-32022` con versión moderna común
- WHEN el probe reintenta una vez
- THEN solo un 2xx que confirme exactamente la versión reintentada puede tener éxito; cualquier segundo 400, incluso `-32020|-32021|-32022`, falla sin legacy.

#### Scenario: Fallback legacy
- GIVEN HTTP 400 vacío, malformado o con código no reconocido
- WHEN finaliza el probe
- THEN devuelve un candidato legacy; solo tras `initialize` legacy exitoso cachea `legacy` y ejecuta la operación.

#### Scenario: Resultado con HTTP 400
- GIVEN HTTP 400 JSON o SSE con terminadores CRLF, LF o CR donde cualquier evento `data` contiene member top-level `result`, sea válido, inválido o `null`
- WHEN finaliza el probe
- THEN falla como respuesta inconclusa, sin downgrade ni caché.

#### Scenario: Error no clasificable
- GIVEN 401, 403, 404, 405, 429, 5xx, error de red, timeout o cancelación
- WHEN falla el probe
- THEN propaga la categoría segura o `ctx.Err()` directo, sin endpoint/query/body/Data, downgrade ni caché.

### Requirement: Caché coordinada

Las decisiones MUST ser singleflight por origen, durar el proceso y excluir TTL, secretos y capacidades.

#### Scenario: Concurrencia
- GIVEN llamadas concurrentes sin decisión
- WHEN negocian un origen
- THEN comparten probe y decisión sin carreras.

#### Scenario: Contradicción segura
- GIVEN una respuesta exclusiva de otra era
- WHEN contradice la caché
- THEN invalida y renegocia una vez; otra contradicción falla sin oscilar.

### Requirement: Overrides estrictos

`modern` y `legacy` MUST seleccionar su adaptador sin probe ni fallback.

#### Scenario: Override
- GIVEN un modo explícito
- WHEN ejecuta una operación
- THEN omite `server/discover`; el fallo conserva la era.

### Requirement: Upstream moderno stateless

Moderno MUST NOT emitir `initialize`, `notifications/initialized`, `Mcp-Session-Id` ni DELETE. MUST usar `trustgate`, `pkg/version` y capacidades vacías o mínimas.

#### Scenario: Petición moderna
- GIVEN upstream moderno
- WHEN ejecuta operaciones
- THEN cada petición es autocontenida, sin sesión MCP, y reutiliza conexiones HTTP.

### Requirement: Semántica moderna

Moderno SHALL preservar paginación, cancelación y errores upstream sin inferir capacidades.

#### Scenario: Resultado o cancelación
- GIVEN páginas, error JSON-RPC/HTTP o cancelación
- WHEN procesa una operación
- THEN conserva cursores/errores o cancela I/O, sin retry indebido.

### Requirement: Normalización segura de errores modernos

Moderno MUST limitar cada response body a 4 MiB post-descompresión. Solo MAY normalizar HTTP 400/404 cuando request y response declaran `application/json` con parámetros MIME válidos y la response es un objeto único JSON-RPC 2.0: ID string/número idéntico en bytes y tipo al request, `method` y `result` ausentes, y `error` objeto con `code` int64 y `message` string presentes. Malformed, batch, duplicados, nulls, tipos incorrectos, IDs distintos y envelopes request-like MUST conservar el status HTTP original.

Al normalizar, el adaptador MUST restaurar el body para el SDK, borrar framing/hop-by-hop conflictivo, `Content-Encoding` y `Content-MD5`, y fijar HTTP 200, `application/json` y el `Content-Length` materializado. `error.data` MUST conservarse por compatibilidad como dato upstream no confiable incluido en el límite total de 4 MiB; no se aplica un segundo cap independiente. Estas reglas no modifican el comportamiento legacy.

#### Scenario: Error moderno estrictamente correlacionado
- GIVEN un HTTP 400/404 con request y response `application/json`
- WHEN el body contiene un único error JSON-RPC 2.0 válido con ID idéntico, sin `method` ni `result`
- THEN el adaptador lo entrega a `mapModernRPCError` con `code`, `message` y `data` preservados; cualquier desviación mantiene el manejo HTTP original.

### Requirement: Paridad legacy

Legacy MUST cachear sesión por identidad completa `origen canónico+fingerprint de URL canónica+ProtocolMode+PinKey+fingerprint de credencial`, TTL 30m. Solo lecturas SHALL refrescar/reintentar; `tools/call` MUST NOT reintentarse. El guard local MUST acotar a 64 KiB el peek de `server/discover`: overflow se delega con el body original intacto. Una intercepción local MUST cerrar el request body original exactamente una vez; una ruta delegada MUST dejar su cierre al transporte delegado.

#### Scenario: Caché legacy
- GIVEN hit legacy por decisión u override y una sesión válida
- WHEN ejecuta lectura o `tools/call`
- THEN omite probes modernos y solo lecturas pueden refrescar/reintentar.

#### Scenario: Identidad y ownership legacy
- GIVEN dos targets que difieren en URL canónica, `ProtocolMode`, `PinKey` o credenciales, o un discover mayor de 64 KiB
- WHEN el dialer busca sesión o el interceptor inspecciona la request
- THEN no colisionan sesiones; el overflow se delega sin mutar/perder body, y solo la respuesta sintética cierra localmente el body original una vez.

### Requirement: Compatibilidad funcional

Credenciales, toolkits, aliases y fail modes MUST preservarse entre eras.

#### Scenario: Enrutado existente
- GIVEN configuración existente
- WHEN cambia la era
- THEN selección, autenticación, nombres y fallos siguen equivalentes.

### Requirement: Protección HTTP

Redirects MUST rechazarse; configuración/credenciales MUST NOT sobrescribir headers MCP/HTTP reservados.

#### Scenario: Redirect o header reservado
- GIVEN redirect o sobrescritura reservada
- WHEN prepara la petición
- THEN falla antes de contactar otro origen o enviar el header.

#### Scenario: Endpoint o configuración inválidos
- GIVEN userinfo, fragment, authority inválida, puerto explícito vacío o header reservado
- WHEN legacy connect o probe prepara la conexión
- THEN el boundary de infraestructura falla antes de cualquier I/O; dominio/API no duplican la política de transporte.

### Requirement: Independencia RUN-1103

Eras northbound/southbound MUST ser independientes. RUN-1108 MUST NOT modificar handlers o rutas northbound ni iniciar I/O southbound fuera de `Dialer.Connect`. Metadata inbound MUST NOT reenviarse. La resolución local de `server/discover` pertenece a RUN-1103 y SHALL conservarse al integrar ambos cambios.

#### Scenario: Discover northbound
- GIVEN RUN-1103 y RUN-1108 integrados
- WHEN llama `server/discover`
- THEN el handler de RUN-1103 responde localmente sin invocar `Dialer.Connect`, probe ni forwarding de identidad, headers o metadata; esa cobertura ejecutable pertenece al límite northbound de RUN-1103.

### Requirement: Observabilidad segura

Cada selección MUST registrar origen no sensible, modo, era, fuente, resultado y latencia; MUST NOT registrar headers, credenciales, bodies, capacidades ni metadata.

#### Scenario: Registro
- GIVEN éxito o fallo
- WHEN emite telemetría
- THEN contiene solo campos permitidos, sin datos sensibles.
