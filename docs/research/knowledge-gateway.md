# Knowledge Gateway — research de producto

> Estado: research exploratorio, no es un commitment de roadmap.
> Fecha: 2026-09-19 · Repo: NeuralTrust/TrustGate · Branch: `claude/knowledge-gateway-research-buaig8`
> Pregunta de partida: *"¿tiene sentido que el gateway acumule, en paralelo y de forma agnóstica al proveedor,
> el conocimiento que Claude y ChatGPT acumulan sobre una gran empresa?"*
>
> **Tesis de categoría (nivel de ambición actual):** [`knowledge-gateway-thesis.md`](knowledge-gateway-thesis.md)
> **Diseño del flujo de datos (el wedge):** [`knowledge-gateway-dataflow.md`](knowledge-gateway-dataflow.md)

---

## 0. TL;DR

**Sí, hay producto — pero no el que sugiere la tesis inicial.**

1. **La tesis "no seas prisionero del proveedor" es la parte más débil.** El coste de cambio del *memory*
   de un proveedor hoy es bajo y **está bajando por decisión de los propios proveedores**: Anthropic lanzó
   import/export de memoria en agosto de 2026, incluyendo importar memorias de ChatGPT y Gemini. Los
   proveedores están compitiendo por *facilitar* el switch para robarse usuarios. Vender miedo al lock-in
   es vender contra una tendencia que juega en contra.
2. **La parte fuerte es la otra mitad: nadie está construyendo el activo.** El conocimiento que hoy se
   genera dentro de ChatGPT/Claude en una gran empresa (decisiones, criterios, resoluciones, contexto de
   cliente, "cómo hacemos las cosas aquí") **se evapora**: vive en transcripciones por usuario, sin
   estructura, sin permisos, sin gobierno y sin que nadie lo convierta en activo reutilizable. Ese es el
   dolor real, y no es un dolor de portabilidad: es un dolor de **capitalización y gobierno**.
3. **La ventaja diferencial de NeuralTrust no es la memoria: es el punto de interceptación.** Mem0, Zep,
   Letta, Supermemory y MemoryLake tienen motor de memoria pero **no tienen plano de interceptación
   empresarial**. LiteLLM, Portkey (ahora Palo Alto), Kong y Cloudflare tienen plano pero **no tienen
   memoria**. TrustGate ya está en la ruta de tráfico API + MCP, y NeuralTrust ya vende al comprador de
   seguridad que firma los accesos de Enterprise. **La intersección gateway × memoria × gobierno está
   vacía.**
4. **La tubería de captura es la Compliance API de Anthropic, no los Inference Hooks.** Da conversaciones
   completas de claude.ai con turnos de asistente, **artifacts versionados**, ficheros generados,
   knowledge base de projects, y transcripts de Cowork / Claude Code / Chrome / M365 con
   **llamadas y resultados de herramientas MCP normalizados** — es decir, lo que el modelo respondió y lo
   que sacó de las integraciones. Retención de 6 años → **backfill histórico**. Los Inference Hooks son un
   complemento en tiempo real y, sobre todo, la palanca del negocio de DLP que ya vendéis. Del lado
   OpenAI solo hay logs de compliance con **~30 días de retención**: lo que no se extraiga, se pierde.
5. **El bottom-up puro solo funciona en una de las dos mitades.** Capturar lo que los *empleados* hacen en
   ChatGPT/Claude Enterprise requiere claves de admin y permisos de Owner: eso es top-down por construcción.
   Lo que sí es PLG es la **memoria agnóstica para desarrolladores y agentes** (cambiar una base URL / un
   `npx`). Recomendación: **PLG en la mitad de agentes, y usar esa adopción como caballo de Troya para la
   venta enterprise de la mitad de asistentes.**

**Veredicto:** construir, pero reposicionado. No es "escapa del lock-in", es **"el conocimiento que tu
empresa genera usando IA se queda en tu empresa, gobernado, y funciona con cualquier modelo"**. La
portabilidad es la *demo*, no la propuesta de valor.

---

## 1. La tesis, desmontada

| Afirmación de partida | Veredicto | Por qué |
|---|---|---|
| "Las empresas son prisioneras del conocimiento acumulado en Claude/ChatGPT" | **Parcialmente falso** | Anthropic (ago-2026) permite exportar memoria e **importar desde ChatGPT y Gemini**. OpenAI expone conversaciones, ficheros, configs de GPTs y **memories** vía Compliance Logs Platform. La salida existe. |
| "Ese conocimiento es un activo valioso" | **Cierto, pero no el que crees** | El valor no está en las "memories" del proveedor (preferencias de usuario, tono, formato — superficiales). Está en la **transcripción agregada**: decisiones, contexto de cliente, resoluciones, criterio. Eso sí es un activo y **nadie lo está estructurando**. |
| "Hace falta una capa paralela agnóstica" | **Cierto** | Ningún proveedor va a construir un almacén de conocimiento que funcione mejor con su competidor. Es un complemento que ellos nunca comoditizarán del todo. |
| "El gateway es el sitio natural" | **Cierto para agentes / API. A medias para asistentes** | El gateway ve el tráfico API. **No ve** claude.ai ni chatgpt.com. Para esa mitad hacen falta otras tuberías (§3). |
| "Debe venderse bottom-up con PLG" | **Cierto solo para la mitad de agentes** | Ver §8. La mitad enterprise es venta top-down con comprador de seguridad. |

### El reframe

> No vendes **portabilidad**. Vendes **capitalización con gobierno**.
> La portabilidad es la prueba de que el activo es tuyo (el *switch test*), no la razón de compra.

Razón: "portabilidad" es un seguro contra un riesgo futuro e hipotético → presupuesto difícil, urgencia baja.
"Estamos tirando a la basura el 100% del criterio que genera la empresa usando IA, y no hay forma de
auditarlo" → dolor presente, comprador identificado (CISO / Head of AI), y encaja con lo que NeuralTrust ya vende.

---

## 2. Dónde vive realmente el conocimiento

Mapa de superficies en una empresa grande, ordenado por volumen de conocimiento generado:

| Superficie | Quién la usa | ¿La ve TrustGate hoy? | ¿Se puede capturar? |
|---|---|---|---|
| Apps de agentes propias (API) | Equipos de producto | **Sí** (proxy `:8081`) | Trivial, ya está |
| Claude Code / Cursor / Copilot | Ingeniería | Parcial (si pasan por el gateway) | Sí, vía MCP o base URL |
| claude.ai / Claude Cowork | Todo el mundo | **No** | Sí — Compliance API (contenido completo, 6 años) + Inference Hooks (señal inline) |
| chatgpt.com (Business/Enterprise) | Todo el mundo | **No** | Solo batch (Compliance Logs) o interceptación de red/navegador |
| Gemini / Copilot M365 | Todo el mundo | **No** | Vía sus propios logs de admin |
| MCP servers corporativos | Agentes + asistentes | **Sí** (plano `:8082`) | Ya está |

**Conclusión operativa:** el gateway cubre hoy la columna de agentes. La columna de asistentes
(que es donde está el *volumen* de conocimiento humano) requiere **tuberías nuevas**, y esas tuberías
existen y están documentadas. Eso es lo que hace que el proyecto sea viable y no una fantasía.

---

## 3. Vías técnicas de captura (el corazón del análisis)

### A. Interceptación en el path API — *ya lo tenéis*

TrustGate ya proxea `/v1/chat/completions`, `/v1/messages`, embeddings, files. Dos mecanismos concretos:

**A1. Ser el backend del Memory Tool de Anthropic.**
El memory tool de Claude es **client-side**: Claude *pide* operaciones de fichero sobre `/memories` y
**la aplicación las ejecuta** y devuelve un `tool_result`. Se activa con el header beta
`context-management-2025-06-27`.
→ Un gateway en el medio puede **ejecutar él mismo esas operaciones** contra el almacén del cliente.
El resultado: la memoria que Claude cree estar escribiendo en el disco de la app **acaba en el grafo de
conocimiento de la empresa**, y es reinyectable en GPT, Gemini o Llama. Esta es, técnicamente, la
demostración más limpia de la tesis completa, y **cuesta poco implementarla** porque TrustGate ya tiene
`toolinjection` y `toolallowlist`.

**A2. Inyección determinista de contexto.**
Antes de reenviar al proveedor: recuperar del grafo y añadir al prompt (como hace el *Memory Router* de
Supermemory, que es un proxy transparente con cambio de base URL). Ventaja frente a MCP: **es
determinista**, no depende de que el modelo decida llamar a una herramienta.

### B. Plano MCP — *ya lo tenéis*

Exponer `memory.search` / `memory.write` como servidor MCP en `:8082`, consumible por Claude Desktop,
Claude Code, Cursor, y por ChatGPT (custom MCP connectors; los write-capable están restringidos a
Business/Enterprise/Edu). Es el patrón de OpenMemory (Mem0).
**Pros:** instalación por usuario, cero permisos de admin, es el vector bottom-up.
**Contras:** el modelo tiene que *querer* llamar a la herramienta (probabilístico), consume tokens de
definición de tools en cada request, y en ChatGPT Enterprise el connector custom lo publica un admin.

### C. Compliance API de Anthropic — **la vía de captura real** 🔑

Es la que cubre exactamente lo que el hook no cubre: **respuestas del modelo, salidas de las
integraciones, ficheros generados y artifacts**. Requiere Claude Enterprise y una `Compliance Access Key`
(`sk-ant-api01-…`) con scope `read:compliance_user_data`.

**Chats de claude.ai** — `GET /v1/compliance/apps/chats` + `GET /v1/compliance/apps/chats/{id}/messages`.
La propia documentación describe el bucle de export incremental: `order_by=updated_at` sin `user_ids[]`
(scope de toda la organización) y paginar con `after_id`, persistiendo el último cursor entre ejecuciones.
Cada mensaje trae `role` (`user` | `assistant`), su texto, y además:

| Campo | Qué es | Por qué importa |
|---|---|---|
| `files` | Lo que subió el usuario | El input real, no solo lo que escribió |
| `generated_files` | Binarios que Claude produjo vía tools (PDF, xlsx, slides) | El output de trabajo |
| `artifacts` | Documentos versionados generados por el asistente, con un `version_id` por revisión | **El conocimiento ya estructurado, y con su historia de revisiones** |

Hay endpoints de descarga para cada uno. Los **projects** exponen además instrucciones personalizadas,
knowledge base y adjuntos.

**Sesiones de agentes** — `GET /v1/compliance/apps/sessions/local|remote/{id}/messages`, para Cowork,
Claude Code, Claude Science, Claude for Microsoft 365 y Claude in Chrome. La doc lo define literalmente
como *"user prompts, assistant responses, and tool calls and results"*. Y el detalle decisivo:
**las llamadas y resultados de MCP se normalizan en bloques `tool_use` / `tool_result`** → la salida de
las integraciones conectadas es recuperable.

**Tres detalles operativos que no son opcionales:**
1. `tool_result_max_bytes` y `tool_use_input_max_bytes` van **truncados a 10.000 bytes por defecto**.
   Hay que pasar `-1` (máximo del servidor, ~1 MiB) o se pierden silenciosamente las respuestas de los
   conectores, que es justo lo que se quiere capturar.
2. **Retención de 6 años por defecto** (o el periodo custom de la organización) → se puede hacer
   **backfill histórico**, no solo captura hacia adelante.
3. Los cursores de paginación caducan a las 24 h; hay que deduplicar por `id` y solapar ventanas
   `updated_at.gte` unos minutos hacia atrás, porque una sesión aún indexándose se pierde de forma
   permanente si se ajusta el límite exacto.

**Lo que aun así no se obtiene:** bloques de *thinking* (nunca), imágenes/PDFs y bloques binarios dentro
del transcript (aparecen como `[image content not shown]`), metadatos de citación, definiciones de tools y
configuración MCP, sesiones locales en organizaciones con ZDR o HIPAA readiness, y el turno de respuesta
cuando el cliente abortó (`client_aborted`).

### D. Anthropic Inference Hooks — **complemento en tiempo real, no la columna vertebral**

Corrección respecto a la primera versión de este documento: **estaba sobrevalorado como vía de captura.**
Conviene ser preciso sobre lo que sí y lo que no lleva el payload, porque la objeción intuitiva
("solo veo la entrada del usuario") no es exacta, y la razón real para no usarlo como backbone es otra.

**Sí lleva** (esquema del *prompt frame*): `messages[]` con `role` de `user` o `assistant` — es decir,
**turnos previos del asistente incluidos** — y bloques `text`, `tool_use` (`tool_name`, `input`),
`tool_result` (`content` como texto, `is_error`, `tool_name`) y `attachment` con el texto extraído.
**La salida de las integraciones viaja en los `tool_result`**, y el propio diagrama de Anthropic engancha
dos puntos: la llegada del prompt y **el retorno del resultado de herramienta**.

**El problema real es otro, y es serio:**

1. **No hay evento de respuesta.** El único evento hoy es `prompt`, *antes* de la inferencia;
   *"response-side enforcement is planned as a later event"*. La respuesta del asistente solo llega
   incrustada en el transcript del turno siguiente → **lag de un turno, y se pierde para siempre la última
   respuesta de cada conversación**. Una conversación de un solo turno no aporta ningún contenido de
   asistente.
2. **Coste de transferencia cuadrático.** Los transcripts se envían **sin truncar** y completos en
   *cada* turno (hasta 64 MiB por protocolo, ~10 MB en la práctica). Archivar por esta vía significa
   retransferir toda la conversación N veces.
3. **Te metes en la latencia de toda la organización.** Presupuesto de veredicto de 1 a 10.000 ms
   (5.000 por defecto), un solo reintento y solo si falla la conexión, circuit breaker tras fallos
   sostenidos, y un ajuste de *failure handling* que ante una caída tuya **o bloquea Claude a toda la
   empresa o desactiva silenciosamente la inspección**. Como vendor de seguridad, eso es una
   responsabilidad de disponibilidad sobre el asistente en producción del cliente.
4. **Nunca incluye** system prompts, definiciones de tools, contexto interno de Anthropic, **el
   razonamiento oculto de Claude** ni bytes crudos.

**Dónde sí encaja:** (a) el producto de **DLP/guardrails inline que ya vendéis** — ahí estar en el path es
justo el objetivo; (b) señal en tiempo real para marcar qué conversaciones merecen extracción cara
(§5.3), delegando el contenido completo a la Compliance API. La propia doc recomienda, si se archiva por
hooks, responder `allow` *antes* de persistir para sacar el round trip del camino crítico.

### D-bis. Lado OpenAI — y la asimetría que crea urgencia

OpenAI Compliance Logs Platform (Enterprise/Edu): JSONL con conversaciones completas, ficheros,
configuraciones de GPTs, **memories**, acciones de admin y eventos de auth. No hay hook inline nativo
equivalente.

> ⚠️ **La asimetría de retención es el dato comercial más accionable de todo este documento.**
> Anthropic retiene 6 años → puedes reconstruir el histórico el día que firmes.
> OpenAI retiene ~30 días en la plataforma → **todo lo que no se extraiga se pierde de forma
> irreversible**. Cada día sin conectar es un día de conocimiento de ChatGPT destruido para siempre.
> Eso no es un argumento de portabilidad: es una urgencia con fecha.

### E. Red / navegador — probablemente no jugar aquí

Es donde compiten Zscaler, Netskope, Microsoft Purview, dope.security. Interceptan por proxy SSL o
extensión. Mem0 hizo la versión consumer con su extensión de Chrome. **Recomendación: no competir por el
plano de red.** Es un mercado de SSE consolidado y no es vuestro punto fuerte.

### Ranking de las vías

| Vía | Fricción | Cobertura | ¿Ve respuestas? | ¿Ve integraciones? | Cuándo |
|---|---|---|---|---|---|
| A. Path API (memory tool + inyección) | **Nula** (ya sois el proxy) | Agentes propios | Sí | Sí | **Ya** |
| B. MCP | Baja (por usuario) | Devs + asistentes | Parcial | Solo lo que pase por vosotros | **Ya** |
| **C. Compliance API** | Media (clave de compliance) | claude.ai + projects + Cowork + Code + Chrome + M365 | **Sí, completas** | **Sí** (`tool_result`, MCP normalizado) | **Fase 2 — la columna vertebral** |
| D. Inference Hooks | Media (Owner de Enterprise) | claude.ai + Cowork + Code, inline | **Con lag de 1 turno; se pierde la última** | Sí | Fase 2, como complemento y como DLP |
| D-bis. OpenAI Compliance Logs | Media/alta (admin) | ChatGPT Enterprise | Sí | Sí | Fase 2 — **urgente por retención de 30 días** |
| E. Red/navegador | Alta | Todo | Sí | Parcial | No |

---

## 4. Landscape competitivo

### 4.1 Motores de memoria (los "competidores" que os preocupan)

| Producto | Modelo | Señal | Riesgo para nosotros |
|---|---|---|---|
| **Mem0** | OSS + cloud, extracción LLM + búsqueda semántica | ~48k estrellas, $24M, memoria integrada en el Agent SDK de AWS, **OpenMemory MCP** + extensión Chrome | **Alto**: es el default mental y ya hace el cross-tool MCP |
| **Zep / Graphiti** | Graphiti OSS Apache-2.0 (~31k ★), Zep gestionado | Grafo temporal bi-temporal, invalidación de hechos en vez de borrado; Community Edition **deprecada** (abr-2025) → Zep es enterprise-only, desde ~$125/mes por créditos/episodio | **Medio**: excelente motor, mala fricción PLG |
| **Letta** (ex-MemGPT) | Runtime de agente completo | $10M seed; memoria en 3 niveles | Bajo: se comen toda la app, no es capa |
| **Supermemory** | **Open-surface, closed-engine** (ver §4.2-bis). Memory Router: proxy transparente con cambio de base URL | 31k ★ en un repo que **no contiene el motor**; playbook de un plugin por agente | **Muy alto** en patrón y en distribución; **bajo en apertura real** |
| **Cognee / MemoryLake** | Pipelines de memoria; MemoryLake se vende como **"memory passport… platform-neutral"** | Provenance y trazabilidad por memoria | **Alto en mensaje**: MemoryLake ya ocupa el discurso de neutralidad |

> ⚠️ **Dato incómodo: la posición de mensaje que queríamos ("memoria agnóstica del proveedor") ya está
> ocupada por Supermemory (a nivel técnico) y MemoryLake (a nivel narrativo).** Lo que *no* está ocupado
> es la combinación con interceptación enterprise y gobierno.

### 4.2-bis Supermemory: qué es open source y qué no (verificado en el repo)

Auditado `supermemoryai/supermemory` @ `57b430b` (2026-09-18), licencia MIT, ~31k estrellas.
**El motor no está.** Lo que contiene el repo:

| Hay | No hay |
|---|---|
| `apps/docs` (web de documentación) | Ningún handler de `/v3/*` ni `/v4/*` |
| `apps/mcp` (worker de Cloudflare) | Ningún servidor de API |
| `apps/web` (solo `layout.tsx` + `page.tsx`) | Ningún Dockerfile ni compose |
| SDKs TS/Python, `@supermemory/tools`, `ai-sdk` | Ningún esquema de base de datos |
| `@supermemory/memory-graph` (**visualización**) | Ningún pipeline de extracción |
| Extensión de Raycast, playgrounds | Ningún build de binario en los workflows |

Evidencia adicional: 26 referencias en el código apuntan a `https://api.supermemory.ai`; el puerto
`6767` y `supermemory-server` aparecen **solo en ficheros `.mdx` de documentación, nunca en código**;
los workflows de publicación solo publican SDKs y el componente de grafo; y el paquete npm
`supermemory` es el SDK de TypeScript (repo `sdk-ts`, Apache-2.0, cero dependencias, `bin/cli`).
El binario self-hosted llega por `curl | bash`, no se compila desde este repo.

Y sus propios documentos de self-hosting explican el modelo sin ambigüedad:

> *"En producción, Supermemory ejecuta sus propios modelos propietarios, específicamente afinados para
> comprensión de datos a largo horizonte y extracción de memoria. Self-hosted, el mismo pipeline corre
> sobre el modelo que le apuntes."*
> Y en la tabla local vs. Enterprise: **conectores `—` en local**, auth de una sola clave, una máquina.

Es decir: **la calidad de la memoria es, por diseño, el diferencial cerrado.** Lo abierto es la
superficie de distribución.

**Dos lecturas estratégicas:**

1. **"Verificablemente abierto" es un diferencial real, no marketing.** TrustGate es Apache-2.0 con un
   motor de verdad en el repo y un binario autocontenido. Frente a Supermemory (motor cerrado) y Zep
   (Community Edition deprecada en abril de 2025 → enterprise-only), es la única de las tres posiciones
   auditables. Para un discurso de neutralidad y no-lock-in, eso importa: **un motor cerrado es otro
   proveedor del que depender.**
2. **Su motor de crecimiento no es el open source del core: es un plugin por ecosistema de agente.**
   `claude-supermemory` (2,8k ★), `opencode-supermemory` (1,6k ★), `openclaw-supermemory` (796 ★),
   `codex-supermemory`, `cursor-supermemory`, `muse-supermemory`, `hermes-supermemory`. **Un repo por
   superficie.** Ahí está la lección de PLG replicable, y no requiere regalar nada crítico.
   *(Nota aparte: `smfs`, en Rust y con 480 ★, "un sistema de ficheros diseñado para agentes", parece una
   apuesta distinta y vale la pena vigilarla.)*

### 4.2-ter Apertura real de los tres: auditoría de código

Los tres repos clonados e inspeccionados directamente (no leyendo su web).

| | **Supermemory** `57b430b` | **Graphiti / Zep** `5764a6c` | **Mem0** `a39a802` |
|---|---|---|---|
| Licencia | MIT | Apache-2.0 | Apache-2.0 |
| **¿Motor en el repo?** | ❌ **No** | ✅ **Sí** — 158 ficheros `.py` en `graphiti_core` | ✅ **Sí** — `memory/main.py`, 3.868 líneas |
| **¿Prompts de extracción?** | ❌ No | ✅ `prompts/extract_nodes.py`, `extract_edges.py`, `dedupe_*`, `summarize_*` | ✅ `configs/prompts.py`, 1.062 líneas |
| Servidor / API | ❌ No hay rutas `/v3` ni `/v4` | ✅ `server/` + `mcp_server/` + Dockerfile + compose | ✅ `server/` + `proxy/main.py` |
| Gating de features | Motor cerrado por diseño | ✅ Ninguno encontrado | ✅ Ninguno encontrado |
| Llamadas a API propietaria | 26 refs a `api.supermemory.ai` | **Cero** en el código Python | Cliente de plataforma, opcional |
| **Riesgo de cierre** | Ya cerrado | ⚠️ **CLA de Zep Software** + Community Edition deprecada (abr-2025) | ⚠️ Sistema de *notices* remoto |

**Orden de apertura real: Graphiti > Mem0 > Supermemory.**

**Graphiti es genuinamente abierto.** Está el pipeline entero —extracción combinada, operaciones de nodos
y aristas, deduplicación, comunidades, migraciones, búsqueda, drivers— y, lo más revelador, **los prompts
de extracción**, que es justo el know-how que Supermemory declara propietario. Cero llamadas a un API
hospedado. La pega no está en el código: está en el **CLA**, que cede a Zep Software, Inc. los derechos
sobre las contribuciones. Con ese CLA y el precedente de haber deprecado la Community Edition, **la
apertura de Graphiti es una concesión revocable, no una garantía estructural.**

**Mem0 está abierto, pero instrumentado como embudo.** El motor y los prompts están. Pero
`mem0/memory/notices.py` **descarga en tiempo de ejecución una configuración remota desde GitHub raw**
y hace **A/B testing sobre los usuarios de OSS** (`variant_split: 0.5`, flags estilo PostHog). El fichero
`oss_notices_config.json` declara avisos para `first_run`, `scale_threshold`, y —esto es lo llamativo—
`temporal_stub` y `decay_stub` **con `notice_type: "error"`**. Hoy solo el de escala está cableado en
`main.py` (salta en `add` y con `top_k` grande) y los demás están deshabilitados con copy vacío: la
maquinaria está instalada y es conmutable en remoto sin publicar una versión. Y hay una skill que se
llama, literalmente, **`mem0-oss-to-platform`**.

**Dos conclusiones para el posicionamiento:**

1. **"Somos open source" no diferencia nada** — compites contra dos Apache-2.0. Lo que diferencia es
   **qué tipo de apertura**, y eso sí es auditable y por tanto defendible: motor en el repo · prompts
   incluidos · sin CLA que permita relicenciar · **sin configuración remota que modifique el
   comportamiento del binario del usuario** · sin phone-home · y un historial de no haber matado la
   edición community. Eso es una tabla comparativa publicable, y cualquiera puede verificarla clonando.
   *(Y conviene mirarse al espejo con esa misma tabla antes de publicarla.)*

2. **El playbook de distribución ya está copiado por los dos líderes.** Supermemory tiene un repo por
   superficie (`claude-supermemory` 2,8k ★, `opencode-supermemory` 1,6k ★, `openclaw-` 796 ★,
   `codex-`, `cursor-`, `muse-`, `hermes-`). Mem0 lo hace dentro del monorepo:
   `.claude-plugin`, `.cursor-plugin`, `.codex-plugin`, `.kimi-plugin`, `marketplace.json` y un
   directorio `skills/`. **Un plugin por superficie de agente ya no es un diferencial: es el precio de
   entrada** — y se llega tarde a esa carrera.

Lo cual refuerza la tesis de `knowledge-gateway-thesis.md`: no hay que pelear en la capa de librería de
memoria, donde ellos tienen decenas de miles de estrellas y presencia en cada superficie, sino en la
posición que estructuralmente no pueden ocupar.

### 4.2 Gateways

Portkey **fue adquirido por Palo Alto Networks** (anunciado el 30-abr-2026, cerrado el 29-may-2026) y se
está integrando en Prisma AIRS como plano de control de AI Gateway. Contraprestación total: **~$117M**,
prácticamente todo en caja, según el 10-K FY2026 de PANW. LiteLLM sigue siendo el self-hosted de
referencia; Cloudflare compite por el edge; Kong desde el mundo API.
→ **Lectura, en dos direcciones.** (1) El mercado de gateways se está consolidando **dentro de vendors de
seguridad**, que es exactamente la tesis de NeuralTrust — buena señal de categoría. (2) Pero $117M es un
múltiplo modesto para el gateway *de referencia* del mercado: dice que **el gateway solo, como plano de
tráfico, no es un negocio grande por sí mismo**; vale como punto de control desde el que vender otra cosa.
Eso sube mucho la urgencia de tener una capa de producto encima que un Palo Alto no replique en un
trimestre. **Memoria gobernada es exactamente ese tipo de capa** (es producto, no feature de proxy).

### 4.3 Knowledge / enterprise search

**Glean** (~$4.6B): +100 conectores, grafo de conocimiento **permission-aware**, explícitamente
*model-agnostic* — es decir, **ya vende el argumento de "no te quedas atado a un LLM"**. En su propia
evaluación afirma que sus respuestas se prefieren ~1,9× sobre *company knowledge* de ChatGPT y ~1,6× sobre
Claude (self-reported, tomarlo como marketing). Alternativas OSS: Onyx, Dust.

**OpenAI Company Knowledge** (Business/Enterprise/Edu): conecta Slack, SharePoint, Drive con citaciones, y
va a soportar **custom MCP connectors con search/fetch**.

> **Distinción crítica que hay que mantener clara:** Glean y Company Knowledge indexan **documentos que ya
> existen**. Lo que proponemos captura **conocimiento que se está creando en la conversación y que no
> existe en ningún documento**. Son capas distintas y complementarias. Si el pitch se confunde con
> "enterprise search", perdéis contra Glean por recursos y contra OpenAI por distribución.

### 4.4 Los proveedores como competidores

- Anthropic: memoria unificada chat + Cowork (25-ago-2026), export en Settings, **import desde ChatGPT y
  Gemini**.
- OpenAI: memories exportables vía Compliance Logs; company knowledge.
- Ambos tienen incentivo para hacer la *entrada* fácil y la *salida* aceptable. **Comoditizarán la
  portabilidad simple.** Lo que no comoditizarán: estructura multi-proveedor, permisos corporativos,
  retención, auditoría y reutilización por agentes propios.

### 4.5 Estándares (relevante para posicionamiento, no para roadmap inmediato)

Hay un **W3C AI Agent Memory Interoperability Community Group**, una propuesta de wire format neutral
(*memorywire*, pensada como extensión de MCP), la **Engram Specification** (Apache-2.0, PLUR) y papers de
transferencia de memoria con provenance verificable. **No hay estándar consolidado.**
→ Oportunidad barata y de alto retorno reputacional: **participar/liderar desde Europa** y publicar el
formato de export de TrustGate como implementación de referencia. Refuerza exactamente el mensaje de
neutralidad y cuesta muy poco.

### 4.6 Palanca regulatoria (útil, pero no la apuesta)

El **EU Data Act** (aplicable desde el 12-sep-2025) impone régimen de switching: derecho contractual a
cambiar de proveedor, procedimiento de migración, periodo transitorio máximo de 30 días, formato
estructurado e interoperable, y **eliminación de tasas de egress a partir del 12-ene-2027**.
**Pero:** la aplicabilidad a servicios de IA "as-a-service" sigue siendo interpretativa y discutida.
→ Úsalo como **acelerador de conversación con Legal/Compliance en cuentas EU**, no como el argumento
central. Si el argumento central es regulatorio, la compra se retrasa hasta que haya obligación clara.

---

## 5. Dónde está la fricción (lo que hay que resolver o esquivar)

1. **Asimetría entre proveedores, en dos ejes.** *Profundidad:* Anthropic expone artifacts versionados,
   ficheros generados, knowledge base de projects y transcripts de agentes con tool calls; OpenAI expone
   conversaciones y memories, sin ese nivel de estructura. *Retención:* 6 años frente a ~30 días.
   **El producto será claramente mejor en Claude que en ChatGPT.** Hay que diseñar admitiendo la asimetría
   —y convertirla en argumento de urgencia en el lado OpenAI— en vez de prometer paridad.
2. **El modelo tiene que usar la memoria.** Si dependes de MCP, la recuperación es probabilística.
   **Mitigación:** inyección determinista en el gateway (vía A2), con MCP como complemento.
3. **El coste está en la escritura, no en la lectura.** Un grafo temporal tipo Graphiti dispara múltiples
   llamadas LLM por episodio (extracción de nodos → dedup → extracción de aristas → resolución →
   timestamping). Cifras de benchmark de terceros apuntan a ~$0,556/episodio (Graphiti) vs ~$0,109 (Mem0)
   — direccionales, no auditadas. **A volumen de chat corporativo, "acumularlo todo en paralelo" no es
   económicamente viable.** Hace falta triage: guardar barato siempre, extraer caro solo lo que supere un
   umbral de valor.
4. **Permisos.** Memoria derivada de documentos hereda los permisos de esos documentos. Aplanar todo en un
   grafo compartido convierte el producto en **una máquina de fugas de información interna**. Este es el
   problema de ingeniería más duro de todos (y el foso real de Glean). No se puede dejar para la v2.
5. **Legal/laboral en Europa — subestimado.** Capturar conversaciones de empleados activa
   **codeterminación del comité de empresa** (§87 BetrVG en Alemania; equivalentes en Austria, Países
   Bajos y Francia), exige **DPIA**, y si el output se usa para evaluar desempeño puede caer en
   **Anexo III del AI Act** como alto riesgo. **Implicación de diseño, no nota al pie:** opt-in por
   workspace, memoria **visible y editable por el usuario**, redacción de PII en escritura, y narrativa de
   *"conocimiento de equipo"*, nunca de *"vigilancia del empleado"*. Un despliegue que parezca monitorización
   se muere en el comité de empresa antes de llegar a producción.
6. **Demostrar valor es difícil.** Los benchmarks de memoria (LoCoMo) están saturados y no predicen
   comportamiento agéntico; las puntuaciones que publican los vendors usan prompts de evaluación distintos
   y no son comparables entre sí. La mayoría de fallos en producción ocurren en la **escritura y el
   mantenimiento**, no en la lectura. **Hay que construir la medición desde el día 1** (tasa de recall útil,
   contradicciones detectadas, reducción de re-explicación) o no se podrá renovar el contrato.
7. **La categoría no existe.** Nadie busca "knowledge gateway". Sirve como nombre interno de la feature;
   externamente hay que hablar el idioma del comprador.

---

## 6. Qué es defendible para NeuralTrust

Tres cosas, en orden de solidez:

1. **El punto de interceptación.** Ser simultáneamente proxy API, plano MCP y *AI security server* de
   Inference Hooks, y consumidor autorizado de las Compliance APIs. Un Mem0 tendría que construir el
   negocio de seguridad entero para que un CISO le entregue una Compliance Access Key; un Palo Alto
   tendría que construir el motor de memoria. **Vosotros ya tenéis las dos mitades a medio camino.**
2. **La memoria como política de gateway, no como base de datos.** Quién puede escribir, quién puede leer,
   qué se redacta al escribir, cuánto se retiene, cómo se borra (derecho al olvido), quién lo auditó.
   Mem0 y Zep venden recall; vosotros podéis vender **recall gobernado**, que es lo único que un banco
   puede desplegar.
3. **Neutralidad creíble y europea.** El mensaje de neutralidad suena hueco en boca de un vendor
   americano dependiente de un proveedor. TrustGate es Apache-2.0, self-hostable, binario Go sin
   dependencias de runtime. **Eso es verificable, no marketing.**

---

## 7. Arquitectura propuesta sobre TrustGate

Lo relevante es cuánto de esto **ya existe** en el repo:

| Pieza necesaria | Qué hay hoy en TrustGate | Qué falta |
|---|---|---|
| Interceptar/mutar requests | `pkg/infra/plugins/*` (stages de plugin, `toolinjection`, `prompttemplate`, `promptcompression`) | Plugin `memory` (read stage + write stage) |
| Embeddings | `pkg/infra/embedding`, `pkg/domain/embedding`, ya usados por `semanticcache` | Reutilizar tal cual |
| Servir tools a asistentes | Plano MCP `:8082` (`pkg/app/mcp`, `pkg/infra/mcp`, OAuth en `pkg/app/mcpoauth`) | Servidor MCP `memory` |
| Multi-proveedor | `pkg/infra/providers` (9+ proveedores, routing, fallback) | Nada — es justo lo que hace agnóstica la memoria |
| Identidad / consumers | auth por consumer, políticas por consumer | Mapear consumer → sujeto de memoria + ACL |
| Redacción / seguridad | `logredact`, `firewall`, `trustguard` | Reutilizar en el write path |
| Almacén de conocimiento | — | **Decisión pendiente (§7.1)** |
| Ingestión batch | — | Workers de Compliance API: bucle `order_by=updated_at` + cursor persistido, `tool_result_max_bytes=-1`, dedup por `id`, ventanas solapadas |
| Endpoint de Inference Hooks | — | Receptor HTTPS (Go, ya es vuestro lenguaje): verificación Standard Webhooks, dedup por `webhook-id`, `allow` antes de persistir |

### 7.1 ¿Graphiti como motor?

**Recomendación: no en la v1; sí evaluarlo en la v2 como motor opcional.**

A favor: Apache-2.0, modelo bi-temporal maduro (invalida hechos en vez de borrarlos → auditoría e
histórico gratis), retrieval híbrido rápido (P95 en cientos de ms), servidor MCP y REST ya incluidos,
soporte multi-LLM y multi-DB (Neo4j, FalkorDB, Neptune).

En contra, y pesa: es **Python** (TrustGate es un binario Go único sin dependencias de runtime — meter
Python + Neo4j destruye literalmente el argumento de despliegue que usáis contra LiteLLM en el README),
el **coste de escritura es alto**, y Zep deprecó su Community Edition, lo que señala que el upstream
optimiza para su cloud enterprise, no para integradores.

**Camino sugerido:** v1 con almacén propio simple (Postgres + pgvector, hechos con validez temporal y
provenance al episodio origen — copiar el *modelo* bi-temporal de Graphiti sin copiar la dependencia).
Dejar el motor detrás de una interfaz para poder enchufar Graphiti o Zep como backend en clientes que ya
lo usen. Eso además convierte a Zep/Mem0 de competidores en *backends*, que es una postura comercial
mucho más cómoda para un gateway neutral.

---

## 8. GTM bottom-up / PLG

### 8.1 El problema estructural del bottom-up aquí

La mitad que más te interesa (conocimiento de empleados en ChatGPT/Claude Enterprise) **es imposible de
adoptar bottom-up**: Inference Hooks requiere `organization:manage` (solo Owner/Primary owner) y las
Compliance APIs requieren claves de admin. No hay atajo. Fingir lo contrario lleva a un funnel roto.

**Por tanto: dos movimientos, no uno.**

```
 PLG (self-serve, dev)                     Enterprise (asistido, seguridad)
 ──────────────────────                    ───────────────────────────────
 Memoria para agentes propios       ──►    Captura de claude.ai / ChatGPT
 vía base URL o MCP                        vía Compliance API (+ hooks para DLP)
 Gratis / OSS / self-host                  Contrato, SSO, permisos, retención
 Usuario: dev de agentes                   Comprador: CISO / Head of AI
 ~10 minutos                               ~2 meses
```

El PLG no vende el producto enterprise: **genera la evidencia interna y el campeón** que lo vende.

### 8.2 El momento de activación: el *switch test*

Una sola demo, reproducible en <10 minutos, que contiene todo el argumento:

1. Pasas tus llamadas por TrustGate (cambio de base URL).
2. Trabajas un rato con Claude. El gateway acumula el conocimiento.
3. Cambias el modelo a GPT-5 **en la config del gateway, sin tocar una línea de código**.
4. Preguntas lo mismo. **Responde igual, porque el conocimiento es tuyo, no de Anthropic.**

Eso es un GIF de 20 segundos, es compartible, es verificable, y es la prueba literal de la tesis del
usuario. **Ese artefacto es el motor de crecimiento.** Si no se consigue hacer memorable, el PLG no arranca.

### 8.3 Reducción de fricción (checklist innegociable)

- Un solo comando: `npx trustgate memory` o `docker run` → funcionando sin cuenta, sin tarjeta, sin SaaS.
- **Sin base de datos externa obligatoria** en el arranque (SQLite/Postgres embebido; Neo4j mata la activación).
- Instalación MCP de un clic para Claude Code, Claude Desktop y Cursor.
- El fallo es *pass-through*: si la capa de memoria cae, la request pasa igual al proveedor
  (Supermemory lo publicita explícitamente; es tabla de apuestas).
- Dashboard local desde el minuto uno: **el usuario tiene que VER su memoria**. Es lo que hace el producto
  tangible, y además es el requisito de transparencia que os salva en la revisión legal (§5.5).

### 8.4 Empaquetado sugerido

| Nivel | Qué incluye | Precio |
|---|---|---|
| OSS / self-host | Memoria en el path API, MCP, un almacén, export completo | Gratis (Apache-2.0) |
| Team | Memoria compartida, ACL por consumer, dashboard, retención | Por workspace |
| Enterprise | Ingestión Compliance API (Claude + OpenAI) con backfill histórico, Inference Hooks para DLP inline, memoria permission-aware, redacción PII, auditoría, SSO | Contrato |

**Evitar el error de Mem0**: su salto $19 → $249 deja un hueco donde los equipos pequeños no pueden
validar en producción. Métrica de cobro: **por workspace y retención**, no por operación de memoria
— cobrar por escritura castiga justo el comportamiento que queréis fomentar (acumular).

### 8.5 Mensaje

- ❌ "Knowledge gateway" (nadie lo busca), "no seas prisionero de tu proveedor" (miedo abstracto).
- ✅ **"El conocimiento que tu empresa genera con IA se queda en tu empresa."**
- Subtítulo para el comprador técnico: *"Memoria gobernada para agentes y asistentes. Cualquier modelo.
  Self-hosted. Exportable."*

---

## 9. Plan por fases y criterios de parada

**Fase 0 — Validación (2–3 semanas, sin código de producto).**
15 conversaciones: 5 plataformas de IA en empresas grandes, 5 devs de agentes, 5 CISOs.
Preguntas que hay que responder con evidencia, no con intuición:
(a) ¿alguien ha intentado ya exportar o reutilizar lo que hay en ChatGPT/Claude Enterprise?
(b) ¿el dolor se articula como portabilidad, como capitalización o como auditoría?
(c) ¿cuántos tienen Claude Enterprise **y** ChatGPT Enterprise a la vez? (si son pocos, la tesis
multi-proveedor se debilita mucho y el producto es "memoria gobernada", sin más).
> **Kill criterion:** si nadie ha *intentado* sacar ese conocimiento, no hay dolor — hay una idea bonita.

**Fase 1 — El switch test (4–6 semanas).**
Plugin `memory` (read+write) + backend del memory tool de Anthropic + servidor MCP `memory` + dashboard.
Todo sobre la infraestructura que ya existe en el repo.
> **Éxito:** X instalaciones self-serve y el GIF del switch test circulando. **Kill:** si los devs lo
> instalan y no lo mantienen encendido a la semana, la memoria no está aportando y hay que parar.

**Fase 2 — La apuesta enterprise (8–12 semanas).**
**Primero** los workers de Compliance API (Anthropic y OpenAI) — es donde está el contenido real y no
toca la latencia de nadie. Empezar por el **backfill** de Anthropic: una cuenta piloto ve, el primer día,
años de su propio conocimiento estructurado. Ese es el momento "ajá" de la venta enterprise, y es
irreproducible por cualquiera que no tenga la clave.
**Después** el receptor de Inference Hooks, en **modo shadow**, vendido como DLP inline — que es el
producto que ya tenéis y la forma de entrar sin fricción. Y memoria permission-aware en paralelo.
> **Kill:** si en 2 cuentas piloto el comité de empresa o Legal bloquean la captura, el producto en EU es
> inviable tal cual y hay que replegarse a "memoria de agentes", que sigue siendo un buen negocio.

**Fase 3 — Neutralidad como estándar.**
Formato de export documentado + participación en el W3C Community Group + backends opcionales
(Zep/Mem0/Graphiti). Convierte la neutralidad en algo auditable y convierte competidores en integraciones.

---

## 10. Preguntas abiertas

1. ¿Cuántas cuentas objetivo tienen **Claude Enterprise** (requisito tanto de la Compliance API de contenido como de los hooks) y no solo acceso por API?
2. ¿Aceptará Anthropic que el AI security server de un tercero archive transcripciones como servicio
   comercial? La documentación lo lista como caso de uso, pero **conviene confirmarlo con ellos antes de
   construir encima**.
3. ¿Merece la pena cubrir Gemini/Copilot M365 en v1, o multi-proveedor = OpenAI + Anthropic?
4. ¿La memoria es **por usuario**, **por equipo** o **por organización**? Es la decisión de producto más
   cara de revertir, y determina el modelo de permisos entero.
5. ¿Cómo se mide "el conocimiento sirvió"? Sin esto no hay renovación.

---

## 11. Fuentes

**Proveedores (documentación oficial)**
- [Anthropic — Inference hooks](https://platform.claude.com/docs/en/manage-claude/inference-hooks)
- [Anthropic — Compliance API](https://platform.claude.com/docs/en/manage-claude/compliance-api)
- [Anthropic — Retrieve and delete chats, files, and projects](https://platform.claude.com/docs/en/manage-claude/compliance-content-data)
- [Anthropic — Retrieve session transcripts](https://platform.claude.com/docs/en/manage-claude/compliance-sessions)
- [Anthropic — Develop an Inference hooks integration (esquema del payload)](https://platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint)
- [Anthropic — Memory tool](https://platform.claude.com/docs/en/agents-and-tools/tool-use/memory-tool)
- [Anthropic — Import and export your memory from Claude](https://support.claude.com/en/articles/12123587-import-and-export-your-memory-from-claude)
- [OpenAI — Compliance Platform for Enterprise and Edu](https://help.openai.com/en/articles/9261474-openai-compliance-platform-for-enterprise-and-edu-customers)
- [OpenAI — New compliance and administrative tools for ChatGPT Enterprise](https://openai.com/index/new-tools-for-chatgpt-enterprise/)
- [OpenAI — Company knowledge in ChatGPT](https://help.openai.com/en/articles/12628342-company-knowledge-in-chatgpt-business-enterprise-and-edu)
- [OpenAI — Developer mode and MCP apps in ChatGPT](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt)

**Landscape de memoria**
- [Graphiti (getzep/graphiti)](https://github.com/getzep/graphiti) · [Zep: A Temporal Knowledge Graph Architecture for Agent Memory (arXiv 2501.13956)](https://arxiv.org/abs/2501.13956) · [Zep pricing](https://www.getzep.com/pricing/)
- [Mem0 — Introducing OpenMemory MCP](https://mem0.ai/blog/introducing-openmemory-mcp) · [OpenMemory Chrome extension](https://mem0.ai/blog/introducing-the-openmemory-chrome-extension) · [State of AI Agent Memory 2026](https://mem0.ai/blog/state-of-ai-agent-memory-2026)
- [Supermemory — Memory Router](https://supermemory.ai/docs/memory-router/overview) · [supermemoryai/supermemory](https://github.com/supermemoryai/supermemory)
- [MemoryLake — cross-agent memory](https://www.memorylake.ai/en/blogs/cross-agent-memory)
- [Comparativa Mem0 / Zep / Letta / Cognee / Supermemory (Q3 2026)](https://mnemoverse.com/docs/library/ai-memory-solutions-2026-q3) · [Feather DB — landscape 2026](https://www.getfeather.store/theory/ai-agent-memory-frameworks-landscape-2026)
- [Coste de ingestión en grafos de memoria](https://codex.danielvaughan.com/2026/03/30/graphiti-agent-memory-store/) · [Graphiti issue #1193 — custom extraction and lower LLM costs](https://github.com/getzep/graphiti/issues/1193)
- [Mem0 — benchmarks de memoria 2026 (LoCoMo, LongMemEval, BEAM)](https://mem0.ai/blog/ai-memory-benchmarks-in-2026) · [Cómo evaluar memoria de agentes](https://labelstud.io/learning-center/how-to-evaluate-agent-memory/)

**Gateways y knowledge**
- [Palo Alto Networks completa la adquisición de Portkey (nota de prensa)](https://www.paloaltonetworks.com/company/press/2026/palo-alto-networks-completes-acquisition-of-portkey-to-secure-ai-agents) · [PANW Form 10-K FY2026 (importe de la operación)](https://www.sec.gov/Archives/edgar/data/0001327567/000132756726000023/panw-20260731.htm) · [Comparativa de AI gateways 2026](https://www.braintrust.dev/articles/ai-gateway-comparison-2026)
- [Glean — evaluación de enterprise search 2026 (self-reported)](https://www.glean.com/blog/enterprise-search-evaluation-2026) · [ChatGPT entra en enterprise search](https://www.reworked.co/knowledge-findability/openai-pushes-into-enterprise-search-with-company-knowledge/)
- [AI DLP para ChatGPT y Claude (2026)](https://dope.security/post/best-ai-dlp-software-chatgpt-claude-compared-2026)

**Estándares y regulación**
- [W3C AI Agent Memory Interoperability Community Group](https://www.w3.org/community/ai-agent-memory-interop/) · [memorywire (arXiv 2606.01138)](https://arxiv.org/pdf/2606.01138) · [Engram Specification](https://plur.ai/blog/open-standard-ai-agent-memory/) · [Portable Agent Memory (arXiv 2605.11032)](https://arxiv.org/html/2605.11032v1)
- [EU Data Act — régimen de switching](https://www.lw.com/en/insights/eu-data-act-significant-new-switching-requirements-due-to-take-effect-for-data-processing-services) · [Garrigues — claves del cambio de proveedor cloud](https://www.garrigues.com/en_GB/garrigues-digital/data-act-and-cloud-switching-keys-new-rules-changing-cloud-service-providers)
- [Protección de datos del empleado e IA en la UE](https://www.fisherphillips.com/en/insights/insights/ai-employee-data-protection-european-union-takeaways-for-multinational-businesses) · [Monitorización de empleados y GDPR](https://secureprivacy.ai/blog/employee-monitoring-gdpr-guide)

> **Nota sobre fiabilidad:** las cifras de benchmark, coste por episodio y cuota de preferencia proceden en
> su mayoría de publicaciones de los propios vendors o de análisis de terceros no auditados. Son útiles
> como orden de magnitud y como señal de mercado; **no deben citarse como dato en material comercial**
> sin verificación propia.
