# La tesis grande: el sistema de registro de lo que la IA de tu empresa cree

> Este documento sustituye al marco de `knowledge-gateway.md` como nivel de ambición.
> Aquel analizaba **una funcionalidad del gateway**. Este plantea **una categoría**.
> El data flow de `knowledge-gateway-dataflow.md` sigue siendo válido: es el *wedge*, no el producto.

---

## 1. El error del planteamiento anterior

Estábamos compitiendo con Supermemory y Zep. Eso ya es perder, porque **Supermemory y Zep no son
competidores: son componentes.**

- **Mem0, Zep, Supermemory, Letta** se venden a *un desarrollador que construye una aplicación*. Memoria
  por app, por agente, por usuario. Son librerías e infraestructura de producto.
- El mercado que importa no es "memoria para tu agente". Es **el sustrato compartido de una empresa que
  va a operar cientos de agentes de proveedores distintos.**

Son capas distintas del stack. Competir con ellos es aceptar ser un componente. La posición interesante
está un nivel por encima, y **está vacía**.

---

## 2. Lo que está pasando de verdad (las tres curvas que se cruzan)

**a) El número de agentes explota.** Las proyecciones de sector hablan de que una gran empresa operará
del orden de **1.600 agentes** a final de 2026, y de que **~70% no puede gobernar ni los que ya tiene**.
*(Cifra de proveedor, direccional.)* A esa escala el fallo deja de ser "el agente se olvidó" y pasa a ser
**"el agente 412 y el agente 908 creen cosas distintas y los dos actuaron"**.

**b) El multi-proveedor es irreversible.** Ninguna empresa grande es de un solo proveedor ya. Y la
memoria de cada proveedor es, por diseño, un silo. No es un bug que vayan a arreglar: es su foso.

**c) Aparece el presupuesto.** Gartner sitúa el gasto en gobierno de IA en ~**$492M en 2026**, y proyecta
que **el 50% de los fallos de agentes se atribuirán a gobierno débil para 2030**. Y una predicción muy
específica que conviene leer dos veces: **el 60% de los proyectos agénticos que se apoyen solo en MCP
fracasarán para 2028 por falta de una capa semántica consistente por debajo.** *(Citas secundarias.)*

**El diagnóstico que se repite en la literatura de 2026 es literal:**
> *"La inconsistencia de contexto, no la elección de patrón, es la razón principal por la que la
> orquestación multiagente falla en producción."*

Eso no es un problema de memoria. **Es un problema de consistencia.** Y los problemas de consistencia
son problemas de infraestructura: más grandes, más pegajosos y más defendibles que los de recuperación.

---

## 3. La categoría que se está formando — y el hueco

El stack que se está consolidando como consenso tiene cuatro capas:

```
┌─────────────────────────────────┐
│  1 · Ejecución de agentes       │  Cowork, Claude Code, agentes propios, SaaS con IA
├─────────────────────────────────┤
│  2 · Control plane              │  ◄── TrustGate está aquí
│      (tráfico, política, audit) │      Portkey→PANW, Kong, LiteLLM
├─────────────────────────────────┤
│  3 · Context layer              │  ◄── Jedify ($24M A), Modus ($10M seed, Insight),
│      (significado, semántica)   │      Zep, Supermemory, Snowflake
├─────────────────────────────────┤
│  4 · Data estate                │  Snowflake, Databricks
└─────────────────────────────────┘
```

**La tesis: las capas 2 y 3 son la misma capa, y todo el mundo las está construyendo por separado.**

- **Contexto sin aplicación es un consejo.** Modelas el significado del negocio en un *context warehouse*
  y el agente puede ignorarlo tranquilamente. No hay nada que lo obligue.
- **Aplicación sin contexto es un firewall tonto.** Bloqueas patrones sin saber qué es verdad en la
  empresa.
- **El único sitio donde puedes a la vez *saber* qué es cierto y *hacerlo vinculante* es el camino de
  ejecución.** Es decir, el gateway.

Quien está financiado en la capa 3 viene del lado del dato (almacén, catálogo, capa semántica): saben
modelar significado, **no pueden impedir que un agente actúe en contra**. Para hacerlo tendrían que
convertirse en un proxy en el path. Quien está en la capa 2 tiene el path pero **no tiene semántica**
— y los $117M de Portkey dicen que el plano de tráfico, solo, no es el premio.

**Nadie tiene las dos. Esa es la posición.**

---

## 4. El producto: un sistema de registro que no existe

Las empresas tienen sistema de registro para lo que **poseen** (ERP), para quiénes son sus **clientes**
(CRM), para su **gente** (HRIS), para su **código** (git).

**No tienen ninguno para lo que la organización sostiene como cierto y lo que permite hacer.** Hasta
ahora no hacía falta, porque eso vivía en la cabeza de la gente. Con 1.600 agentes actuando sobre ello,
hace falta.

Las categorías de sistema de registro son las más grandes y pegajosas del software empresarial. Y esta
no tiene dueño.

### Los cuatro primitivos

| Primitivo | Qué es | Ejemplo |
|---|---|---|
| **Creencia** | Lo que la organización sostiene como cierto, con procedencia, intervalo de validez y confianza | *"El año fiscal empieza en abril"* |
| **Decisión** | Lo que ha elegido, por qué, y si es reversible | *"Migramos a Postgres; descartamos Mongo por X"* |
| **Restricción** | Lo que permite — y esto **es política, y es vinculante** | *"Ningún agente envía datos de cliente a un modelo fuera de la UE"* |
| **Atestación** | Qué agente actuó sobre qué creencia, cuándo, con qué evidencia | El registro auditable |

**Aquí está la idea que unifica todo esto y que es específicamente vuestra:**

> *"Nuestro año fiscal empieza en abril"* y *"ningún agente puede mandar datos de cliente fuera de la UE"*
> **son el mismo tipo de objeto.** Las dos son verdades organizativas que tienen que llegar a todas las
> superficies de IA, con procedencia, versión y auditoría. La diferencia es solo que una informa y la
> otra obliga.
>
> Los productos de memoria solo hacen la primera. Los productos de seguridad solo hacen la segunda.
> **Un gateway puede hacer las dos, y pertenecen al mismo almacén.**

Eso no es "memoria con gobierno". Es un objeto nuevo, y es lo que hace que esto sea un producto nuevo y
no una feature de Mem0.

### Los cuatro trabajos del plano

1. **Ingerir** — capturar creencias desde cualquier superficie *(el data flow que ya diseñamos: es 1 de 4)*
2. **Reconciliar** — detectar contradicción, versionar, invalidar, resolver ← **la parte difícil, y
   la que nadie hace**
3. **Distribuir** — inyectar y **hacer cumplir** en cada superficie, de forma determinista
4. **Atestar** — demostrar qué se creía, quién lo creía y cuándo ← lo que va a exigir el regulador

El trabajo 2 es el foso. Es, en el fondo, **consenso distribuido sobre lenguaje natural**: un problema
duro de verdad. Difícil de construir = difícil de copiar.

---

## 4-bis. ¿Hacen ya los demás la capa de "company brain"? — verificado en código

Todos usan el vocabulario ("organizational memory", "company brain", "contexto de empresa"). **Ninguno ha
construido el primitivo organizativo.** Los tres hacen lo mismo: memoria particionada por una clave plana.

| | Primitivo de scope | Qué es de verdad |
|---|---|---|
| **Mem0** | `user_id` · `agent_id` · `run_id` | Memoria por usuario, agente o ejecución. **No existe org, team ni tenant** en la firma de `add()` / `search()`. |
| **Graphiti** | `group_id` | Clave de partición plana. |
| **Supermemory** | `containerTag` | Clave de partición plana. Su propia doc: *"un container puede ser cualquier cosa: un usuario, un proyecto, un equipo, una organización, etc."* |

**"Puede ser cualquier cosa" es precisamente el problema: es un namespace, no un modelo organizativo.**
Una clave de partición significa que todo lo que hay dentro es una bolsa indiferenciada, y que nada
cruza entre bolsas. De ahí salen las tres carencias que *son* el problema del company brain:

**1. No hay reconciliación entre personas.** La deduplicación y la invalidación de Graphiti corren
*dentro* de un `group_id`. Si María y Juan creen cosas distintas, o están en particiones distintas —y
entonces la contradicción no se detecta nunca— o están en la misma —y sus creencias se funden sin
noción de quién dijo qué—. Ninguna de las dos es un cerebro de empresa.

**2. No hay recuperación sensible a permisos.** No hay ACL en el motor de Graphiti ni en el de Mem0
*(los aciertos de `grep` por "permission" eran cabeceras de licencia Apache y parámetros IAM de SDKs
cloud)*. Supermemory es el único con control de acceso, pero es **autorización sobre el contenedor, no
sobre el conocimiento**: una API key está o no autorizada en un tag, y una petición fuera de su
conjunto devuelve `403`. Eso es scoping de claves, no *"María puede ver este hecho y Juan no"*. Y es
solo Enterprise.

> Consecuencia directa: un company brain sobre una partición compartida **es una máquina de fugas**;
> sobre particiones por persona **no es un company brain**. **Ninguno de los tres tiene término medio.**

**3. No hay autoridad ni procedencia entre actores.** Nadie modela que lo que afirma el CFO sobre el año
fiscal pesa más que la suposición de un becario. Sin eso no se puede resolver una contradicción: solo se
puede detectar.

Nota de honestidad: esto es la superficie abierta y documentada. Zep Cloud y Supermemory Enterprise
podrían hacer más de lo visible — aunque la propia tabla de Enterprise de Supermemory anuncia
*"autenticación y controles de acceso para toda la organización"*, que sigue siendo cuenta, no semántica
del conocimiento. Y las "Organizations" de su consola gestionan, en sus palabras, *"miembros, claves y
separación de facturación"*.

**Y la contracautela que hay que sostener:** que nadie lo haya construido puede significar que es
difícil… o que nadie lo quiere. Es exactamente la apuesta 2 del §8, y sigue sin validar.

## 5. Por qué no lo ganan los que ya están

| Quién | Por qué no |
|---|---|
| **Mem0 / Zep / Supermemory** | Componentes vendidos a un dev para una app. Sin posición en el runtime empresarial, sin política, sin comprador de seguridad. Tendrían que convertirse en una empresa de seguridad. |
| **Jedify / Modus / Snowflake** | Lado del dato. Modelan el significado; no pueden impedir una acción. Tendrían que convertirse en un proxy en el path. |
| **OpenAI / Anthropic** | Nunca harán que su conocimiento funcione mejor en el competidor. Estructuralmente incapaces de ser neutrales. |
| **Glean** | Indexa documentos que ya existen, no creencias que los agentes generan. Y se está convirtiendo en una app, no en un plano. |
| **Palo Alto / Portkey** | Tienen el plano, sin semántica. Pueden comprarla — es el riesgo real, y es el argumento para moverse ya. |

---

## 6. El wedge que demuestra la tesis

Una tesis grande sin cuña estrecha es como mueren las empresas. Segment no lanzó "la categoría CDP":
lanzó **un `<script>`**. El nombre de la categoría llegó después, y se lo quedaron ellos.

**La cuña propuesta: el informe de contradicciones.** → diseño completo en [`contradiction-report.md`](contradiction-report.md)

> *"Tus agentes se contradicen entre sí. Aquí están los 40 sitios donde pasa."*

- Se genera con el tráfico que **ya** pasa por un gateway, o con tres exports. **Coste cero para el cliente.**
- Tiene forma de **informe de seguridad**, que es exactamente lo que NeuralTrust ya sabe vender y lo que
  el comprador ya sabe leer.
- Es **alarmante y compartible**: se reenvía solo dentro de la empresa.
- **No se puede producir sin el plano** → el propio informe demuestra la necesidad.
- Y el remedio —resolver las contradicciones y hacer cumplir la resolución en todas las superficies— **es
  el producto de pago**.

Y encaja con el bottom-up: un dev puede apuntarlo a los agentes de su propio equipo sin pedirle permiso
a nadie. El data flow de correcciones que diseñamos es el mecanismo de captura que lo alimenta.

---

## 7. La escalera

```
Informe de contradicciones   →  Resolución        →  Distribución        →  Atestación
gratis · viral · sin compra     (creencias)          (+ restricciones)      (auditoría)
"vuestras IAs no concuerdan"    "una sola verdad"    "vinculante en todas"  "demuéstralo"
        ↑                              ↑                     ↑                    ↑
   entra por el dev            valor de equipo        valor de empresa      valor de regulador
```

Cada peldaño se paga solo y hace inevitable el siguiente. En ningún punto hace falta empezar pidiendo
una Compliance Access Key.

---

## 8. Lo que hay que creerse para que esto sea verdad

Honestamente, tres apuestas. Si alguna falla, la tesis se cae:

1. **Que las empresas acaben operando agentes de varios proveedores a la vez**, y no consolidando en uno.
   *(Si consolidan, el proveedor se come esta capa.)*
2. **Que la contradicción entre agentes se convierta en un dolor sentido y costoso**, no en una molestia
   teórica. *(Es lo primero que hay que validar, y el informe de contradicciones es a la vez la
   validación y el producto.)*
3. **Que reconciliar creencias en lenguaje natural sea lo bastante difícil como para ser un foso** — pero
   lo bastante posible como para construirlo. *(Es el riesgo técnico central.)*

Y un riesgo de ejecución que no es menor: **el peligro de una tesis grande es construir la plataforma
primero.** El marco sirve para decidir a qué decir que no. Lo que se construye el lunes sigue siendo
estrecho.

---

## 9. Fuentes

- [Inconsistencia de contexto como causa principal de fallo multiagente](https://atlan.com/know/multi-agent-system-orchestration/) · [Arquitectura en cuatro capas: control plane y context layer](https://atlan.com/know/ai-agent/ai-platform-architecture/) · [Qué es una context layer para agentes](https://atlan.com/know/context-layer-for-ai-agents/)
- [1.600 agentes por empresa y el hueco de gobierno](https://beam.ai/agentic-insights/ibm-says-enterprises-will-run-1600-ai-agents-by-year-end-70-cant-govern-the-ones-they-have) · [Gobierno de respuestas de agentes y contradicciones](https://www.egain.com/blog/how-to-govern-ai-agent-responses-a-2026-guide-for-cx/) · [Playbook de gobierno de datos para agentes](https://promethium.ai/guides/ai-agent-data-governance-enterprise-playbook-2026/)
- [Jedify levanta $24M Serie A para la context layer](https://www.calcalistech.com/ctechnews/article/bkcksmp11gx) · [Modus sale de stealth con $10M (Insight Partners) para el "context warehouse"](https://thenextweb.com/news/modus-10m-seed-insight-partners-context-warehouse-enterprise-ai) · [La context layer en Snowflake Summit](https://siliconangle.com/2026/06/04/enterprise-context-layer-snowflakesummit/)
- [Orquestación multiagente dirigida por eventos (arXiv 2606.20058)](https://arxiv.org/pdf/2606.20058) · [Control de concurrencia en sistemas multiagente (arXiv 2606.15376)](https://arxiv.org/pdf/2606.15376) · [Gobierno en runtime para agentes (arXiv 2603.16586)](https://arxiv.org/pdf/2603.16586)

> Las cifras de sector (1.600 agentes, $492M, 50%, 60%) proceden de proyecciones de analistas y de
> proveedores citados de segunda mano. Sirven para dimensionar la tendencia, **no para una nota de prensa
> sin verificación propia**.
