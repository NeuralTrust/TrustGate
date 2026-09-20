# El informe de contradicciones

> Cuña de entrada y, a la vez, instrumento para validar la apuesta 2 de
> [`knowledge-gateway-thesis.md`](knowledge-gateway-thesis.md): *¿duele de verdad que los agentes se
> contradigan, o es una molestia teórica?*

---

## 1. La decisión de diseño que lo cambia todo: es un escáner, no un dashboard

La tentación es construir analítica: ingerir tráfico, acumular, detectar contradicciones a posteriori.
**Eso es lento, necesita permisos y toca datos de empleados** — es decir, arrastra los tres problemas de
fricción que identificamos (admin, comité de empresa, cold start).

La alternativa: **no observar, preguntar.** Le haces la misma pregunta a todas las superficies de IA de
la empresa y comparas las respuestas. Como un escaneo de vulnerabilidades.

| | Analítica de tráfico | **Escáner activo** |
|---|---|---|
| Tiempo hasta el primer resultado | Semanas de acumulación | **Minutos** |
| Permisos | Claves de admin, Compliance API | **Acceso a los agentes, nada más** |
| Datos de empleados | Los lee | **No los toca** → sin DPIA, sin comité de empresa |
| Cold start | Sí | **No** |
| Reproducible | No | **Sí** — se vuelve a pasar y se compara |
| Competencia existente en NeuralTrust | Parcial | **Total: es la forma de un red team** |

Esto elimina de un plumazo la fricción más grave del proyecto. **Y es exactamente la forma de producto
que NeuralTrust ya sabe construir y ya sabe vender.**

---

## 2. Dos tipos de contradicción, con costes distintos

**Tipo A · Entre lo que a los agentes se les *dice*** (estático, sin tráfico).
Comparar system prompts, bases de conocimiento, corpus RAG, descripciones de herramientas MCP,
`CLAUDE.md`, `.cursor/rules`, documentación de producto.
> *El prompt del agente de soporte dice 30 días de devolución. El KB del de ventas dice 60.*

Se analiza sin ejecutar nada. Es el suelo del informe y ya produce hallazgos el día 1.

**Tipo B · Entre lo que los agentes *responden*** (conductual, mediante sondeo).
Misma pregunta a N superficies, comparación de respuestas. Es donde aparecen las contradicciones que
*ninguna* revisión de configuración habría encontrado, porque emergen del modelo, del retrieval o del
orden de las fuentes.

**Tipo B-bis · El agente contra sí mismo.** La misma pregunta, tres veces, al mismo agente.
La inestabilidad temporal es más alarmante que el desacuerdo entre agentes, y **no requiere más que un
agente** — es la versión que puede correr un dev solo.

---

## 3. De dónde salen las preguntas

Por orden de calidad:

1. **Derivadas de las propias fuentes de cada agente.** Extraer afirmaciones de cada system prompt,
   corpus y documento; convertir cada afirmación en pregunta. *"El plazo de devolución es 30 días"* →
   *"¿Cuál es nuestro plazo de devolución?"*.
   Ventaja doble: las preguntas son específicas de la empresa **y traes la procedencia gratis** — sabes
   qué fuente sostiene cada respuesta antes de preguntar.
2. **Derivadas del tráfico real**, si la empresa ya pasa por el gateway: agrupar las consultas reales y
   priorizar las frecuentes. No genera preguntas nuevas: **ordena** las del punto 1 por impacto.
3. **Catálogo de categorías de alto riesgo**, como suelo cuando no hay ni fuentes ni tráfico:
   precios y descuentos · plazos y SLA · devoluciones y cancelaciones · elegibilidad y aprobaciones ·
   tratamiento y retención de datos · postura de seguridad · afirmaciones legales o regulatorias ·
   límites y capacidades del producto.

Esas ocho categorías no son arbitrarias: son las respuestas que **constituyen un compromiso**. Ahí una
contradicción cuesta dinero o crea responsabilidad legal.

---

## 4. El estándar de detección (aquí se gana o se pierde la credibilidad)

**El riesgo número uno del producto son los falsos positivos.** Dos respuestas pueden diferir en redacción
y coincidir en fondo. Un informe con 200 hallazgos ruidosos vale menos que uno con 12 innegables.

Regla: **solo se reporta lo mutuamente excluyente.** Las dos afirmaciones no pueden ser ciertas a la vez.

| Se reporta | No se reporta |
|---|---|
| `30 días` vs `60 días` | `30 días` vs `un mes` |
| `Sí, cubre X` vs `No, no cubre X` | Una responde con más detalle que la otra |
| `Los datos se borran` vs `se retienen 2 años` | Diferencias de tono, formato o longitud |
| `Requiere aprobación` vs `no la requiere` | Una se abstiene y la otra responde |

Clasificación de cada hallazgo:
- **Contradicción** — mutuamente excluyentes. *Es lo único que va en la portada.*
- **Obsolescencia** — una es una versión anterior de la verdad (detectable si las fuentes tienen fecha).
- **Laguna** — una superficie no sabe algo que otra sí. No es contradicción, pero es señal de
  distribución desigual del conocimiento.
- **Abstención asimétrica** — una se niega a responder y otra no. Es un hallazgo de *política*, no de
  conocimiento, y suele interesar mucho al comprador de seguridad.

Cada hallazgo se acompaña de **las dos respuestas literales**. Sin verbatim no hay informe.

---

## 5. Severidad

No todo desacuerdo importa. Cuatro ejes:

| Eje | Pregunta | Peso |
|---|---|---|
| **Exposición** | ¿Alguna de las superficies habla con clientes o con el exterior? | El más alto |
| **Compromiso** | ¿La respuesta constituye una promesa — precio, plazo, elegibilidad, afirmación legal? | Alto |
| **Confianza** | ¿Ambas respondieron con seguridad, sin matizar? | Medio — el desacuerdo confiado es peor que el dubitativo |
| **Frecuencia** | ¿Con qué asiduidad se pregunta esto? *(solo si hay tráfico)* | Modula |

Lo que va en la portada del informe: **contradicciones, confiadas, sobre compromisos, en superficies
externas.** El resto va en el anexo.

---

## 6. Anatomía del informe

**Portada — un número que aterrice:**
> *De 140 preguntas, **27 obtuvieron respuestas incompatibles** entre tus 6 superficies de IA.
> **9 de ellas son compromisos con el cliente.***
>
> **Índice de coherencia: 81%**

El índice de coherencia es deliberado: **es un número que van a querer subir.** Convierte un susto
puntual en una métrica recurrente, y una métrica recurrente en una suscripción.

**Por hallazgo:**

```
┌ CRÍTICO · compromiso con cliente · alta confianza en ambos
│
│ "¿Cuál es el plazo de devolución?"
│
│  Agente de soporte (cliente)   →  "30 días desde la entrega."
│  Asistente de ventas (cliente) →  "60 días, sin preguntas."
│
│ Procedencia
│   soporte : kb/politica-devoluciones.md, actualizado 2026-03-14
│   ventas  : system prompt del asistente, sin fecha, sin dueño
│
│ Por qué pasa
│   No hay una sola fuente para este hecho. Cada superficie tiene su copia,
│   y una de ellas se actualizó en marzo.
└
```

**La procedencia es la mitad del valor.** Sin ella el informe produce alarma; con ella produce una
acción. Y, sobre todo, **demuestra la tesis**: el arreglo no es editar dos prompts —eso vuelve a
divergir en un mes— sino tener un sitio donde ese hecho viva una sola vez.

**Cierre:** cuántos hallazgos se resolverían con una sola fuente compartida, y cuáles necesitan una
decisión humana porque nadie sabe cuál es la respuesta correcta. *Ese segundo grupo suele ser el que más
inquieta.*

---

## 7. La versión bottom-up (un dev, un comando)

```
npx trustgate coherence
```

Sin cuenta, sin admin, sin tarjeta. Apunta a lo que ese dev ya tiene:
- Su agente (o sus agentes) de desarrollo
- El `CLAUDE.md` del repo, `.cursor/rules`, el README, los ADRs

Y responde dos preguntas incómodas:
1. **¿Tu agente se contradice a sí mismo?** (misma pregunta ×3)
2. **¿Tu agente contradice tu propia documentación?**

> *"Tu agente contradice el README en 12 sitios."*

Eso es verificable en un minuto, es personal, y es compartible. Es la versión del informe que no necesita
que la empresa exista todavía.

---

## 8. Qué se está midiendo en realidad

El informe es el instrumento del experimento. En 10 empresas, registrar:

| Medida | Qué decide |
|---|---|
| Contradicciones por par de superficies | Si el fenómeno existe |
| **Densidad frente a nº de agentes** | **A partir de cuántos agentes empieza a doler = la definición del ICP** |
| Cuántas son compromisos externos | Si hay riesgo real o solo desorden |
| **Qué hacen al verlo** | **La medida de verdad** |
| Cuántas saben resolver | Si el remedio es vendible |

**Criterio de éxito:** que pidan volver a pasarlo, o que pregunten cómo evitar que vuelva a ocurrir.

**Criterio de kill:** que miren 30 contradicciones —con compromisos de cara al cliente incluidos— y se
encojan de hombros. Si eso pasa en la mayoría, la apuesta 2 es falsa y hay que parar. Es una prueba
barata, rápida y difícil de auto-engañarse, que es justo lo que se necesita.

---

## 9. Riesgos del diseño

1. **Falsos positivos.** Mata la credibilidad en la primera reunión. Mitigación: el estándar estricto del
   §4, verbatim siempre, y preferir 12 innegables a 200 ruidosos.
2. **Sondear agentes en producción cuesta dinero y puede parecer un ataque.** Consentimiento explícito,
   throttling, preferencia por entornos de staging, ventana acordada. NeuralTrust ya tiene este protocolo
   del red teaming.
3. **"¿Y ahora qué?"** Un informe sin remedio es solo ansiedad, y la ansiedad no se renueva. El informe
   tiene que terminar en un camino de resolución.
4. **Puede salir casi limpio** en empresas pequeñas u ordenadas. Entonces el producto solo funciona
   arriba, lo que choca con el bottom-up. **No es un fallo del experimento: es su resultado más
   informativo** — dice dónde está el suelo del mercado.
5. **Nadie sabe cuál es la respuesta correcta.** En muchos hallazgos no habrá autoridad. Es incómodo en
   la demo y es, a la vez, la mejor prueba de que hace falta un sistema de registro.

---

## 10. Lo mínimo para salir a validar

| Pieza | Esfuerzo |
|---|---|
| Extractor de afirmaciones desde prompts, KBs y docs | Bajo — un LLM con salida estructurada |
| Generador de preguntas a partir de afirmaciones | Bajo |
| Ejecutor de sondeo multi-superficie | **Ya existe**: TrustGate enruta a 9+ proveedores; el plano MCP enumera herramientas |
| Juez de contradicción con estándar estricto | Medio — **aquí está la calidad del producto** |
| Puntuación de severidad | Bajo — reglas, no modelo |
| Render del informe | Bajo |

No hace falta almacén de creencias, ni reconciliación, ni sincronización, ni permisos. **Todo eso viene
después de saber si a alguien le importa.**
