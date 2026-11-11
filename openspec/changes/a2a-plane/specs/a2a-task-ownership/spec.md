# Delta para a2a-task-ownership

Cambio `a2a-plane`. Capability nueva: el gateway liga cada tarea y cada contexto A2A a quien los creó. El agente ve a todos los que llaman a través del gateway con la misma credencial, así que no puede separarlos. Sin este ligado, quien conoce un task id ajeno puede leer o cancelar esa tarea.

## ADDED Requirements

### Requirement: Quién es el dueño

El dueño de una tarea o de un contexto MUST ser el par (consumer, sujeto del principal) que fija `a2a-agent-plane`:

- el `sub` del IdP;
- `EndUserSubject` para un usuario nombrado por la aplicación;
- `AppSubject` para la aplicación misma.

Dos keys de la misma aplicación sin usuario comparten, por tanto, sus tareas. Dos usuarios de la misma aplicación, no.

#### Scenario: Dos usuarios con la misma app

- GIVEN un consumer A2A cuya aplicación nombra a dos usuarios, U1 y U2, con `X-NeuralTrust-End-User`
- WHEN U1 crea una tarea
- THEN su dueño es (consumer, U1), y U2 no es su dueño

### Requirement: El gateway registra la propiedad al verla

Cuando una respuesta o un evento de streaming del agente trae un `taskId` o un `contextId` que el gateway no tiene registrado para ese registry, MUST registrarlo con el dueño de la llamada, en Redis, con TTL `A2A_TASK_OWNERSHIP_TTL` (por defecto 7 días). Cada llamada que lo use MUST renovar el TTL.

Si el agente devuelve un `taskId` o `contextId` ya registrado con otro dueño, MUST NOT entregarse esa respuesta: MUST responder `-32092`, registrar el conflicto y cancelar el stream si lo hay.

Si Redis no puede escribir, la respuesta MUST entregarse igualmente (quien llama ya la tiene) y MUST quedar un log y una métrica. Las llamadas posteriores sobre esa tarea fallarán cerradas según el requisito siguiente.

#### Scenario: Primera respuesta con tarea

- GIVEN un `message/send` de U1 al que el agente responde con una Task `t1` en el contexto `c1`
- WHEN el gateway entrega la respuesta
- THEN `t1` y `c1` quedan registrados para (consumer, U1)

### Requirement: Solo el dueño usa una tarea o un contexto

Antes de llamar al agente, el gateway MUST comprobar el dueño:

- del task id de `tasks/get`, `tasks/cancel`, `tasks/resubscribe`, `GetTask`, `CancelTask` y `SubscribeToTask`;
- del `taskId` y del `contextId` del mensaje de `message/send`, `message/stream`, `SendMessage` y `SendStreamingMessage`, cuando los lleva.

Si el dueño registrado es otro, o no hay ninguno registrado, MUST responder `TaskNotFoundError` de la versión, sin llamar al agente. Esto vale igual para un task id y para un `contextId`. Los dos casos MUST ser indistinguibles para quien llama. Un mensaje que empieza una conversación nueva no lleva `contextId`: el agente lo genera y el gateway lo registra al verlo. Aceptar un `contextId` desconocido permitiría reclamar uno ajeno cuya entrada caducó.

Si Redis no puede leer, MUST responder `-32092` sin llamar al agente.

#### Scenario: Lectura de una tarea ajena

- GIVEN `t1`, propiedad de (consumer, U1)
- WHEN U2 llama a `tasks/get` con `t1`
- THEN `TaskNotFoundError`, igual que para un id que no existe, y el agente no recibe nada

#### Scenario: Continuar en un contexto ajeno

- GIVEN `c1`, propiedad de (consumer, U1)
- WHEN U2 envía `message/send` con `contextId: c1`
- THEN `TaskNotFoundError`, y el agente no recibe nada

#### Scenario: Tarea caducada

- GIVEN `t1`, cuya propiedad caducó en Redis
- WHEN U1 llama a `tasks/get` con `t1`
- THEN `TaskNotFoundError`

#### Scenario: Redis caído

- GIVEN Redis no responde
- WHEN U1 llama a `tasks/cancel` con `t1`
- THEN `-32092`, y el agente no recibe nada
