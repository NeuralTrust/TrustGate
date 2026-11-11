# Delta para a2a-delegated-identity

Cambio `a2a-plane`. Capability nueva: cómo le dice el gateway a un agente para quién es cada llamada. Reutiliza el STS que ya usa el plano MCP (`pkg/app/identity/sts`): el gateway firma un JWT propio, o pide a un IdP un token del usuario. La cadena entre agentes (un agente que reenvía su token al gateway) no entra en este cambio.

## ADDED Requirements

### Requirement: Modos de identidad de un registry A2A

Un registry A2A con `auth.mode: "exchange"` MUST llevar `pattern`:

| `pattern` | Qué recibe el agente | Requiere |
|---|---|---|
| `delegation` | Un JWT firmado por el gateway (requisito siguiente) | Nada más: vale con usuario o sin él |
| `obo` | Un token del IdP Entra para el usuario, obtenido on-behalf-of | Un principal autenticado por un IdP de Entra que el gateway conoce |
| `token_exchange` | Un token del IdP obtenido por RFC 8693 | Un principal autenticado por un IdP con token exchange |

`impersonation` MUST responder 422 en un registry A2A: oculta qué aplicación actúa.

`audience` es opcional. Por defecto MUST ser el endpoint JSON-RPC fijado del agente, el que el gateway llama.

Para `obo` y `token_exchange`, los campos que fijan el IdP (`identity_id`, `scope` y los que ya acepta `MCPAuth` para esos patrones) MUST validarse igual que en un registry MCP. El campo `actor` de `MCPAuth` MUST ignorarse en A2A, porque el actor es siempre la aplicación que llama.

#### Scenario: Impersonation rechazado

- WHEN se crea un registry A2A con `auth: {"mode": "exchange", "pattern": "impersonation"}`
- THEN 422 que explica que el agente debe saber qué aplicación actúa

### Requirement: El token de delegación

Con `pattern: "delegation"`, cada llamada al agente MUST llevar `Authorization: Bearer <jwt>`, firmado por el `TokenSigner` del gateway. Sus claims:

| Claim | Valor |
|---|---|
| `iss` | El emisor del STS del gateway |
| `aud` | `auth.audience`, o por defecto el endpoint fijado |
| `sub` | Según el principal de la llamada (`a2a-agent-plane`): el `sub` del JWT del IdP, si lo autenticó un IdP; `EndUserSubject(consumer, usuario)`, si la aplicación lo nombró con `X-NeuralTrust-End-User`; `AppSubject(consumer)` (`app:<consumer_id>`), si no hay usuario |
| `act` | `{"sub": "app:<consumer_id>"}` cuando `sub` es un usuario. Se omite cuando `sub` ya es la aplicación. |
| `orig_iss` | El emisor del IdP cuando el principal lo autenticó un IdP. Se omite cuando el usuario lo nombra la aplicación, de modo que el agente distingue una identidad verificada de una afirmada. |
| `scope` | Los scopes del principal, si tiene |
| `iat`, `exp` | Los que pone el STS, con su TTL por defecto |

MUST NOT incluir email, nombre ni grupos.

El token MUST cachearse por (registry, sujeto, audiencia) y renovarse antes de caducar, como hace el STS con MCP.

El plano agent MUST servir `/.well-known/jwks.json` con las mismas claves que el plano MCP. Eso exige una clave compartida entre pods: `STS_SIGNING_KEY`, o la clave compartida en Redis que ya usa producción.

Si el plano agent arranca con una clave efímera, MUST avisar en el log de arranque, y un registry con `delegation` MUST responder `-32092` con `reason: "signing_key_unavailable"`. Así nunca firma un token que otro pod no sabría verificar.

#### Scenario: Usuario del IdP de la organización

- GIVEN un consumer A2A cuya aplicación llama con el JWT de Entra de la usuaria `u-42`, y un registry con `delegation`
- WHEN llama a `message/send`
- THEN el agente recibe un JWT con `sub` el de `u-42`, `act.sub: "app:<consumer_id>"`, `orig_iss` el emisor de Entra, y `aud` igual a su endpoint, verificable con el JWKS del gateway

#### Scenario: Usuario nombrado por la aplicación

- GIVEN una aplicación que llama con su API key y `X-NeuralTrust-End-User: user_123`
- WHEN llama a `message/send` contra un registry con `delegation`
- THEN el agente recibe `sub: "app:<consumer_id>:user_123"`, `act.sub: "app:<consumer_id>"`, y ningún `orig_iss`

#### Scenario: Aplicación sin usuario

- GIVEN una aplicación que llama solo con su API key, y un registry con `delegation`
- WHEN llama a `message/send`
- THEN el agente recibe un JWT con `sub: "app:<consumer_id>"`, sin `act` ni `orig_iss`

### Requirement: OBO y token exchange necesitan un usuario del IdP

Con `obo` o `token_exchange`, el gateway MUST obtener el token del IdP con el principal de la llamada, por el mismo camino que usa MCP para esos patrones. Si la llamada no tiene un principal autenticado por un IdP válido para el registry, MUST responder `-32093` con `reason: "identity_required"`, sin llamar al agente. Esto incluye una aplicación sin usuario o un usuario nombrado por la aplicación.

Si el IdP rechaza el intercambio, MUST responder `-32092` con `reason: "identity_exchange_failed"`. MUST NOT reintentar con otra credencial.

#### Scenario: OBO sin usuario

- GIVEN un registry con `obo` y una aplicación que llama solo con su API key
- WHEN llama a `message/send`
- THEN `-32093`, y el agente no recibe nada

### Requirement: Qué queda en la traza

El span `a2a` MUST registrar el modo (`none`, `static`, `client_credentials`, `delegation`, `obo`, `token_exchange`) y el tipo de sujeto (`user` o `app`). MUST NOT registrar el token ni el sujeto completo.

#### Scenario: Traza de una delegación

- GIVEN una llamada con `delegation` de un usuario
- WHEN se emite el span
- THEN lleva `identity_mode=delegation` e `identity_subject_kind=user`, y no lleva el JWT
