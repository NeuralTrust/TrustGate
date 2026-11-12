# Delta para a2a-whoami-agents

Cambio `a2a-plane`. Capability nueva: `GET /whoami` le dice a quien tiene una key qué agentes alcanza y dónde están sus cards. Así el SDK y cualquier cliente encuentran los agentes sin que nadie les pase una URL a mano.

## ADDED Requirements

### Requirement: Un consumer A2A en whoami

Para cada consumer A2A que alcanza la key, `GET /whoami` MUST devolver en `consumers[]`:

- `type: "A2A"`;
- `url`: `https://{gateway_slug}.{AGENT_BASE_DOMAIN}/{slug}/agents`, el host del plano agent (`a2a-agent-plane`), aunque `/whoami` se sirva en el host MCP;
- `agents`: la lista de sus registries A2A habilitados, ordenada por nombre.

Cada elemento de `agents`:

```json
{
  "id": "0192…",
  "name": "Travel planner",
  "card_url": "https://gw-x.agents.example.com/research-bot/agents/0192…/.well-known/agent-card.json",
  "protocol_version": "1.0"
}
```

`card_url` MUST ser la URL del card en el gateway, nunca la del agente. Un consumer A2A sin agentes habilitados MUST devolver `agents: []`. Los consumers LLM y MCP MUST NOT cambiar: no llevan `agents`.

Si `AGENT_BASE_DOMAIN` no está definido en el plano que sirve `/whoami`, un consumer A2A MUST aparecer sin `url` y con `agents: []`, en lugar de inventar un host.

`/whoami` se sigue sirviendo donde está hoy (plano MCP, con el módulo de consumers). Servirlo también en el plano agent queda fuera de este cambio.

#### Scenario: Aplicación con tools y agentes

- GIVEN una key adjunta a un consumer MCP y a un consumer A2A con dos agentes habilitados
- WHEN se llama a `GET /whoami`
- THEN `consumers` trae los dos; el MCP sin `agents`, y el A2A con `agents` de dos elementos cuyos `card_url` apuntan al host de agents

#### Scenario: Agente deshabilitado

- GIVEN un consumer A2A con un agente habilitado y otro deshabilitado
- WHEN se llama a `GET /whoami`
- THEN `agents` trae solo el habilitado
