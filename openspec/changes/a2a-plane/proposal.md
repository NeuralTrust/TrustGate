# Proposal: A2A plane MVP

Linear: pending (no issue yet). Repos: TrustGate (Go) and app (Next.js console). Base branch: `develop` in both.
Exploration: [`exploration.md`](./exploration.md).

## Intent

TrustGate reserves A2A as a plane (consumer type, plugin protocol, span type, policy semantics) but serves no A2A traffic, while the README sells it as shipped. This change makes an A2A consumer usable: an admin registers an A2A agent, attaches it to an A2A consumer with policies, and callers reach the agent only through the gateway.

The aim is not parity with LiteLLM's breadth (protocol bridges, many agent backends). It is the part a security gateway should own and LiteLLM leaves open: every method inspected or refused, tasks bound to the caller that created them, and an agent card that cannot change under clients without an admin approving it.

Ship the MVP behind real demand: validate with two or three customers running A2A agents before taking on the follow-ups listed under Out of scope.

## Scope

### In scope

#### TrustGate

**Registry and admin**

- New registry type `A2A` with an `a2a_target`: `card_url`, `protocol_version` (`"0.3"` or `"1.0"`; when omitted, detected from the card: 1.0 if it offers it, else 0.3), optional `url` override, static `headers` (encrypted like MCP headers), `auth` (reusing `MCPAuth`, modes `none`, `static` and `client_credentials` only), optional `allowed_methods`, and read-only `card`, `card_digest` and `card_pinned_at`.
- Migration: `registries_type_check` accepts `'A2A'`.
- **Card pinning.** On create (and on an update that changes `card_url` or `protocol_version`) the admin plane fetches the card through `netguard`, validates it against the pinned version, and stores it with a digest. The data plane serves and routes from the pinned copy only.
- `POST /v1/gateways/{gw}/agent-cards/preview` with `{card_url}` fetches a card under the same rules and returns it, its digest and the wire versions it offers, without writing anything. The console's add panel shows the card before anything is stored.
- `POST /v1/gateways/{gw}/registries/{id}/agent-card/refresh` fetches the live card and reports whether it changed and which top-level fields differ. It writes nothing.
- `POST /v1/gateways/{gw}/registries/{id}/agent-card/approve` with `{digest}` re-fetches the card and pins it only if it still has that digest (409 otherwise).

**Data plane (on the MCP plane, `:8082`)**

- After `MatchPath`, an A2A consumer is handed to a new A2A handler instead of the MCP 404.
- `GET /{consumer}/agents/{agent}/.well-known/agent-card.json` serves the pinned card, rewritten: the interface URL points at the gateway, security schemes are the gateway's, push notifications and the extended card are switched off, upstream signatures are dropped. It requires the same credential as a call.
- `POST /{consumer}/agents/{agent}` forwards JSON-RPC 2.0 to the agent in the pinned wire format. No translation between 0.3 and 1.0.
- `{agent}` is the registry id, or its name when exactly one A2A registry of the consumer has it.
- **Every method is either inspected or refused.**
  - Inspected:
    - `message/send` and `SendMessage`: request and response.
    - `message/stream` and `SendStreamingMessage`: request, then each content event.
    - `tasks/resubscribe` and `SubscribeToTask`: each content event.
    - `tasks/get` and `GetTask`: response.
  - Forwarded without content to inspect, after the ownership check: `tasks/cancel` and `CancelTask`.
  - Refused in the MVP with the A2A error the spec defines: push-notification config, the extended card, and `ListTasks`.
- **Task ownership.** The gateway records which caller created each task and context, in Redis. A call that names a task or context owned by another caller gets `TaskNotFoundError`, the same answer as for a task that does not exist.
- Upstream request: gateway credentials per `auth`, static headers, `A2A-Version` set to the pinned version, and `X-AG-Trace-Id`. The caller's credentials and `X-AG-*` headers are never forwarded.
- Gateway-owned JSON-RPC error codes in `-32090…-32099`, so they never collide with A2A's `-32001…-32007`.

**Policies**

- `ratelimit`, `requestsize` and `trustguard` declare `A2A`. `trustguard_v2` shares the implementation but does not declare `A2A` while its engine skips `a2a`, so attaching it to an A2A consumer answers 422 instead of accepting a policy that inspects nothing.
- Fix: `validatePolicyProtocol` validates A2A consumers. An LLM-only plugin answers 422 instead of attaching silently.
- An A2A consumer's plan excludes plugins that do not declare `A2A`, global policies included. LLM and MCP plans are not changed by this change.
- TrustGuard reads A2A content through a normalised parts payload: text and data become text, URLs become attachments, and raw bytes become attachments up to the existing cap.
- On A2A, a **mask** verdict blocks. The gateway cannot rewrite parts yet, and blocking never leaks what the guard wanted hidden.

**Observability and docs**

- One `a2a` span per JSON-RPC call (registry, agent, method, wire version, task id, context id, final task state, upstream status, block reason). New telemetry attributes follow `telemetry-event-contract.mdc`: additive only, in the schema descriptor.
- `docs/a2a.md`, plus README FAQ and comparison table rewritten to describe what ships.

#### app (console)

Audited at `origin/develop` @ `1fb4d0be`; paths are under `app/[locale]/v2/features`. The console already carries A2A in its types (`RegistryType`, `ConsumerProtocol`, `PolicyProtocol`, `GatewayProtocol`), copy (`v2Registry.tabs.a2a`, `actions.addA2a`, `card.descriptionA2a`), and topology node kinds. Registry even fetches A2A rows (`useRegistryScreen.ts`), but `REGISTRY_TABS` does not render the tab. What is missing is the plane in Applications: `PLANES = ['MCP', 'LLM']` (`applications/types.ts:4`).

The product rule is the applications model's (`TrustGate/docs/applications-model.md`, which leaves A2A open in §10): agents are a third plane, called **Agents**, next to Tools and Models. Nobody is asked "A2A or not". The plane is born when the first agent is added, and the Application's keys reach it like the others.

- **Registry → Agents tab.** Render the existing `a2a` tab, labelled *Agents*.
  - **Add agent** side panel: card URL → preview (name, description, skills, versions offered, the auth the agent asks for) → name, wire version (preselected), and how the gateway signs in to the agent (none, static header, OAuth client credentials) → **Pin and add**.
  - **Agent card** section on the agent's detail: the pinned card (skills, version, pinned at), and **Check for changes** (`refresh`), which opens a per-field diff with **Approve new card** (`approve` with the digest) or **Keep current**.
- **Applications.** `PLANES` gains `A2A`, shown as *Agents*.
  - **General:** a third routing section whose rows are agents, with no tool or model sub-selection. Its empty state ("This application calls no other agents through the gateway.") is how the plane is added.
  - **Add modal:** a third tab, *Agents*, picking from registered agents, as servers and providers are picked today.
  - **Connect:** per agent, the card URL (`consumerBaseUrl(connection, 'mcp', slug)` + `/agents/{registry_id}/.well-known/agent-card.json`) and an a2a-sdk snippet that sends `X-AG-API-Key` when it resolves the card.
  - **Policies:** `PLANE_PROTOCOL` gains `A2A`, so a policy lands on the agents consumer only when the catalog's `supported_protocols` lists A2A. TrustGuard says, on agents, that mask blocks.
  - **Auth:** the key's plane chips include Agents.
  - **Analytics:** `consumerIdsOf` includes the agents consumer. Agents are measured in calls, task states, blocks and refused methods, never tokens or cost.
- **Fixes this exposes in the console:**
  - `planeOf` (`applications/lib/groupApplications.ts`) drops any consumer that is not MCP or LLM. Today an A2A consumer created through the API vanishes from Applications, against the model's "no orphans" rule.
  - `slugToProtocols` (`policies/constants/policies.constants.ts`) falls back to LLM + MCP + A2A for most slugs the catalog does not list. With a real A2A plane, that offers policies the gateway refuses with 422. The fallback must not claim A2A.
  - `ApplicationGeneralTab` hard-codes two plane drafts (`plane === 'LLM' ? llm : mcp`), and `AddToApplicationModal` seeds `{ MCP: '', LLM: '' }`. Both go plane-generic.
  - The A2A badge has three colours: dark-yellow in Registry and Activity, yellow in Policies, lila in Topology. Pick one.
  - Requests and Activity leave out the A2A kind filter until traffic exists (ENG-1203). Re-add it.
- **Not shown, because the MVP does not do it:**
  - per-user accounts for agents (the Tools "Accounts for these servers" control has no agent counterpart until delegation);
  - cost per agent;
  - an agent's own model calls inside its trace.

### Out of scope (follow-ups)

| Follow-up | Why later |
|---|---|
| **Delegation identity** (`a2a-delegation-identity`): `exchange`/`obo` upstream auth, a gateway-signed delegation token, parent-trace linking across hops, a max delegation depth, and sub-agent spend rolled into the parent trace | Needs an authenticated hop token (RUN-1138 forbids trusting inbound trace ids). This is the "one trace tree" the README promises, and the strongest differentiator, but it is its own design. |
| Masking A2A parts | Needs a per-part rewrite like `mcp_rewrite.go`. Until then mask blocks (fail closed). |
| Push notifications through a gateway webhook relay with inspection | Without a relay the callback bypasses the gateway entirely. |
| Extended card (`agent/getAuthenticatedExtendedCard`, `GetExtendedAgentCard`) | Depends on per-caller upstream auth, which is the delegation follow-up. |
| `ListTasks` filtered to the caller's tasks | Filtering a paginated upstream list breaks page sizes and tokens. Refused until designed. |
| Verifying upstream card signatures; re-signing the served card with the gateway JWKS | Pinning already stops silent drift. Signatures add provenance, not the MVP's protection. |
| Periodic drift detection with alerts, and an automatic "card changed" badge in the console | Refresh/approve covers it manually; the console shows a **Check for changes** button instead. |
| Protocol bridges (LangGraph, Bedrock AgentCore, Vertex Agent Engine, Foundry) and `/chat/completions` with `a2a/` models | Breadth play with lossy translations and high upkeep. |
| gRPC and HTTP+JSON bindings | JSON-RPC is the binding every SDK speaks. |
| Agent search and discovery, an "Agent Store" like the MCP Store | No demand yet. |
| Per-call pricing on agents | Real cost comes from the delegation follow-up. |
| An `agents` host alias for the data-plane URLs | Ingress only (`k8s/overlays/*` HTTPRoutes, DNS, certificates). Until then agent URLs live on the MCP host. |

## Decisions

| # | Question | Decision |
|---|---|---|
| Q1 | Which plane serves A2A? | The MCP plane, dispatched by consumer type (exploration P1). Moving to its own binary later is a router change. |
| Q2 | Translate between 0.3 and 1.0? | No. Each registry pins one version. A method from the other version answers `-32601`. |
| Q3 | Inspect `tasks/*` too, or only send/stream like LiteLLM? | Every content-bearing response is inspected, and every method that names a task is ownership-checked. Anything else is refused. |
| Q4 | Push notifications | Refused, and `capabilities.pushNotifications` is rewritten to `false`. The callback would bypass the gateway, and its URL is a client-controlled target on the agent's network. |
| Q5 | Upstream auth modes in the MVP | `none`, `static` and `client_credentials`. `passthrough` is refused for good: a caller's token never reaches an agent. `exchange` and `forwarded` come with the delegation follow-up. |
| Q6 | Is the card public? | No. It needs the same credential as a call, and the served `securitySchemes` say how to send it. A2A SDK card resolvers accept extra headers. |
| Q7 | Mask verdict on A2A | Blocks, until part rewriting ships. |
| Q8 | Ownership store and fail mode | Redis, TTL `A2A_TASK_OWNERSHIP_TTL` (default 7 days), refreshed on use. If Redis cannot answer, a method that needs the owner fails closed. A new message keeps its answer and is logged, but its follow-ups fail closed. |
| Q9 | Owner identity | Consumer plus principal subject when the caller has one, else consumer plus auth id. |
| Q10 | Global policies whose plugin lacks A2A | Excluded from A2A plans. The filter is applied to A2A plans only, so LLM and MCP behaviour does not move in this change. |
| Q11 | Card digest | SHA-256 over the card with `signatures` removed, re-marshalled with sorted keys. It is internal and never presented as a JWS. |
| Q12 | Where an agent is registered in the console | The Registry screen's Agents tab, like servers and providers. Applications only pick from registered agents, which is how the add modal already works. |
| Q13 | How the add panel shows a card before it is stored | A new read-only `agent-cards/preview` endpoint. `refresh` needs a registry that already exists. |
| Q14 | Must an admin choose the wire version? | No. `protocol_version` is optional and detected (1.0 when offered, else 0.3). The panel preselects it and lets an admin pin 0.3 when the card offers both. |
| Q15 | How the console knows a card changed | A **Check for changes** button calling `refresh`. There is no automatic badge until the periodic check ships. |
| Q16 | Which host agent URLs use | The MCP host (`mcpHost`), because the plane is the MCP plane. An `agents` alias is an ingress-only follow-up. |
| Q17 | Labels | *Agents* in Applications and Registry. "A2A" appears only as a protocol badge. |

## Open questions (need an owner)

1. **TrustGuard support for `a2a`.** The v2 engine (`trustguard_v2`) skips `a2a` today (`skip_reason=unsupported_protocol`), so this change keeps it off A2A consumers (422). The TrustGuard team must confirm that the v1 service evaluates a payload sent with `protocol: "a2a"` the way it evaluates `llm`, and say when v2 will. If v1 does not, A2A has no content inspection at all. **Blocks GA of inspection, not the slices.**
2. Is an authenticated-only card (Q6) acceptable for the first customers' clients, or do they need an opt-in public card?
3. Linear issue and owner. Delivery is proposed as an integration branch with `size:exception` (see Delivery); confirm.

## Rollout

1. Ship on admin and MCP planes together. An older MCP plane keeps answering 404 to A2A consumers, which is today's behaviour.
2. The migration only widens a CHECK, so it is safe on a live database. Rolling back to an older binary keeps any `A2A` registry rows, which an older binary can neither read nor serve. Before a rollback, list them with `SELECT id, gateway_id, name FROM registries WHERE type = 'A2A'` and delete them through the API, or accept that the A2A consumers they serve go dark.
3. No feature flag: an A2A consumer does nothing until an admin attaches an A2A registry to it.
4. The console's Agents tab (A1) and plane (A2) deploy only after the TrustGate PR is live on admin and MCP planes. An older TrustGate answers 404 to `agent-cards/preview` and 422 to an `A2A` registry, which the console would surface as a failed save.

## Delivery

TrustGate: about 2,700 production and 2,000 test lines, well over the 400-line budget. [`tasks.md`](./tasks.md) splits it into twelve slices on an integration branch (`feat/a2a-plane`) with one final PR to `develop`. Intermediate states (forwarding before ownership and policies land) must never reach an environment, so slices do not merge into `develop` one by one.

app: about 900 production and 450 test lines in four units. A1 (Registry Agents tab) ships after the TrustGate PR is deployed. A2 (the Agents plane in Applications, which also fixes `planeOf`) and A3 (filters, badges) follow. The `slugToProtocols` fix (A0) can ship ahead of everything, since it is wrong today.
