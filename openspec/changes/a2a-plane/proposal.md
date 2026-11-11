# Proposal: A2A agent plane

Linear: pending (no issue yet). Repos: TrustGate (Go) and app (Next.js console). Base branch: `develop` in both.
Exploration: [`exploration.md`](./exploration.md). Design: [`design.md`](./design.md). Tasks: [`tasks.md`](./tasks.md).

## Intent

TrustGate reserves A2A as a plane (consumer type, plugin protocol, span type, policy semantics) but serves no A2A traffic, while the README sells it as shipped. This change ships it: an admin registers an agent, adds it to an application, and the application calls the agent only through the gateway, under policies, with its tasks bound to it, and with the agent told who the call is for.

What TrustGate does that LiteLLM's agent gateway does not (verified against its docs and code, 2026-11-11):

| | LiteLLM | This change |
|---|---|---|
| Methods under policy | `message/send` and `message/stream`; task methods and push config forwarded raw | Every method inspected or refused |
| Task ids across callers | Not bound: one shared upstream credential, the agent cannot tell callers apart | Bound to the caller that created them; anyone else gets `TaskNotFound` |
| Identity sent to the agent | Plain `X-LiteLLM-User-Id` / `X-LiteLLM-Team-Id` headers; JWT signing is MCP-only | A gateway-signed JWT (or an IdP token through OBO) the agent verifies |
| Caller credential | Can be forwarded with `extra_headers` | Never reaches an agent |

Card pinning with a reviewed re-sync is **parity**, not a differentiator: LiteLLM stores the card and re-syncs it with a diff.

Ship the MVP behind real demand: validate with two or three customers running A2A agents before taking on the follow-ups.

## Scope

### In scope — TrustGate

**A new data plane, `agent`**

- `./trustgate agent` boots its own server on its own port and host (`*.agents.<domain>`), like `proxy`, `mcp` and `worker`. It serves A2A consumers only. The proxy and MCP planes keep answering 404 to an A2A consumer and are not otherwise changed.
- It runs DB-less like the other data planes (config snapshot), and has its own Deployment, Service, HTTPRoute, HPA and PDB. **An environment without agent pods serves no A2A at all**, which is how A2A is enabled environment by environment.
- Its host is `{gateway_slug}.{AGENT_BASE_DOMAIN}`. `GET /v1/gateways/{id}` returns `hosts.agent` only when `AGENT_BASE_DOMAIN` is set, which is what tells the console an environment has agents.
- Caller authentication uses the MCP plane's chain resolver, scoped to `/{consumer}/agents/…`, with the same 401/403 rules. It accepts:
  - an API key;
  - mTLS or XFCC;
  - a JWT from the organisation's IdP;
  - an end user named with `X-NeuralTrust-End-User`.

  MCP session tokens and the default IdP stay MCP-only. The MCP auth transport cannot be mounted as it is: it is bound to `/mcp` paths, MCP metrics and MCP error codes.

**Registry and admin**

- Registry type `A2A` with an `a2a_target`:
  - `card_url`: an agent card URL, or the agent's base URL; for a base URL the gateway probes `/.well-known/agent-card.json`, `/.well-known/agent.json` and `/agentCard/v1.0` in that order;
  - `protocol_version`: `"0.3"` or `"1.0"`, optional, detected from the card (1.0 when offered);
  - `url`: optional override of the endpoint the card names;
  - `headers`: static, encrypted at rest like MCP headers;
  - `auth`: `none`, `static`, `client_credentials`, or `exchange` (identity, below);
  - `allowed_methods`: optional narrowing;
  - read-only: `card`, `resolved_card_url`, `card_digest`, `card_pinned_at`.
- `POST /v1/gateways/{gw}/registries/preview-agent-card` (next to `test-connection` and `validate-openapi`) resolves and fetches a card and returns it with its digest and offered versions. It writes nothing.
- `POST /v1/gateways/{gw}/registries/{id}/agent-card/refresh` reports whether the live card changed and which fields. It writes nothing.
- `POST /v1/gateways/{gw}/registries/{id}/agent-card/approve` with `{digest}` pins the live card only if it still has that digest.
- Migration: `registries.a2a_target JSONB` and `registries_type_check` accepting `'A2A'`.

**Agent plane behaviour**

- `GET /{consumer}/agents/{agent}/.well-known/agent-card.json` serves the pinned card rewritten: gateway URL, gateway security schemes, push notifications and the extended card off, upstream signatures dropped. It needs the same credential as a call.
- `POST /{consumer}/agents/{agent}` forwards JSON-RPC 2.0 in the pinned wire format, with no translation between 0.3 and 1.0.
- Every method is inspected, ownership-checked, or refused:
  - send and stream: request, plus the buffered response or each content event;
  - get and subscribe: response or events;
  - cancel: ownership only;
  - push-notification config, extended card and `ListTasks`: refused.
- Task and context ownership in Redis. A task or context of another caller, or an unknown one, answers `TaskNotFoundError`.
- Gateway JSON-RPC errors in `-32090…-32099`, never colliding with A2A's `-32001…-32007`.

**Delegated identity (phase 1)**

- `auth.mode: exchange` on an A2A registry reuses the gateway STS that MCP already uses, with three patterns:
  - `delegation` (recommended): the gateway mints a JWT with `sub` = the end user, `act` = the calling application, and `aud` = the agent;
  - `obo` (Entra) and `token_exchange` (RFC 8693): the agent gets a real IdP token for the user.
- With no end user (an application calling on its own behalf), `delegation` uses `sub = app:<consumer_id>` instead of failing. `obo` and `token_exchange` need an IdP-authenticated user and answer `-32093` otherwise.
- `impersonation`, `passthrough` and `forwarded` are refused on A2A registries.
- Agents verify the token against the gateway's JWKS. An agent that accepts only gateway tokens cannot be called around the gateway.

**Discovery for callers**

- `GET /whoami` lists, for each A2A consumer the key reaches, its agents: id, name, card URL and wire version. The SDK and the console read agents from there, so a caller never has to be handed a URL by hand.

**Policies**

- `ratelimit`, `requestsize` and `trustguard` declare `A2A`. `trustguard_v2` does not while its engine skips `a2a`, so attaching it answers 422.
- Fix: `validatePolicyProtocol` validates A2A consumers.
- An A2A consumer's plan drops plugins without `A2A`, global ones included. LLM and MCP plans are unchanged.
- TrustGuard reads normalised A2A parts. A mask verdict blocks on A2A.

**Observability and docs**

- One `a2a` span per call, with additive telemetry attributes per `telemetry-event-contract.mdc`.
- `docs/a2a.md`, README FAQ and comparison table, and `make docs`.

### In scope — app (console)

- **Registry → Agents tab** (the hidden `a2a` tab, labelled *Agents*):
  - add panel with a URL step, a preview step, and a version and sign-in step, ending in **Pin and add**;
  - agent detail with the pinned card, **Check for changes** (diff, then Approve or Keep), sign-in (including "As the user, signed by TrustGate"), allowed methods, and a "Verify TrustGate's token" box for agent developers (JWKS URL, issuer, audience).
- **Applications → Agents plane**, next to Models and Tools:
  - General: a routing section and its empty state;
  - Connect: card URLs on the agents host, plus an a2a-sdk snippet;
  - Policies: by catalog protocol;
  - key chips;
  - analytics scope.
- **The gateway connection learns the agents host**, next to the proxy and MCP hosts.
- **Fixes:**
  - `planeOf` drops A2A consumers today;
  - `slugToProtocols` claims A2A for slugs the catalog does not list;
  - two-plane literals become maps over `PLANES`;
  - one A2A badge tone;
  - the A2A filters in Requests and Activity (ENG-1203) come back.
- **Not shown, because the MVP does not do it:** per-user agent accounts, cost per agent, chained traces.

### Out of scope (follow-ups)

| Follow-up | Why later |
|---|---|
| **`a2a-delegation-chain`** (phase 2): an agent forwards its token back into TrustGate. It covers the application ↔ agent binding, parent-trace linking, a max delegation depth, budgets per chain, sub-agent spend in the root trace, and group-scoped policies on A2A | It is the real design work behind the README's "one trace tree". It builds on phase 1's token. |
| `forwarded` per-user accounts for SaaS agents with their own OAuth (phase 3) | Wait for a real agent that needs it |
| ID-JAG (Okta cross-app access), `required_claims`-style caller rules, configurable subject mapping | Identity work that spans MCP and A2A |
| Agents as MCP tools (an MCP → A2A bridge for Claude, Cursor and the Store) | Lossy, but likely the most-asked consumption path. It needs its own design. |
| `trustgate-sdk`: `tg.agents()` / `tg.agent(name)` over `whoami.agents[]` | Separate repo. The contract ships here. |
| Masking A2A parts | Needs a per-part rewrite. Mask blocks until then (fail closed). |
| Push notifications through a gateway webhook relay | Without a relay the callback bypasses the gateway |
| Extended card; `ListTasks` filtered to the caller | Per-caller upstream auth, and pagination semantics |
| Card signature verification; re-signing the served card | Pinning already stops silent drift |
| Periodic drift check and an automatic "card changed" badge | **Check for changes** covers it manually |
| Skills curation (hiding skills from the served card) | Cosmetic: A2A messages do not name a skill, so it is not access control |
| Protocol bridges (LangGraph, AgentCore, Vertex, Foundry), `a2a/` models on chat completions, gRPC and HTTP+JSON bindings, agent search, per-call pricing | Breadth with no demand yet |

## Decisions

| # | Question | Decision |
|---|---|---|
| Q1 | Which plane serves A2A? | A new `agent` plane. It leaves the MCP plane untouched, scales on its own (calls last minutes), gets its own host, gates A2A per environment by deployment, and matches the console's three planes. Cost: one more Deployment per environment, and one more pod for hybrid customers who want A2A. |
| Q2 | Translate between 0.3 and 1.0? | No. Each registry pins one version. A method from the other version answers `-32601`. |
| Q3 | Inspect `tasks/*` too? | Every content-bearing response is inspected, and every method naming a task is ownership-checked. The rest is refused. |
| Q4 | Push notifications | Refused, and `capabilities.pushNotifications` is rewritten to `false`. |
| Q5 | Upstream auth modes | `none`, `static`, `client_credentials` and `exchange` (`delegation`, `obo`, `token_exchange`). `passthrough`, `forwarded` and `impersonation` are refused. |
| Q6 | Is the served card public? | No. It needs the same credential as a call, and its `securitySchemes` say how to send it. |
| Q7 | Mask verdict | Blocks, until part rewriting ships. |
| Q8 | Ownership store | Redis, TTL `A2A_TASK_OWNERSHIP_TTL` (7 days) renewed on use. Fails closed when Redis cannot answer. |
| Q9 | Owner identity | Consumer plus principal subject: the IdP `sub`, the end user the application names, or the application itself. Two keys of one application share its tasks; two users never do. |
| Q10 | Globals whose plugin lacks A2A | Dropped from A2A plans only. |
| Q11 | Card digest | SHA-256 of the card without `signatures`, keys sorted. Internal only. |
| Q12 | Where agents are registered in the console | Registry's Agents tab. Applications pick from registered agents, as with servers and providers. |
| Q13 | Card URL or base URL? | Either. A base URL is probed on the three known paths, Foundry's included. |
| Q14 | Must an admin choose the wire version? | No. It is detected and preselected, and can be overridden. |
| Q15 | Approve granularity | All or nothing, by digest. A field-by-field merge would serve a card nobody published. |
| Q16 | `sub` when there is no end user | `app:<consumer_id>` under `delegation`, so an application's own calls still carry a verifiable identity. |
| Q17 | Who `act` names | The calling application (`app:<consumer_id>`), not a configured string. A2A ignores MCP's static `Actor`. |
| Q18 | Labels | *Agents* in the console. "A2A" only as a protocol badge. |
| Q19 | Phase 2 in this change? | No. Phase 1 alone tells the agent who the call is for. The chain needs the application ↔ agent binding and deserves its own design. |

## Open questions (need an owner)

1. **TrustGuard support for `a2a`.** v1 must evaluate `protocol: "a2a"` the way it evaluates `llm`; v2 skips it today. If v1 does not, A2A has no content inspection. **Blocks GA of inspection, not the slices.**
2. Is an authenticated-only card acceptable for the first customers' A2A clients?
3. Agents host names per environment (dev, prod, prod-us, hybrid), DNS and certificates. The platform team owns this.
4. Linear issue and owner. Delivery is proposed as an integration branch with `size:exception`.

## Rollout

1. Merge TrustGate. Admin understands `A2A` registries. In each environment that should serve A2A, three steps, in order:
   1. create DNS and certificates for `*.agents.<domain>`;
   2. deploy the agent plane;
   3. set `AGENT_BASE_DOMAIN` on admin and MCP planes.

   Until step 3, the console offers no agents there.
2. The migration only adds a nullable column and widens a CHECK. Before rolling back to an older binary, delete the `A2A` registries (`SELECT id, gateway_id, name FROM registries WHERE type = 'A2A'`) or accept that the older admin cannot read them.
3. The console ships after the agent plane runs in the environment it targets. It shows the Agents tab only when the gateway connection has an agents host, so an environment without the plane never offers it.

## Delivery

- **TrustGate:** about 3,550 production and 2,650 test lines. Fifteen slices on the integration branch `feat/a2a-plane`, then one PR to `develop` with `size:exception`. Forwarding without identity, ownership and streams must never reach an environment.
- **app:** about 1,200 production and 600 test lines in five units:
  - A0 (policy fallback) can ship now;
  - A1 (gateway connection) ships after `hosts.agent` is deployed;
  - A2 (Registry Agents tab) ships after the admin endpoints are deployed;
  - A3 and A4 ship after the agent plane runs.

See [`tasks.md`](./tasks.md).
