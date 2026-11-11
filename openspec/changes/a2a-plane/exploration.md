# Exploration: a2a-plane

SDD phase: **explore**. Branch `feat/a2a-plane` cut from `origin/develop` @ `de098c6f`. Date: 2026-11-11. Linear: pending.

## Why now

The README already sells A2A as a shipped feature: "multi-protocol gateway engine (LLM, MCP, A2A routing …)" (`README.md:446`) and "any A2A delegation resolve[s] into one unified trace tree" (`README.md:468`). The code reserves the plane but serves no A2A traffic. LiteLLM has shipped an A2A "Agent Gateway" since v1.80.8, so the comparison table in the README is also out of date.

## Current state (verified on develop)

### What exists

| Piece | Where | State |
|---|---|---|
| Consumer type `A2A` | `pkg/domain/consumer/consumer.go:32-41`, `consumers_type_check` in `migrations/20260528113134_create_initial_schema.go:74` | Can be created and listed. |
| Plugin protocol `A2A` | `pkg/app/plugins/protocol.go:27` | Valid value, but **no plugin declares it**. `ratelimit`, `requestsize`, `trustguard`, `toolallowlist` and `pertoolratelimit` declare LLM+MCP; the rest declare LLM only. |
| Span type `a2a` | `pkg/infra/trace/span.go:33` | Never emitted. |
| TrustGuard protocol `a2a` | `pkg/infra/plugins/trustguard/plugin.go:56,1232-1240` | `protocolFor` maps an A2A consumer to `a2a`. The **v2 engine skips it** with `skip_reason=unsupported_protocol` (`plugin.go:347`, `stream_segment.go:99`). v2 is the `trustguard_v2` slug on the same implementation (`plugin.go:42-44`). |
| Policy model | `docs/mcp-policy-scope.md`, `openspec/specs/policy-inert-scope` | Already treats A2A as a plane: `global` reaches it, `mcp_wide` never does, group scope is inert on it. |

### What is missing

- **No registry type for an agent.** `Registry.Type` is `LLM` or `MCP` (`pkg/domain/registry/mcp_target.go:29-30`). `Validate()` refuses anything else (`registry.go:176-195`), and the DB CHECK is `type IN ('LLM','MCP')` (`migrations/20260609200000_add_mcp_registry_and_toolkit.go:32`). `AttachRegistry` already requires registry type == consumer type (`pkg/app/consumer/associator.go:100-103`), so an A2A consumer can never get a target today.
- **No plane serves an A2A consumer.** The proxy answers 404 to any consumer that is not LLM (`pkg/api/handler/http/proxy/proxy_handler.go:630`). The MCP plane answers 404 "consumer is not an MCP consumer" (`pkg/api/handler/http/mcp/mcp_handler.go:618`). There are no A2A routes.
- **Attaching a policy to an A2A consumer is not validated.** `validatePolicyProtocol` returns early for any type other than LLM or MCP (`associator.go:224`), so an LLM-only plugin attaches to an A2A consumer without a 422.
- **Plugin protocols are never checked at plan build.** `SupportedProtocols` is read only at attach time (`associator.go:227`) and by policy validation (`pkg/app/policy/validate.go:93,100`). Nothing in `plan.go`, `chain.go` or `data_finder.go` filters a chain by protocol. A **global** policy of an LLM-only plugin would therefore enter an A2A chain.

### What can be reused

| Need | Existing piece |
|---|---|
| Caller identity resolution (API key, mTLS/XFCC, external IdP JWT), principal admission, end-user header | MCP plane: `ChainIdentityResolver` (`middleware/auth_chain.go`), `mcp_handler.go:593-752` (`hasAuth`, `consumerAdmitsPrincipal`, `endUserPrincipal`, `appPrincipal`). The resolver is reusable with a new path scope. The MCP auth *transport* is not: it is bound to `/mcp` paths (`SlugFromMCPPath`), MCP metrics (`KindMCP`), MCP usage codes (`-32005`) and the MCP protected-resource handler. |
| Running a plugin chain over a JSON-RPC call with a synthetic request body, and mapping a block to a JSON-RPC error | `pkg/app/mcp/plugin_runner.go:132` (`PreRequest`), `:216` (`PreResponse`), `:376` (`buildRequestContext`) |
| Upstream auth modes, static headers encrypted at rest | `registry.MCPAuth` (`mcp_target.go:69-74,108`: `none`, `static`, `passthrough`, `exchange`, `forwarded`, `client_credentials`; exchange patterns `obo`, `delegation`, `token_exchange`), `secrets_rewrite.go`, `UnreadableHeaders` |
| SSRF-safe outbound HTTP | `pkg/infra/netguard` (`NewHTTPClient`, `CheckRedirect`) |
| Config snapshot for DB-less data planes | `Registry` travels as domain JSON (`pkg/infra/configsnapshot/proto/snapshot.proto:114-116`), so a new target needs no proto change |
| Redis on every data plane | `REDIS_HOST` is required on DB-less planes too (`.agents/AGENTS.md`) |

### Constraints found

- **Inbound trace ids are never reused** (`pkg/api/middleware/trace_id.go:27`, RUN-1138): a caller-supplied `X-AG-Trace-Id` could overwrite another tenant's telemetry row. Linking an A2A hop to its parent trace therefore needs an authenticated token, not a header. That is why trace linking is a follow-up here.
- **Telemetry is a data contract** (`.cursor/rules/telemetry-event-contract.mdc`): new attributes are additive only and go through the schema descriptor.
- **JSON-RPC error codes collide.** A2A defines `-32001`…`-32007` (`TaskNotFoundError` is `-32001`). The MCP plane uses `-32001` for a policy block (`plugin_runner.go`, `CodePolicyBlocked`). The A2A plane needs its own gateway codes.

## A2A protocol facts that shape the design

- Two wire formats in use: **0.3** (methods `message/send`, `message/stream`, `tasks/get`, `tasks/cancel`, `tasks/resubscribe`, `tasks/pushNotificationConfig/*`, `agent/getAuthenticatedExtendedCard`; parts discriminated by `kind`; card `url` + `preferredTransport` + `additionalInterfaces`) and **1.0** (methods `SendMessage`, `SendStreamingMessage`, `GetTask`, `ListTasks`, `CancelTask`, `SubscribeToTask`, `*TaskPushNotificationConfig*`, `GetExtendedAgentCard`; `Part` is one of `text` / `raw` / `url` / `data`; card `supportedInterfaces[]` of `{url, protocolBinding, protocolVersion}`; `A2A-Version` header, empty means 0.3).
- Card discovery at `/.well-known/agent-card.json`. Cards can carry JWS `signatures` over the RFC 8785 canonical form without `signatures`. Rewriting a card invalidates them.
- `ListTasks` MUST return only tasks visible to the authenticated client, and servers SHOULD NOT tell "not found" from "not authorized". A gateway that calls the agent with one shared credential collapses every caller into one identity at the agent, so **task ids leak across callers unless the gateway binds them**.
- Push notifications make the agent call a client-supplied webhook directly: the traffic bypasses the gateway, and the URL is a client-controlled outbound target on the agent's network.

## How LiteLLM does it (for contrast, checked 2026-11-11)

- **Registration.** Manual, one agent at a time: UI, `POST /v1/agents` or `config.yaml`. Given a base URL, it probes `/.well-known/agent-card.json`, `/.well-known/agent.json` and `/agentCard/v1.0`.
- **Card.** Stored in the database and served from the stored copy with the URL rewritten. The admin can choose which skills and fields to expose. A "Re-sync from upstream" button shows a diff and accepts changes field by field. Signatures are not verified. **Pinning is therefore parity, not a differentiator.**
- **Discovery.** No automatic discovery of agents (no scan, no import from AgentCore, Vertex or Foundry). Callers find registered agents through:
  - the AI Hub (`GET /public/agent_hub`);
  - `GET /v1/agents`, filtered by key, with semantic search on `?query=`;
  - an `agent_search` virtual MCP tool.
- **Traffic.** JSON-RPC proxy at `/a2a/{agent_id}`, with virtual-key and team permissions and per-agent spend (estimated). Only `message/send` and `message/stream` run through its pipeline. Task methods and push config are forwarded unchanged.
- **Bridges.** Two protocol bridges: an A2A client to LangGraph, AgentCore, Vertex, Foundry or Pydantic AI, and OpenAI `/chat/completions` with `model: a2a/<agent>`.
- **Identity to the agent.**
  - Static API key, SigV4 or provider-native auth.
  - Plain `X-LiteLLM-User-Id` / `X-LiteLLM-Team-Id` headers, unsigned.
  - The caller's key and end user are not forwarded unless `extra_headers` or `x-a2a-{agent}-{header}` pass them.
  - JWT signing (`mcp_jwt_signer`), OBO / RFC 8693 and Okta ID-JAG exist **for MCP only**.
- **Chains.** `X-LiteLLM-Trace-Id` and `X-LiteLLM-Agent-Id` are trusted from the client. Iteration budgets (calls and $ per session) hang off that unauthenticated trace id.

## Agents on AWS, Azure and Google (checked 2026-11-11)

All three clouds now host agents that serve A2A natively, so none of them needs the kind of bridge LiteLLM builds:

- **Amazon Bedrock AgentCore Runtime** ([protocol contract](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-a2a-protocol-contract.html)):
  - JSON-RPC 2.0 at the runtime's `InvokeAgentRuntime` URL, with the card at `…/invocations/.well-known/agent-card.json`;
  - SigV4, or an OAuth Bearer validated by a JWT authorizer the customer configures;
  - the platform session header `X-Amzn-Bedrock-AgentCore-Runtime-Session-Id`;
  - JSON-RPC errors returned with their real HTTP status, including a retryable `-32054`;
  - streaming is supported.
- **Microsoft Foundry Agent Service** ([enable incoming A2A](https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/enable-agent-to-agent-endpoint), [A2A authentication](https://learn.microsoft.com/en-us/azure/foundry/agents/concepts/agent-to-agent-authentication)):
  - `…/agents/{agent}/endpoint/protocols/a2a`, with cards at `agentCard/v1.0` (GA, JSON-RPC only) and `agentCard/v0.3` (preview);
  - without an `A2A-Version` header it serves 0.3;
  - Microsoft Entra only, card included: scope `https://ai.azure.com/.default` and the *Foundry Agent Consumer* role, as a service identity or on behalf of the user;
  - text only, no streaming, tasks kept 60 days.
- **Google Vertex AI Agent Engine** ([use an A2A agent](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/runtime/use-an-a2a-agent)):
  - HTTP+JSON only: `/v1/card` (authenticated only), `/v1/message:send`, `/v1/tasks/{id}` and `/v1/tasks/{id}:cancel`, A2A 0.3;
  - a Google OAuth token with scope `cloud-platform`;
  - no streaming documented, and the page shows two different request body shapes.

TrustGate already has the credential code for all three in its LLM providers:

- `pkg/infra/providers/bedrock` (SigV4, assume role);
- the Azure provider (service principal, managed identity);
- `pkg/infra/providers/gcpauth` (service-account JSON, ADC, impersonation).

Classic Bedrock Agents (`InvokeAgent`) do not speak A2A and remain a bridge (out of scope).

## Approaches

| # | Approach | Pros | Cons |
|---|---|---|---|
| P1 | Serve A2A on the **MCP plane**, dispatched by consumer type after `MatchPath` | Same JSON-RPC + SSE shape, auth transport, principal admission and deployment as agent traffic already uses | The MCP handler grows a branch; the plane's name stops matching its scope |
| P2 | Serve A2A on the **proxy plane** | One plane for "outbound to a model or agent" | The proxy is built around LLM provider adapters, model routing and token streams; none of it applies |
| P3 | A new `agent` **binary plane** | Clean separation; scales alone; MCP untouched; own host; deploy-gated | One more pod, router, DI set and health surface per environment |

**Decision: P3**, a new `agent` plane. A first draft chose P1; the review reversed it:

- P1 needed the riskiest refactor of the change inside the MCP handler, which serves production MCP traffic.
- Agent calls last minutes and need their own scaling and limits.
- A deployment per environment is a natural on/off switch for A2A.
- A dedicated host avoids agent URLs under an `mcp` hostname.
- Three planes match the console's model.

The cost is one more Deployment per environment, and one more pod for hybrid customers who want A2A. The `worker` plane shows the wiring pattern.

## Identity building blocks already in the code

The MCP plane already has an STS (`pkg/app/identity/sts`):

- **`delegation` and `impersonation`:** the gateway mints its own JWT (`sub`, `aud`, `orig_iss`, `scope`, and an `act` for delegation), signed by `TokenSigner` and published at `/.well-known/jwks.json` (`exchanger.go:154`).
- **`obo`:** Entra on-behalf-of (`exchanger.go:175`).
- **`token_exchange`:** RFC 8693 (`exchanger.go:193`).

`Exchange` fails with `ErrNoUserIdentity` when there is no principal. `AppSubject` and `EndUserSubject` (`pkg/domain/consumer/identity.go`) already define the subjects for an application and for an end user it names. Phase 1 of delegated identity is mostly reuse.
