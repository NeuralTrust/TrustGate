# Design: A2A plane MVP

Inputs: [`proposal.md`](./proposal.md) (binding decisions Q1–Q11), [`exploration.md`](./exploration.md), specs under [`specs/`](./specs).
Base audited: `origin/develop` @ `de098c6f`. Binding conventions: `.agents/AGENTS.md` (hexagonal layout, one use case per file, DTO placement, comment policy), `go-comments.mdc`, `telemetry-event-contract.mdc`.

## Technical approach

Three additions and two fixes:

1. **A third registry target**, `A2ATarget`, stored as a JSONB column next to `mcp_target`. It holds the pinned card and travels in the snapshot's registry JSON.
2. **An A2A handler on the MCP plane.** The router resolves the consumer once. MCP consumers keep today's handler, and A2A consumers go to the new one. The handler is a JSON-RPC reverse proxy with three seams around the upstream call: ownership check, `pre_request`, and `pre_response` (buffered or per SSE event).
3. **A Redis ownership store**, keyed per gateway, registry and task or context.
4. Fix: `validatePolicyProtocol` covers A2A consumers.
5. Fix: A2A plans drop plugins that do not declare A2A.

Nothing here touches the LLM proxy or the MCP request path, beyond the dispatch branch.

## Architecture decisions

| # | Decision | Alternatives rejected | Rationale |
|---|---|---|---|
| D1 | `registries.a2a_target JSONB NULL`, plus `registries_type_check` widened to `'LLM','MCP','A2A'`, in one migration | Reuse `mcp_target` with a discriminator | The MCP target's fields (catalog code, URL variables, OpenAPI, transport) mean nothing for an agent. A separate column keeps `validateMCP` untouched. |
| D2 | `A2ATarget.Auth` reuses `*MCPAuth`. A2A validation accepts only `none`, `static` and `client_credentials` | A new `UpstreamAuth` type | Encryption, masking and `UnreadableHeaders` handling, plus the client-credentials token source in `pkg/app/mcp/credentials.go`, already work on `MCPAuth`. A rename can come with the delegation follow-up, which needs the exchange modes anyway. |
| D3 | The card is stored as `json.RawMessage` (exact bytes received) plus `CardDigest` and `CardPinnedAt`. Typed access goes through small read-only views (`InterfaceURL(version)`, `HasInterface(version)`) | A full Go struct for both card versions | Unknown fields must survive the rewrite (spec), and two versions of a full struct would be most of the code with no reader. |
| D4 | The card fetcher is an app port (`appregistry.CardFetcher`) with its infra adapter in `pkg/infra/a2a/card_fetcher.go`, built on `netguard.NewHTTPClient` and capped at 1 MiB | Fetch inside the use case with `net/http` | Hexagonal rule: no HTTP in `pkg/app`. The netguard client brings SSRF and redirect checks. |
| D5 | Digest: remove `signatures`, unmarshal to `any`, `json.Marshal` (map keys sorted), SHA-256, `sha256:<hex>` | RFC 8785 JCS | The digest is internal and only ever compared with itself. JCS matters only when verifying signatures, which is out of scope. |
| D6 | Dispatch: the MCP router's `GET /*` and `POST /*` go through one resolver, generalised from `resolveMCPConsumer` (`mcp_handler.go:593`), that runs `MatchPath`, `hasAuth` and `consumerAdmitsPrincipal` and then branches on `Consumer.Type` instead of refusing non-MCP at `:618` | A2A routes registered before `/*` with their own resolution | One resolution means the same 401/403 behaviour as MCP by construction, and no second copy of the Store special case. The extraction is a refactor with no behaviour change, covered by the existing handler tests. |
| D7 | `pkg/app/a2a` owns the protocol: version tables (method → kind), part normalisation, card view rewrite, ownership rules and the plugin runner. `pkg/api/handler/http/a2a` only decodes, calls, and writes JSON or SSE | Put the protocol in the handler | Hexagonal rule, and every protocol rule becomes unit-testable without fiber. |
| D8 | The A2A plugin runner mirrors `pkg/app/mcp/plugin_runner.go`: it builds `infracontext.RequestContext` with `ConsumerType: "A2A"`, a new `A2A: true` flag, the normalised body, and `Content-Length` set to the real request size. A block maps to `-32090`, 429 to `-32091` | Reuse the MCP runner with a mode flag | The MCP runner's `ToolCall` shape and its rewrite of `arguments` do not fit. Copying about 150 lines is cheaper than a shared abstraction over two shapes. |
| D9 | Plan filter: `data_finder.go` drops, for A2A consumers only, any policy whose plugin's `SupportedProtocols` lacks `A2A`, through the `pluginProtocolResolver` port `pkg/app/consumer` already has (`plugin_protocol_resolver.go:17`) | Filter in `plan.go` for every plane | Applying it to every plane would change LLM and MCP behaviour for globals of single-plane plugins, which this change promises not to do. Track the general fix separately. |
| D10 | `trustguard.SupportedProtocols()` returns LLM, MCP and A2A when `!p.v2`, and LLM and MCP when `p.v2` | Declare A2A on both and warn | A policy that cannot inspect must not attach silently (spec). One method, two answers, already keyed on the existing field. |
| D11 | TrustGuard A2A payload: new `pkg/infra/plugins/trustguard/a2a.go` reads the normalised body when `in.Request.A2A`, next to `mcp.go`. Mask verdict on A2A → block with reason `mask_unsupported` | Teach the LLM adapter registry an "a2a format" | Same split as MCP. The adapter registry is about LLM wire formats. |
| D12 | Ownership in Redis as `a2a:own:{gateway}:{registry}:t:{taskId}` and `…:c:{contextId}`, value `{consumer_id, principal}`, written `SET NX` with TTL, read `GET` plus `EXPIRE` on hit | Postgres table | Data planes may be DB-less. Redis is required on every plane, and the data is a cache of facts the agent already holds. |
| D13 | Streams: the handler reads upstream SSE with `bufio.Scanner` (1 MiB max line), decodes each `data:` payload, runs `pre_response` only on content events, writes, and flushes. On a block it writes an error event, closes, and fires `CancelTask` in a goroutine bounded by `A2A_UPSTREAM_TIMEOUT` and the server's shutdown context | Buffer the whole stream | Agents stream for minutes. Per-event inspection keeps latency at one guard call per content event. |
| D14 | Gateway error codes `-32090` (blocked), `-32091` (rate limited), `-32092` (unavailable or upstream failure), defined in `pkg/app/a2a/errors.go` | Reuse MCP's `-32001`, `-32004` and `-32005` | They collide with A2A's `TaskNotFoundError` (`-32001`) and `UnsupportedOperationError` (`-32004`). |
| D15 | `agent-cards/preview` is a gateway-scoped admin route served by the same `AgentCard` use case (`Preview(ctx, gatewayID, cardURL)`), sharing the fetcher and `ValidateCard`. Its permission is the registry create permission | A dry-run flag on registry create | A dry run would need every create field and would run the auth and name validations the panel has not reached yet. The preview only answers "what is behind this URL". |
| D16 | Version detection lives in the domain (`registry.DetectVersion(card) ([]A2AProtocolVersion)`). The creator uses the highest one when `protocol_version` is empty, and the preview returns the list | Detect in the console | The gateway must accept an API client that omits the version, and one rule in one place keeps the console's preselection identical to what the gateway would pick. |

### Methods by version

| Kind | 0.3 | 1.0 | Ownership check | Inspection |
|---|---|---|---|---|
| send | `message/send` | `SendMessage` | `taskId`, `contextId` of the message | request + buffered response |
| stream | `message/stream` | `SendStreamingMessage` | same | request + each content event |
| get | `tasks/get` | `GetTask` | task id | buffered response |
| cancel | `tasks/cancel` | `CancelTask` | task id | none |
| subscribe | `tasks/resubscribe` | `SubscribeToTask` | task id | each content event |
| list | (where present) `tasks/list` | `ListTasks` | — | refused: `UnsupportedOperationError` |
| push config | `tasks/pushNotificationConfig/*` | `*TaskPushNotificationConfig*` | — | refused: `PushNotificationNotSupportedError` |
| extended card | `agent/getAuthenticatedExtendedCard` | `GetExtendedAgentCard` | — | refused: the version's "extended card not configured" error |

The exact parameter paths for the task id and the message (`params.id` and `params.message` in 0.3; their 1.0 names) are pinned in S4 against fixtures produced by the a2a-sdk 1.x client for both versions, not from memory.

## Data flow

```
client ──POST /{consumer}/agents/{agent}──▶ MCP plane
  auth transport (X-AG-API-Key | gateway OAuth | default IdP)
  resolver: MatchPath → hasAuth → consumerAdmitsPrincipal → Type == A2A
  a2a handler
    decode JSON-RPC, resolve {agent} → A2A registry of the consumer
    app/a2a: method kind for the pinned version ──refused?──▶ A2A error
    ownership.Check(task/context) ──Redis──▶ not owner / unknown ▶ TaskNotFound
    runner.PreRequest(normalised parts) ──block──▶ -32090
    upstream client (netguard, auth mode, static headers, A2A-Version, X-AG-Trace-Id)
        buffered: read ≤ A2A_MAX_BODY_BYTES → runner.PreResponse → ownership.Record
        stream:   per SSE event → content? PreResponse : pass → ownership.Record → flush
    span a2a (registry, method, version, task, context, state, outcome)
  ◀── JSON-RPC result | error, or SSE events
```

Admin flow: create or update an A2A registry → `CardFetcher.Fetch(card_url)` → detect the version when none was sent (D16) → validate for the version → store card, digest and timestamp → `invalidation.GatewayData` → `Signal` (snapshot recompile). `preview` and `refresh` read only. `approve` re-fetches, compares digests, and stores.

Console flow (Registry → Agents → **Add agent**): `preview(card_url)` → the panel shows the card and preselects the highest of `versions` → **Pin and add** sends create with that `protocol_version`. On the agent's detail, **Check for changes** → `refresh` → per-field diff → **Approve new card** → `approve(fetched_digest)`; a 409 reloads the diff.

## File changes

| Area | File | Change | Hand lines |
|---|---|---|---|
| Domain | `pkg/domain/registry/mcp_target.go` | `TypeA2A` next to `TypeLLM` and `TypeMCP` | 2 |
| | `pkg/domain/registry/a2a_target.go` (new) | `A2ATarget`, `A2AProtocolVersion`, `Validate`, auth mode subset | 110 |
| | `pkg/domain/registry/a2a_card.go` (new) | `ValidateCard(raw, version)`, `CardDigest`, `InterfaceURL`, `ChangedFields(a, b)` | 140 |
| | `pkg/domain/registry/registry.go` | `A2ATarget` field, `NewA2ARegistry`, `Validate` branch, `Rehydrate` param | 45 |
| Storage | `pkg/infra/database/migrations/<ts>_registry_a2a_target.go` (new) | Column and CHECK, idempotent up and down | 45 |
| | `pkg/infra/repository/registry/repository.go`, `secrets.go` | Read and write `a2a_target`; encrypt headers and auth like `mcp_target` | 70 |
| Admin | `pkg/app/registry/creator.go`, `updater.go` | Fetch and pin on create, and on change of `card_url` or version | 60 |
| | `pkg/app/registry/card_fetcher.go` (new) | `CardFetcher` port with mockery | 25 |
| | `pkg/app/registry/agent_card.go` (new) | `AgentCard{Preview, Refresh, Approve}` use case (D15) | 140 |
| | `pkg/domain/registry/a2a_card.go` | `DetectVersion` (D16) | 25 |
| | `pkg/infra/a2a/card_fetcher.go` (new) | netguard client, 1 MiB cap, JSON check | 70 |
| | `pkg/api/handler/http/registry/agent_card_handler.go` + request/response DTOs | Three endpoints (preview, refresh, approve) with swagger annotations | 160 |
| | `pkg/server/router/admin_router.go`, `pkg/container/modules/registry.go` | Routes and wiring | 20 |
| Policies | `pkg/app/consumer/associator.go:224` | Include `TypeA2A` | 2 |
| | `pkg/app/consumer/data_finder.go` | A2A-only protocol filter (D9) | 35 |
| | `pkg/infra/plugins/{ratelimit,requestsize}/plugin.go` | Declare A2A | 4 |
| | `pkg/infra/plugins/trustguard/plugin.go`, `a2a.go` (new) | D10, D11 | 120 |
| | `pkg/infra/context/request_context.go` | `A2A bool` | 3 |
| Data plane | `pkg/api/handler/http/mcp/mcp_handler.go`, `pkg/server/router/mcp_router.go` | Extract the resolver, dispatch by type (D6) | 60 |
| | `pkg/app/a2a/wire.go` (new) | Version tables, request decode, part normalisation | 170 |
| | `pkg/app/a2a/card_view.go` (new) | Card rewrite for both versions | 110 |
| | `pkg/app/a2a/forwarder.go` (new) | Buffered call: check, pre, upstream, post, record | 150 |
| | `pkg/app/a2a/stream.go` (new) | Per-event loop, block-and-cancel | 140 |
| | `pkg/app/a2a/plugin_runner.go` (new) | D8 | 150 |
| | `pkg/app/a2a/ownership.go` (new) | Port and rules | 80 |
| | `pkg/app/a2a/errors.go` (new) | Codes and A2A errors per version | 50 |
| | `pkg/infra/a2a/upstream_client.go` (new) | HTTP client, auth modes, header allowlist | 130 |
| | `pkg/infra/a2a/ownership_redis.go` (new) | D12 | 70 |
| | `pkg/api/handler/http/a2a/a2a_handler.go` (new) | Card GET, JSON-RPC POST, SSE writer | 160 |
| | `pkg/container/modules/a2a.go` (new), `server_mcp.go` | Wiring into the MCP plane module sets, full and DB-less | 50 |
| Telemetry | `pkg/infra/trace/span.go`, `pkg/metrics` descriptor | `A2AAttrs`, additive attributes | 60 |
| Config | `pkg/config/config.go`, `.env.example` | Env vars below | 40 |
| Docs | `docs/a2a.md` (new), `README.md` FAQ and comparison table, `make docs` | | 150 + generated |

Unit tests sit next to each file. They come to about 60% of the hand lines above and are counted in the forecast in `tasks.md`.

## app (console)

Audited at `origin/develop` @ `1fb4d0be`. `$F` = `app/[locale]/v2/features`. Binding: the applications model (`TrustGate/docs/applications-model.md`): a plane is born when its first thing is added, the keyring reaches every plane, and the console never asks which plane.

### Decisions

| # | Decision | Alternatives rejected | Rationale |
|---|---|---|---|
| C1 | Agents are registered in Registry (the hidden `a2a` tab), and Applications pick from them | A card-URL field inside the application's add modal | Servers and providers already work this way (`AddToApplicationModal` picks a `registryId`). One agent serves several applications, and pinning and approving a card is gateway-level work. |
| C2 | `PLANES = ['MCP', 'LLM', 'A2A']`, with every `Record<Plane, …>` filled in and the two-plane literals replaced by maps over `PLANES` | A2A as a sub-kind of the Tools plane | It is its own consumer type in the gateway. Folding it into Tools would break `planeOf`, policies routing and analytics scoping, which all key on the consumer type. |
| C3 | Plane order in every list: Models, Tools, Agents | Alphabetical | Matches how a team adds them. Agents is the newest and least used, so it goes last. |
| C4 | The agents routing row has no sub-selection: a row is a registry, nothing more | Let an application narrow an agent's skills | The gateway has nothing to enforce it with. `allowed_methods` is a registry-level setting. |
| C5 | The policy protocol fallback (`slugToProtocols`) never returns `A2A`. Only the catalog's `supported_protocols` can put a policy on Agents | Keep the heuristic and add exceptions | The gateway answers 422 to a plugin without A2A (`a2a-policy-chain`). The console should only offer what the catalog says. |
| C6 | One A2A badge colour everywhere: `lila`, from Topology | Keep per-screen tones | Three tones for one protocol read as three things. Check in A3 that lila does not collide with a status badge next to it, as cyan was chosen over green for MCP. |

### File changes

| Area | File | Change | Lines |
|---|---|---|---|
| Registry | `$F/registry/constants/registry.constants.ts` | Add the `a2a` tab entry (label *Agents*, action *Add agent*) | 10 |
| | `$F/registry/components/add-registry-side-panel/AddAgentSidePanel.tsx` (new) | URL → preview → version, auth → create | 200 |
| | `$F/registry/components/AgentCardSection.tsx` (new) | Pinned card summary, Check for changes, diff, approve or keep | 160 |
| | `$F/registry/actions/{previewAgentCard,createA2aRegistry,refreshAgentCard,approveAgentCard}Action.ts` (new) | Server actions over the TrustGate endpoints | 120 |
| | `$F/registry/lib/agentCardDiff.ts` (new) | Changed fields in words (skills added and removed, endpoint, security) | 60 |
| Applications | `$F/applications/types.ts` | `PLANES` (C2) | 2 |
| | `$F/applications/lib/groupApplications.ts` | `planeOf` keeps A2A consumers | 2 |
| | `$F/applications/components/ApplicationGeneralTab.tsx`, `ApplicationPlaneRouting.tsx` | Plane-generic drafts; Agents section with no sub-selection (C4) | 90 |
| | `$F/applications/components/AddToApplicationModal.tsx` | Seed from `PLANES`; *Agents* tab | 10 |
| | `$F/applications/components/ApplicationConnectTab.tsx`, `lib/applicationConnectSnippets.ts` | Card URL per agent and the a2a-sdk snippet | 80 |
| | `$F/applications/lib/applicationPolicies.ts` | `PLANE_PROTOCOL.A2A` | 2 |
| | `$F/applications/components/ApplicationDetailSidePanel.tsx`, `ApplicationKeyringSection.tsx` | Plane tones and chips | 10 |
| Policies | `$F/policies/constants/policies.constants.ts` | C5, C6 | 10 |
| Filters, badges | `$F/gateway/constants/protocol.ts`, `$F/requests/constants/requests.constants.ts`, `$F/runtime-activity/constants/runtimeActivity.constants.ts`, `$F/registry/components/RegistryAccessTab.tsx` | Re-add A2A to the filters (ENG-1203); C6 | 20 |
| Copy | `messages/en/v2Registry.json`, `v2Applications.json`, `v2Policies.json` | English only | 60 |

Tests follow the repo's `__tests__/v2/...` layout: `groupApplications` keeps an A2A consumer, `policiesForPlanes` routes by catalog protocol and never by fallback, the add panel walks preview → create with the preselected version, the diff names added and removed skills, and approve handles a 409 by reloading.

## Configuration

| Env | Meaning | Default |
|---|---|---|
| `A2A_UPSTREAM_TIMEOUT` | Whole buffered call, and the bound on the cancel after a blocked stream | `300s` |
| `A2A_STREAM_IDLE_TIMEOUT` | Max gap between upstream SSE events | `120s` |
| `A2A_MAX_BODY_BYTES` | Request body and buffered response cap. Over it: `-32092` | `10485760` |
| `A2A_TASK_OWNERSHIP_TTL` | TTL of an ownership entry, renewed on use | `168h` |

## Testing strategy

- **Domain:** card validation per version (missing interface, wrong version, non-object), digest stability (key order, `signatures` only, whitespace), `ChangedFields`.
- **App:** a table over every method × version for kind, ownership and inspection; card rewrite golden files for 0.3 and 1.0 (unknown fields kept, signatures dropped, skill security removed); ownership with a fake store (owner, other owner, unknown, store down on read, store down on write); stream loop with a scripted upstream (pass, block mid-stream, idle timeout, malformed event).
- **Infra:** upstream client header allowlist (no `Authorization`, `Cookie` or `X-AG-*` from the caller); `client_credentials` through the existing token source; Redis store against a real Redis in `make test-repositories` style.
- **Policies:** `validatePolicyProtocol` returns 422 for an LLM-only plugin and for `trustguard_v2` on A2A; the A2A plan drops a global `tokenratelimit` while the LLM plan keeps it; TrustGuard A2A payload, and mask → block.
- **Functional** (`tests/functional`, tag `functional`): a fake A2A agent on `httptest` serving a 0.3 card and a 1.0 card. Register, pin, call send, stream and get, cross-caller `tasks/get` → `TaskNotFound`, push config refused, card served rewritten, refresh after the fake changes its skills, approve with a stale digest → 409. Run against both Postgres and DB-less planes.
- **Interop smoke** (manual, recorded in the PR): the official a2a-sdk client (Python, 1.x) against the gateway for both versions, including the card resolver with the API key header.

## Risks

| Risk | Mitigation |
|---|---|
| TrustGuard v1 may not evaluate `protocol: "a2a"` the way it does `llm` (open question 1) | Confirm before GA. If it does not, A2A ships with rate limit and size only, and the docs say so. |
| The dispatch refactor in the MCP handler regresses MCP | D6 keeps it a pure extraction. Land it as its own commit in S4 with the existing MCP handler tests green before any A2A branch is added. |
| Agents that answer with ids reused across callers | Spec: conflicting ownership withholds the response with `-32092`. Count it and alert. |
| Content split across artifact chunks evades inspection | Documented limitation. Follow-up: reuse `stream_segmenter.go` with a per-artifact window. |
| SDK clients that only fetch public cards | Open question 2. An opt-in public card is a small follow-up if needed. |
