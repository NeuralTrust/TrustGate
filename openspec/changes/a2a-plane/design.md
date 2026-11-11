# Design: A2A agent plane

Inputs: [`proposal.md`](./proposal.md) (decisions Q1–Q19), [`exploration.md`](./exploration.md), and the specs:

- TrustGate: `a2a-agent-registry`, `a2a-agent-plane`, `a2a-task-ownership`, `a2a-policy-chain`, `a2a-delegated-identity`, `a2a-whoami-agents`.
- app: `console-agents-registry`, `console-agents-plane`.

Audited bases:

- TrustGate `origin/develop` @ `de098c6f`. Paths are from the repo root.
- app `origin/develop` @ `1fb4d0be`. `F/` = `app/[locale]/v2/features`, `V/` = `app/[locale]/v2`, `R/` = repo root.

Binding conventions:

- **TrustGate:** `.agents/AGENTS.md` (hexagonal layout, one use case per file, DTO per file, mockery, comment policy), `telemetry-event-contract.mdc`.
- **app:** `AGENTS.md` and `.cursor/rules`. Writes are Server Actions returning `ActionResult<T>`; reads use SWR; use DS components only; show gateway errors through `formatAgentGatewayError`; test ids live in constants; update `V/COMPONENTS.md` and `docs/v2/SDD.md`.

```
                  ┌─────────────── TrustGate ────────────────┐
 console ──admin──▶ admin :8080  registries(A2A) · preview ·  │
                  │              refresh/approve · hosts.agent │
                  │      │ snapshot (registry JSON, no proto)  │
                  │      ▼                                     │
 caller ─────────▶│ agent :8084  auth chain → consumer(A2A) → │──▶ A2A agent
 (X-AG-API-Key,   │   card rewrite · method gate · ownership   │    (Bearer: gateway JWT /
  IdP JWT, mTLS)  │   (Redis) · plugins · STS · span a2a       │     IdP token / static)
                  │ mcp :8082  /whoami → agents[] · JWKS       │
                  └────────────────────────────────────────────┘
```

---

# Part 1 — TrustGate

## 1.1 Decisions

| # | Decision | Rejected | Why |
|---|---|---|---|
| D1 | `registries.a2a_target JSONB NULL`; `registries_type_check` gains `'A2A'`; one in-code migration, idempotent up and down | Reuse `mcp_target` | MCP target fields mean nothing for an agent; `validateMCP` stays untouched |
| D2 | `A2ATarget.Auth` is `*MCPAuth`. A2A validation allows `none`, `static`, `client_credentials` and `exchange` with `delegation`, `obo` or `token_exchange` | A new auth type | Encryption, masking (`secret.Mask`), `ResolveSecretsFrom` and `SecretUnreadable` already work on `MCPAuth` |
| D3 | The card is stored as `json.RawMessage` (bytes received) with read-only views (`Versions()`, `InterfaceURL(v)`, `Skills()`) | Full Go structs for both versions | Unknown fields must survive; two full schemas would be most of the code with no reader |
| D4 | `appregistry.CardFetcher` port; adapter `pkg/infra/a2a/card_fetcher.go` on `netguard.NewHTTPClient`, 1 MiB per response, 10 s total, probing the three paths | Fetch inside the use case | Hexagonal rule; netguard brings SSRF and redirect checks |
| D5 | Digest = SHA-256 of the card without `signatures`, re-marshalled with sorted keys (`sha256:<hex>`) | RFC 8785 JCS | Internal comparison only |
| D6 | **New plane `agent`**: `modules.PlaneAgent`, `cmd/trustgate` param, run function, dispatch and both `isDataPlane` copies, `server_agent.go`, `agent_router.go`, `o11y.PlaneAgent`, `classifyRoute` | Serve on the MCP plane | Proposal Q1 |
| D7 | **Its own auth transport.** Base: RequestID, SecurityHeaders, PanicRecover, AccessLog (as MCP). Auth: `AgentAuthMiddleware` over the existing `ChainIdentityResolver` with an agent path scope, then `HybridGatewayGuard`, `AgentMetricsMiddleware` and `UsageGuard.ForAgent()`. No OAuthChallenge and no session-token path | Mount `mcpAuth` | The MCP transport is bound to `/mcp` (`SlugFromMCPPath`), and to MCP metrics, MCP error codes and the protected-resource handler (exploration) |
| D8 | Gateway and consumer resolution: `PathResolver` learns `AGENT_BASE_DOMAIN` hosts and `/{consumer}/agents/…` paths (`SlugFromAgentPath`); `consumer.Data` gains `MatchAgentPath` | Generic path matching | Mirrors the MCP code, so the resolver keeps one shape per plane |
| D9 | `pkg/app/a2a` owns the protocol (version tables, decode, normalisation, card view, errors, ownership rules, plugin runner, forwarder, stream). `pkg/api/handler/http/a2a` only decodes and writes | Logic in the handler | Hexagonal rule; testable without fiber |
| D10 | The A2A plugin runner mirrors `app/mcp/plugin_runner.go`. A block becomes `-32090`, a 429 becomes `-32091`, any other error fails open | Share the MCP runner | Different payload shape; ~150 lines |
| D11 | The plan filter by `SupportedProtocols` applies to A2A consumers only, in `data_finder.go`, through the `pluginProtocolResolver` port | Every plane | Keeps LLM and MCP unchanged |
| D12 | `trustguard.SupportedProtocols()` includes A2A only when `!p.v2`. New `trustguard/a2a.go` builds the payload from the normalised parts. On A2A, a mask verdict blocks with `mask_unsupported` | Warn and attach | A policy that cannot inspect must not attach |
| D13 | Ownership store: port `appa2a.OwnershipStore`, Redis adapter in the style of `infra/oauth/connect_store.go`, `cache.Client.RedisClient()` | Postgres | Planes can be DB-less; Redis is always present |
| D14 | Streams: per-event inspection; idle and maximum-duration timers; on block, an error event, close, and a bounded async cancel | Buffer the stream | Agents stream for minutes |
| D15 | Gateway JSON-RPC codes `-32090`…`-32093` in `pkg/app/a2a/errors.go` | MCP's codes | They collide with A2A's `-32001` and `-32004` |
| D16 | `preview-agent-card` sits in the registries group, next to `test-connection` and `validate-openapi` | A new resource | Same RBAC (`ResourceRegistries`) with no new scope |
| D17 | Version detection in the domain (`registry.DetectVersions(card)`) | In the console | One rule for API clients and the console |
| D18 | **A2A credentials** live in `pkg/app/a2a/credentials.go` and call `sts.Exchanger` directly. For `delegation`, each call uses a copy of `MCPAuth`:<br>• a user principal sets `Actor = AppSubject(consumer)`;<br>• the application principal uses the impersonation path, so no `act` is minted;<br>• an empty `Audience` becomes the pinned endpoint.<br>`client_credentials` reuses the token client `app/mcp/credentials.go` uses, with its own cache keyed by registry id and `UpdatedAt` | Refactor MCP's `CredentialResolver` into a shared package | Leaves MCP code untouched, which is the point of the separate plane. About 120 lines of duplication. |
| D19 | The STS signer provider moves from `modules/mcp.go` into `modules/sts.go`, included by every set that has the MCP or agent plane. On ephemeral keys, the agent plane refuses `delegation` (`signing_key_unavailable`) | Give the agent plane its own signer | One key, one JWKS. Per-pod ephemeral keys would make tokens unverifiable. |
| D20 | `whoami.consumerURL` gains an A2A case, and `WhoAmIConsumer` gains `agents []WhoAmIAgent` (`omitempty` except for A2A, which always sends the field) | A new endpoint | The SDK already reads `whoami` |
| D21 | `GatewayHosts` gains `Agent string \`json:"agent,omitempty"\``, set when `AGENT_BASE_DOMAIN` is configured | A console-side setting | The console already reads hosts from TrustGate |
| D22 | Telemetry: `events.KindA2A`, `events.Event.A2A *A2A`, OTLP keys `trustgate.a2a.*` in `otlp/mapping.go`, `trace.A2AAttrs` and `builder.buildA2A`, documented in `docs/telemetry/otlp-metadata-contract.md` | Reuse the MCP block | Additive contract (`telemetry-event-contract.mdc`) |

## 1.2 Domain

`pkg/domain/registry/a2a_target.go`:

```go
type A2AProtocolVersion string

const (
	A2AVersion03 A2AProtocolVersion = "0.3"
	A2AVersion10 A2AProtocolVersion = "1.0"
)

type A2ATarget struct {
	CardURL           string             `json:"card_url"`
	ResolvedCardURL   string             `json:"resolved_card_url,omitempty"`
	ProtocolVersion   A2AProtocolVersion `json:"protocol_version"`
	URL               string             `json:"url,omitempty"`
	Headers           map[string]string  `json:"headers,omitempty"`
	Auth              *MCPAuth           `json:"auth,omitempty"`
	AllowedMethods    []string           `json:"allowed_methods,omitempty"`
	Card              json.RawMessage    `json:"card,omitempty"`
	CardDigest        string             `json:"card_digest,omitempty"`
	CardPinnedAt      time.Time          `json:"card_pinned_at,omitzero"`
	UnreadableHeaders []string           `json:"-"`
}
```

Methods:

- `Validate()`: URL schemes, reserved headers (`Authorization`, `Cookie`, `Host`, `Content-Length`, `A2A-Version`, `X-AG-*`), the auth subset (D2), and `AllowedMethods` known for the version.
- `Endpoint()`: `URL` when set, else `InterfaceURL(ProtocolVersion)` from the card.
- `ResolveSecretsFrom(existing *A2ATarget)`: delegates to the MCP helpers for headers and auth.

`pkg/domain/registry/a2a_card.go`:

- `ValidateCard(raw) error`: an object with `name`.
- `DetectVersions(raw) []A2AProtocolVersion`, by the spec rules.
- `CardDigest(raw) (string, error)`.
- `InterfaceURL(raw, v) string`.
- `ChangedFields(a, b) []string` (top-level keys except `signatures`).
- `SkillDiff(a, b) (added, removed []string)`, comparing skill `id`, reporting `name`.

`registry.go`:

- `TypeA2A` next to `TypeLLM` and `TypeMCP` (`mcp_target.go:26-31`).
- `Registry.A2ATarget`, `NewA2ARegistry`, the `Validate` branch, `validateLLM` and `validateMCP` refusing `a2a_target`, and `RehydrateParams.A2ATarget`.

## 1.3 Admin API contracts

Routes go in the registries group (`admin_router.go:194`, `RequireGatewayAccess(ResourceRegistries)`):

| Method | Path | Handler |
|---|---|---|
| POST | `/v1/gateways/:gateway_id/registries` | existing, plus an A2A branch |
| PUT | `/v1/gateways/:gateway_id/registries/:id` | existing, plus an A2A branch |
| POST | `/v1/gateways/:gateway_id/registries/preview-agent-card` | new `PreviewAgentCardHandler` |
| POST | `/v1/gateways/:gateway_id/registries/:id/agent-card/refresh` | new `AgentCardHandler.Refresh` |
| POST | `/v1/gateways/:gateway_id/registries/:id/agent-card/approve` | new `AgentCardHandler.Approve` |

Register `preview-agent-card` before `/:id` routes, as `test-connection` is.

**Create** (`CreateRegistryRequest` gains `A2ATarget *A2ATargetRequest \`json:"a2a_target"\``; `Validate` gains an A2A branch that needs `a2a_target` and refuses `provider`, `auth` and `mcp_target`):

```json
{
  "name": "Travel planner",
  "type": "A2A",
  "description": "optional",
  "a2a_target": {
    "card_url": "https://travel.example.com",
    "protocol_version": "1.0",
    "url": null,
    "headers": { "X-Tenant": "acme" },
    "auth": { "mode": "exchange", "pattern": "delegation", "audience": "https://travel.example.com/a2a" },
    "allowed_methods": ["SendMessage", "SendStreamingMessage", "GetTask", "CancelTask", "SubscribeToTask"]
  }
}
```

`A2ATargetRequest.Auth` reuses `MCPAuthRequest` (`create_registry_request.go:65-92`). The client-credentials fields are the same (`client_id`, `client_secret`, `token_url`, `scopes`, `token_endpoint_auth_method`, `resource`).

`creator.go` gains `CreateInput.A2ATarget` and a branch before the LLM default (`Create`, 77-129). Today every non-MCP type goes to `NewLLMRegistry`, which forces `TypeLLM`. The branch:

1. calls `CardFetcher.Resolve(ctx, cardURL)`;
2. calls `DetectVersions`, then validates the requested version;
3. sets `Card`, `CardDigest`, `CardPinnedAt` and `ResolvedCardURL`;
4. calls `NewA2ARegistry`.

**Response** (`RegistryResponse` gains `A2ATarget *A2ATargetResponse \`json:"a2a_target,omitempty"\``):

```json
{
  "id": "0192…", "type": "A2A", "name": "Travel planner", "enabled": true,
  "a2a_target": {
    "card_url": "https://travel.example.com",
    "resolved_card_url": "https://travel.example.com/.well-known/agent-card.json",
    "protocol_version": "1.0",
    "endpoint": "https://travel.example.com/a2a",
    "headers": { "X-Tenant": "***acme" },
    "auth": { "mode": "exchange", "pattern": "delegation", "audience": "https://travel.example.com/a2a" },
    "allowed_methods": [],
    "card": { "name": "Travel planner", "skills": [] },
    "card_digest": "sha256:…",
    "card_pinned_at": "2026-11-11T10:00:00Z"
  }
}
```

`endpoint` is a computed read-only field, so the console can show the audience default without parsing the card. Masking uses `secret.Mask`, as `fromMCPTarget` does (`registry_response.go:297-336`).

**Update** (`UpdateRegistryRequest` gains `a2a_target`; `UpdateInput.A2ATarget`). A new `applyA2ATargetUpdate`:

- fills omitted fields from the stored row;
- re-pins only when `card_url` or `protocol_version` change;
- keeps masked secrets via `ResolveSecretsFrom`.

**Preview** (`PreviewAgentCardRequest{CardURL}` → `PreviewAgentCardResponse{ResolvedCardURL, Card, CardDigest, Versions, DefaultVersion}`). **Refresh** and **approve**: `AgentCardRefreshResponse{Changed, PinnedDigest, FetchedDigest, ChangedFields, SkillsAdded, SkillsRemoved, FetchedCard}` and `ApproveAgentCardRequest{Digest}`. The response bodies are as in the spec.

Use case `pkg/app/registry/agent_card.go`:

```go
type AgentCard interface {
	Preview(ctx context.Context, gatewayID ids.GatewayID, cardURL string) (*AgentCardPreview, error)
	Refresh(ctx context.Context, gatewayID ids.GatewayID, id ids.RegistryID) (*AgentCardRefresh, error)
	Approve(ctx context.Context, gatewayID ids.GatewayID, id ids.RegistryID, digest string) (*domain.Registry, error)
}
```

`Approve` writes through the repository (it needs a narrow `UpdateA2ACard` or the generic update), then `invalidation.GatewayData` and `Signal`, as the updater does.

**Errors:**

| Case | Status | Sentinel |
|---|---|---|
| Card not found on any path, not an object, too big, timeout, SSRF refusal | 422 | `ErrAgentCardUnavailable` (wraps `ErrValidation`) |
| Version not offered | 422 | `ErrAgentVersionUnsupported` |
| Reserved header, refused auth mode | 422 | `ErrInvalidRegistry` |
| Digest moved | 409 | `ErrAgentCardChanged` (wraps `ErrConflict`) |
| Registry of another gateway | 404 | existing |
| Refresh or approve on a non-A2A registry | 422 | `ErrNotAgentRegistry` |

**Storage** (`pkg/infra/repository/registry`):

- Every `SELECT`, `INSERT` and `UPDATE` carries `a2a_target`.
- New `marshalA2ATarget` / `openA2ATargetForRead`.
- `secrets.go` seals `registries.a2a_target.auth.value`, `.auth.client_secret` and `.headers.<name>` with `FieldAAD(field, registryID)`, behind the same `STORED_SECRETS_ENCRYPTION_ENABLED`, and keeps unreadable ciphertext on update as MCP does.

## 1.4 The agent plane

**Wiring** (the checklist; the MCP plane is the template):

| File | Change |
|---|---|
| `pkg/container/modules/modules.go` | `PlaneAgent = "agent"`; `isDataPlane` includes it; `fullModules` and `dataPlaneModules` add `A2A` and `ServerAgent` (and `STS`, D19) |
| `cmd/trustgate/main.go` | `serverAgent`; `agentParam{Srv server.Server \`name:"agent"\`, ConfigWorker?, …}`; `runAgent`; dispatch before the proxy default; `isDataPlane` copy |
| `pkg/container/modules/server_agent.go` | `agentBaseTransport`, `agentAuthTransport` (named `agentBase` and `agentAuth`), router `dig.Name("agent")`, server `server.NewHTTPServer("agent", ":"+cfg.Server.AgentPort, …)` |
| `pkg/container/modules/a2a.go` | Providers: card view, forwarder, stream, plugin runner, credentials, ownership store, upstream client, handler |
| `pkg/container/modules/sts.go` | Signer provider moved from `mcp.go:74-89` (D19) |
| `pkg/server/router/agent_router.go` | `app.Use(opsMetrics)`; `/health`, `/healthz`, `/readyz`; base transport; `/.well-known/jwks.json`; then auth transport, then `GET /:consumer/agents/:agent/.well-known/agent-card.json` and `POST /:consumer/agents/:agent` |
| `pkg/infra/o11y/provider.go`, `pkg/api/middleware/ops_metrics.go` | `PlaneAgent`, and route classes `agent_card` and `agent_rpc` |
| `pkg/api/middleware/agent_auth.go` | `AgentAuthMiddleware`: `Resolve` with the agent scope, `attach` (locals and `WithPrincipal`), the end-user swap for api_key and mTLS principals (as `mcp_handler.go:640-682`), consumer match, `hasAuth` and `auth_binding` checks → 401/403 |
| `pkg/api/middleware/auth_chain.go` | An agent path scope next to the MCP one; the session-token path stays MCP-only |
| `pkg/api/resolver/path_resolver.go` | `SlugFromAgentPath`; agent host parsing with `AGENT_BASE_DOMAIN` and `AGENT_EXTRA_BASE_DOMAINS` |
| `pkg/app/consumer/consumer_data.go` | `MatchAgentPath(path)` |
| `pkg/api/middleware/agent_metrics.go` | Kind `a2a`, sets `X-AG-Trace-Id` |
| `pkg/api/middleware/usage_guard.go` | `ForAgent()` answering `-32092` `plan_unavailable` |
| `pkg/container/di_smoke_test.go` | Loop includes `"agent"` |

**Handler** (`pkg/api/handler/http/a2a/a2a_handler.go`):

- `Card(c)`: resolve the agent, `CardView.Render(target, origin, consumerSlug)`, `200 application/json`.
- `RPC(c)`:
  1. decode the request (single object, JSON);
  2. call `Forwarder.Kind(version, method)`;
  3. buffered kinds: `Forwarder.Call`, then write the JSON;
  4. stream kinds: `Stream.Run` with an SSE writer that flushes per event;
  5. any `*RPCError` is written with HTTP 200 and the caller's `id`.

**Buffered call** (`pkg/app/a2a/forwarder.go`):

```
1  agent := resolveAgent(rc, param)                       // 404 if none
2  kind := wire.Kind(version, method)                     // -32601 / refused
3  allowed(target.AllowedMethods, method)                 // -32601
4  ids  := wire.Ownership(version, kind, params)          // task id, context id
5  ownership.Check(ctx, gw, agent, owner, ids)            // TaskNotFound / -32092
6  parts := wire.RequestParts(version, kind, params)
7  runner.PreRequest(ctx, rc, agent, parts, rawBody)      // -32090 / -32091
8  cred := credentials.For(ctx, rc, agent, principal)     // -32093 / -32092
9  resp := upstream.Call(ctx, endpoint, cred, headers, body)  // -32092
10 out  := wire.ResponseParts(version, kind, resp)
11 runner.PreResponse(ctx, rc, agent, out, resp)          // -32090
12 ownership.Record(ctx, gw, agent, owner, wire.IDs(resp))   // conflict → -32092
13 span.Finish(...)
```

**Stream** (`pkg/app/a2a/stream.go`): steps 1–8 as above, then `upstream.Stream`. A `bufio.Scanner` with a 1 MiB max line reads `data:` frames. Each event:

- is decoded;
- runs `PreResponse` if it carries content;
- has its ids recorded;
- is written and flushed.

The idle timer (`A2A_STREAM_IDLE_TIMEOUT`) and the max duration (`A2A_STREAM_MAX_DURATION`) end the stream with an error event. On a block, the stream:

1. writes the error event;
2. closes;
3. calls `CancelTask` or `tasks/cancel` in a goroutine bounded by `A2A_UPSTREAM_TIMEOUT` and the server's shutdown context.

A client disconnect cancels the upstream read.

**Methods by version** (from the spec; param paths are pinned in S5b against a2a-sdk 1.x fixtures, not from memory):

| Kind | 0.3 | 1.0 | Ownership | Inspection |
|---|---|---|---|---|
| send | `message/send` | `SendMessage` | message `taskId`, `contextId` | request + response |
| stream | `message/stream` | `SendStreamingMessage` | same | request + content events |
| get | `tasks/get` | `GetTask` | task id | response |
| cancel | `tasks/cancel` | `CancelTask` | task id | — |
| subscribe | `tasks/resubscribe` | `SubscribeToTask` | task id | content events |
| list | `tasks/list` (if present) | `ListTasks` | — | refused |
| push | `tasks/pushNotificationConfig/*` | `*TaskPushNotificationConfig*` | — | refused |
| extended card | `agent/getAuthenticatedExtendedCard` | `GetExtendedAgentCard` | — | refused |

**Upstream request** (`pkg/infra/a2a/upstream_client.go`, port `appa2a.Upstream`):

- `netguard.NewHTTPClient(A2A_UPSTREAM_TIMEOUT)` for buffered calls, and a client with no total timeout but the idle and duration timers for streams.
- Headers: start from an empty set, never a copy of the inbound headers. Add the static headers, then the credential header, `A2A-Version` (1.0), `X-AG-Trace-Id`, `Content-Type`, `Accept`, and `A2A-Extensions` (1.0) or `X-A2A-Extensions` (0.3) when the caller sent one.
- Read the response up to `A2A_MAX_RESPONSE_BYTES`.

**Card view** (`pkg/app/a2a/card_view.go`): decode the pinned card to `map[string]any`, apply the spec rewrite per version, re-encode. Golden files for both versions live under `testdata/`.

## 1.5 Delegated identity

`pkg/app/a2a/credentials.go`:

```go
type Credentials interface {
	For(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry, p *identity.Principal) (http.Header, IdentityTrace, error)
}
```

| `auth.mode` / `pattern` | Behaviour |
|---|---|
| `none` | no header |
| `static` | `{Auth.Header: Auth.Value}` |
| `client_credentials` | token from the same client MCP uses; cache keyed by (registry id, `UpdatedAt`); `Authorization: Bearer` |
| `exchange` / `delegation` | `cfg := *reg.A2ATarget.Auth`. If `cfg.Audience == ""`, it becomes `target.Endpoint()`. A user subject (IdP or end-user header) sets `cfg.Actor = AppSubject(consumer)` and keeps `Pattern=delegation`. An application subject sets `cfg.Pattern = impersonation`, so no `act` is minted. Then `Exchanger.Exchange(ctx, p, gw, &cfg, cacheKey)` with `cacheKey = registryID+subject+audience+pattern` |
| `exchange` / `obo`, `token_exchange` | `Exchange` with the principal; `ErrNoUserIdentity` or missing `RawToken` → `-32093`; an IdP error → `-32092` `identity_exchange_failed` |

`IdentityTrace{Mode, SubjectKind}` feeds the span. The signer issuer is `STS_ISSUER`. JWKS is served on the agent router from the same `TokenSigner`. `modules/sts.go` exposes `SigningKeyEphemeral bool`, which the A2A credentials read to refuse `delegation` (D19).

## 1.6 Task ownership

Port (`pkg/app/a2a/ownership.go`):

```go
type Owner struct{ ConsumerID ids.ConsumerID; Subject string }
type OwnershipStore interface {
	Owner(ctx context.Context, key OwnershipKey) (*Owner, error)       // nil, nil when absent
	Claim(ctx context.Context, key OwnershipKey, o Owner, ttl time.Duration) (claimed bool, existing *Owner, err error)
	Touch(ctx context.Context, key OwnershipKey, ttl time.Duration) error
}
```

Redis keys are `a2a:own:{gateway}:{registry}:t:{taskId}` and `a2a:own:{gateway}:{registry}:c:{contextId}`. Values are JSON `Owner`. `Claim` is `SET NX EX`, then `GET` when it was not claimed. `Touch` is `EXPIRE`. The rules (check before, record after, conflict, fail closed) live in `ownership.go`, and the adapter is `pkg/infra/a2a/ownership_redis.go`.

## 1.7 Policies

| File | Change |
|---|---|
| `pkg/app/consumer/associator.go:224` | Include `TypeA2A` |
| `pkg/app/consumer/data_finder.go` | A2A-only filter (D11) |
| `pkg/infra/plugins/{ratelimit,requestsize}/plugin.go` | Declare A2A |
| `pkg/infra/plugins/trustguard/plugin.go`, `a2a.go` (new) | D12 |
| `pkg/infra/context/request_context.go` | `A2A bool`, `A2AMethod string`, `A2ATaskID string` |
| `pkg/app/a2a/plugin_runner.go` | D10. `RequestContext{ConsumerType:"A2A", A2A:true, Body: normalised, Headers: inbound clone with Content-Length of the real body}` |

Normalised body:

```json
{
  "method": "message/send",
  "agent": "Travel planner",
  "parts": [
    { "type": "text", "text": "…" },
    { "type": "file", "url": "https://…", "media_type": "application/pdf", "filename": "a.pdf" },
    { "type": "data", "data": { } }
  ]
}
```

## 1.8 Telemetry

New OTLP attributes (additive, `trustgate.a2a.*`), emitted only for `kind = a2a`:

| Key | Type |
|---|---|
| `trustgate.a2a.method` | string |
| `trustgate.a2a.registry_id` | string |
| `trustgate.a2a.agent_name` | string |
| `trustgate.a2a.protocol_version` | string |
| `trustgate.a2a.task_id` | string |
| `trustgate.a2a.context_id` | string |
| `trustgate.a2a.task_state` | string |
| `trustgate.a2a.upstream_status` | int |
| `trustgate.a2a.outcome` | string (`ok`, `blocked`, `refused`, `not_found`, `upstream_error`, `upstream_timeout`) |
| `trustgate.a2a.reason` | string |
| `trustgate.a2a.blocked_by` | string |
| `trustgate.a2a.identity_mode` | string |
| `trustgate.a2a.identity_subject_kind` | string (`user`, `app`) |
| `trustgate.a2a.rpc_error_code` | int |

Files:

- `infra/metrics/events/event.go`: `KindA2A`, `A2A` struct.
- `infra/trace/span.go`: `A2AAttrs`, `SetA2ARequest`, `SetA2AStatus`; `newSpan` gives A2A spans `A2AAttrs`.
- `app/metrics/builder.go`: `buildA2A`.
- `infra/telemetry/otlp/mapping.go`: the keys.
- `docs/telemetry/otlp-metadata-contract.md`: the documentation.

## 1.9 whoami and gateway hosts

`whoami_handler.go`:

```go
type WhoAmIAgent struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	CardURL         string `json:"card_url"`
	ProtocolVersion string `json:"protocol_version"`
}
// WhoAmIConsumer gains: Agents []WhoAmIAgent `json:"agents,omitempty"`. A2A consumers always set a non-nil slice.
```

`consumerURL` gains `case TypeA2A` → `https://{gateway.Slug}.{AGENT_BASE_DOMAIN}/{slug}/agents`, or `""` when the domain is unset. Agents come from the consumer's enabled A2A registries in the gateway data, sorted by name.

`gateway_response.go:52-55`: `GatewayHosts.Agent` is filled where `Proxy` and `MCP` are, from `AGENT_BASE_DOMAIN`.

## 1.10 Configuration

| Env | Default | Read by |
|---|---|---|
| `SERVER_AGENT_PORT` | `8084` | agent |
| `AGENT_BASE_DOMAIN` | empty (no agents) | admin (hosts), mcp (whoami), agent (host parsing) |
| `AGENT_EXTRA_BASE_DOMAINS` | empty | agent |
| `A2A_UPSTREAM_TIMEOUT` | `300s` | agent |
| `A2A_STREAM_IDLE_TIMEOUT` | `120s` | agent |
| `A2A_STREAM_MAX_DURATION` | `55m` | agent |
| `A2A_MAX_RESPONSE_BYTES` | `8388608` | agent |
| `A2A_TASK_OWNERSHIP_TTL` | `168h` | agent |
| `A2A_CARD_FETCH_TIMEOUT` | `10s` | admin |

Each follows the `pkg/config` pattern (const → field → getter → `Validate` → `.env.example`). `Validate` refuses a non-positive duration or size, and an `A2A_STREAM_MAX_DURATION` not below `A2A_UPSTREAM_TIMEOUT`. Below 1h, so the stream always closes before the LB cuts it.

## 1.11 Deployment

| Where | Change |
|---|---|
| `k8s/base/deployment/agentgateway-agent.yaml` | Copy of the MCP deployment: args `agent`, port 8084, `CONFIG_SYNC_DATA_PLANE_ENABLED=true`, probes `/healthz` and `/readyz` |
| `k8s/base/{service,horizontalpodautoscaler,poddisruptionbudget}/agentgateway-agent.yaml` | Service 8084, HPA, PDB (`minAvailable` 2) |
| `k8s/base/httproute/agentgateway-routes.yaml` | `agentgateway-agent-route` for `*.agents.internal.neuraltrust.ai` → 8084 |
| `k8s/base/healthcheckpolicy/agentgateway-healthchecks.yaml` | `/readyz` on 8084 |
| `k8s/base/kustomization.yaml` | The new resources |
| `k8s/overlays/{dev,prod,prod-us}` | `patches/httproute-patch.yaml` (`*.agents.dev.neuraltrust.ai`, `*.agents.neuraltrust.ai`, `*.agents.us.neuraltrust.ai`); hpa, pdb, resources and config-sync-tls patches; `config.env` (`SERVER_AGENT_PORT`, `AGENT_BASE_DOMAIN` on admin, mcp and agent); backend policies with `timeoutSec: 3600` for the agent backend (dev `gcp-backendpolicy.yaml`, prod and prod-us `psc-*` and `cloudflare-backendpolicy.yaml`) |
| `docker-compose.api.yaml` | Service `agent`, `command: ["agent"]`, port 8084 |
| `Makefile` | `run-agent`; the `up` banner |
| `.env.example` | The variables above |

DNS and certificates for `*.agents.<domain>` belong to the platform team (proposal, open question 3).

## 1.12 TrustGate file map and estimates

| Slice | Files | Prod / test |
|---|---|---|
| S1 Domain | `domain/registry/{a2a_target.go, a2a_card.go, registry.go, mcp_target.go}` | 330 / 230 |
| S2 Storage | migration; `infra/repository/registry/{repository.go, secrets.go}` | 160 / 120 |
| S3a Admin create/update | `app/registry/{card_fetcher.go, creator.go, updater.go}`; `infra/a2a/card_fetcher.go`; request/response DTOs; `create`/`update` handlers | 300 / 200 |
| S3b Preview, refresh, approve | `app/registry/agent_card.go`; handler and DTOs; routes; `modules/registry.go`; swagger | 300 / 180 |
| S4 Policies | associator, data_finder, plugins, trustguard, request_context | 170 / 150 |
| S5a Plane skeleton | modules, main, `server_agent.go`, `agent_router.go`, o11y, `sts.go` move, config, health only, di smoke | 260 / 60 |
| S5b Auth and resolution | `agent_auth.go`, `auth_chain.go`, `path_resolver.go`, `consumer_data.go`, `agent_metrics.go`, `usage_guard.go` | 280 / 220 |
| S5c Protocol core | `app/a2a/{wire.go, card_view.go, errors.go}` + golden files | 340 / 260 |
| S6 Buffered forwarding | `app/a2a/{forwarder.go, plugin_runner.go}`; `infra/a2a/upstream_client.go`; handler; `modules/a2a.go` | 450 / 260 |
| S7 Credentials and identity | `app/a2a/credentials.go`; JWKS route; ephemeral-key guard | 180 / 160 |
| S8 Ownership | `app/a2a/ownership.go`; `infra/a2a/ownership_redis.go`; hooks | 190 / 160 |
| S9 Streaming | `app/a2a/stream.go`; SSE writer | 200 / 170 |
| S10 Telemetry | events, span, builder, otlp, contract doc | 160 / 90 |
| S11 whoami and hosts | `whoami_handler.go`, `gateway_response.go` | 70 / 70 |
| S12 Deployment, functional, docs | k8s, compose, Makefile; `tests/functional/a2a_*`; `docs/a2a.md`; README; `make docs` | 150 + yaml / 320 |

---

# Part 2 — app (console)

## 2.1 Decisions

| # | Decision | Rejected | Why |
|---|---|---|---|
| C1 | Agents are registered in Registry's `a2a` tab. Applications pick them in General's routing rows | A URL field in the application | Servers and providers work this way; one agent serves many applications |
| C2 | `PLANES = ['MCP', 'LLM', 'A2A']`; every `Record<Plane, …>` and two-plane literal is generalised | A2A inside Tools | It is its own consumer type; plane strings must equal `PolicyProtocol` |
| C3 | Visible order Models, Tools, Agents | — | Matches how teams add them |
| C4 | An agents row is one registry select; no strategy, models, tools or weights | Weights | Agents are not interchangeable backends |
| C5 | `slugToProtocols` defaults to `['LLM', 'MCP']` | Heuristic exceptions | Only the catalog may claim A2A |
| C6 | One A2A tone: `lila` | Per-screen tones | One protocol, one colour |
| C7 | `GatewayConnection.agentHost` / `agentOrigin` are optional and nullable; absent means no agents anywhere in the UI | A feature flag | The gateway already says whether the environment has the plane (`hosts.agent`) |
| C8 | `AddToApplicationModal` and `ApplicationPlaneSection` are unused today; leave them unchanged | Wire them | Not part of the add flow |
| C9 | Snippets with `TourCodeBlock`; URLs with the local `CopyRow` | A new DS snippet | Reuse before creating |
| C10 | `AgentCardDiff` is a feature component built on `SimpleList` | A DS diff | No DS diff exists; one consumer |
| C11 | Hybrid gateways: a nullable `TeamGateway.agentEndpoint` written wherever `mcpEndpoint` is | Derive from `endpoint` | Hybrid data planes may not run the agent plane |

## 2.2 Types

`F/registry/types.ts`:

```ts
export type A2AProtocolVersion = '0.3' | '1.0'
export type A2aExchangePattern = 'delegation' | 'obo' | 'token_exchange'

export type A2aTargetAuth =
	| { mode: 'none' }
	| { mode: 'static'; header: string; value: string }
	| { mode: 'client_credentials'; client_id: string; client_secret: string; token_url: string; scopes?: string[]; token_endpoint_auth_method?: string; resource?: string }
	| { mode: 'exchange'; pattern: A2aExchangePattern; audience?: string; identity_id?: string; scope?: string }

export type A2aTarget = {
	card_url: string
	resolved_card_url?: string
	protocol_version?: A2AProtocolVersion
	endpoint?: string
	url?: string | null
	headers?: Record<string, string>
	auth?: A2aTargetAuth
	allowed_methods?: string[]
	card?: AgentCard
	card_digest?: string
	card_pinned_at?: string
}

export type AgentCard = {
	name: string
	description?: string
	provider?: { organization?: string; url?: string }
	skills?: { id: string; name?: string; description?: string }[]
	[key: string]: unknown
}

export type AgentCardPreview = { resolved_card_url: string; card: AgentCard; card_digest: string; versions: A2AProtocolVersion[]; default_version?: A2AProtocolVersion }
export type AgentCardRefresh = { changed: boolean; pinned_digest: string; fetched_digest: string; changed_fields: string[]; skills_added: string[]; skills_removed: string[]; fetched_card: AgentCard }
```

- `RegistryListItem` gains `a2aTarget?: A2aTarget`.
- `AgentGatewayRegistryItem` gains `a2a_target?`.
- `registrySourceFromAgentGatewayItem` maps it, with version and skills count for the card.

## 2.3 Registry screen

| File | Change |
|---|---|
| `registry/constants/registry.constants.ts` | Add `{id:'a2a', type:'A2A', labelKey:'tabs.a2a', addActionKey:'actions.addA2a', testId: REGISTRY_TEST_IDS.tabA2a}`; `visibleRegistryTabs(connection)` drops it without `agentHost`; `isRegistryTabId` validates against the visible tabs |
| `registry/hooks/useRegistryScreen.ts` | `eagerTypes` from the visible tabs, so A2A is fetched only when shown |
| `registry/lib/loadRegistryRowsForType.ts` | A2A → `listRegistriesAction({type:'A2A'})`; drop the mock path; update `loadRegistryRowsForType.test.ts:105` |
| `registry/components/RegistryScreen.tsx` | Tabs from `visibleRegistryTabs`; A2A filters status only; empty-state copy; `primaryAction` *Add agent* opens `AddAgentSidePanel`; `handleSettings` on A2A opens `AgentDetailSidePanel`; mount both overlays |
| `registry/context/RegistryContext.tsx` | `openEdit` A2A branch; `previewAgentCard`, `createAgent`, `updateAgent`, `refreshAgentCard`, `approveAgentCard` handlers with the existing error pattern (`formatAgentGatewayError`, toast, `screen.reload()`); `openInstances` unchanged |
| `registry/components/RegistryCard.tsx` | A2A: `bot` icon; version and skills meta; *Settings* button; no instances |
| `registry/components/RegistryAccessTab.tsx` | A2A tone `lila` |

New components (in `registry/components/agents/`):

| Component | Props | Notes |
|---|---|---|
| `AddAgentSidePanel` | `open, onClose, teamId, gatewayId, onCreated(id)` | Steps `url → card → settings`; state machine in `useAddAgentFlow`; footer *Continue*, *Back*, *Pin and add* |
| `AgentDetailSidePanel` | `open, onClose, teamId, gatewayId, registry: RegistryListItem, onUpdated, onDelete, onDisable` | Sections per spec; *Change URL* reuses the URL and card steps |
| `AgentCardSummary` | `card, version, resolvedUrl, pinnedAt?` | `SimpleList` for metadata and skills |
| `AgentSignInFields` | `value: A2aTargetAuth, onChange, identities` | Shared by add and detail; OBO identities from `listEntraOboIdentitiesAction` |
| `AgentCardDiff` | `refresh: AgentCardRefresh, onApprove, onKeep, isApproving` | Copy from `agentCardDiff.ts` |
| `VerifyAgentTokenBox` | `issuer, jwksUrl, audience` | `CopyRow` items and a `TourCodeBlock` (Python and Node verification) |

Server actions (`registry/actions/`), each with `'use server'`, `withTrustGateAuth({teamId, minLevel: EDITOR, preferredGatewayId})` and `agentGatewayRequest`, returning `ActionResult`:

- `previewAgentCardAction`;
- `createA2aRegistryAction` (audit `REGISTRY_CREATED`, `revalidateRegistryPath`, PostHog `agent_registered`);
- `updateA2aRegistryAction`;
- `refreshAgentCardAction`;
- `approveAgentCardAction` (audit `AGENT_CARD_APPROVED`, `revalidateRegistryPath`).

`agentCardDiff.ts` turns a refresh into lines:

- "Added skill: X" and "Removed skill: X";
- "Endpoint changed" (`url`, `supportedInterfaces`, `additionalInterfaces`, `preferredTransport`);
- "Security changed" (`securitySchemes`, `security`, `securityRequirements`);
- "Other details changed: a, b".

## 2.4 Applications

| File:line (develop) | Change |
|---|---|
| `applications/types.ts:4` | `PLANES` (C2) |
| `applications/index.ts:5` | Re-export unchanged; types follow |
| `lib/groupApplications.ts:12, 87` | `planeOf` keeps A2A; `consumerIdsOf` follows `PLANES` |
| `lib/applicationName.ts:16` | `PLANE_NAME.A2A = 'Agents'` |
| `lib/applicationDescription.ts:28`, `lib/applicationRow.ts:31,36`, `lib/mcpUpstream.ts:35` | Read the A2A entry or ignore it explicitly |
| `lib/applicationPolicies.ts:9, 64, 69, 74` | `PLANE_PROTOCOL.A2A`; `isRefusedOffMcp` unchanged (A2A is off-MCP) |
| `lib/applicationPolicyScope.ts:13, 31, 54, 89` | Works once the Plane strings include `A2A`; add tests |
| `lib/applicationApiKeys.ts:44` | Follows `PLANES` |
| `hooks/useApplicationAuthDraft.ts:55` | `consumers.MCP ?? consumers.LLM ?? consumers.A2A` |
| `hooks/useApplicationPlaneDraft.ts:192-238` | For `A2A`, create with `protocol: 'A2A'` and registries only |
| `components/ApplicationGeneralTab.tsx:127-153, 174, 181, 223-224, 275, 373-374` | `planeRows` and drafts keyed by plane (`useApplicationPlaneDraft` per entry of the visible planes); third `<ApplicationPlaneRouting plane="A2A">` when `agentHost`; `onDraftPlanesChange` takes a `Set<Plane>` |
| `components/ApplicationPlaneRouting.tsx:61, 105, 222-409` | `plane === 'A2A'`: no strategy, no default model, no tool or model select, no weight; registry options from `type === 'A2A'`; empty-state link to Registry → Agents |
| `components/ApplicationDetailSidePanel.tsx:85, 162, 206, 286, 334-338` | `PLANE_TONE.A2A = 'lila'`; `creationPlanes` from the draft set; traffic labels stay LLM-only; header badges |
| `components/ApplicationConnectTab.tsx:59, 60, 62, 102, 127, 151, 170, 178, 220` | `PLANE_PATH.A2A = '/agents'`; tone; `PLANE_ORDER = ['LLM','MCP','A2A']`; URL plane `'agent'`; Agents section (agent rows with `CopyRow` and an `AgentsSnippets` block) |
| `components/ApplicationKeyringSection.tsx:277-281` | `planes.A2A` chip |
| `consumers/lib/consumerRoutingMapper.ts:463-484` | `applyInlineRoutingToDraft`: A2A → `registries` only |
| `consumers/lib/consumerIdentity.ts:25-39` | Unchanged (identity is ignored by TrustGate) |
| `consumers/lib/consumerBaseUrl.ts:11-35` | Plane union `'proxy' \| 'mcp' \| 'agent'` |
| `analytics/hooks/useAnalyticsScopes.ts:82-83` | Follows `consumerIdsOf` |
| `topology/types.ts:6`, `topology/lib/buildTopologyAssets.ts:38-41` | `TopologyPlane` includes `A2A`; `planeOf` keeps A2A consumers |

New `applications/lib/applicationAgentSnippets.ts`, with `buildAgentsConnectSnippets({cardUrl, endpointUrl, version})` returning:

- **cURL:** `GET` the card with `-H "X-AG-API-Key: $KEY"`; `POST` `message/send` with `{"kind":"text"}` parts (0.3), or `SendMessage` with `{"text": …}` parts and `A2A-Version: 1.0` (1.0).
- **Python:** a2a-sdk 1.x resolving the card through an `httpx.AsyncClient(headers={"X-AG-API-Key": …})`. The exact API is pinned in A2 against the SDK.

## 2.5 Gateway connection

| File | Change |
|---|---|
| `V/lib/gatewayConnection/types.ts` | `agentHost?: string \| null; agentOrigin?: string \| null`; `gatewayPlaneOrigin` plane union |
| `V/lib/gatewayConnection/resolveGatewayConnection.ts:12-15, 30-68` | Read `hosts.agent` (SaaS) and `TeamGateway.agentEndpoint` (hybrid or dedicated) |
| `R/prisma/schema.prisma:1450-1454` + migration | `agentEndpoint String?` on `TeamGateway` |
| Writers of `mcpEndpoint` (dedicated and custom-domain admin) | Accept and save `agentEndpoint` |
| `R/__tests__/setup.ts` and fixtures | Compile unchanged, because the fields are optional; add cases with an agent host |

## 2.6 Policies, filters, badges

| File | Change |
|---|---|
| `policies/constants/policies.constants.ts:67-96` | Default `['LLM','MCP']` (C5); A2A tone `lila` (C6) |
| `requests/constants/requests.constants.ts:30-36, 139-145` | Tone; add A2A to `KIND_FILTER_OPTIONS`; remove the ENG-1203 note |
| `runtime-activity/constants/runtimeActivity.constants.ts:57-61, 284-292` | Tone; add A2A to `PROTOCOL_FILTER_OPTIONS`; remove the ENG-1347 note |
| `gateway/constants/protocol.ts:1-13` | `GATEWAY_PROTOCOLS` and filter options include A2A |
| `consumers/constants/consumers.constants.ts` | A2A tone `lila` |
| `ApplicationPoliciesTab.tsx` | TrustGuard line about masking on agents, shown when the application has the A2A plane |

## 2.7 i18n (`messages/en` only; the repo routes `en` alone)

- **`v2Registry.json`:**
  - `tabs.a2a` "Agents" and `actions.addA2a` "Add agent";
  - new `agents.*` keys for `empty.*`, `add.{url,card,settings}.*`, `signIn.*`, `detail.*`, `diff.*`, `verify.*`, and `errors.noJsonRpc`.
- **`v2Applications.json`:**
  - `planes.A2A` "Agents";
  - `general.A2A.*`, `planeSection.A2A.{title,empty,add,registerLink}`, `connect.A2A.{title,description,cardUrl,snippets}`;
  - `policies.trustguardMaskOnAgents`.

No new namespace file, so `i18n/request.ts` does not change.

## 2.8 app file map and estimates

| Unit | Scope | Prod / test |
|---|---|---|
| A0 | `slugToProtocols` default | 5 / 20 |
| A1 | Gateway connection (types, resolver, Prisma column and writers) | 90 / 80 |
| A2 | Registry Agents tab: types, actions, screen wiring, the six components, diff lib | 650 / 260 |
| A3 | Applications Agents plane: types, groups, drafts, routing, side panel, Connect and snippets, keyring, policies, analytics, topology | 380 / 220 |
| A4 | Filters, badges, copy pass, `COMPONENTS.md`, `SDD.md` | 60 / 30 |

---

## Testing strategy

**TrustGate:**

- **Domain:**
  - card validation and version detection per version, including the 0.3 `additionalInterfaces` case;
  - digest stability;
  - `ChangedFields` and `SkillDiff`;
  - target validation (reserved headers, auth subset, methods per version).
- **Admin:** handler tests per spec scenario; a repository integration test (`PG_TEST_URL`) for `a2a_target` with encryption on and off; `docs/openapi_test.go` for the three new routes.
- **Plane:**
  - DI smoke for `agent`;
  - auth matrix (api key, end-user header, external JWT, mTLS, MCP session token refused; 401/403 before the body);
  - resolver tests for host and path.
- **Protocol:** a method × version table; card golden files; normalisation fixtures from a2a-sdk 1.x for both versions.
- **Forwarding:**
  - header allowlist;
  - refusals;
  - upstream timeout, non-JSON response and oversize response;
  - plugin block on request and response;
  - mask → block.
- **Identity:**
  - claims for IdP, end-user and app subjects;
  - `obo` with no user → `-32093`;
  - an ephemeral key refuses `delegation`;
  - the cache key includes the audience.
- **Ownership:** every spec scenario; Redis down on read (fail closed) and on write (answer kept, metric).
- **Stream:**
  - block mid-stream and cancel;
  - idle timeout and max duration;
  - client disconnect;
  - malformed event;
  - `-race`.
- **Telemetry:** the event builder emits `trustgate.a2a.*` only for A2A, and the LLM and MCP events stay byte-identical.
- **Functional** (`tests/functional`, tag `functional`):
  - fake agents (0.3 and 1.0) on `httptest`;
  - register through a base URL, preview, call send, stream and get;
  - cross-caller `tasks/get` → `TaskNotFound`;
  - push refused;
  - card served rewritten;
  - refresh after a skill change, then approve with a stale digest → 409;
  - `delegation` JWT verified against the agent plane's JWKS;
  - `whoami.agents`;
  - Postgres and DB-less.
- **Interop smoke** (manual, recorded in the PR): the a2a-sdk 1.x client, both versions.

**app:**

- Vitest under `__tests__/v2/{registry,features/registry,applications}`:
  - `loadRegistryRowsForType` for A2A;
  - every new action (success, `AgentGatewayApiError`, audit call);
  - `agentCardDiff`;
  - the `AddAgentSidePanel` flow (preview → create with the preselected version, gRPC-only card);
  - `AgentDetailSidePanel` save without card fields;
  - approve 409 reload;
  - `groupApplications` with A2A;
  - `useApplicationPlaneDraft` creating an A2A consumer with registries only;
  - `applicationPolicies` routing by catalog (`ratelimit` on Agents, `tokenratelimit` not);
  - Connect snippets per version;
  - `resolveGatewayConnection` with and without `hosts.agent`;
  - the Registry tab hidden without an agent host.
- `npm run lint`, `npm run test:unit`, and `npm run build:local` before the push.

## Risks

| Risk | Mitigation |
|---|---|
| TrustGuard v1 may not evaluate `a2a` (open question 1) | Confirm before GA. Otherwise A2A ships with rate limit and size only, and the docs say so. |
| Moving the STS signer provider (D19) changes MCP wiring | Pure move in its own commit; DI smoke and MCP functional tests green before anything else lands |
| `ChainIdentityResolver` gains an agent scope | The MCP scope code path stays byte-identical; tests pin MCP resolution |
| Agents host DNS and certificates per environment | Open question 3; no agents until `AGENT_BASE_DOMAIN` is set |
| Hybrid customers need another pod | Documented; optional |
| Content split across artifact chunks evades inspection | Documented limitation; follow-up reuses `stream_segmenter.go` |
| SDK clients that only fetch public cards | Open question 2 |
| `/whoami` is not served by DB-less MCP planes (pre-existing) | Out of scope; recorded |
