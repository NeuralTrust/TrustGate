# Exploration: RUN-1102 support the MCP Tasks extension

**Change**: `run-1102-mcp-tasks-extension`
**Linear**: [RUN-1102](https://linear.app/neuraltrust/issue/RUN-1102/featmcp-support-the-mcp-tasks-extension)
**Workspace**: `/Users/edu/Neuraltrust/TrustGate-run-1102`
**Branch**: `feat/run-1102-mcp-tasks-extension`
**Base**: `feat/run-1103-dual-era-northbound-protocol-boundary` @ `8b87f8da`
**Depends on**: RUN-1103 (dual-era boundary), RUN-1101 (MRTR ticket — landed on this base), RUN-1109 (telemetry)

## Contract (source of truth)

`io.modelcontextprotocol/tasks`, draft — <https://tasks.extensions.modelcontextprotocol.io/specification/draft/tasks> (SEP-2663).

| Item | Contract |
|---|---|
| Negotiation | Client declares per-request in `params._meta["io.modelcontextprotocol/clientCapabilities"].extensions["io.modelcontextprotocol/tasks"] = {}`. Server advertises in `server/discover` → `capabilities.extensions["io.modelcontextprotocol/tasks"] = {}` |
| Task creation | Server-directed only. `tools/call` may answer `CreateTaskResult` = `Result & Task` with `resultType: "task"`. MUST NOT be returned to a client that did not declare the extension on **that** request |
| Methods | `tasks/get {taskId}` → `Result & DetailedTask` (`resultType: "complete"`); `tasks/update {taskId, inputResponses}` → empty ack; `tasks/cancel {taskId}` → empty ack |
| Task shape | `taskId`, `status` ∈ `working\|input_required\|completed\|cancelled\|failed`, `statusMessage?`, `createdAt`, `lastUpdatedAt`, `ttlMs` (nullable), `pollIntervalMs?`; plus `inputRequests` (input_required), `result` (completed), `error` (failed) |
| Cancellation | `tasks/cancel` **only**. `notifications/cancelled` MUST NOT be used for tasks. Cooperative and eventually consistent — the ack does not promise a terminal state |
| Errors | invalid/unknown/expired `taskId` → `-32602`; internal → `-32603`; non-declaring client issuing `tasks/*` → `-32003` (Missing Required Client Capability) with `data.requiredCapabilities` |
| Transport | Over Streamable HTTP the client **MUST** set `Mcp-Name: <params.taskId>` and `Mcp-Method: tasks/...` |
| Security | Task IDs are bearer-grade: unguessable, no `tasks/list`, `inputRequests` carry the same trust model as direct elicitation/sampling |
| Out of scope here | `notifications/tasks` + `subscriptions/listen` (RUN-1104), MCP Apps (RUN-1107) |

**Terminology collision to keep straight:** MRTR `input_required` (retry the *original* method with `requestState`) and task `input_required` (poll `tasks/get`, answer via `tasks/update`) are different mechanisms that share a vocabulary. The spec is explicit that a server resolves MRTR *before* creating a task.

## Current State

TrustGate is a stateless POST-only MCP gateway: one `POST /{slug}/mcp` = one full policy pass (auth → era classify → modern validate → consumer resolve → acceptance gate → role scope → rate limit → plugins → composer re-discovery + toolkit filter → dial → upstream). Nothing is remembered between POSTs.

RUN-1101 already solved *this exact shape of problem* for MRTR and is the template to follow:

```
pkg/app/mcp/mrtr_ticket.go      tg1.<kid>.<b64url(json claims)>.<b64url(hmac-sha256)>
                                 claims {v,cid,rid,expn,upn,m,r,exp,st}; kid c|p rotation;
                                 injectable clock; empty secret ⇒ Enabled()==false ⇒ fail closed
pkg/app/mcp/composer.go          unwrap → Binds(consumer,registry,exposed,upstream,method)
                                 → re-resolve by EXPOSED name → dial → re-mint
pkg/app/mcp/errors.go            -32023 replay/expiry/mismatch, -32024 round limit
server_discover.go               advertise only when signer.Enabled() && HasNonLegacyMCPRegistry(rc)
                                 — local view only, never dials upstreams at discover time
```

### What is missing for Tasks

| Layer | Today | Tasks gap |
|---|---|---|
| `mcp_handler.go` `isSupportedModernMethod` | 8 methods, no `tasks/*` | modern `tasks/get\|update\|cancel` → HTTP 404 `-32601` |
| `modern_validation.go` | `Mcp-Name` enforced only for `tools/call`, `prompts/get`, `resources/read` | spec **requires** `Mcp-Name == params.taskId` for `tasks/*` |
| `mrtr_caps.go` `AllowlistedClientCapabilities` | keeps only `elicitation`, `sampling`, `roots` | drops `extensions` entirely — the client's tasks declaration is destroyed before it reaches the composer |
| `server_discover.go` `configuredCapabilities` | emits `tools/prompts/resources` only | no `extensions` key at all |
| `modern_response.go` `applyMRTRFields` | forces `resultType: "complete"` unless `tools/call` + `input_required` | **clobbers** `resultType: "task"` — a `CreateTaskResult` is silently corrupted into a bogus complete result |
| `rpc_dispatcher.go` | 8-method switch | no tasks dispatch, no taskId parsing, no per-method rate limit for polls |
| `composer.go` / `protocol.go` `Composer`/`Upstream` | tools/resources/prompts only | no `GetTask`/`UpdateTask`/`CancelTask` port |
| `modern_upstream.go` | hand-built JSON-RPC over `sdk.StreamableClientTransport`; `modernRoundTripper` sets only `Mcp-Protocol-Version` + `User-Agent` | no `tasks/*` calls, and **no `Mcp-Method`/`Mcp-Name` headers southbound** — the spec requires them for task routing |
| `modern_upstream.go` `metadata()` | `MetaKeyClientCapabilities: {}`, MRTR caps forwarded from ctx | no `extensions` forwarding; an upstream will (correctly) never create a task |
| `plugin_runner.go` | scans `tools/call` args + `inputResponses`, and `tools/call` results | a task's final tool result arrives inside `tasks/get` → **TrustGuard bypass** unless wired |
| `protocol_metrics.go` / `trace/span.go` | bounded MRTR enums | no tasks outcome enums |
| Registry / credentials | `target()` + `creds.Apply()` per request, `PinKey` includes principal for per-principal auth modes | a poll must re-resolve credentials for the *originating* registry only |

### go-sdk v1.7.0 has no Tasks types

Verified in the module cache: no `tasks.go`, and no `tasks/get`, `TaskMetadata`, `CreateTaskResult`, or `io.modelcontextprotocol/tasks` symbol anywhere in the SDK. It *does* expose `ClientCapabilities.Extensions map[string]any` / `ServerCapabilities.Extensions` with `AddExtension`, but those are the `initialize` shapes, not the modern per-request `_meta` ones TrustGate builds by hand.

**Consequence:** the `Task` / `CreateTaskResult` / `GetTaskResult` wire types must be hand-rolled in `pkg/app/mcp`. That is consistent with how the modern path already works (`Tool`/`Prompt`/`Resource` are envelope-preserving local types, and `modernUpstream` already hand-builds JSON-RPC). Do **not** wait for or fork the SDK.

### Dual-era constraints

Tasks is modern-only (`2026-07-28`). Legacy `initialize` advertises `{tools, resources, prompts}` and must stay untouched; `classifyEra` sends any `initialize` or known legacy header down the legacy path, so `tasks/*` from a legacy client already falls out as an unknown legacy method. `denyModernIfLegacyOnly` additionally blocks modern for `protocol_acceptance=legacy_only` consumers. A `legacy` `protocol_mode` registry can never serve tasks — legacy `Session.CallTool` has no task surface.

### Error-code collisions (real, and pre-existing)

| Code | TrustGate today | Tasks spec wants |
|---|---|---|
| `-32003` | `codeConsentRequired` (northbound OAuth connect prompt) | Missing Required Client Capability |
| `-32021` | `codeAcceptanceDenied` northbound / `codeRequiredCapability` in `pkg/infra/mcp/client/protocol.go` southbound | — |

RUN-1101's exploration already flagged the `-32021` overload. `-32003` is a new one and must be resolved in design (disambiguate by `data` shape, or avoid emitting the capability error at all by never routing `tasks/*` from a non-declaring client past validation).

## Affected Areas

- `pkg/app/mcp/task_handle.go` *(new)* — task-handle claims, mint/unwrap, binding check
- `pkg/app/mcp/signed_envelope.go` *(new)* — shared HMAC envelope extracted from `mrtr_ticket.go` (see decision below)
- `pkg/app/mcp/mrtr_ticket.go` — re-expressed on the shared envelope; wire format and behaviour unchanged
- `pkg/app/mcp/tasks.go` *(new)* — `Task`/`CreateTaskResult`/`DetailedTask` envelope types, status enum, `resultType` discriminator helpers
- `pkg/app/mcp/protocol.go` — `Upstream` gains `GetTask`/`UpdateTask`/`CancelTask`; `TaskRef` value type
- `pkg/app/mcp/composer.go` — `Composer` gains the three task use cases: unwrap handle → recompose → re-authorize consumer/principal/registry/toolkit → dial only the originating registry → re-wrap any `taskId` in the response
- `pkg/app/mcp/mrtr_caps.go` — allowlist `extensions` (bounded set: `io.modelcontextprotocol/tasks` only) alongside `elicitation`/`sampling`/`roots`
- `pkg/app/mcp/errors.go` — task sentinels (`ErrTaskHandleRejected`, `ErrTaskNotFound`) → `-32602`; capability sentinel → `-32003`
- `pkg/app/mcp/plugin_runner.go` — scan `tasks/update` `inputResponses` (PreRequest) and the inlined tool `result` on a `completed` `tasks/get` (PreResponse), using the exposed tool name recovered from the handle
- `pkg/app/mcp/mocks/mcp_composer_mock.go` — regenerate (`go:generate mockery`)
- `pkg/api/handler/http/mcp/mcp_handler.go` — `isSupportedModernMethod` + `mcpRequestAttrs` (never span-stamp a taskId), tasks recorder wiring
- `pkg/api/handler/http/mcp/modern_validation.go` — `Mcp-Name == params.taskId` for `tasks/*`; taskId shape/size bound
- `pkg/api/handler/http/mcp/rpc_dispatcher.go` — dispatch the three methods, parse `taskId`/`inputResponses`, rate limit every poll
- `pkg/api/handler/http/mcp/modern_response.go` — stop clobbering `resultType: "task"`; strip `resultType: "task"` when the client did not declare the extension; clamp `pollIntervalMs`/`ttlMs`
- `pkg/api/handler/http/mcp/server_discover.go` — conditional `capabilities.extensions["io.modelcontextprotocol/tasks"]`
- `pkg/api/handler/http/mcp/protocol_metrics.go` — `mcp.northbound.tasks.outcome_total` bounded recorder
- `pkg/infra/mcp/client/modern_upstream.go` — `tasks/*` southbound calls; forward the extension in `_meta` client capabilities; set `Mcp-Method` and `Mcp-Name` headers
- `pkg/infra/mcp/client/client.go` (legacy `Session`) — task methods return `ErrNotSupported`
- `pkg/infra/trace/span.go` — bounded `TaskOperation` / `TaskStatus` labels (no ids, no payloads)
- `pkg/config/config.go` + `pkg/container/modules/mcp.go` — `MCP_TASK_HANDLE_SECRET` (+ `_PREV`), handle TTL, poll-interval floor, max handle bytes; provide the signer
- `openspec/specs/mcp-dual-era-northbound/spec.md` — delta: `resultType` may be `task`; `tasks/*` are supported modern methods
- `openspec/changes/run-1102-mcp-tasks-extension/specs/mcp-tasks-extension/spec.md` *(new)*
- `docs/operational-metrics.md`, `docs/mcp/` — new counter + operator notes

Unchanged by design: router, auth middleware, role scoper, registry `protocol_mode` semantics, legacy `initialize`, MRTR ticket wire format, MCP Apps, subscriptions.

## Decision: generalize the MRTR ticket, or add a parallel one?

**Recommendation: extract the envelope, keep the claims and the secrets separate.**

Create `signedEnvelope` in `pkg/app/mcp` owning exactly what is generic — version tag, `kid` (`c`/`p`) rotation, base64url framing, `hmac.Equal` verification, injectable clock, `Enabled()` fail-closed — parameterised by a **purpose tag that is part of the MAC input**. `TicketSigner` (MRTR) and `TaskHandleSigner` become thin typed wrappers over it with their own claim structs and their own secrets.

| Option | Verdict | Why |
|---|---|---|
| **A. Shared envelope, separate claims + separate secrets** | **Chosen** | One audited crypto/rotation implementation; domain separation in the MAC input makes cross-primitive confusion impossible by construction; independent fail-closed rollout levers (`MCP_MRTR_TICKET_SECRET` vs `MCP_TASK_HANDLE_SECRET`); TTLs stay independent |
| B. Reuse `TicketSigner` and widen `TicketClaims` with `tid`/`sub` | Rejected | One struct serving two lifecycles invites claim confusion; `Binds()` would need a mode flag; a 5-minute MRTR TTL and a task TTL that can be hours cannot share `defaultTicketTTL`; one secret means one blast radius and no independent rollback |
| C. Fully parallel copy of `mrtr_ticket.go` | Rejected | Duplicated HMAC/rotation/parsing drifts; the next security fix has to land twice |

Concretely, the two differ enough to justify separate claims and identical enough to justify a shared envelope:

| | MRTR ticket | Task handle |
|---|---|---|
| Lifetime | 5 min, bounded by round count | bounded by upstream `ttlMs` (may be hours); no round counter |
| Bound method | exactly `tools/call` | any of `tasks/get`, `tasks/update`, `tasks/cancel` |
| Payload | upstream `requestState` blob | upstream `taskId` |
| Principal | not bound | **must** be bound (RUN-1102 requires principal re-authorization) |
| Replay window | single continuation | repeated polling by design |

Note the gap that forces a new claim: `TicketClaims` binds `{cid, rid, expn, upn, m, r, exp}` but **not the principal**. Tasks explicitly require principal re-authorization on every operation, so `TaskHandleClaims` adds a principal fingerprint (`sha256(issuer|subject)`, matching how `discoveryKey` already fingerprints principals) and must reject a handle minted under a different principal even within the same consumer.

Proposed handle: `tg1k.<kid>.<b64url(claims)>.<b64url(hmac)>`, claims
`{v, cid, rid, sub, expn, upn, tid, exp}`. Distinct version prefix + purpose tag in the MAC input ⇒ an MRTR ticket can never verify as a task handle and vice versa.

## Approaches

1. **Stateless signed task handle, mediated per operation (recommended)** — mirror RUN-1101 exactly. `tools/call` returning `resultType: "task"` gets its `taskId` replaced by a signed handle. Each `tasks/*` POST unwraps the handle, runs the full policy pass, re-composes the consumer's surface, verifies the bound registry is still attached and the toolkit still exposes `expn → upn`, verifies the principal fingerprint, dials **only** that registry, and calls southbound with the real `taskId`.
   - Pros: no new datastore and no sticky routing; every poll is a fresh authz decision, which is exactly what the ticket says ("principal and toolkit changes enforced on subsequent calls"); a handle is useless to a different consumer, principal, registry, or exposed tool; TTL and revocation come free from `exp` + re-authorization; identical mental model and test patterns as MRTR; fail-closed by omitting the secret.
   - Cons: handle is larger than a raw id (~400 chars — fine for `Mcp-Name`); re-composition cost on every poll (mitigated by the existing discovery TTL cache + singleflight); a toolkit change mid-task orphans a live upstream task (correct, but must be documented and ideally best-effort `tasks/cancel`d).
   - Effort: Medium–High

2. **Server-side task registry (Redis/Postgres) mapping handle → {registry, upstream taskId, consumer, principal}** — TrustGate stores the mapping.
   - Pros: short opaque ids; central revocation; could support a TrustGate-level `tasks/list`.
   - Cons: reintroduces the transport state RUN-1103/RUN-1101 deliberately removed; needs retention/GC and multi-replica consistency; stores identifiers that are bearer-grade upstream credentials; the spec deliberately dropped `tasks/list` for exactly the cross-caller-leak reason this would re-open.
   - Effort: High

3. **Transparent pass-through of the upstream `taskId`** — forward ids unchanged.
   - Pros: smallest diff.
   - Cons: fails every Linear QA item — a stolen id replays across consumers, and in a federation TrustGate cannot even tell *which* upstream owns an opaque id, so `tasks/get` either fans out (leaking existence across upstreams) or guesses. Also leaks upstream identifiers northbound.
   - Effort: Low, and unshippable

4. **TrustGate-owned task execution** — TrustGate creates and drives its own tasks over synchronous upstreams.
   - Pros: uniform client experience over non-task-capable upstreams.
   - Cons: explicitly out of scope ("generic durable workflow execution owned by TrustGate"); requires durable state and a worker; would have TrustGate hold a tool call open for hours.
   - Effort: Very High

## Recommendation

**Approach 1**, structured as a direct transposition of RUN-1101.

1. **Types.** Hand-roll `Task`/`CreateTaskResult`/`DetailedTask` as envelope-preserving types in `pkg/app/mcp` (same pattern as `Tool`), so unknown upstream fields survive round-tripping. go-sdk v1.7.0 offers nothing here.
2. **Handle.** Extract `signedEnvelope`; add `TaskHandleSigner` with its own secret and its own claims including the principal fingerprint and the upstream `taskId`.
3. **Negotiation, three-sided.**
   - Northbound advertise on `server/discover` when **modern era AND handle secret set AND `HasNonLegacyMCPRegistry(rc)`** — same local-only test as MRTR, no discover-time dial (RUN-1103 forbids it).
   - Per request, allowlist the client's `extensions` declaration onto the request context (extend `AllowlistedClientCapabilities`).
   - Southbound, forward `extensions: {io.modelcontextprotocol/tasks: {}}` in `_meta` client capabilities **only** to modern upstreams and **only** when the northbound client declared it. A non-declaring client therefore never causes an upstream to mint a task — which is the cheapest way to satisfy the spec's "MUST NOT return `CreateTaskResult` to a non-declaring client".
4. **Federation.** Advertisement means *"TrustGate can mediate tasks"*, not *"every upstream supports tasks"* — TrustGate cannot know the latter without dialling at discover time. Degradation is naturally per-call: a task-capable upstream returns `resultType: "task"` and gets a handle; a non-task-capable one returns a normal `CallToolResult` and nothing changes. Legacy-pinned registries never receive the extension. This is the answer to "task-capable upstream federated with non-task-capable upstreams".
5. **Re-authorization on every operation.** Unwrap → full pipeline (rate limit, plugins, consumer resolve, role scope) → `compose()` → assert the bound registry is still in `mcpRegistries(rc)`, the toolkit still maps `expn → upn` on that registry, and the principal fingerprint matches. Any mismatch → `-32602` with a constant message (never reveal *which* check failed).
6. **Plugins.** `tasks/update.inputResponses` goes through `PreRequest` exactly like MRTR's. A `completed` `tasks/get` carries the tool's final `result` — it MUST go through `PreResponse` under the recovered exposed tool name, otherwise tasks become a TrustGuard bypass for tool output.
7. **Cancellation and terminal state.** Support `tasks/cancel` as a first-class method; never accept `notifications/cancelled` as task cancellation. Treat the ack as intent, not as a terminal transition. After a terminal status (`completed`/`failed`/`cancelled`) or after handle `exp`, further operations answer `-32602`, indistinguishable from a purged upstream task.
8. **TTL / retention.** TrustGate stores nothing. `exp = min(now + MCP_TASK_HANDLE_TTL, createdAt + upstream ttlMs)` when the upstream declares one. Clamp northbound `pollIntervalMs` to a configured floor so a client cannot be told to hammer the gateway.
9. **Transport headers.** Enforce `Mcp-Name == params.taskId` northbound (the handle) and set `Mcp-Method` + `Mcp-Name` (the real upstream `taskId`) southbound. Southbound header emission does not exist today and is required by the spec for task routing.
10. **Telemetry.** Ops-gated `mcp.northbound.tasks.outcome_total{operation, outcome, era}` with `operation` ∈ `create|get|update|cancel` and `outcome` ∈ `working|input_required|completed|failed|cancelled|handle_rejected|not_found|policy_denied|expired`. Never record `taskId`, `result`, `error.data`, `statusMessage`, `inputRequests`, or `inputResponses` — in metrics, spans, or logs.

Reject 2–4.

### Delivery: 400-line budget risk is High

Recommended chained slices, each independently shippable and revertible by omitting the secret:

1. Shared envelope extraction + `TaskHandleSigner` + wire types + config/container (no behaviour change).
2. Northbound plumbing: modern method set, `Mcp-Name` validation, dispatcher, `resultType: "task"` preservation, composer task use cases, southbound `tasks/*` + headers.
3. Negotiation: discover `extensions`, client-capability allowlist, southbound forwarding, non-declaring fail-closed, federation.
4. Plugins on task payloads + telemetry + specs + docs.

## Risks

- **Silent corruption today**: `applyMRTRFields` rewrites any non-`input_required` result to `resultType: "complete"`, so a `CreateTaskResult` reaching the current code is emitted as a malformed "complete" result carrying a bare `taskId`. Until slice 2 lands, do not forward the extension southbound.
- **Capability declaration is destroyed before use**: `AllowlistedClientCapabilities` drops `extensions`. Forgetting this makes every negotiation test pass northbound while the upstream never sees the declaration.
- **TrustGuard bypass on task output** — the highest-severity functional risk. Tool results delivered through `tasks/get` skip `PreResponse` unless explicitly wired.
- **`-32003` collision** with `codeConsentRequired`; **`-32021`** is already double-booked (`codeAcceptanceDenied` northbound vs `codeRequiredCapability` southbound). Design must pick and document.
- **Handle in a header**: `Mcp-Name` must carry the handle. `plainHeaderValue` accepts printable ASCII, and base64url + `.` qualifies, but handle size must be bounded (target < 1 KiB) and a size check added, or Fiber's header limits become an obscure failure mode.
- **Orphaned upstream tasks** when a toolkit/registry/principal change invalidates a handle mid-flight. Correct security behaviour, but the upstream keeps working. Consider best-effort `tasks/cancel` — and note it needs credentials that may no longer be resolvable.
- **Polling amplification**: `tasks/get` is designed to be called repeatedly. Every poll re-composes (discovery cache + singleflight absorb most of it) and consumes rate-limit budget. A `pollIntervalMs` floor and a rate-limit story are required, not optional.
- **`statusMessage` is free text from the upstream** and may echo user or tool content — classify it as payload for logging purposes.
- **Per-principal credential resolution on polls**: registries in `passthrough`/`exchange`/`forwarded` auth mode need a live principal token to be dialled. A long-running task polled after the principal's token expires fails at credential resolution, not at the handle check — the error mapping must not leak the difference.
- **Draft spec churn**: the extension is draft and versioned; `tasks/list` was removed relative to `2025-11-25`. Pin the reviewed revision in the spec delta.
- **RUN-1104 overlap**: `notifications/tasks` requires `subscriptions/listen`. Keep the task-handle claims forward-compatible so subscriptions can reuse them without a wire break.

## Open questions for sdd-propose

1. `-32003`: emit per spec and disambiguate from `codeConsentRequired` by `data` shape, or never emit it (reject non-declaring `tasks/*` at validation as `-32602`)?
2. Is `tasks/cancel` in scope for this change? Linear's in-scope list names `tasks/get` + `tasks/update`, but "preserve cancellation semantics" is unimplementable without it. Recommend: in scope.
3. Best-effort upstream `tasks/cancel` when a handle is rejected by re-authorization — worth the credential-resolution complexity, or document the orphan?
4. Default `MCP_TASK_HANDLE_TTL`, `pollIntervalMs` floor, and max handle bytes.
5. Does the handle bind the *auth id* / gateway id in addition to consumer + principal?
6. Does `tasks/get` count against the same rate-limit bucket as `tools/call`, or its own poll bucket?

## Ready for Proposal

Yes. Approach 1 with the shared-envelope decision (Option A) is locked unless design rejects the separate secret. Run **sdd-propose** for `run-1102-mcp-tasks-extension`.
