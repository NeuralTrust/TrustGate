# MCP Tasks Extension Specification

## Purpose

Stateless mediation of the `io.modelcontextprotocol/tasks` draft extension (SEP-2663, revision <https://tasks.extensions.modelcontextprotocol.io/specification/draft/tasks>). One POST equals one full policy pass. TrustGate stores no task state; the upstream `taskId` travels northbound only inside a signed handle.

## Requirements

### Requirement: Capability negotiation

Advertisement means *TrustGate can mediate tasks*, never that an upstream supports them. `server/discover` MUST advertise `capabilities.extensions["io.modelcontextprotocol/tasks"] = {}` only when the request is modern, `MCP_TASK_HANDLE_SECRET` is set, and at least one bound registry is not `protocol_mode=legacy`, and MUST NOT dial an upstream to decide. The client's per-request declaration in `params._meta["io.modelcontextprotocol/clientCapabilities"].extensions` MUST survive capability allowlisting, bounded to `io.modelcontextprotocol/tasks`. It MUST be forwarded southbound in `_meta` only to modern upstreams and only when declared on that request. Legacy-era requests and legacy-pinned registries MUST NOT see or receive the extension.

#### Scenario: Advertised without dialling
- GIVEN modern `server/discover`, the secret set, one non-legacy registry
- WHEN discover completes
- THEN `capabilities.extensions` contains the tasks key and no upstream was dialled

#### Scenario: Hidden when disabled, legacy-only, or legacy era
- GIVEN the secret unset, or every bound registry `legacy`, or a legacy `initialize`
- WHEN discover completes
- THEN the `extensions` key is absent and legacy capabilities are byte-identical to before this change

#### Scenario: Declaration preserved and forwarded
- GIVEN a declaring modern client calls `tools/call`
- WHEN capabilities are allowlisted and the southbound call is built
- THEN `extensions` is retained and southbound `_meta` carries `{"io.modelcontextprotocol/tasks":{}}`

#### Scenario: Mixed federation degrades per call
- GIVEN one task-capable and one non-task-capable modern registry on the same consumer
- WHEN a declaring client calls a tool on each
- THEN the first yields a handle-bearing `CreateTaskResult` and the second a normal `CallToolResult`

### Requirement: Task handle mint and binding

When a mediated `tools/call` answers `resultType: "task"`, the upstream `taskId` MUST be replaced northbound by `tg1k.<kid>.<b64url(claims)>.<b64url(hmac)>` binding `{v, gid, cid, rid, sub, expn, upn, tid, exp}`, where `gid` is the gateway id and `sub` is `sha256(issuer|subject)`. The MAC input MUST include the purpose tag `mcp.task.handle.v1`, distinct from MRTR's `mcp.mrtr.ticket.v1`, so an MRTR ticket can never verify as a handle. `exp` MUST be `min(now + MCP_TASK_HANDLE_TTL, createdAt + upstream ttlMs)`, with `MCP_TASK_HANDLE_TTL` defaulting to `1h` and clamped to a `24h` ceiling. A handle MUST NOT exceed `MCP_TASK_HANDLE_MAX_BYTES` (default `1024`); exceeding it at mint MUST fail closed with `-32603`. `kid` MUST select `c` (`MCP_TASK_HANDLE_SECRET`) or `p` (`MCP_TASK_HANDLE_SECRET_PREV`) so rotation does not invalidate live handles. The handle MUST be stable for the task's life: `tasks/*` responses MUST echo the inbound handle and MUST NOT re-mint. TrustGate MUST NOT persist any task record and MUST NOT expose `tasks/list`.

#### Scenario: Handle replaces the upstream id
- GIVEN a declaring client and an upstream `CreateTaskResult`
- WHEN the result is serialized
- THEN `taskId` is the signed handle and the raw upstream id appears nowhere northbound

#### Scenario: TTL bounded by upstream and ceiling
- GIVEN an upstream `ttlMs` shorter than the configured TTL, and a configured TTL above `24h`
- WHEN handles are minted
- THEN `exp` is `createdAt + ttlMs` in the first case and `now + 24h` in the second

#### Scenario: Handle stable across polls
- GIVEN a client polls `tasks/get` three times before completion
- WHEN each response is serialized
- THEN every response echoes the handle it received

#### Scenario: Oversize handle fails closed
- GIVEN claims that would exceed 1024 bytes
- WHEN the handle is minted
- THEN `-32603` is returned and no task result is delivered

#### Scenario: Rotation keeps live handles valid, state stays absent
- GIVEN a handle minted under the old secret, now moved to `MCP_TASK_HANDLE_SECRET_PREV`
- WHEN `tasks/get` runs against a restarted gateway with no shared store
- THEN the `p` handle verifies, the task resolves from the handle alone, and no task record exists anywhere in TrustGate

#### Scenario: Unset secret disables the feature
- GIVEN `MCP_TASK_HANDLE_SECRET` is empty
- WHEN any task path runs
- THEN nothing is advertised or forwarded southbound, no handle is minted, and `tasks/*` answers `-32025`

### Requirement: Per-operation re-authorization

Every `tasks/get`, `tasks/update`, and `tasks/cancel` MUST run the full policy pass (auth, era, modern validation, consumer resolve, acceptance, role scope, rate limit, plugins, compose) before any southbound call, then MUST assert that the handle parses with a valid MAC, is unexpired and within the size bound, that the bound registry is still attached, that the toolkit still maps `expn → upn` on it, and that the principal fingerprint matches. Any failure — tamper, replay by another consumer or principal, expiry, detached registry, toolkit change, unknown or purged upstream task, credential-resolution failure, or an operation after a terminal state — MUST return `-32602` with one constant message and no `data`, so a handle cannot be used as an existence oracle. `tasks/*` MUST share the consumer's existing MCP rate-limit bucket.

#### Scenario: Replay across consumers rejected
- GIVEN a handle minted for consumer A
- WHEN consumer B posts it to `tasks/get`
- THEN `-32602` is returned and no upstream is dialled

#### Scenario: Principal change enforced on the next call
- GIVEN a valid handle presented by a different principal of the same consumer
- WHEN `tasks/get` runs
- THEN `-32602` is returned and no upstream is dialled

#### Scenario: Toolkit change enforced on the next call
- GIVEN a valid handle whose exposed tool is no longer mapped by the toolkit
- WHEN `tasks/update` runs
- THEN `-32602` is returned, no upstream is dialled, and the upstream task is left orphaned

#### Scenario: Every rejection is indistinguishable
- GIVEN a mutated claims segment, a bad MAC, an oversize handle, an expired handle, a detached registry, an unknown upstream task, and an unresolvable per-principal credential
- WHEN each is dispatched
- THEN all return `-32602` with a byte-identical message and no `data`

### Requirement: Origin-bound routing

A `tasks/*` operation MUST be dispatched only to the registry bound in the handle, using the real upstream `taskId`. TrustGate MUST NOT fan out, probe, or guess across the consumer's other registries.

#### Scenario: Poll routes to the originating upstream only
- GIVEN a consumer bound to two modern registries and a handle minted against the first
- WHEN `tasks/get` runs
- THEN only the first is dialled, with the real `taskId`, and the second receives nothing

### Requirement: Capability-required error

A client that did not declare `io.modelcontextprotocol/tasks` on the request MUST NOT receive a `CreateTaskResult`, and MUST receive `-32025` (`CodeTaskCapabilityRequired`) with `data.requiredCapabilities: ["io.modelcontextprotocol/tasks"]` when it issues `tasks/*`. `-32025` MUST NOT reuse `-32003` (`codeConsentRequired`) or `-32021`.

#### Scenario: Non-declaring client issues tasks/get
- GIVEN a modern request without the declaration
- WHEN `tasks/get` is dispatched
- THEN `-32025` with `data.requiredCapabilities` is returned and no upstream is dialled

#### Scenario: Non-declaring client never reaches a task
- GIVEN a non-declaring modern `tools/call`
- WHEN it is processed
- THEN southbound `_meta` omits `extensions` and the client never receives `resultType: "task"`

#### Scenario: Legacy client is untouched
- GIVEN a legacy-era client issuing `tasks/*`
- WHEN handled
- THEN existing legacy unknown-method behaviour applies and no extension was ever advertised to it

### Requirement: Cancellation and terminal state

`tasks/cancel` MUST be a first-class method returning an empty ack that expresses intent, not an asserted terminal transition. `notifications/cancelled` MUST NOT be accepted as task cancellation. After `completed`, `failed`, or `cancelled`, or after the handle's `exp`, every further `tasks/*` MUST return the same `-32602` constant message.

#### Scenario: Cancel acknowledged as intent
- GIVEN a `working` task
- WHEN `tasks/cancel` is accepted
- THEN an empty ack is returned and no terminal status is asserted

#### Scenario: Post-terminal operation rejected
- GIVEN a task that already returned `completed`
- WHEN `tasks/get` or `tasks/update` runs with the same handle
- THEN `-32602` is returned

#### Scenario: Expiry is deterministic
- GIVEN a handle whose `exp` passed by one second on the injected clock
- WHEN `tasks/get` runs
- THEN `-32602` is returned and no upstream is dialled

### Requirement: Poll interval floor

Northbound `pollIntervalMs` MUST be `max(upstream pollIntervalMs, MCP_TASK_POLL_INTERVAL_FLOOR_MS)`, default floor `1000`, and MUST be emitted even when the upstream omits it.

#### Scenario: Floor applied and always emitted
- GIVEN one upstream omits `pollIntervalMs` and another returns `250`
- WHEN each result is serialized
- THEN both carry `pollIntervalMs: 1000`

### Requirement: Plugin coverage on task payloads

`tasks/update` `inputResponses` MUST be passed to `PreRequest`. The terminal tool result carried by a `completed` `tasks/get` MUST be passed to `PreResponse` under the exposed tool name recovered from the handle, so task delivery is never a TrustGuard bypass. A plugin denial MUST prevent delivery of that content.

#### Scenario: Terminal result passes PreResponse
- GIVEN a `tasks/get` returning `completed` with the tool's final result
- WHEN the response is composed
- THEN `PreResponse` ran once with that result under the exposed tool name

#### Scenario: Denial blocks task output
- GIVEN a `PreResponse` plugin denies the terminal result
- WHEN `tasks/get` is serialized
- THEN the tool content is not delivered and the outcome is `policy_denied`

#### Scenario: Input responses scanned
- GIVEN `tasks/update` with `inputResponses`
- WHEN the request is processed
- THEN `PreRequest` received those `inputResponses`

### Requirement: Task transport headers

Northbound `tasks/get|update|cancel` MUST carry `Mcp-Name` equal to `params.taskId` (the handle) and a matching `Mcp-Method`; a mismatch MUST fail modern header validation before any policy effect. Southbound, TrustGate MUST set `Mcp-Method: tasks/...` and `Mcp-Name` to the real upstream `taskId`.

#### Scenario: Handle northbound, real id southbound
- GIVEN a valid `tasks/get` whose `Mcp-Name` equals the handle
- WHEN the southbound call is issued
- THEN it carries `Mcp-Method: tasks/get` and `Mcp-Name` equal to the upstream `taskId`

### Requirement: Task telemetry without content

When ops metrics are enabled, the system MUST increment a bounded `mcp.northbound.tasks.outcome_total{operation,outcome,era}` with `operation` ∈ {`create`,`get`,`update`,`cancel`} and `outcome` ∈ {`working`,`input_required`,`completed`,`failed`,`cancelled`,`handle_rejected`,`not_found`,`policy_denied`,`expired`}. No metric, span, or log MUST contain a handle, `taskId`, `result`, `error.data`, `statusMessage`, `inputRequests`, or `inputResponses`.

#### Scenario: Bounded labels, no content
- GIVEN a poll returning `working` and, separately, a rejected handle
- WHEN telemetry emits
- THEN labels are `operation=get`, `outcome=working|handle_rejected`, `era=modern`, with no identifier, payload, or rejection discriminator
