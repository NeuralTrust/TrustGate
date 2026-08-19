# Proposal: RUN-1102 support the MCP Tasks extension

**Change**: `run-1102-mcp-tasks-extension` · **Linear**: [RUN-1102](https://linear.app/neuraltrust/issue/RUN-1102/featmcp-support-the-mcp-tasks-extension)
**Branch**: `feat/run-1102-mcp-tasks-extension` · **Base**: `feat/run-1103-dual-era-northbound-protocol-boundary` @ `8b87f8da`
**Contract**: `io.modelcontextprotocol/tasks` draft (SEP-2663), revision pinned in the spec delta.

## Intent

A modern upstream may answer `tools/call` with `resultType: "task"` and expect the client to poll `tasks/get`, answer `tasks/update`, and stop with `tasks/cancel`. TrustGate is a stateless POST-only gateway and today (a) 404s `tasks/*`, (b) **corrupts** a `CreateTaskResult` (`applyMRTRFields` clobbers `resultType`), and (c) **destroys** the client's extension declaration (`AllowlistedClientCapabilities` drops `extensions`). Long-running tool output delivered via `tasks/get` would also bypass TrustGuard `PreResponse`.

## Scope

### In Scope

- Shared `signedEnvelope` extracted from `mrtr_ticket.go`; new `TaskHandleSigner` with its own secret and claims. MRTR wire format unchanged.
- Hand-rolled `Task` / `CreateTaskResult` / `DetailedTask` envelope-preserving types (go-sdk v1.7.0 has none).
- `tasks/get`, `tasks/update`, **`tasks/cancel`** as modern methods: validation, dispatch, composer use cases, southbound calls.
- Three-sided negotiation: `server/discover` `capabilities.extensions`, client-capability allowlist, southbound `_meta` forwarding.
- Fix the two live blockers (`resultType` clobbering, dropped `extensions`).
- `PreRequest` on `inputResponses`; `PreResponse` on the terminal tool result inside a `completed` `tasks/get`.
- Southbound `Mcp-Method` + `Mcp-Name` headers (absent today); northbound `Mcp-Name == params.taskId`.
- Bounded telemetry, spec delta + new spec, operator docs.

### Out of Scope

- `notifications/tasks` + `subscriptions/listen` (RUN-1104); MCP Apps (RUN-1107).
- Any server-side task store, `tasks/list`, or TrustGate-owned task execution.
- Best-effort upstream `tasks/cancel` when re-authorization rejects a handle — orphan is documented instead.
- Renumbering the pre-existing `-32021` overload (wire break for existing clients).

## Capabilities

### New Capabilities
- `mcp-tasks-extension`: negotiation, task-handle mediation, per-operation re-authorization, plugin coverage, telemetry.

### Modified Capabilities
- `mcp-dual-era-northbound`: `resultType` may be `task`; `tasks/get|update|cancel` are supported modern methods; `Mcp-Name` binding extends to `tasks/*`.

## Approach

**Stateless signed task handle, mediated per operation** — a direct transposition of RUN-1101 MRTR.

When `tools/call` returns `resultType: "task"`, the upstream `taskId` is replaced by a signed handle. Every `tasks/*` POST unwraps it and runs the **full** policy pass (auth → era → validate → consumer resolve → acceptance → role scope → rate limit → plugins → compose), then asserts the bound registry is still attached, the toolkit still maps `expn → upn` on that registry, the principal fingerprint matches, and only then dials that one registry with the real `taskId`.

Advertising means *"TrustGate can mediate tasks"*, never *"every upstream supports tasks"* — no discover-time dial (forbidden by RUN-1103). Degradation is per call: a non-task-capable upstream simply returns a normal `CallToolResult`. Legacy-pinned registries never receive the extension.

### Locked decisions

| # | Decision |
|---|---|
| 1 | Handle `tg1k.<kid>.<b64url(claims)>.<b64url(hmac)>`; claims `{v, gid, cid, rid, sub, expn, upn, tid, exp}`. `sub` = `sha256(issuer\|subject)` principal fingerprint. Gateway id bound. |
| 2 | Purpose tag `mcp.task.handle.v1` is part of the MAC input; MRTR uses `mcp.mrtr.ticket.v1`. Cross-primitive verification impossible by construction. `TicketClaims` is **not** widened. |
| 3 | Separate secrets: **`MCP_TASK_HANDLE_SECRET`** + **`MCP_TASK_HANDLE_SECRET_PREV`** (`c`/`p` rotation, mirroring `MCP_MRTR_TICKET_SECRET`). Empty ⇒ `Enabled()==false` ⇒ never advertise, never forward the extension southbound, never mint. |
| 4 | **Handle is stable across polls.** Mint once at task creation; `tasks/*` responses **echo the inbound handle**. No sliding re-mint (would invalidate the client's stored `Mcp-Name`). |
| 5 | `exp = min(now + MCP_TASK_HANDLE_TTL, createdAt + upstream ttlMs)`. **`MCP_TASK_HANDLE_TTL` default `1h`**, operator-raisable, hard ceiling `24h`. |
| 6 | **`MCP_TASK_POLL_INTERVAL_FLOOR_MS` default `1000`.** Northbound `pollIntervalMs = max(upstream, floor)`; emitted even when upstream omits it. |
| 7 | **`MCP_TASK_HANDLE_MAX_BYTES` default `1024`.** Over-size at mint fails closed (`-32603`); over-size at parse rejects (`-32602`). Keeps `Mcp-Name` inside Fiber header limits. |
| 8 | **Retention: TrustGate stores nothing.** No registry, no GC, no `tasks/list`. Revocation is `exp` + re-authorization. |
| 9 | `tasks/*` share the consumer's existing MCP rate-limit bucket. No separate poll bucket; the `pollIntervalMs` floor is the amplification control. |
| 10 | `tasks/cancel` is **in scope**. `notifications/cancelled` is never accepted as task cancellation. The ack is intent, not a terminal transition. |

### Locked error codes

Free northbound range confirmed: `-32002/-32003` (handler), `-32020/-32021/-32022` (validation), `-32023/-32024` (MRTR).

| Condition | Code | Constant | Note |
|---|---|---|---|
| Non-declaring client issues `tasks/*` | **`-32025`** | `CodeTaskCapabilityRequired` (new) | Deliberate deviation from the draft's `-32003`, which is already `codeConsentRequired` on this same surface — a client switching on `code` alone could not tell an OAuth consent prompt from a capability error. `data.requiredCapabilities: ["io.modelcontextprotocol/tasks"]` is still emitted; the deviation is documented in the spec delta. |
| Handle unparseable / bad MAC / expired / registry detached / toolkit no longer maps `expn→upn` / principal mismatch / unknown or purged upstream task / operation after terminal state | **`-32602`** | `CodeTaskHandleRejected` → `-32602` | Spec-mandated. **One code, one constant message, no `data`** — deliberately indistinguishable so a handle cannot be used as an existence oracle. Credential-resolution failure on a poll maps here too. |
| Internal / upstream transport failure | `-32603` | existing | |
| `-32021`, `-32003` | — | — | **Not reused.** The pre-existing `-32021` northbound/southbound overload is documented, not renumbered. |

## Affected Areas

| Area | Impact | Description |
|---|---|---|
| `pkg/app/mcp/signed_envelope.go` | New | Shared HMAC envelope: version, `kid` rotation, base64url framing, `hmac.Equal`, injectable clock, purpose tag in MAC, `Enabled()` |
| `pkg/app/mcp/mrtr_ticket.go` | Modified | Re-expressed on the envelope; wire format and behaviour unchanged |
| `pkg/app/mcp/task_handle.go` | New | `TaskHandleClaims`, `TaskHandleSigner`, `Binds()` |
| `pkg/app/mcp/tasks.go` | New | Envelope-preserving `Task`/`CreateTaskResult`/`DetailedTask`, status enum, `resultType` helpers |
| `pkg/app/mcp/protocol.go`, `composer.go`, `mocks/` | Modified | `Upstream` + `Composer` gain `GetTask`/`UpdateTask`/`CancelTask`; re-authorization; regenerate mocks |
| `pkg/app/mcp/mrtr_caps.go` | Modified | Allowlist `extensions`, bounded to `io.modelcontextprotocol/tasks` |
| `pkg/app/mcp/errors.go` | Modified | Task sentinels + `CodeTaskCapabilityRequired` |
| `pkg/app/mcp/plugin_runner.go` | Modified | `inputResponses` → `PreRequest`; terminal task result → `PreResponse` under the recovered exposed tool name |
| `pkg/api/handler/http/mcp/{mcp_handler,modern_validation,rpc_dispatcher,modern_response,server_discover,protocol_metrics}.go` | Modified | Method set, `Mcp-Name` binding, dispatch, stop clobbering `resultType`, conditional `extensions`, bounded recorder |
| `pkg/infra/mcp/client/modern_upstream.go` | Modified | `tasks/*` calls, `_meta` extension forwarding, `Mcp-Method`/`Mcp-Name` headers |
| `pkg/infra/mcp/client/client.go` | Modified | Legacy `Session` task methods → `ErrNotSupported` |
| `pkg/infra/trace/span.go` | Modified | Bounded `TaskOperation`/`TaskStatus` labels |
| `pkg/config/config.go`, `pkg/container/modules/mcp.go` | Modified | Four new env vars + signer wiring |
| `openspec/specs/…`, `docs/` | New/Modified | Spec delta, new spec, metrics + operator docs |

Unchanged by design: router, auth middleware, role scoper, registry `protocol_mode` semantics, legacy `initialize`, MRTR wire format.

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| TrustGuard bypass on task output (highest severity) | High if unwired | `PreResponse` on the terminal result is an acceptance criterion with its own test |
| `applyMRTRFields` corrupts `CreateTaskResult` before the fix lands | High | Never forward the extension southbound until the `resultType` fix and dispatch are in the same PR |
| Dropped `extensions` makes northbound tests green while upstreams never see the declaration | Med | End-to-end negotiation test asserting the southbound `_meta` payload |
| Polling amplification | Med | `pollIntervalMs` floor, shared rate-limit bucket, discovery TTL cache + singleflight |
| Handle exceeds header limits | Low | 1 KiB bound enforced at mint and parse |
| Orphaned upstream task after a toolkit/principal change | Med | Correct security behaviour; documented, not auto-cancelled |
| Per-principal credential expiry mid-task | Med | Maps to the same `-32602` constant message — no leak of the difference |
| Draft spec churn | Med | Pin the reviewed revision; version tag `tg1k` allows a clean `tg2k` |
| RUN-1104 overlap | Low | Claims kept forward-compatible so subscriptions reuse them without a wire break |

## Rollback Plan

1. **Instant, no deploy**: unset `MCP_TASK_HANDLE_SECRET`. `Enabled()` goes false ⇒ discover stops advertising `extensions`, southbound stops forwarding the declaration, no upstream mints a task, `tasks/*` answers `-32025`. Behaviour is byte-identical to today.
2. `MCP_TASK_HANDLE_SECRET_PREV` covers secret rotation without invalidating live handles.
3. Full revert = `git revert` the PR. MRTR wire format is unchanged by the envelope extraction, so MRTR tickets minted before or after the revert stay valid — verified by keeping the MRTR golden-vector tests untouched.

## Dependencies

- RUN-1103 dual-era boundary and RUN-1101 MRTR ticket — both on the base branch.
- RUN-1109 telemetry conventions for the bounded recorder.
- No new modules. go-sdk v1.7.0 is **not** upgraded or forked.

## Delivery

400-line budget risk: **High**. Per standing preference (RUN-1106, RUN-1112, RUN-1101), ship **one PR with `size:exception`**, sequenced as atomic commits: (1) envelope + signer + wire types + config, (2) northbound plumbing + composer + southbound, (3) negotiation, (4) plugins + telemetry + specs + docs. Slices 1 and 3 are individually revertible; slice 2 must not ship without slice 1.

## Success Criteria

- [ ] A modern client declaring the extension receives a handle for `resultType: "task"`, polls `tasks/get` to `completed`, and the terminal tool result passes through `PreResponse`.
- [ ] A client that did **not** declare the extension never receives a `CreateTaskResult` and gets `-32025` on `tasks/*`; the upstream never sees the declaration.
- [ ] A handle replayed by a different consumer, principal, registry, or after the toolkit stops exposing the tool answers `-32602` with an identical message in every case.
- [ ] `Mcp-Name` carries the handle northbound and the real `taskId` southbound; `Mcp-Method` is set southbound.
- [ ] Unsetting `MCP_TASK_HANDLE_SECRET` restores pre-change behaviour with no code change.
- [ ] MRTR golden vectors still pass after the envelope extraction; legacy `initialize` capabilities are byte-identical.
- [ ] No `taskId`, `result`, `error.data`, `statusMessage`, `inputRequests`, or `inputResponses` in any metric, span, or log.
