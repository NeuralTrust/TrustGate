# Tasks: RUN-1102 support the MCP Tasks extension

**Branch**: `feat/run-1102-mcp-tasks-extension` · **Base**: `feat/run-1103-dual-era-northbound-protocol-boundary` @ `8b87f8da`

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | 2200–2800 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | One PR (`size:exception`); fallback chain 1→2→3→4 |
| Delivery strategy | exception-ok |
| Chain strategy | size-exception |

Decision needed before apply: No
Chained PRs recommended: Yes
Chain strategy: size-exception
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Envelope, signer, wire types, config/DI | commit 1 | Inert alone |
| 2 | Composer, northbound, southbound | commit 2 | **Never ships without unit 1** |
| 3 | Negotiation: caps, choke point, discover | commit 3 | Revertible |
| 4 | Plugins, telemetry, specs, docs | commit 4 | Revertible |

Apply phases 1→5 sequentially in one worktree. Chain only if `size:exception` is refused.

### Locked decisions (override design Open Questions)

1. MRTR MAC stays **untagged permanently**: no `legacyPurposes`, no flip. Empty purpose ⇒ today's MAC input.
2. Southbound `Mcp-Method`/`Mcp-Name` stay scoped to `tasks/*` — see Deferred.
3. `principalFingerprint` = **full** sha256 hex; `discoveryKey` slices it to keep its bytes.

## Phase 1: Foundation (commit 1)

- [x] 1.1 Create `pkg/app/mcp/signed_envelope.go`: `<ver>.<kid>.<b64url>.<b64url mac>`, `c`/`p`, `hmac.Equal`, injected clock, `maxBytes`, `enabled()`; purpose `""` ⇒ untagged. Tests: rotation, tamper, expiry, bad ver/kid, size, tagged⇎untagged.
- [x] 1.2 Modify `mrtr_ticket.go`: `TicketSigner` on the envelope, purpose `""` forever. Signatures, `ErrMRTRReplayRejected`, `tg1` bytes unchanged; keep `ticketKidCurrent`. MRTR tests unedited.
- [x] 1.3 Create `task_handle.go`: claims `{v,gid,cid,rid,sub,expn,upn,tid,iat,exp}`, `Binds`, signer (purpose `mcp.task.handle.v1`, TTL ≤`24h`, 1 KiB), full-digest `principalFingerprint`. Tests: binding, `exp=min(now+TTL,createdAt+ttlMs)`, clamp, oversize, `p`, ticket⇎handle.
- [x] 1.4 Create `tasks.go`: `Task`/`CreateTaskResult`/`DetailedTask` on `marshalEnvelope`, `TaskStatus`+`Terminal`, `numberField`, `TaskResultFields`, `RewriteTaskEnvelope`, `TerminalTaskResult`, `ReplaceTaskResult`, `StripTaskResult`. Tests: unknown-field round trip, poll floor, extract/replace/strip.
- [x] 1.5 Modify `errors.go`: three sentinels, `-32025` `CodeTaskCapabilityRequired`, `-32602` `CodeTaskHandleRejected`, constant-message RPC error with `Data == nil`, `MapTaskError`.
- [x] 1.6 Modify `pkg/config/config.go` + `pkg/container/modules/mcp.go`: `MCPTasksConfig`, four env vars (`1h`/`1000`/`1024`), provide the signer. Empty secret ⇒ disabled.

## Phase 2: Mediation (commit 2 — requires Phase 1)

- [x] 2.1 Modify `protocol.go`: `TaskRef` + optional `TaskUpstream`. `Upstream`, `client.go`, and all fakes untouched.
- [x] 2.2 Modify `composer.go`: `tasks` signer + `pollFloorMs`, `NewComposerWithMediation` (`NewComposerWithSigner` delegates `nil,0`), task branch in `wrapContinuation` before MRTR: mint, or `StripTaskResult` when disabled.
- [x] 2.3 Add `resolveTask` + `UnwrapTaskHandle`/`GetTask`/`UpdateTask`/`CancelTask`: assert RID attached, toolkit maps `expn→upn`, `sub` matches; dial only that registry; any failure → `ErrTaskHandleRejected`.
- [x] 2.4 Create `composer_tasks_test.go`: re-auth matrix returns one identical `-32602`; dial counter proves origin-bound routing.
- [x] 2.5 Regenerate `mocks/mcp_composer_mock.go`.
- [x] 2.6 Modify `mcp_handler.go`: `tasks/*` supported, `TasksSupport`, `NewHandlerWithMediation`, `mcpRequestAttrs`, `writeAppError`.
- [x] 2.7 Modify `modern_validation.go`: `sourceField="taskId"` for `tasks/*`; size bound before the compare.
- [x] 2.8 Modify `rpc_dispatcher.go`: three cases, `requireTasksCapability` → `-32025`, consumer's existing rate-limit bucket.
- [x] 2.9 Modify `modern_response.go`: `isTask` computed before `_meta`; skip `applyMRTRFields` **and** the `ttlMs` delete; `tasks/*` → `complete`, `ttlMs:0`, filtered `inputRequests`.
- [x] 2.10 Modify `modern_upstream.go`: three task calls, `withModernRouting` ctx value, round tripper sets `Mcp-Method` + sentinel `Mcp-Name` (real `taskId`), `metadataForTask`. Test: params, headers, `_meta` only when declared.

## Phase 3: Negotiation (commit 3)

- [x] 3.1 Modify `mrtr_caps.go`: allowlist `extensions` bounded to the tasks key, value forced `{}`; add `DeclaredTasksExtension`.
- [x] 3.2 Modify `mcp_handler.go`: drop `extensions` when `!signer.Enabled()` — the single fail-closed choke point.
- [x] 3.3 Modify `server_discover.go`: advertise `capabilities.extensions` when enabled, modern, `tools` visible, ≥1 non-legacy registry; after `configuredCapabilities`.
- [x] 3.4 Create `tasks_handler_test.go`: no `-32601`; name mismatch `-32020`; oversize `-32602`; non-declaring `-32025` with `data.requiredCapabilities`; advertise/hide; legacy `initialize` byte-identical.

## Phase 4: Plugins and telemetry (commit 4)

- [x] 4.1 Modify `plugin_runner.go`: `inputResponses` → `PreRequest`; terminal task result → `PreResponse` under the recovered exposed name. Extend `plugin_runner_test.go`.
- [x] 4.2 Wire in `rpc_dispatcher.go`: `TerminalTaskResult` → `PreResponse(ctx, rc, ref.Exposed, nil, inner)`; denial withholds content, records `policy_denied`; rewrite spliced via `ReplaceTaskResult`.
- [x] 4.3 Modify `pkg/infra/trace/span.go`: bounded `TaskOperation`/`TaskOutcome`, `SetMCPTask`. No task-id field.
- [x] 4.4 Modify `protocol_metrics.go`: ops-gated `mcp.northbound.tasks.outcome_total{operation,outcome,era}`; every rejection records `handle_rejected` only. Tests: unknown labels dropped, no ids or payloads.

## Phase 5: Specs, docs, verify (commit 4)

- [x] 5.1 Apply the delta to `openspec/specs/mcp-dual-era-northbound/spec.md`; add `openspec/specs/mcp-tasks-extension/spec.md`.
- [x] 5.2 Update `docs/operational-metrics.md` and `docs/mcp/`: counter, four env vars, rollback lever, orphaned-task note.
- [x] 5.3 Integration: create → poll → terminal → cancel on a scripted upstream; secret unset restores pre-change behaviour.
- [x] 5.4 Verify: `go test ./... -race`, `go vet`, `golangci-lint run`, `gofmt`; clean-comments on touched Go.

## Deferred

- Southbound headers for `tools/call`, `prompts/get`, `resources/read` — follow-up ticket.
- `notifications/tasks` + `subscriptions/listen` (RUN-1104); MCP Apps (RUN-1107); `-32021` renumbering.
