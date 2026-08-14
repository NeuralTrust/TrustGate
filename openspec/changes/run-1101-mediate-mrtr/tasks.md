# Tasks: Mediate Multi Round-Trip Requests (RUN-1101)

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | 1600–2100 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | One PR (`size:exception`); fallback chain 1→2→3 below |
| Delivery strategy | exception-ok |
| Chain strategy | size-exception |

Decision needed before apply: No
Chained PRs recommended: Yes
Chain strategy: size-exception
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Preserve/forward/SDK caps | PR 1 | Sequential in this worktree |
| 2 | Ticket+replay+limits | PR 1 | Depends on unit 1 |
| 3 | Advertise+metrics+docs | PR 1 | Depends on unit 2 |

Apply 1→5 in one worktree. Split to chained PRs only if `size:exception` is rejected.

## Phase 1: Foundation

- [x] 1.1 Add `MCP_MRTR_TICKET_SECRET`, `_PREV`, defaults (8, 5m, 256KiB) in `pkg/config/config.go`. Env-only; not k8s overlays.
- [x] 1.2 Map HMAC/expiry/mismatch → `-32023`, round ≥ 8 → `-32024` in `pkg/app/mcp/errors.go`. Never `-32021`.
- [x] 1.3 Add `ToolCall` (`Name`, `Arguments`, `InputResponses json.RawMessage`, `RequestState`) and `CallTool(ctx, ToolCall)` on Composer/Upstream in `pkg/app/mcp/protocol.go`.
- [x] 1.4 Create `pkg/app/mcp/mrtr_ticket.go`: `tg1.<kid>.<b64url>.<hmac>`; mint `c`, verify `c` then `p`; injectable clock; `Enabled()`. Tests: HMAC/exp/kid/bind; mint empty `st`.
- [x] 1.5 Provide `TicketSigner` in `pkg/container/modules/mcp.go`; empty secret = fail-closed.

## Phase 2: Preserve, forward, southbound

- [x] 2.1 Parse continuation in `pkg/api/handler/http/mcp/rpc_dispatcher.go`; >256KiB/`-32602`; pass `ToolCall`. Full policy every round.
- [x] 2.2 Scan/rewrite `inputResponses` (not ticket) in `pkg/app/mcp/plugin_runner.go`; ignore name; never log answers.
- [x] 2.3 In `pkg/infra/mcp/client/modern_upstream.go`: SDK `InputResponses`/`RequestState`; `metadata()` from ctx caps (`elicitation`,`sampling`,`roots`); no `{}` on MRTR.
- [x] 2.4 Switch `pkg/infra/mcp/client/{client,cached_dialer,negotiating_dialer}.go` to `ToolCall`; legacy drops continuation.
- [x] 2.5 Preserve `input_required` on `tools/call` only in `pkg/api/handler/http/mcp/modern_response.go`; strip MRTR on `prompts/get`/`resources/read`; invert clobber tests.
- [x] 2.6 Put declared caps on request ctx in `pkg/api/handler/http/mcp/mcp_handler.go`.

## Phase 3: Ticket bind

- [x] 3.1 In `pkg/app/mcp/composer.go`: unwrap+bind `{cid,rid,exposed,upstream,method,round,exp}`; re-resolve by exposed name; mint on `input_required` even if `st` empty; secret off → strip `input_required`.
- [x] 3.2 Tests: retry original tool; cross-tenant/alias `-32023` no upstream; round ≥8 → `-32024`; one-round `complete`; policy deny on retry.
- [x] 3.3 Regen `pkg/app/mcp/mocks/mcp_composer_mock.go` (`go:generate mockery`).

## Phase 4: Advertise, cancel, metrics

- [x] 4.1 In `pkg/api/handler/http/mcp/server_discover.go`: `tools={"inputRequests":{}}` iff secret set and ≥1 non-legacy registry; else `{}`; never on legacy `initialize`.
- [x] 4.2 `notifications/cancelled` → HTTP 202 (no store) in handler; meter `cancelled`.
- [x] 4.3 Ops-gated `mcp.northbound.mrtr.outcome_total{outcome,era,round}` in `protocol_metrics.go`; fold `mrtr_outcome`/`mrtr_round` in `span.go`, `events/event.go`, `builder.go`. Round ∈ {1,2,3+}. Never log ticket/answers.
- [x] 4.4 Tests: advertise vs hide; cancelled 202; round-2 `input_required` metric; timeout; secret-missing fail-closed.

## Phase 5: Docs and verify

- [x] 5.1 Amend `openspec/specs/mcp-dual-era-northbound/spec.md`; document counter in `docs/operational-metrics.md`.
- [x] 5.2 Handler tests: one-round unchanged; two-round fake upstream. `gofmt` + package tests. Strip narrative comments on touched Go.
