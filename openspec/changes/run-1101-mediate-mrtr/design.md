# Design: Mediate Multi Round-Trip Requests (RUN-1101)

## Technical Approach

Approach 1 (locked): HMAC ticket on modern `tools/call`. One POST = full authz/plugins/limits. Composer re-resolves by exposed name; ticket bind rejects retarget. Specs: `mcp-mrtr-mediation`; delta `mcp-dual-era-northbound` (`input_required` on `tools/call` only).

## Architecture Decisions

| Decision | Options | Choice | Rationale |
|----------|---------|--------|-----------|
| Ticket | JWT vs HMAC | `tg1.<kid>.<b64url(json)>.<b64url(hmac-sha256)>` | Not JWT; SDK `requestState` is `string` |
| Secret | Reuse JWT key vs dedicated | `MCP_MRTR_TICKET_SECRET` + optional `_PREV` | Isolation; empty current = fail-closed |
| Rotation | One key vs kid | Mint `c`; verify `c` then `p` (`hmac.Equal`) | Overlap without a kid registry |
| CallTool | Extra args vs ctx vs struct | `appmcp.ToolCall` on Composer + Upstream | Hexagonal; no context smuggling |
| Caps | `{}` vs forward | Allowlisted `_meta` caps on request ctx | Spec forbids undeclared `inputRequests` |
| Discover | Probe vs local | Secret set **and** ≥1 registry not `legacy` | No discover-time dial |
| Non-tools | Preserve vs clobber | Force `complete`; strip MRTR fields | Tools-first |
| Fail-closed | 5xx vs degrade | No advertise; strip `input_required`; ticket → `-32023` | Rollback = omit secret |
| Plugins | Scan ticket | Scan `inputResponses` only | PII in answers; ticket is HMAC |
| Cancel | Store vs 202 | `notifications/cancelled` → 202 + `cancelled` | No session; modern notifs already 202 |

## Data Flow

```
POST /{slug}/mcp tools/call
  auth → classify/validate → resolve → plugins+limits (every round)
    → Composer.CallTool(ToolCall)
         compose()+resolveNames(exposed)
         Unwrap → bind {cid,rid,exposed,upstream,method} + round/exp
         Upstream.CallTool(SDK InputResponses + unwrapped RequestState)
         if input_required && signer on: Mint (round+1, TTL 5m)
    → normalizeModernResult keeps input_required on tools/call only
    → JSON-RPC (requestState = ticket)

notifications/cancelled (no id) → 202 + outcome=cancelled
```

Round 1 = first POST (no ticket). Ticket stores the producing round. Inbound `claims.Round >= 8` → `-32024` (max 8 POSTs).

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `pkg/app/mcp/mrtr_ticket.go` (+ `_test.go`) | Create | Signer, claims, mint/unwrap, `Enabled()` |
| `pkg/app/mcp/protocol.go` | Modify | `ToolCall`; `CallTool(ctx, ToolCall)` on Composer/Upstream |
| `pkg/app/mcp/composer.go` | Modify | Unwrap+bind; mint on `input_required` |
| `pkg/app/mcp/plugin_runner.go` | Modify | Scan/rewrite `inputResponses`; ignore name; no ticket in body |
| `pkg/app/mcp/errors.go` | Modify | Sentinels → `-32023`/`-32024` |
| `pkg/app/mcp/mocks/mcp_composer_mock.go` | Modify | `go:generate mockery` |
| `pkg/api/handler/http/mcp/rpc_dispatcher.go` | Modify | Parse continuation; 256 KiB; forward `ToolCall` |
| `pkg/api/handler/http/mcp/modern_response.go` | Modify | Preserve `input_required` on `tools/call`; strip others |
| `pkg/api/handler/http/mcp/server_discover.go` | Modify | `tools={"inputRequests":{}}` when e2e |
| `pkg/api/handler/http/mcp/mcp_handler.go` | Modify | Caps on ctx; cancelled metric; wire signer |
| `pkg/api/handler/http/mcp/protocol_metrics.go` | Modify | `mcp.northbound.mrtr.outcome_total` |
| `pkg/infra/mcp/client/modern_upstream.go` | Modify | SDK fields; `metadata()` from ctx caps |
| `pkg/infra/mcp/client/{client,cached_dialer,negotiating_dialer}.go` | Modify | `ToolCall`; legacy drops continuation |
| `pkg/config/config.go` | Modify | Secret + prev + defaults (8, 5m, 256KiB) |
| `pkg/container/modules/mcp.go` | Modify | Provide `TicketSigner` |
| `pkg/infra/trace/span.go` | Modify | Bounded `MRTROutcome`, `MRTRRound` |
| `pkg/infra/metrics/events/event.go` + `pkg/app/metrics/builder.go` | Modify | Fold `mrtr_outcome` / `mrtr_round` |
| `openspec/specs/mcp-dual-era-northbound/spec.md` | Modify | `tools/call` may be `input_required` |
| `docs/operational-metrics.md` | Modify | New counter |
| `*_test.go` peers above | Modify | Invert clobber; advertise; replay; plugins |

Unchanged: router, auth, role scoper, Tasks, Apps, legacy initialize, probe caps `{}`. Secret is env-only — not `k8s/overlays/*/config.env`.

## Interfaces / Contracts

HMAC over `tg1.<kid>.<payload>`:

```
{"v":1,"cid":"<uuid>","rid":"<uuid>","expn":"<exposed>","upn":"<upstream>","m":"tools/call","r":1,"exp":<unix>,"st":"<upstream state or empty>"}
```

`ToolCall`: `Name`, `Arguments json.RawMessage`, `InputResponses json.RawMessage`, `RequestState string` (north=ticket; south=unwrapped `st`).

SDK v1.7: `CallToolParams.InputResponses` (`InputResponseMap`), `RequestState string`. Caps allowlist: `elicitation`, `sampling`, `roots`. Strip unknown `inputRequests` kinds northbound.

| Code | When (never `-32021`) |
|------|------------------------|
| `-32023` | HMAC fail, expired, bind mismatch, secret missing + ticket |
| `-32024` | `round >= 8` |
| `-32602` | size > 256 KiB or bad shape |

JSON-RPC on HTTP 200 except existing policy/rate denials.

Ops (`OPS_METRICS_ENABLED`): `mcp.northbound.mrtr.outcome_total{outcome,era,round}`  
`outcome` ∈ `input_required\|complete\|cancelled\|policy_denied\|timeout\|round_limit\|replay_rejected`; `round` ∈ `1\|2\|3+`. Never log answers or ticket plaintext.

## Testing Strategy

| Layer | What | Approach |
|-------|------|----------|
| Unit | Ticket HMAC/exp/kid/bind | Table tests, injectable clock |
| Unit | Normalizer / discover / plugins / dispatcher | Invert clobber; advertise iff e2e; scan answers not ticket; size `-32602` |
| Unit | Composer / southbound / metrics | Replay/alias `-32023`; round `-32024`; SDK fields; legacy drop; cancelled 202 |
| Integration | Handler | One-round unchanged; two-round fake upstream |
| E2E | `multi-agent-tests` | Capable client (follow-up, not this slice) |

## Migration / Rollout

No migration. Chain: (1) preserve/forward/SDK caps (2) ticket+replay (3) advertise+metrics. Omit secret to fail-closed. Revert reverse-order.

## Open Questions

- None blocking. Keep `InputResponses` as `json.RawMessage` until `modern_upstream` unmarshals into the SDK map.
