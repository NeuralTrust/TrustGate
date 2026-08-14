# Proposal: Mediate Multi Round-Trip Requests (RUN-1101)

## Intent

MCP `2026-07-28` tools may return `input_required`; the client retries with `inputResponses`. TrustGate drops continuation, forces `complete`, and sends empty southbound caps — e2e MRTR fails; unsigned `requestState` is a replay vector.

## Scope

### In Scope
- Preserve `input_required` on modern `tools/call`; HMAC-wrap `requestState`
- Forward opaque `inputResponses` + ticket; full policy pass every POST
- Bind `{consumer, registry, exposed tool, upstream tool, method, round, exp}`
- Forward declared client caps southbound; fill SDK fields
- Advertise MRTR on modern `server/discover` only when e2e
- `notifications/cancelled` → HTTP 202; plugins scan `inputResponses` (never log)
- Ops-gated enum metrics; delta RUN-1103 for `input_required`

### Out of Scope
- `prompts/get` / `resources/read` MRTR (keep `complete`; strip MRTR fields)
- Session stores; policy-skip retries; naive pass-through
- Legacy Sampling/Roots; TrustGate-originated sampling; Tasks; Apps

## Capabilities

### New Capabilities
- `mcp-mrtr-mediation`: Ticket bind, `tools/call` continuation, advertise, limits, metrics

### Modified Capabilities
- `mcp-dual-era-northbound`: `tools/call` may return `input_required`; discover may nest `tools.inputRequests`; cancelled is 202

## Approach

**Approach 1 — Stateless signed-ticket mediation (locked).** One POST = one policy pass. Composer re-resolves by exposed name; ticket mismatch rejects retarget. Reject 2–4.

## Closed Decisions

- Tools-first. Shared ticket types allowed; other methods stay `complete`.
- Dedicated HMAC secret (`MCP_MRTR_TICKET_SECRET`). Fail closed if unset. Not JWT.
- Defaults: 8 rounds; TTL 5m; continuation 256 KiB. Mint ticket even if upstream omitted `requestState`.
- Pass-through declared `inputRequests` kinds; strip others.
- Discover: `tools={"inputRequests":{}}` when e2e; else `{}`. Never on legacy `initialize`. No advertise if all registries are `legacy` or secret missing.
- Codes: `-32023` replay/expired/mismatch; `-32024` round_limit; `-32602` size/shape. Never `-32021`.
- Meter `mcp.northbound.mrtr.outcome_total{outcome,era}` + `round` ∈ {1,2,3+}: `input_required`, `complete`, `cancelled`, `policy_denied`, `timeout`, `round_limit`, `replay_rejected`. Never log user input.

## Affected Areas

- `pkg/api/handler/http/mcp/`: preserve/forward, advertise, cancelled, limits
- `pkg/app/mcp/`: ticket + `CallTool` continuation; plugin scan
- `pkg/infra/mcp/client/`: SDK fields + caps
- metrics / `mcp-dual-era-northbound` spec: outcomes + `resultType` delta

## Risks

- Secret missing/rotation (Med): fail closed; design `kid` rotation
- Plugin bypass / PII (Med): scan `inputResponses`; never log
- Alias retarget (Med): bind exposed + upstream + registry
- PR > 400 lines (High): chain preserve/forward → ticket → advertise+metrics

## Rollback Plan

Revert slices reverse-order. Stop emitting `input_required` and advertisement. Legacy unchanged. Omit secret to fail-closed.

## Dependencies

RUN-1109 on this base. Requires RUN-1103.

## Success Criteria

- [ ] One-round tools unchanged; capable clients see `input_required`
- [ ] Retries reach the original authorized tool
- [ ] Every round re-runs policies; cross-tenant replay rejected
- [ ] Cancel / timeout / round-limit tested; no user input logged
- [ ] Discover advertises MRTR only when e2e; never on legacy initialize
