# Proposal: Harden API-key connect security and observability

## Intent

Harden RUN-1141’s public API-key connect flow against distributed credential abuse and secret disclosure while making successful linking auditable and preserving OAuth2 compatibility.

## Scope

### In Scope
- Rate-limit every `POST /:slug/connect` by source and resolved consumer.
- Preserve uniform authorization misses; add generic `429` and fail-closed `503`.
- Enforce no-store/no-referrer and secret non-disclosure through regression coverage.
- Emit identifier-only ticket/link/unlink audit events.
- Classify connect paths as MCP OAuth metrics and conditionally emit Bearer challenges.
- Preserve reusable connect tickets at 15 minutes and one-time OAuth states at 10 minutes.

### Out of Scope
- Human attribution behind shared API keys.
- Provider revocation redesign.
- Global OAuth credential ownership or a durable audit ledger.

## Capabilities

### New Capabilities
- `mcp-connect-security-observability`: Abuse controls, lifecycle audit, bounded route metrics, and challenge policy for MCP connect flows.

### Modified Capabilities
- `api-key-self-service-connect`: Add rate limits, fail-closed behavior, lifecycle identifiers, and security-header/leakage guarantees without changing target-first authorization.

## Approach

- Add a dedicated Redis fixed-window limiter, enabled by default at 10/source/minute and 100/consumer/minute. Use versioned, domain-separated HMAC-SHA-256 bucket keys and return no bucket details.
- Derive source from the canonical peer; trust `X-Forwarded-For` only behind configured trusted CIDRs.
- Add `ConsumerID` and `AuthID` to tickets. Emit JSON `slog` audit events only after successful persistence and only for identity-complete API-key-origin tickets; use `MCPAuth.Provider`.
- Reuse path-first OAuth eligibility via a request-local boolean; forms never challenge, known API-key-only consumers suppress it, and unknown paths retain compatibility.
- Match connect route shapes using bounded metric enums. Keep `ticketTTL=15m` with reusable `GET` tickets and `connectTTL=10m` with one-time state `GETDEL`; do not change either constant.

## Chain/Base Strategy

Implement on `fix/api-key-connect-security-observability` from `feat/api-key-self-service-connect-endpoint` at `fd8782b5`. The child PR targets that feature branch, never `develop`; retarget/rebase if its diff includes unrelated chain slices.

## Affected Areas

| Area | Impact |
|---|---|
| `pkg/app/oauth`, `pkg/infra/{ratelimit,oauth}` | Limiting, ticket identity, audit |
| `pkg/api/handler/http/oauth`, `pkg/api/middleware` | HTTP policy, metrics, challenge |
| `pkg/config`, `pkg/container/modules`, `.env.example` | Validated settings and wiring |
| `pkg/server/router` and focused tests | End-to-end regressions |

## Risks

- Unconfigured proxy CIDRs produce coarse peer buckets; safe default prevents spoofing.
- Fixed windows allow boundary bursts; distributed sources can exhaust consumer quota.
- Audit durability depends on platform log retention; mixed-version tickets omit new events.
- Scope may exceed the 400-line review budget and require further child slices.

## Rollback Plan

Revert the child branch/PR. If operational mitigation is needed first, disable the dedicated limiter while retaining uniform errors, no-leakage protections, and existing ticket/state semantics.

## Dependencies

- Redis and existing `SERVER_SECRET_KEY`.
- Infrastructure-confirmed immediate GKE proxy CIDRs before trusting forwarding headers.
- RUN-1141 base at `fd8782b5`.

## Success Criteria

- [ ] Limits enforce 10/source/minute and 100/consumer/minute; backend failure returns generic `503`.
- [ ] All auth misses remain indistinguishable and submitted secrets appear nowhere observable.
- [ ] Audit uses the exact identifier allowlist and successful lifecycle boundaries.
- [ ] Connect metrics/challenges follow resolved policy without OAuth2 regressions.
- [ ] Tickets remain reusable for 15 minutes, OAuth states remain one-time for 10 minutes, and lint, unit, and race suites pass.
