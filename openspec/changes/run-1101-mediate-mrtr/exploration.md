# Exploration: RUN-1101 mediate Multi Round-Trip Requests (MRTR)

**Change**: `run-1101-mediate-mrtr`
**Linear**: [RUN-1101](https://linear.app/neuraltrust/issue/RUN-1101/featmcp-mediate-multi-round-trip-requests)
**Workspace**: `/Users/edu/Neuraltrust/TrustGate-run-1101`
**Branch**: `feat/run-1101-mediate-mrtr`
**Base**: `feat/run-1103-dual-era-northbound-protocol-boundary` @ `6e8b3c2e`
**Blocked by**: RUN-1109 (telemetry already present on this base)

## Current State

TrustGate is already a **stateless POST-only** MCP gateway. Each `POST /{consumer_slug}/mcp` independently authenticates, classifies era, validates modern wire metadata, resolves/role-scopes the consumer, then dispatches. `Mcp-Session-Id` is ignored and never emitted. There is **no continuation or MRTR state** today.

### Dispatch path (modern `tools/call`)

```
auth → parse/classify/validate → resolve consumer → protocol_acceptance gate
  → role scope → RPCGateway.Dispatch
    → rate limit → PluginRunner.PreRequest → composer.CallTool
      → compose() rediscovers + resolveNames(aliases)
      → dialer.Connect(target) → upstream.CallTool(upstreamName, arguments)
    → PluginRunner.PreResponse → normalizeModernResult → HTTP JSON-RPC
```

Key facts from code:

| Layer | Today | MRTR impact |
|---|---|---|
| `rpc_dispatcher.go` `tools/call` | Unmarshals only `name` + `arguments` | **Drops** `inputResponses` and `requestState` |
| `normalizeModernResult` | Always sets `resultType: "complete"` | **Clobbers** upstream `input_required` (test asserts this) |
| `Composer.CallTool` / `Upstream.CallTool` | `(ctx, name, arguments)` | No continuation fields |
| `modernUpstream.CallTool` | Builds `sdk.CallToolParams{Name, Arguments}` only | SDK already has `InputResponses` + `RequestState`; unused |
| `modernUpstream.metadata()` | `clientCapabilities: {}` | Spec forbids upstreams from sending `inputRequests` the client did not declare — empty caps **block e2e MRTR** |
| `server/discover` | Role-visible `tools`/`prompts`/`resources` as `{}` | No MRTR advertisement |
| Legacy `initialize` | tools/resources/prompts only | Must stay MRTR-free |
| Plugins | Scan `name`+`arguments`; ignore rewritten `name` | `inputResponses` currently **bypass** TrustGuard |
| Binding | `compose()` + `resolveNames` + `ExposeAs` every request | Retry already re-resolves by **exposed name**; no session needed for routing |
| Telemetry (RUN-1109) | `MCPAttrs` era/version; ops meters gated; enum labels; no payloads | Extend with bounded MRTR outcome enums |

MCP `2026-07-28` MRTR ([SEP-2322](https://modelcontextprotocol.io/seps/2322-MRTR)): a supported method may return `resultType: "input_required"` with `inputRequests` and/or opaque `requestState`. The client retries the **same method** with `inputResponses` + echoed `requestState`. Rounds are independent JSON-RPC ids. Spec allows MRTR on `tools/call`, `prompts/get`, and `resources/read`. Linear scope is tools-first; the same normalizer/dispatcher holes affect the other two.

### Dual-era constraints

- MRTR is **modern-only**. Legacy clients must not see `input_required`, `inputResponses`, or MRTR capability hints.
- RUN-1103 spec currently requires every modern success to add `resultType: "complete"` — this delta **must be amended**.
- `-32021` is already used as `codeAcceptanceDenied` (consumer `legacy_only`). RUN-1103 reserved `-32021` for missing client capability (MRTR). **Do not reuse `-32021` for capability-required**; pick a distinct code or map capability gaps to `-32602` / filtered `inputRequests`.

### Continuation / session

None. Composer rediscovers on every call. That is the correct MRTR substrate: **no hidden transport session**. Security still requires a **signed binding ticket** because `requestState` is attacker-controlled once it passes through the client (spec § security).

## Affected Areas

- `pkg/api/handler/http/mcp/modern_response.go` — stop forcing `complete`; preserve `input_required` + `inputRequests` + `requestState` (after ticket wrap)
- `pkg/api/handler/http/mcp/modern_response_test.go` — current test expects clobber; invert for `tools/call` / `prompts/get` / `resources/read`
- `pkg/api/handler/http/mcp/rpc_dispatcher.go` — parse and forward continuation fields; keep plugins + rate limit on every round
- `pkg/api/handler/http/mcp/server_discover.go` — advertise MRTR only when mediation is end-to-end and era is modern
- `pkg/api/handler/http/mcp/mcp_handler.go` — accept `notifications/cancelled` as modern notification (202); do not advertise on legacy `initialize`
- `pkg/api/handler/http/mcp/modern_validation.go` — optional size/shape checks; do not treat continuation as `Mcp-Param-*`
- `pkg/app/mcp/composer.go` + `protocol.go` — extend `CallTool` (and likely `GetPrompt`/`ReadResource`) with opaque continuation; selection stays exposed-name
- `pkg/app/mcp/plugin_runner.go` — include `inputResponses` in PreRequest scan body; never log contents; keep ignoring name rewrites
- `pkg/infra/mcp/client/modern_upstream.go` — set `CallToolParams.InputResponses`/`RequestState`; forward **declared** northbound client capabilities (not `{}`)
- `pkg/infra/mcp/client/client.go` — legacy session `CallTool` must reject/ignore continuation (legacy era)
- `pkg/infra/trace/span.go` + `pkg/infra/metrics/events/event.go` + `pkg/app/metrics/builder.go` — bounded `mrtr_outcome` / `mrtr_round` enums; no user input
- `pkg/api/handler/http/mcp/protocol_metrics.go` — ops counter for MRTR outcomes, gated like validation meters
- `openspec/specs/mcp-dual-era-northbound/spec.md` — delta: `resultType` may be `input_required` on supported methods
- New focused files (recommended): `pkg/app/mcp/mrtr_ticket.go` (HMAC wrap) + handler `mrtr.go` (normalize/advertise/limits)

Unchanged by design: router, auth middleware, role scoper, registry `protocol_mode` semantics, Tasks (RUN-1102), Apps (RUN-1107), legacy Sampling/Roots streams.

## Approaches

1. **Stateless signed-ticket mediation (recommended)** — Keep one POST = one policy pass. Preserve modern MRTR shapes. Wrap/unwrap `requestState` with HMAC binding `{consumer, registry, exposed tool, upstream tool, method, round, exp}` plus the upstream blob. Forward `inputResponses` as opaque JSON after size limits. Re-resolve the tool by exposed name every round; reject ticket mismatch (cross-consumer / cross-registry / alias bypass). Advertise MRTR only on modern `server/discover` when TrustGate can complete the loop (modern northbound + southbound can carry fields + client caps forwarded).
   - Pros: Matches SEP-2322 (no shared store / sticky LB); re-runs authz/plugins/limits every round; blocks replay retargeting; max-round and TTL without session memory; hexagonal (ticket is app/infra, wire stays in handler).
   - Cons: Need a signing secret; wrap/unwrap must be invisible to clients and reversible for upstream; composer/upstream signatures grow.
   - Effort: Medium

2. **In-memory / Redis continuation session** — Store pending MRTR keyed by session or ticket; look up original registry on retry.
   - Pros: Easy max-round / cancel / single-use.
   - Cons: Violates “no hidden transport session state”; breaks multi-replica; conflicts with ignored `Mcp-Session-Id`; sticky-LB smell SEP-2322 exists to avoid.
   - Effort: Medium–High

3. **Naive pass-through (no ticket)** — Forward `inputResponses`/`requestState` unchanged; route only by exposed name.
   - Pros: Smallest diff; SDK fields already exist.
   - Cons: Cannot enforce max-round/TTL; cannot reject cross-consumer replay of stolen `requestState`; empty southbound caps still block e2e; fails Linear QA (“cross-consumer and cross-registry continuation replay rejected”).
   - Effort: Low

4. **Separate MRTR handler / skip policies on retry** — Fast-path retries to the remembered upstream.
   - Pros: Lower latency on round 2+.
   - Cons: Directly violates “re-run authn, authz, toolkit, rate limits, TrustGuard on EVERY round”.
   - Effort: High (and unsafe)

## Recommendation

**Approach 1.** TrustGate already rediscovers and re-authorizes every POST; MRTR should ride that path.

Implementation shape:

1. **Preserve** `input_required` on modern `tools/call` (and, if kept in-scope, `prompts/get` / `resources/read`). List/discover stay `complete`.
2. **Parse** `inputResponses` + `requestState` in the dispatcher; pass opaque bytes through composer → modern dialer. Do not interpret user content.
3. **Bind** with a signed ticket wrapping `requestState` so continuation cannot change consumer, registry, exposed name, or upstream tool. Mint a ticket even when the upstream omitted `requestState` (spec allows `inputRequests`-only).
4. **Re-run** the full pipeline every round. Plugins see `inputResponses` as input; name rewrite still ignored.
5. **Southbound**: populate SDK `CallToolParams` continuation fields; forward the northbound client's declared capabilities (elicitation / MRTR sampling / roots as **pass-through kinds**, not TrustGate-implemented primitives). Empty `{}` stays only for non-MRTR calls or legacy-forced registries.
6. **Advertise** MRTR only on modern `server/discover` once (1–5) work. Never on legacy `initialize`. If every bound registry is `protocol_mode=legacy`, do not advertise (cannot mediate e2e). Do not probe upstreams at discover time.
7. **Limits**: payload cap on continuation fields (tighter than 8 MiB `BodyLimit`); max rounds and TTL inside the ticket; in-flight cancel via `ctx`; accept modern `notifications/cancelled` as 202 no-op (rounds are independent POSTs — no store to cancel).
8. **Telemetry**: ops meter `mcp.northbound.mrtr.outcome_total{outcome,era}` gated by `OPS_METRICS_ENABLED`. Outcomes: `input_required`, `complete`, `cancelled`, `policy_denied`, `timeout`, `round_limit`, `replay_rejected`. Optional bounded `round` bucket (`1`,`2`,`3+`). Never log `inputResponses`, `requestState` plaintext, or elicitation content. Product `events.MCP` may add `mrtr_outcome` enum only.

Reject 2–4.

## Risks

- **Clobber + drop is the live bug**: capable modern clients never see `input_required`; retries never reach upstream with answers.
- **Empty southbound clientCapabilities** make spec-compliant upstreams refuse to emit `inputRequests` — mediation is not e2e until caps are forwarded.
- **Unsigned `requestState`** is a cross-tenant replay vector; ticket secret and rotation must be designed in propose/design.
- **`-32021` collision** with `protocol_acceptance`.
- **Plugin bypass** if `inputResponses` are not scanned; conversely, logging them would leak user input.
- **Alias / collision retarget**: `resolveNames` is deterministic for a stable toolkit, but a stolen ticket for `search` must not apply to `github_search`. Ticket must bind exposed + upstream + registry ids.
- **Legacy Sampling vs MRTR sampling**: out of scope is the *old bidirectional* Sampling/Roots stream. MRTR may still *carry* `sampling/createMessage` / `roots/list` inside `inputRequests` as opaque pass-through when the client declared those caps. Do not implement TrustGate-originated sampling.
- **`prompts/get` and `resources/read`**: spec allows MRTR; Linear text is tools-first. Propose should lock whether this change covers all three or tools only (normalizer still must not clobber the other two if left for a follow-up).
- **400-line PR budget**: likely High — split preserve/forward, ticket+replay, advertise+telemetry.
- **RUN-1103 spec amendment** required; archived dual-era change assumed `complete` forever.

## Open questions for sdd-propose

1. Tools-only vs also `prompts/get` + `resources/read` in this change.
2. Ticket secret source (existing JWT/gateway secret vs dedicated HMAC key).
3. Default max rounds and continuation TTL.
4. Whether MRTR-carried sampling/roots are pass-through or stripped (recommend pass-through if client declared the cap).
5. Exact `server/discover` advertisement shape (capability object vs implicit by preserving `input_required`).
6. Distinct JSON-RPC code for capability/replay/round-limit vs reuse `-32602`.

## Ready for Proposal

Yes. Orchestrator should run **sdd-propose** for `run-1101-mediate-mrtr` with Approach 1 locked unless product rejects the signed ticket.
