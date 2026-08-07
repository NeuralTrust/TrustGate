# Proposal: Dual-era northbound MCP protocol boundary

## Intent

Add MCP 2026-07-28 northbound support at TrustGate's HTTP boundary while preserving legacy behavior and `POST /{consumer_slug}/mcp`. The effective implementation base is `origin/main`, overriding Linear's `develop`.

## Scope

### In Scope
- Classify requests as legacy or modern before consumer resolution.
- Validate modern protocol metadata, mirrored headers, method/name headers, Base64 sentinel names, and reject `Mcp-Param-*` before routing or policies.
- Normalize both eras into the existing gateway/composer; adapt modern responses only at the boundary.
- Add role-scoped local `server/discover`, `-32022`, private cache hints, server identity, and recursive northbound `x-mcp-header` removal.
- Preserve modern notification HTTP 202, ignore `Mcp-Session-Id`, and keep DELETE at 405.

### Out of Scope
- Upstream negotiation, MRTR, Tasks, Apps, subscriptions, Roots, Sampling, and Logging.

## Capabilities

### New Capabilities
- `mcp-dual-era-northbound`: Era selection, modern validation, discovery, response adaptation, and legacy compatibility.

### Modified Capabilities
- None; no matching baseline OpenSpec capability exists.

## Approach

Use an explicit transport envelope: parse, classify, and validate; then resolve and role-scope; then execute local discovery or existing dispatch. No new interface is required. `server/discover` projects configured role-visible kinds without probes or upstream targets.

## Closed Decisions

- `initialize` and known legacy headers select legacy; extra modern metadata is ignored.
- Any explicit `2026-07-28` signal selects modern; a missing counterpart yields `-32020`. Unknown non-legacy headers yield `-32022`.
- Modern-only `Mcp-Param-*` rejection.
- Cache hints: private; `300000` ms for discover/lists, `0` for `resources/read`.
- Allowed kinds use `{}`; denied kinds are omitted.
- Supported revisions, newest-first: `2026-07-28`, `2025-06-18`, `2025-03-26`, `2024-11-05`.
- Every modern result includes `io.modelcontextprotocol/serverInfo`.
- Authenticated parse errors may precede consumer-path resolution.

## Affected Areas

| Area | Impact |
|---|---|
| `pkg/api/handler/http/mcp/` | Handler ordering, classifier, validator, local discovery, response adapter, tests |
| `pkg/app/mcp/` | Existing composer behavior retained; behavioral coverage |

## Risks

- Era downgrade or status-code regressions could break security or legacy clients.
- Sanitizing cached payloads in place could race or corrupt shared state.
- Role discovery could leak capabilities if built outside the scoped view.
- Validation tests may exceed the 400-line review budget; plan chained/stacked slices.

## Rollback Plan

Revert the boundary classifier, modern validator/adapter, and local discovery together; legacy routing and composer contracts remain intact.

## Dependencies

- RUN-1103 blocks RUN-1105; no new runtime dependency.

## Success Criteria

- [ ] Legacy tests and behavior remain green.
- [ ] Modern mismatches fail before scoping, plugins, rate limits, or composer.
- [ ] Discovery is role-scoped and local; unsupported versions return `-32022` with requested/supported.
- [ ] Modern session, cache, schema, notification, and 405 semantics match the binding QA.
- [ ] Affected packages pass `go test -race`, vet, and lint.
