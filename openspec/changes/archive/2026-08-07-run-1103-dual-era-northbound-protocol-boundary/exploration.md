# Exploration: RUN-1103 dual-era northbound protocol boundary

## Current State

### Source of truth and worktree decision

- Linear: [RUN-1103](https://linear.app/neuraltrust/issue/RUN-1103/featmcp-add-dual-era-northbound-protocol-boundary), Backlog, assigned to Edu, no blockers, blocks RUN-1105.
- Worktree: `/Users/edu/Neuraltrust/TrustGate-run-1103-dual-era-northbound-protocol-boundary`.
- Branch: `feat/run-1103-dual-era-northbound-protocol-boundary`.
- Linear names `develop` as the base, but the user explicitly selected `origin/main`. The worktree is clean and both `HEAD` and `origin/main` resolve to `3f35cc54bbc1754f6d2e22c479850922a22ff01d`; `origin/develop` resolves to `c7d077e8a1eb93b1a70ebbb108ed06d2b655e40d`. All later SDD phases must preserve `origin/main` as the effective base unless the user reverses this decision.
- Artifact mode is hybrid. This repository has `openspec/` but no `openspec/config.yaml`, so this artifact follows the shared default convention and is also persisted to Engram.

### Current request flow

1. `pkg/server/router/mcp_router.go` installs ops metrics and base middleware, exposes OAuth/connect routes, returns 405 for GET and DELETE, then installs authenticated transport and routes every POST path to `mcp.Handler.Handle`.
2. `Handler.Handle` currently resolves the virtual MCP consumer from the authenticated request path before parsing the JSON-RPC body.
3. Role-based consumers are scoped before parsing. `RoleScoper.Scope` resolves OIDC roles and replaces the consumer view with the union of role-visible MCP registries and toolkit entries.
4. The handler then unmarshals `{jsonrpc,id,method,params}`, validates only `jsonrpc == "2.0"` and non-empty method, and returns 202 for any notification.
5. `initialize` and `ping` are handled directly in the HTTP handler.
6. Every other request is passed as `(scoped consumer, method, raw params)` to `RPCGateway.Dispatch`.
7. `RPCGateway` starts telemetry, validates method-specific body params, applies gateway rate limits, invokes plugins where applicable, and calls the existing `appmcp.Composer`.
8. The composer federates tools/resources/prompts across role- or consumer-visible upstream registries, applies toolkit filtering/renaming, and uses a five-minute discovery cache. Per-principal upstream auth already adds a hash of issuer and subject to the internal discovery-cache key.
9. The handler writes legacy JSON-RPC results and errors. JSON-RPC application errors intentionally ride on HTTP 200 so existing MCP clients parse them rather than treating them as transport failures.

### Current protocol behavior

- Supported northbound revisions are `2024-11-05`, `2025-03-26`, and `2025-06-18`.
- `initialize` echoes a supported requested revision or silently falls back to `2025-06-18`.
- The initialization response advertises tools, resources, and prompts and embeds a deterministic consumer/toolkit fingerprint in `serverInfo.version`.
- There is no explicit era classification.
- There is no parsing of request `_meta`, no validation of `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, or `Mcp-Param-*`, and no Base64 sentinel decoder.
- `server/discover` is currently method-not-found.
- Modern `resultType`, result `_meta`, `ttlMs`, and `cacheScope` are not emitted.
- Tool envelopes preserve arbitrary upstream fields through an internal raw JSON payload. Consequently, an upstream `x-mcp-header` annotation would currently pass through unchanged.
- GET and DELETE already return 405 with `Allow: POST`; no session ID is minted by the handler today.
- Focused baseline is green: `go test -race ./pkg/api/handler/http/mcp ./pkg/app/mcp`.

### Protocol facts relevant to RUN-1103

- Revision `2026-07-28` is stateless: every request carries `params._meta["io.modelcontextprotocol/protocolVersion"]` and `params._meta["io.modelcontextprotocol/clientCapabilities"]`.
- Streamable HTTP requires `MCP-Protocol-Version` and `Mcp-Method` on all modern POSTs, plus `Mcp-Name` for `tools/call`, `resources/read`, and `prompts/get`.
- Header/body mismatch or a missing/malformed required mirrored header returns HTTP 400 with `HeaderMismatch` (`-32020`).
- Unsupported revision returns HTTP 400 with `UnsupportedProtocolVersion` (`-32022`) and `data.requested` plus `data.supported`.
- A modern unknown method returns HTTP 404 with JSON-RPC `-32601`; this differs from the current legacy HTTP-200 behavior.
- Successful modern results require `resultType`. Cacheable complete results require non-negative `ttlMs` and `cacheScope`.
- `server/discover` is mandatory for modern servers and returns supported versions, server capabilities, and server identity.
- `Mcp-Session-Id` is ignored in modern requests, never minted or echoed, and DELETE remains 405.
- `ping`, `initialize`, and `notifications/initialized` are legacy-era constructs; `initialize` remains a deliberate legacy selector in this dual-era server.

## Affected Areas

### Direct implementation surface

| Area | Expected impact |
|---|---|
| `pkg/api/handler/http/mcp/mcp_handler.go` | Reorder the handler into parse/classify/validate first, then consumer resolution/role scoping, then era-specific local handling or normalized dispatch. Preserve the legacy response and error path. |
| `pkg/api/handler/http/mcp/rpc_dispatcher.go` | Add the version-neutral `server/discover` operation or a focused discover helper, while keeping all existing composer/plugin behavior unchanged for current methods. |
| `pkg/api/handler/http/mcp/protocol_era.go` | New focused transport file for legacy/modern classification and supported-revision sets. |
| `pkg/api/handler/http/mcp/modern_validation.go` | New focused transport file for `_meta`, header/body checks, Base64 sentinel decoding, unsupported revision data, client-capability object presence, and `Mcp-Param-*` rejection. |
| `pkg/api/handler/http/mcp/modern_response.go` | New focused transport file for modern result normalization, server identity, private cache hints, and recursive `x-mcp-header` removal from northbound tool schemas. |
| `pkg/api/handler/http/mcp/mcp_handler_test.go` | Preserve all legacy tests and add the era/validation/error/status/session/cache/schema/role-scope matrix at the HTTP boundary. |
| `pkg/api/handler/http/mcp/rpc_dispatcher_test.go` | Add `server/discover` capability projection and prove validation failures never reach plugins, rate limiter, or composer. |

The exact new filenames are a design choice, but responsibilities should remain split. Do not create a multi-interface contracts file; no new interface is required for the recommended transport-only design.

### Coupled code that should normally remain unchanged

| Area | Coupling and constraint |
|---|---|
| `pkg/server/router/mcp_router.go` | Already keeps the public POST route and returns 405 for GET/DELETE. A router test may be useful, but implementation change is not expected. |
| `pkg/app/mcp/role_scope.go` | Supplies the effective role-scoped registries/toolkit. Modern validation must run before this use case, but `server/discover` must use its returned view. |
| `pkg/app/mcp/composer.go`, `composer_resources.go`, `composer_prompts.go` | Existing version-neutral execution contract. Do not push HTTP headers, era types, or modern wire DTOs into this application layer. |
| `pkg/app/mcp/protocol.go` | Raw envelope model preserves upstream schema fields. Avoid changing it solely for northbound sanitization; transport output sanitization prevents southbound behavior changes. |
| `pkg/container/modules/mcp.go` | Constructors are already wired by Dig. Focused pure helpers should not require DI changes. |
| `pkg/api/middleware/mcp_metrics.go` and trace code | Pre-dispatch modern errors should continue to skip events; successful `server/discover` needs an explicit telemetry decision so it is not misclassified as an upstream operation. |
| `pkg/infra/cache/ttlmap_manager.go` and `pkg/container/modules/cache.go` | Internal discovery cache is five minutes. This provides a defensible default `ttlMs=300000`, but wire cache scope must remain private. No cache implementation change is required. |
| `tests/functional/mcp_e2e_test.go` | Legacy end-to-end coverage exists. Full dual-era conformance belongs primarily to blocked follow-up RUN-1105; RUN-1103 still needs focused unit/integration coverage. |

## Compatibility Invariants

1. `POST /{consumer_slug}/mcp` remains the only request endpoint.
2. The explicit user-selected base remains `origin/main`, despite Linear naming `develop`.
3. `initialize` always selects legacy semantics, even if modern-looking headers are also present.
4. A known legacy version header selects legacy semantics.
5. Requests with no modern signal remain legacy-compatible during migration.
6. Existing legacy revisions, initialization fallback, notifications, ping, application-error HTTP-200 behavior, tool filtering, masking, rate limiting, consent, and telemetry remain unchanged.
7. Modern metadata is per-request and never stored in the handler or inferred from earlier requests.
8. Modern mirrored headers are untrusted until compared with the parsed body.
9. Modern validation must complete before path matching, role scoping, rate limiting, plugins, composer calls, or upstream discovery. Authentication middleware still precedes the handler by current architecture.
10. Modern `Mcp-Name` comparison uses the decoded UTF-8 value when the exact `=?base64?...?=` sentinel is present.
11. No inbound `Mcp-Param-*` value is trusted or forwarded into execution until schema-to-argument validation is implemented end to end.
12. `Mcp-Session-Id` has no effect on modern handling and is never emitted.
13. The modern response adapter adds wire-only fields without changing the existing gateway/composer signatures or southbound upstream negotiation.
14. `server/discover` uses the already authenticated and role-scoped virtual consumer view; it must not expose registries or primitive kinds unavailable to that role.
15. Modern list/discover results use `cacheScope: "private"` because role grants and per-principal upstream authorization can change the surface. Public caching is unsafe even when a particular inline consumer appears static.
16. Northbound tool schemas omit every recursively nested `x-mcp-header` key, while the internal/southbound envelope remains intact.
17. GET and DELETE remain HTTP 405 with `Allow: POST`.

## Approaches

### 1. Transport envelope with explicit era strategy

Parse a minimal JSON-RPC envelope first, classify the era, run a focused modern validator when selected, then resolve/scope the consumer and dispatch through the existing gateway. Adapt only modern results/errors at the wire.

- Pros:
  - Places trust-boundary checks before routing and policy execution.
  - Preserves the current gateway/composer contract and hexagonal dependency direction.
  - Keeps legacy behavior isolated and testable.
  - Makes modern HTTP status differences explicit without changing legacy application-error semantics.
  - Supports small focused files with no new DI interface.
- Cons:
  - The handler orchestration must be carefully reordered.
  - Modern success/error normalization needs method-aware tests for raw upstream results.
  - `server/discover` capability derivation needs an explicit rule.
- Effort: Medium.

### 2. Separate legacy and modern handlers behind a selector

Keep `Handler.Handle` as a selector and delegate to two complete request pipelines.

- Pros:
  - Strong conceptual separation between eras.
  - Easy to reason about different HTTP status and response shapes.
- Cons:
  - Duplicates consumer resolution, role scoping, telemetry, error translation, and dispatch plumbing.
  - Greater drift risk for authorization and policy behavior.
  - More constructor/interface complexity and likely exceeds the intended focused change.
- Effort: High.

### 3. Push modern protocol types into the application composer

Expand `appmcp.Composer` and protocol models so modern metadata, discovery, cache hints, and schema sanitization are application concerns.

- Pros:
  - Strongly typed modern objects can be reused elsewhere.
  - Composer could expose a single comprehensive discovery projection.
- Cons:
  - Leaks HTTP-era concerns across the hexagonal boundary.
  - Forces mock regeneration and broad edits across application and infra tests.
  - Risks changing southbound envelopes and legacy behavior.
  - `x-mcp-header` removal is specifically a northbound trust-boundary policy, not a composer responsibility.
- Effort: High.

## Recommendation

Use Approach 1.

Recommended pipeline:

1. Parse the JSON-RPC envelope before resolving the consumer.
2. Classify with explicit precedence:
   - `method == "initialize"` → legacy.
   - known legacy `MCP-Protocol-Version` → legacy.
   - any unambiguous modern signal (`2026-07-28` header or modern protocol-version key in `_meta`) → modern validation.
   - no modern signal → legacy-compatible.
   - unknown non-legacy revision → modern protocol error `-32022`, using the declared value as `requested`.
3. For modern requests, validate JSON-RPC shape, `params._meta`, protocol header/meta equality, client-capabilities object presence, method header equality, method-specific decoded name equality, and absence of all `Mcp-Param-*` headers.
4. Only after validation, resolve the consumer and apply role scoping.
5. Handle modern `server/discover` from the effective scoped view. Derive capability kinds from the scoped toolkit:
   - nil toolkit means the virtual consumer permits all currently supported primitive kinds;
   - an explicit empty toolkit advertises none;
   - otherwise advertise only kinds represented by allowed tool, prompt, or resource entries.
   This avoids upstream calls, rate limiting, plugins, consent flows, and cross-role leakage during discovery.
6. Dispatch tools/resources/prompts through the existing `RPCGateway` and composer unchanged.
7. Normalize modern success results at the HTTP boundary by adding `resultType: "complete"` and server identity, then add private cache hints to `server/discover` and list/read operations required by the modern schema. A five-minute list/discover TTL aligns with the existing discovery cache; use private scope. Resource reads should be private and may use `ttlMs: 0` unless product explicitly chooses a freshness window.
8. Recursively remove `x-mcp-header` from serialized modern `tools/list` output after composition/plugin evaluation and before writing the response. Do not mutate cached `appmcp.Tool` payload maps.
9. Keep distinct modern protocol-error writers: 400 for `-32020`, `-32021`, `-32022`; 404 for modern `-32601`; preserve existing legacy HTTP-200 application errors.

## Test Surfaces

### Era classification

- `initialize` wins over all headers/metadata.
- Each known legacy revision selects legacy.
- No header/no `_meta` remains legacy.
- Matching `2026-07-28` header and `_meta` selects modern.
- Unknown revision produces `-32022` with exact requested and supported values.
- Partial or conflicting modern signals follow the product decision recorded below.

### Modern metadata and mirrored headers

- Missing/malformed params or `_meta` → HTTP 400.
- Missing protocol version or client capabilities in `_meta` → HTTP 400 `-32602`.
- Header/meta version mismatch → HTTP 400 `-32020`.
- Missing/mismatched `Mcp-Method` → HTTP 400 `-32020`.
- `Mcp-Name` required only for `tools/call`, `resources/read`, `prompts/get`.
- Plain ASCII, non-ASCII Base64, leading/trailing whitespace Base64, literal-sentinel Base64, invalid Base64, malformed sentinel, and decoded-value mismatch.
- Case-insensitive header names but case-sensitive header values.
- Any inbound `Mcp-Param-*` is rejected before dispatch.
- Inbound `Mcp-Session-Id` is ignored and absent from the response.

### Dispatch isolation

- For every validation failure, assert no role scoper, rate limiter, plugin executor, composer method, or upstream mock is called.
- Modern unknown method returns HTTP 404/`-32601` without composer/plugin calls.
- Legacy unknown method retains current HTTP-200/`-32601`.
- Existing tools/call masking, policy denial, consent, and rate-limit tests remain unchanged.

### Modern responses

- Every successful modern result has `resultType: "complete"` and server identity without losing existing result fields.
- Legacy results remain byte-shape compatible and do not gain modern fields.
- All modern list results have `ttlMs >= 0` and `cacheScope: "private"`.
- `server/discover` lists `2026-07-28`, reports only scoped primitive capabilities, and uses the existing surface fingerprint in server version.
- Two principals with different role grants receive different discover capability surfaces.
- `tools/list` recursively strips `x-mcp-header` while preserving all other JSON Schema fields.
- Modern tool-call raw results remain valid after normalization.

### Transport and telemetry

- POST path remains unchanged.
- GET and DELETE return 405 and `Allow: POST`.
- No response emits `Mcp-Session-Id`.
- Pre-dispatch failures set skip-metrics and create no composer span.
- Decide and assert whether `server/discover` is recorded as local discovery or skipped.
- Run `go test -race ./pkg/api/handler/http/mcp ./pkg/app/mcp`; run broader affected-package vet/lint during verify. Full modern functional conformance remains RUN-1105.

## Open Questions

### Resolvable from code or protocol

| Question | Resolution |
|---|---|
| Must the public endpoint or router change? | No. POST wildcard already serves `/{consumer_slug}/mcp`; GET and DELETE already return 405. |
| Where must strict validation run? | In the HTTP transport before `resolveMCPConsumer`, `RoleScoper.Scope`, rate limiting, plugins, or composer. |
| Does modern metadata belong in the composer contract? | No. The existing `(ctx, scoped consumer, method, params)` contract is version-neutral; metadata/header checks are wire concerns. |
| Are specific client primitive capabilities required for current in-scope methods? | No. The required field itself must be a JSON object on every modern request. `-32021` is needed only when TrustGate actually requires an optional client capability, such as MRTR input, which is out of scope. |
| Should `server/discover` call upstream servers? | No for RUN-1103. The scoped consumer/toolkit already gives a safe configured capability projection; upstream calls would introduce consent, availability, latency, rate-limit, and plugin side effects. |
| Can modern list responses be public-cacheable? | No. Role-scoped toolkits and per-principal upstream credentials make the surface authorization-dependent. Use `private`. |
| Where should `x-mcp-header` be stripped? | At northbound serialization after composition, recursively and without mutating the app-layer raw payload or internal cache. |
| What happens to modern `ping`? | It is not a 2026-07-28 core method; return modern method-not-found. Preserve the local ping result only for legacy traffic. |
| What happens to `notifications/initialized`? | It remains a legacy notification. A modern notification gets no JSON-RPC response, but must still pass modern metadata/header validation before being ignored. |
| Should modern resource-not-found use the legacy `-32002`? | No. `-32002` is reserved from earlier revisions; modern mapping should use `-32602` while legacy retains current behavior. |
| Does authentication still run before protocol validation? | Yes. The router installs auth middleware before the POST handler. RUN-1103 can guarantee validation before consumer routing and policy evaluation, not before authentication, without moving validation into middleware. |
| Is a new DI interface required? | No. Pure classifier/validator/normalizer helpers and the existing `RPCGateway` are sufficient. |

### Genuine product/design decisions to settle in proposal/design

1. **Partial modern intent:** If only one of the modern version header or modern `_meta` key is present, should the request be classified modern and fail closed, or remain legacy-compatible? Recommendation: any explicit `2026-07-28` signal selects modern and the missing counterpart yields `-32020`; otherwise an attacker can downgrade validation by deleting one field.
2. **Unknown revision without `_meta`:** Recommendation: a non-empty unknown/non-legacy protocol header is modern intent and returns `-32022`, not legacy fallback.
3. **Known legacy header plus modern `_meta`:** The stated precedence says known legacy header selects legacy. Confirm that modern `_meta` is ignored in this mixed case rather than treated as a downgrade mismatch.
4. **`Mcp-Param-*` rejection scope:** Should rejection apply to every POST or only modern-classified requests? Recommendation: reject for modern requests; preserve legacy behavior when no modern signal exists unless threat modeling requires a global fail-closed rule.
5. **Modern cache TTLs:** Recommendation: `300000` ms for discover/list results to align with the internal MCP discovery cache and `0` for `resources/read`; all scopes private. Product may prefer `0` everywhere for the first release.
6. **Discover capability semantics:** Confirm that capabilities represent configured role-visible primitive kinds, not successful live upstream probes or non-empty current lists. The former is deterministic and avoids availability leakage.
7. **Discover capability shape:** Confirm whether empty capabilities should omit tools/resources/prompts or include empty objects for every TrustGate-supported primitive. Recommendation: omit kinds denied by the scoped toolkit and include `{}` for allowed kinds.
8. **Supported versions in modern discovery/error:** Should `supportedVersions`/`data.supported` list only `2026-07-28`, or all modern and legacy revisions? Recommendation: discovery for a dual-era server may list all implemented revisions, but modern retry guidance is clearer if ordering is newest first. This must align with expected RUN-1105 clients.
9. **Server identity on every modern result:** The modern spec says it should be included. Confirm whether RUN-1103 should add it universally or only to `server/discover`. Recommendation: add it universally in the modern response adapter.
10. **Telemetry for `server/discover`:** Should it be skipped like ping/notifications, or emitted as a local discovery operation with no upstream? Recommendation: record it as MCP discovery for observability, with zero upstream targets, unless metrics cardinality/noise argues for skipping.
11. **Modern notification HTTP status:** Current legacy notifications return 202. Confirm whether modern validated notifications should also return 202 or strict transport semantics require 204/200. Recommendation: retain 202 for compatibility unless conformance tests dictate otherwise.
12. **Malformed JSON precedence:** Authentication middleware currently runs first. Within the handler, parse error should precede route/role lookup. Confirm that revealing a protocol parse error before consumer-path existence is acceptable for authenticated callers.

## Risks

- The largest security risk is validating after path/role/plugin selection; reordering is mandatory to prevent header/body confusion and to satisfy the early-rejection acceptance criterion.
- Era downgrade ambiguity can create a validation bypass if partial modern requests silently enter legacy mode.
- A shared/public cache hint could leak role- or credential-specific tools across users even though the internal cache is per principal for OAuth registries.
- Mutating `appmcp.Tool` raw payload maps during sanitization could corrupt cached discovery objects and create race conditions; sanitize a serialized copy.
- Adding modern fields directly to raw upstream JSON can fail if an upstream returns a non-object result. The adapter needs a deterministic error policy and tests.
- Current legacy tests do not cover role-scoped handler behavior, only the role-scoper use case. `server/discover` needs an HTTP-level role isolation test.
- Modern HTTP status requirements differ from the current intentional HTTP-200 JSON-RPC application-error policy. Era-aware writers are necessary to avoid breaking legacy clients.
- `server/discover` implemented by calling existing list operations would unexpectedly trigger rate limits, policies, consent, and upstream I/O; capability projection should remain local.
- The work will likely exceed the 400-line review budget once the validation matrix is included. SDD tasks should forecast a split, likely protocol classifier/validator first and modern dispatch/response/discovery second, while preserving one coherent feature branch chain.
- RUN-1105 is blocked by this change; ambiguous wire decisions should be fixed before its conformance matrix is authored.

## Ready for Proposal

Yes. Proceed to `sdd-propose` with the transport-envelope approach, preserve `origin/main` as the explicitly selected base, and resolve the twelve product/design questions above before `sdd-design` or implementation.
