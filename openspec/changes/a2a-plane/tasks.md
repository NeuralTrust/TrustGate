# Tasks: A2A plane MVP

Inputs: [`proposal.md`](./proposal.md) (binding), [`design.md`](./design.md) (D1–D14), [`exploration.md`](./exploration.md), specs under [`specs/`](./specs). Paths start at the repo root.

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | TrustGate hand-written ≈4,700: production ≈2,700, tests ≈2,000. app hand-written ≈1,350: production ≈900, tests ≈450. Generated ≈600 (swagger/openapi, mocks). openspec ≈850, outside the budget. |
| 400-line budget risk | High in total. Most slices are ≤ ≈450 hand-written lines; S1, S5b and S5c1 are over and are flagged below. |
| Chained PRs recommended | Yes |
| Suggested split | S1 → S2 → S3a → S3b. S4 and S5a run in parallel with S1. S5b after S1. S5c1 after S2 + S5a + S5b. S5c2 after S4 + S5c1. S6 after S5c1. S7 after S5c2 + S6. S8 last. In app, A0 can ship any time; A1 after the TrustGate PR is deployed; then A2 → A3. |
| Delivery strategy | **Integration branch.** Slice PRs target `feat/a2a-plane`; one final PR `feat/a2a-plane → develop` with `size:exception`. |

Why an integration branch rather than slices straight into `develop`: from S5c1 until S6 and S5c2 land, the gateway would forward A2A traffic without task ownership or policies. That intermediate state must never reach an environment. The repo has done this before (ENG-1618).

Decision needed before apply: Yes. Confirm the integration-branch strategy and open a Linear issue (proposal, open question 3).

How to measure the budget (excludes openspec/ and generated files):
`git diff --shortstat <parent> -- pkg tests docs README.md ':!docs/swagger.*' ':!docs/docs.go' ':!docs/openapi.json' ':!**/mocks/**'`

## Work units

| Unit | Goal | Depends on | Prod / test |
|------|------|------------|-------------|
| S1 | Domain: `TypeA2A`, `A2ATarget`, card validation, digest, `ChangedFields` | — | ≈300 / ≈200 ⚠ |
| S2 | Storage: migration, repository, secrets, snapshot round trip | S1 | ≈115 / ≈100 |
| S3a | Admin: card fetcher (port and netguard adapter), version detection, pin on create and update | S2 | ≈180 / ≈140 |
| S3b | Admin: `preview`, `refresh` and `approve` use case, handlers, routes, swagger | S3a | ≈320 / ≈170 |
| S4 | Policies: associator fix, A2A plan filter, plugin declarations, TrustGuard A2A payload, mask → block | — | ≈165 / ≈150 |
| S5a | MCP plane: generalise `resolveMCPConsumer` and dispatch by type, A2A still answers 404 | — | ≈60 / ≈40 |
| S5b | `pkg/app/a2a` protocol core: version tables, part normalisation, card view, errors | S1 | ≈330 / ≈250 ⚠ |
| S5c1 | Buffered forwarding without plugins: upstream client, forwarder, handler (card GET, POST), wiring, config | S2, S5a, S5b | ≈440 / ≈220 ⚠ |
| S5c2 | A2A plugin runner, `pre_request` and `pre_response` on buffered calls, `a2a` span and telemetry attributes | S4, S5c1 | ≈260 / ≈130 |
| S6 | Task ownership: port, Redis adapter, checks and records in the forwarder | S5c1 | ≈180 / ≈150 |
| S7 | Streaming: per-event inspection, block and cancel, idle timeout | S5c2, S6 | ≈180 / ≈150 |
| S8 | Functional suite (0.3 and 1.0 fake agents, Postgres and DB-less), `docs/a2a.md`, README, `make docs` | all | ≈150 / ≈300 |
| A0 | app: `slugToProtocols` stops claiming A2A for policies the catalog does not list (wrong today: it puts an A2A chip on them) | — | ≈5 / ≈20 |
| A1 | app: Registry Agents tab, add panel with preview, agent card section with diff and approve | S3b deployed | ≈550 / ≈220 ⚠ |
| A2 | app: the Agents plane in Applications (types, General routing, add modal, Connect, Policies, keyring) | A1 | ≈300 / ≈150 |
| A3 | app: A2A kind filters in Requests and Activity, one badge colour, copy pass | A2 | ≈40 / ≈40 |

⚠ Over 400 hand-written lines. In each, tests are most of the excess. Split further only if review asks.

## Tasks

### S1 — Domain

- [ ] 1.1 `TypeA2A` in `pkg/domain/registry/mcp_target.go`; `Registry.A2ATarget`, `NewA2ARegistry`, the `Validate` branch, and `Rehydrate` (`registry.go`). `validateLLM` and `validateMCP` refuse an `a2a_target`.
- [ ] 1.2 `a2a_target.go`: fields per spec `a2a-agent-registry`; `Validate` (version, `card_url` scheme, auth mode subset with 422 for `passthrough`, `exchange` and `forwarded`, `allowed_methods` known for the version).
- [ ] 1.3 `a2a_card.go`: `ValidateCard(raw, version)`, `CardDigest`, `InterfaceURL(version)`, `ChangedFields`.
- [ ] 1.4 Tests: each spec scenario of the registry requirement; digest stable under key order and under `signatures`-only changes.

### S2 — Storage

- [ ] 2.1 Migration `<ts>_registry_a2a_target.go`: `a2a_target JSONB NULL`; `registries_type_check` with `'A2A'`; idempotent up and down in one transaction.
- [ ] 2.2 `pkg/infra/repository/registry`: insert, update, select and list carry `a2a_target`; `secrets.go` encrypts `headers` and `auth.value`, and fills `UnreadableHeaders`, as for MCP.
- [ ] 2.3 Repository integration test (`PG_TEST_URL`) and a snapshot compile round trip test proving `snapshot.proto` is untouched.

### S3a — Pin on create and update

- [ ] 3a.1 `pkg/app/registry/card_fetcher.go`: `CardFetcher` port with `//go:generate mockery`.
- [ ] 3a.2 `pkg/infra/a2a/card_fetcher.go`: `netguard.NewHTTPClient`, `CheckRedirect`, 1 MiB cap, JSON object check.
- [ ] 3a.3 `creator.go` and `updater.go`: fetch, `DetectVersion` when `protocol_version` is empty (D16), `ValidateCard`, store card, digest and timestamp. Client-sent `card*` fields are ignored. Update re-pins only on a change of `card_url` or version.
- [ ] 3a.4 Tests: private IP refused, wrong version → 422 with nothing stored, omitted version → 1.0 when offered else 0.3, update without URL change does not fetch.

### S3b — Preview, refresh and approve

- [ ] 3b.1 `pkg/app/registry/agent_card.go`: `AgentCard{Preview, Refresh, Approve}` (D15). Preview returns card, digest and `versions`. Approve re-fetches, compares, stores, then `invalidation.GatewayData` and `Signal`; equal digest → no-op.
- [ ] 3b.2 Handler and DTOs under `pkg/api/handler/http/registry/` (one DTO per file), swagger annotations, routes under `RequireGatewayAccess` for registries (preview with the create permission), DI in `modules/registry.go`.
- [ ] 3b.3 Tests: spec scenarios (preview with two versions, preview of a gRPC-only card → `versions: []`, new skill, digest moved between refresh and approve → 409, other gateway → 404, non-A2A → 422). `docs/openapi_test.go` asserts the three routes.

### S4 — Policies

- [ ] 4.1 `associator.go:224`: include `TypeA2A`.
- [ ] 4.2 `data_finder.go`: A2A-only plan filter by `SupportedProtocols` (D9).
- [ ] 4.3 `ratelimit` and `requestsize` declare A2A. Check `requestsize` reads `Content-Length` and `ratelimit` keys by consumer on an A2A request context.
- [ ] 4.4 `infracontext.RequestContext.A2A`. `trustguard`: `SupportedProtocols` by `p.v2` (D10); `a2a.go` payload from the normalised body; mask → block with `mask_unsupported` (D11).
- [ ] 4.5 Tests: `tokenratelimit` and `trustguard_v2` attach → 422 on A2A; a global `tokenratelimit` is in the LLM plan and not in the A2A plan; TrustGuard A2A payload (text, data, url, raw over the cap); mask → block.

### S5a — Dispatch seam

- [ ] 5a.1 Generalise `resolveMCPConsumer` into a resolver shared by `GET /*` and `POST /*`. MCP behaviour is byte-identical. One commit, existing MCP handler tests green.
- [ ] 5a.2 Branch on `Consumer.Type`: MCP → today's handler; A2A → a handler that answers 404 until S5c1; LLM → 404 as today.

### S5b — Protocol core

- [ ] 5b.1 `pkg/app/a2a/wire.go`: method tables per version (design, Methods by version), JSON-RPC decode (single object, no batch), task-id and message extraction pinned against a2a-sdk 1.x fixtures for both versions, part normalisation.
- [ ] 5b.2 `card_view.go`: rewrite per spec `a2a-plane-routing`, golden files for 0.3 and 1.0.
- [ ] 5b.3 `errors.go`: `-32090`, `-32091`, `-32092`, and the A2A errors per version.

### S5c1 — Buffered forwarding

- [ ] 5c1.1 `pkg/infra/a2a/upstream_client.go`: netguard client, `none`, `static` and `client_credentials` (existing token source in `pkg/app/mcp/credentials.go`), header allowlist, `A2A-Version`, `X-AG-Trace-Id`, `A2A_MAX_BODY_BYTES`.
- [ ] 5c1.2 `pkg/app/a2a/forwarder.go`: resolve `{agent}`, refuse by kind and `allowed_methods`, call, map upstream failures to `-32092`, keep the caller's JSON-RPC `id`.
- [ ] 5c1.3 `pkg/api/handler/http/a2a/a2a_handler.go`: card GET, JSON-RPC POST (buffered kinds only; stream kinds answer `-32092` until S7).
- [ ] 5c1.4 Config: the four env vars (`pkg/config`, `.env.example`). Module `modules/a2a.go` in the MCP plane's full and DB-less sets.
- [ ] 5c1.5 Tests: header allowlist, refused methods per version, ambiguous agent name → 404, upstream timeout and non-JSON → `-32092`.

### S5c2 — Policies on buffered calls

- [ ] 5c2.1 `pkg/app/a2a/plugin_runner.go` (D8); `pre_request` before the call, `pre_response` on the buffered result per the content rules of `a2a-policy-chain`.
- [ ] 5c2.2 `a2a` span with `A2AAttrs`. Telemetry attributes are additive and declared in `pkg/metrics` per `telemetry-event-contract.mdc`.
- [ ] 5c2.3 Tests: request block → no upstream call; response block → `-32090` instead of the result; span outcome and blocking plugin.

### S6 — Task ownership

- [ ] 6.1 `pkg/app/a2a/ownership.go`: port and rules (owner identity, check before call, record after, conflict → `-32092`).
- [ ] 6.2 `pkg/infra/a2a/ownership_redis.go` (D12), TTL from `A2A_TASK_OWNERSHIP_TTL`, renewed on use.
- [ ] 6.3 Forwarder hooks for every kind in the design table.
- [ ] 6.4 Tests: each spec scenario of `a2a-task-ownership`, Redis down on read (fail closed) and on write (answer delivered, metric).

### S7 — Streaming

- [ ] 7.1 `pkg/app/a2a/stream.go` (D13): content events through `pre_response`, others passed through; ownership recorded from events; idle timeout.
- [ ] 7.2 Block: error event, close, `CancelTask` in a bounded goroutine tied to the shutdown context. No leak under `-race`.
- [ ] 7.3 Handler SSE writer with flush per event.
- [ ] 7.4 Tests: block mid-stream (spec scenario), malformed event, idle timeout, client disconnect cancels the upstream read.

### S8 — Functional and docs

- [ ] 8.1 `tests/functional/a2a_plane_test.go`: fake agents for 0.3 and 1.0; the flows listed in the design's testing strategy; Postgres and DB-less (`TestDBLessDataPlane` style).
- [ ] 8.2 `docs/a2a.md`: setup, card pinning and approval, ownership, refused methods and why, limits, error codes.
- [ ] 8.3 README: FAQ answers and comparison table describe what ships. Delegation and trace linking are listed as coming, not as shipped.
- [ ] 8.4 `make docs`; manual interop smoke with the a2a-sdk 1.x client recorded in the PR body.

### A0 — Policy protocol fallback (app)

- [ ] A0.1 `policies/constants/policies.constants.ts`: `slugToProtocols` never returns `A2A` (C5). Test: a slug missing from the catalog shows LLM and MCP only.

### A1 — Registry Agents tab (app)

- [ ] A1.1 `REGISTRY_TABS` gains the `a2a` entry, labelled *Agents* with action *Add agent*; `isRegistryTabId` and the product tour accept it.
- [ ] A1.2 `AddAgentSidePanel`: card URL → `previewAgentCardAction` → card summary (name, description, skills, versions, the auth the agent asks for) → name, version (highest preselected), sign-in mode (none, static header, OAuth client credentials) → **Pin and add**. A card with `versions: []` explains why it cannot be added.
- [ ] A1.3 `AgentCardSection` on the agent's detail: pinned card, **Check for changes** → diff in words (`agentCardDiff.ts`) → **Approve new card** or **Keep current**; a 409 reloads the diff.
- [ ] A1.4 Tests: preview → create with the preselected version; gRPC-only card; diff wording for added and removed skills, endpoint and security; approve 409.

### A2 — Agents plane in Applications (app)

- [ ] A2.1 `PLANES` includes `A2A` (C2, order C3), so `planeOf` stops dropping A2A consumers; every `Record<Plane, …>` filled; `ApplicationGeneralTab` and `AddToApplicationModal` plane-generic.
- [ ] A2.2 General: Agents routing section with the empty state that creates the consumer; rows without sub-selection (C4).
- [ ] A2.3 Connect: card URL per agent and the a2a-sdk snippet with `X-AG-API-Key`.
- [ ] A2.4 Policies: `PLANE_PROTOCOL.A2A`; the TrustGuard line that says mask blocks on agents. Keyring chips and panel tones.
- [ ] A2.5 Tests: an application with three planes groups, creates and attaches keys; `policiesForPlanes` puts `ratelimit` on Agents and keeps `tokenratelimit` off it.

### A3 — Filters, badges, copy (app)

- [ ] A3.1 Re-add A2A to the protocol and kind filters (`gateway/constants/protocol.ts`, `requests.constants.ts`, `runtimeActivity.constants.ts`), closing the ENG-1203 note.
- [ ] A3.2 One A2A badge tone (C6), checked next to status badges.
- [ ] A3.3 Copy pass in `messages/en`: *Agents* everywhere a plane is named; "A2A" only as a protocol badge.

## Verification (every slice)

- `go build ./...`, `go vet ./...`, `make lint`, `make test-race`; `go vet -tags functional ./tests/...` when `tests/` changes.
- `make generate` for new mockery ports; never hand-written mocks.
- Comment policy: exported doc comments only, swagger annotations kept, no narrative comments or TODOs.
- CI `functional-tests` green.

For app units: the repo's typecheck, lint and Vitest suites, and a manual pass in the console against a gateway running the TrustGate PR.

## PR rules

- Bare titles with the Linear id once it exists, e.g. `feat(a2a): pin agent cards on registry create (RUN-####)`.
- Slice PRs target `feat/a2a-plane`. The final PR to `develop` carries `size:exception` and the measured line breakdown.
- app: A0 is its own small PR to `develop`. A1, A2 and A3 are one PR each, merged only after the TrustGate PR is deployed.
