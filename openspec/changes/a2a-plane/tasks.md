# Tasks: A2A agent plane

Inputs: [`proposal.md`](./proposal.md) (binding), [`design.md`](./design.md) (D1–D22, C1–C11), [`exploration.md`](./exploration.md), specs under [`specs/`](./specs). TrustGate paths from the repo root; app paths as in the design (`F/`, `V/`, `R/`).

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | TrustGate hand-written ≈6,200 (production ≈3,550, tests ≈2,650). app hand-written ≈1,800 (production ≈1,190, tests ≈610). Generated ≈700 (swagger, openapi, mocks, Prisma). openspec ≈1,600, outside the budget. |
| 400-line budget risk | High in total. Most slices are ≤ ≈500 hand-written lines; S6 and A2 are over and flagged ⚠. |
| Chained PRs recommended | Yes |
| Delivery strategy | **TrustGate:** integration branch `feat/a2a-plane`. Slice PRs target it; one final PR to `develop` with `size:exception`. **app:** one PR per unit to `develop`. |

Decision needed before apply: **Yes.** Open a Linear issue, confirm the integration-branch strategy, and resolve open question 3 (agents hosts) before S12.

Budget measure (excludes openspec and generated files):
- TrustGate: `git diff --shortstat <parent> -- pkg cmd tests docs k8s README.md Makefile docker-compose.api.yaml ':!docs/swagger.*' ':!docs/docs.go' ':!docs/openapi.json' ':!**/mocks/**'`
- app: `git diff --shortstat <parent> -- app __tests__ messages prisma ':!prisma/migrations/**'`

## Work units

| Unit | Goal | Depends on | Prod / test |
|------|------|------------|-------------|
| S1 | Domain: `TypeA2A`, `A2ATarget`, card helpers, version detection, digest, diffs | — | 330 / 230 |
| S2 | Storage: migration, repository, field encryption | S1 | 160 / 120 |
| S3a | Admin create/update: card fetcher, pinning, DTOs, handlers | S2 | 300 / 200 |
| S3b | Admin preview, refresh, approve | S3a | 300 / 180 |
| S4 | Policies: associator, A2A plan filter, plugin declarations, TrustGuard A2A, request context | — | 170 / 150 |
| S5a | Plane skeleton: `agent` plane, router with health only, config, o11y, STS module move, DI smoke | — | 260 / 60 |
| S5b | Agent auth and resolution: path resolver, `MatchAgentPath`, auth middleware, metrics, usage guard | S5a | 280 / 220 |
| S5c | Protocol core: version tables, decode, normalisation, card view, errors | S1 | 340 / 260 |
| S6 ⚠ | Buffered forwarding: upstream client, forwarder, plugin runner, handler, `modules/a2a.go` | S2, S4, S5b, S5c | 450 / 260 |
| S7 | Credentials and delegated identity, JWKS on the agent plane | S6 | 180 / 160 |
| S8 | Task ownership | S6 | 190 / 160 |
| S9 | Streaming | S7, S8 | 200 / 170 |
| S10 | Telemetry: events, span, builder, OTLP keys, contract doc | S6 | 160 / 90 |
| S11 | `whoami.agents` and `hosts.agent` | S1, S5a | 70 / 70 |
| S12 | Deployment, functional suite, docs | all | 150 + yaml / 320 |
| A0 | app: `slugToProtocols` default | — | 5 / 20 |
| A1 | app: gateway connection learns the agents host | S11 deployed | 90 / 80 |
| A2 ⚠ | app: Registry Agents tab | S3b deployed, A1 | 650 / 260 |
| A3 | app: Agents plane in Applications | A2 | 380 / 220 |
| A4 | app: filters, badges, copy, docs | A3 | 60 / 30 |

Order on the integration branch: S1 → S2 → S3a → S3b, with S4, S5a and S5c in parallel. Then S5b → S6 → (S7, S8, S10, S11) → S9 → S12. Until S7, S8 and S9 land, the branch forwards without identity, ownership or streams. That is why nothing merges into `develop` before the final PR.

## Tasks — TrustGate

### S1 — Domain
- [ ] 1.1 `TypeA2A` (`mcp_target.go`); `Registry.A2ATarget`, `NewA2ARegistry`, `Validate` branch, `validateLLM`/`validateMCP` refuse `a2a_target`, `RehydrateParams.A2ATarget` (`registry.go`).
- [ ] 1.2 `a2a_target.go`:
  - `A2AProtocolVersion`, `A2ATarget` (design §1.2);
  - `Validate`: schemes, reserved headers, auth subset with 422 messages for `passthrough`, `forwarded` and `impersonation`, methods per version;
  - `Endpoint()`, `ResolveSecretsFrom`.
- [ ] 1.3 `a2a_card.go`: `ValidateCard`, `DetectVersions` (0.3 `url`, `protocolVersion`, `additionalInterfaces`; 1.0 `supportedInterfaces`), `CardDigest`, `InterfaceURL`, `ChangedFields`, `SkillDiff`.
- [ ] 1.4 Tests: every scenario of `a2a-agent-registry` that the domain decides; digest stable under key order and `signatures`; detection matrix.

### S2 — Storage
- [ ] 2.1 Migration `<ts>_registry_a2a_target.go`: `ADD COLUMN IF NOT EXISTS a2a_target JSONB`; CHECK `('LLM','MCP','A2A')`; down drops the column and restores the CHECK only if no A2A rows exist (else error).
- [ ] 2.2 `repository.go`: `a2a_target` in insert, update, select and list; `marshalA2ATarget`, `openA2ATargetForRead`.
- [ ] 2.3 `secrets.go`: seal `a2a_target.auth.value`, `.auth.client_secret` and `.headers.<name>`; keep unreadable ciphertext on update.
- [ ] 2.4 Tests: integration (`PG_TEST_URL`) with encryption on and off; snapshot compile round trip with `snapshot.proto` unchanged.

### S3a — Create and update
- [ ] 3a.1 `app/registry/card_fetcher.go` (port, mockery) and `infra/a2a/card_fetcher.go`: probe order, `.json` and `/agentCard/v1.0` direct, netguard, 1 MiB, `A2A_CARD_FETCH_TIMEOUT`.
- [ ] 3a.2 DTOs: `A2ATargetRequest` (create and update), `A2ATargetResponse` with masked secrets and `endpoint`; `CreateRegistryRequest.Validate` A2A branch.
- [ ] 3a.3 `creator.go` A2A branch before the LLM default; `updater.go` `applyA2ATargetUpdate` (re-pin only on `card_url` or version change).
- [ ] 3a.4 Tests: base URL with a legacy card path; private IP refused; version not offered → 422; reserved header; update of headers does not fetch; masked secret kept.

### S3b — Preview, refresh, approve
- [ ] 3b.1 `app/registry/agent_card.go` (`Preview`, `Refresh`, `Approve`); sentinels `ErrAgentCardUnavailable`, `ErrAgentVersionUnsupported`, `ErrAgentCardChanged`, `ErrNotAgentRegistry`.
- [ ] 3b.2 Handlers and DTOs (one per file); routes in the registries group, `preview-agent-card` before `/:id`; DI in `modules/registry.go`; swagger annotations; `make docs`; `docs/openapi_test.go` asserts the three routes.
- [ ] 3b.3 Tests: every scenario of those requirements (gRPC-only preview, new skill, digest moved → 409, version dropped → 422, other gateway → 404, non-A2A → 422).

### S4 — Policies
- [ ] 4.1 `associator.go:224` includes `TypeA2A`.
- [ ] 4.2 `data_finder.go`: A2A-only protocol filter (D11).
- [ ] 4.3 `ratelimit` and `requestsize` declare A2A; check `requestsize` reads the real `Content-Length` and `ratelimit` keys by consumer.
- [ ] 4.4 `RequestContext`: `A2A`, `A2AMethod`, `A2ATaskID`. `trustguard`: `SupportedProtocols` by `p.v2`; `a2a.go` payload; mask → block with `mask_unsupported`.
- [ ] 4.5 Tests: `tokenratelimit` and `trustguard_v2` attach → 422 on A2A; global `tokenratelimit` absent from the A2A plan and present in the LLM plan; TrustGuard A2A payload (text, data, url, raw over the cap).

### S5a — Plane skeleton
- [ ] 5a.1 `modules/sts.go`: move the signer provider out of `modules/mcp.go:74-89`, no behaviour change, in its own commit. Expose whether the key is ephemeral.
- [ ] 5a.2 `PlaneAgent`; `isDataPlane` (both copies); module sets; `server_agent.go`; `agent_router.go` with health routes only; `runAgent` and dispatch in `main.go`.
- [ ] 5a.3 Config: `SERVER_AGENT_PORT`, `AGENT_BASE_DOMAIN`, `AGENT_EXTRA_BASE_DOMAINS`, `A2A_*` (design §1.10), with `Validate` rules and `.env.example`.
- [ ] 5a.4 `o11y.PlaneAgent`; `classifyRoute` classes; `di_smoke_test.go` includes `"agent"`; `make run-agent`.

### S5b — Auth and resolution
- [ ] 5b.1 `path_resolver.go`: agent host parsing and `SlugFromAgentPath`; `consumer_data.go`: `MatchAgentPath`.
- [ ] 5b.2 `auth_chain.go`: agent scope; session tokens stay MCP-only. `agent_auth.go`: resolve, attach, end-user swap, consumer match, `hasAuth`, `auth_binding` → 401/403.
- [ ] 5b.3 `agent_metrics.go` (kind `a2a`, `X-AG-Trace-Id`); `UsageGuard.ForAgent()` (`-32092 plan_unavailable`); wire the agent transports.
- [ ] 5b.4 Tests: auth matrix; MCP resolution unchanged (existing tests plus one pinning MCP scope); a non-A2A consumer gets 404 on the agent plane.

### S5c — Protocol core
- [ ] 5c.1 `app/a2a/wire.go`: method tables, single-object decode, `-32700`/`-32600`/`-32601`, ownership ids and parts per kind. Record fixtures from the a2a-sdk 1.x client for both versions under `testdata/`.
- [ ] 5c.2 `card_view.go` with golden files (unknown fields kept, signatures dropped, skill security removed, capabilities off).
- [ ] 5c.3 `errors.go`: gateway codes and A2A errors per version.

### S6 — Buffered forwarding ⚠
- [ ] 6.1 `infra/a2a/upstream_client.go`: header allowlist built from scratch; `A2A_MAX_RESPONSE_BYTES`; timeouts.
- [ ] 6.2 `app/a2a/plugin_runner.go` (D10) and `forwarder.go` (design §1.4 steps 1–13, with credentials stubbed to `none` and `static`, and ownership stubbed).
- [ ] 6.3 `api/handler/http/a2a/a2a_handler.go` (`Card`, `RPC` buffered; stream kinds answer `-32092` until S9); `modules/a2a.go`; routes.
- [ ] 6.4 Tests: header allowlist; refusals per version; ambiguous name → 404; upstream timeout, non-JSON and oversize → `-32092`; request and response block → `-32090`.

### S7 — Credentials and identity
- [ ] 7.1 `app/a2a/credentials.go` (design §1.5): `client_credentials` through the MCP token client with its own cache; `exchange` per pattern; `-32093` and `identity_exchange_failed`.
- [ ] 7.2 JWKS route on the agent router; ephemeral-key guard (`signing_key_unavailable`).
- [ ] 7.3 Tests: claims for IdP, end-user and app subjects (`act` and `orig_iss` presence); `obo` without a user; cache key includes the audience; JWT verifies against the agent plane's JWKS.

### S8 — Ownership
- [ ] 8.1 `app/a2a/ownership.go` (port and rules) and `infra/a2a/ownership_redis.go` (in the style of `connect_store.go`).
- [ ] 8.2 Forwarder hooks for every kind; conflict → `-32092`; read failure → `-32092`; write failure → answer kept, plus log and metric.
- [ ] 8.3 Tests: every scenario of `a2a-task-ownership`, against miniredis or a real Redis.

### S9 — Streaming
- [ ] 9.1 `app/a2a/stream.go`: per-event inspection, ownership from events, idle and max-duration timers, block → error event, close and bounded cancel.
- [ ] 9.2 Handler SSE writer with a flush per event; client disconnect cancels the upstream.
- [ ] 9.3 Tests (with `-race`): block mid-stream, idle, max duration, malformed event, disconnect; no goroutine leak.

### S10 — Telemetry
- [ ] 10.1 `events.KindA2A`, `events.Event.A2A`; `trace.A2AAttrs`, `SetA2ARequest`, `SetA2AStatus`; `builder.buildA2A`; OTLP keys (design §1.8).
- [ ] 10.2 `docs/telemetry/otlp-metadata-contract.md`; the LLM and MCP events stay byte-identical (golden test).

### S11 — whoami and hosts
- [ ] 11.1 `WhoAmIAgent`, `WhoAmIConsumer.Agents`, `consumerURL` A2A case.
- [ ] 11.2 `GatewayHosts.Agent` when `AGENT_BASE_DOMAIN` is set.
- [ ] 11.3 Tests: the spec scenarios, plus "no domain → no url, empty agents".

### S12 — Deployment, functional, docs
- [ ] 12.1 k8s base (deployment, service, hpa, pdb, httproute, healthcheck, kustomization) and overlays (design §1.11); compose; Makefile.
- [ ] 12.2 `tests/functional/a2a_*_test.go`: the flows in the design's testing strategy, on Postgres and DB-less.
- [ ] 12.3 `docs/a2a.md`: setup, hosts, card pinning, identity modes with a verification snippet, ownership, refused methods, limits, error codes. Update the README FAQ and comparison table.
- [ ] 12.4 Manual interop smoke with the a2a-sdk 1.x client, both versions, recorded in the final PR.

## Tasks — app

### A0 — Policy protocol fallback
- [ ] A0.1 `slugToProtocols` default `['LLM','MCP']`; test.

### A1 — Gateway connection
- [ ] A1.1 `GatewayConnection.agentHost`/`agentOrigin` (optional); `gatewayPlaneOrigin` and `consumerBaseUrl` accept `'agent'`.
- [ ] A1.2 `resolveGatewayConnection` reads `hosts.agent`, and `TeamGateway.agentEndpoint` (Prisma column and migration); the writers of `mcpEndpoint` also write `agentEndpoint`.
- [ ] A1.3 Tests: SaaS with and without `hosts.agent`; hybrid with and without `agentEndpoint`.

### A2 — Registry Agents tab ⚠
- [ ] A2.1 Types (design §2.2); `registrySourceFromAgentGatewayItem` maps `a2a_target`; `loadRegistryRowsForType` A2A → real list.
- [ ] A2.2 `visibleRegistryTabs`, tab entry, `useRegistryScreen` eager types; `RegistryScreen` filters, empty state, primary action and overlays; `RegistryContext` handlers; `RegistryCard` A2A variant.
- [ ] A2.3 Actions: preview, create, update, refresh, approve (audit and revalidation as specified).
- [ ] A2.4 Components: `AddAgentSidePanel` (+ `useAddAgentFlow`), `AgentDetailSidePanel`, `AgentCardSummary`, `AgentSignInFields`, `AgentCardDiff` (+ `agentCardDiff.ts`), `VerifyAgentTokenBox`; test ids in `REGISTRY_TEST_IDS`.
- [ ] A2.5 Copy in `v2Registry.json`.
- [ ] A2.6 Tests: the spec scenarios of `console-agents-registry`.

### A3 — Agents plane in Applications
- [ ] A3.1 `PLANES`; every location in the design §2.4 table.
- [ ] A3.2 General: the third routing section gated by `agentHost`; plane-generic drafts; A2A consumer creation with registries only.
- [ ] A3.3 Connect: Agents section, `applicationAgentSnippets.ts` (cURL per version, Python a2a-sdk 1.x pinned against the SDK).
- [ ] A3.4 Policies (`PLANE_PROTOCOL.A2A`, TrustGuard line), keyring chip, side panel tone, analytics, topology.
- [ ] A3.5 Copy in `v2Applications.json`; tests for the spec scenarios of `console-agents-plane`.

### A4 — Filters, badges, docs
- [ ] A4.1 A2A in `GATEWAY_PROTOCOLS`, Requests and Activity filters; remove the ENG-1203 and ENG-1347 notes.
- [ ] A4.2 One `lila` tone across policies, requests, activity, consumers, `RegistryAccessTab` and `PLANE_TONE`; check it next to the status badges.
- [ ] A4.3 `V/COMPONENTS.md` and `docs/v2/SDD.md`.

## Verification

- **TrustGate, every slice:** `go build ./...`, `go vet ./...`, `make lint`, `make test-race`, and `go vet -tags functional ./tests/...` when tests change. Mocks come from `make generate`. Comment policy: exported docs only, and swagger annotations kept. CI `functional-tests` must be green.
- **app, every unit:** `npm run lint`, `npm run test:unit`, and `npm run build:local` before the push. Then a manual pass in the console against a gateway running the TrustGate PR, with and without `AGENT_BASE_DOMAIN`.

## PR rules

- Titles carry the Linear id once it exists, for example `feat(a2a): agent plane skeleton (RUN-####)`.
- TrustGate slice PRs target `feat/a2a-plane`. The final PR to `develop` has `size:exception` and the measured breakdown.
- app: A0 any time. A1 after S11 is deployed. A2 after S3b is deployed. A3 and A4 after the agent plane runs in the target environment.
