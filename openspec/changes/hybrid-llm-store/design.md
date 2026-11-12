# Design: LLM Store on hybrid gateways

All references are to `origin/develop` of TrustGate and app as of 2026-11-12.

## Facts

| # | Fact | Evidence |
|---|---|---|
| F1 | TrustGate refuses personal consumers and personal keys on a hybrid gateway. | `AllowsPersonal` in `pkg/domain/gateway/gateway.go:147`. It is used by `consumer/creator.go:148`, `auth/personal_keys.go:271`, the three MCP Store tools (`mcp/store_models_tool.go:93`, `store_personal_key_tool.go:63`, `store_request_models_tool.go:83`), `oauth/personal_key_page.go:308` and the `PersonalKeys` gRPC (`configsync/grpc/personal_keys.go:125,212`). |
| F2 | Every data plane answers 404 on `/store/v1` for a hybrid gateway, whatever its build. | `serveStore`, `pkg/api/middleware/auth.go:125`, added in v0.64.0 (5cee17e1d). |
| F3 | Personal consumers first shipped in v0.64.0. BV, the one hybrid plane checked, runs v0.70.0; the rest of the prod inventory is unchecked (QA 3.4). | `git tag --contains 43bcfa0d0`; BV `/healthz`. |
| F4 | A personal consumer can be reached at its slug on hosted planes today, so that alone is no hazard. | `consumerAdmitsCaller` returns true for API keys (`auth.go:357`). `apiKeyAttachedElsewhere` skips personal consumers (`auth.go:341`). |
| F5 | Auths and consumers are grouped by gateway, and every gateway, hybrid included, gets its scoped snapshot. Only the global snapshot leaves hybrid out. Incremental compiles are per gateway: markers carry a `GatewayID`, and the fragment encoder holds one fragment per gateway. Auth writes mark their gateway (`repository/auth/repository.go:74`, `WithGatewayMarkedTx`), and the incremental property test covers auths on hybrid planes (`incremental_test.go`). | `compiler.go:371-389`, `compiler.go:782`, `cursor.go:53`, `infra/configsnapshot/fragments.go:116` (`Put`). |
| F6 | The control plane stores, per instance, the build version a plane reports. Planes older than v0.76.0 send no heartbeat, so their `version` is empty, but their stream keeps `last_seen` fresh. The heartbeat is sent every 30 s by default. The console already reads this table. | `config_sync_connections.version`, `last_seen`, `last_heartbeat` (`repository/configsyncconn/repository.go:36-48,115`), `config.go:184`, `GET /v1/config-sync/connections`, app `instances/lib/instancePresence.ts`. Heartbeat introduced in e2766d94d, v0.76.0. |
| F7 | Cost by user comes from the metrics event, which carries the personal key's owner. That event is metadata, not raw, so hybrid planes export it through enrolment ingest. | `pkg/app/metrics/builder.go:102`; DataCore `dashboard` byUser ("for a personal key of the LLM Store, the key owner's platform user id"). |
| F8 | The console gates the LLM Store on `deploymentType === 'hybrid'` in 15 places. | See § Console changes. |
| F9 | The console already resolves a hybrid gateway's public origin, the one set by the operator. The Store root assumes hosted only. | `consumers/lib/consumerBaseUrl.ts` ("the operator-set origin for hybrid gateways"); `portal/lib/portalStoreBaseUrl.ts` comment. |

## What actually breaks today

The risk named in RUN-1763 (F4) does not hold. The real blockers are:

- The data-plane 404 (F2).
- The control-plane and console vetoes (F1, F8).

These are the consequences when personal data reaches a plane older than the
release that lifts F2:

- `/store/v1` still answers 404, so the key works nowhere except at slugs, as
  on hosted planes.
- MCP Store tools on that plane keep saying "not available".

Nothing leaks and nothing is billed to the wrong person. The open data is
inert. This has been checked for v0.64.0 and later. For planes below that it
is an assumption, and QA 3.4 confirms that none exist in prod.

## Decisions

### D1 Gate: derived from the plane's version, not a stored flag (decided 2026-11-12: A)

| Option | Mechanics | Cost |
|---|---|---|
| **A. Version-derived (recommended)** | TrustGate computes, per gateway, whether the Store is available from `config_sync_connections`. The console reads it. The control plane drops its veto with no condition. | No new stored state, migration, snapshot field or `updater.go` change. It turns on when the customer upgrades, with no action from us. |
| B. Stored per-gateway flag | An admin enables it, the control plane checks versions when it is enabled, the flag travels in the snapshot, and the plane serves `/store` only when it is set. | A new contract (gateway field, snapshot field, `updater.go`, which never changes `data_plane` today) and one more manual step per customer. It does not protect against a later downgrade either. |

**Recommendation: A.** The writes stay harmless on an old plane (§ What
actually breaks), so the control plane does not need to block them. The gate
only has to keep the console honest. Option A is the additive change and
breaks no token in prod.

### D2 Availability rule

**Which instances count.** An instance of the gateway's scope counts when its
state is `connected` and its `last_seen` falls within the same freshness
window Topology uses (`instancePresence.ts`). This is deliberately not based
on the heartbeat: a v0.70.0 plane never sends one, and it is still connected.

**Classification.** Each counted instance is then classified by its
heartbeat:

| Reason | When |
|---|---|
| `available` | Every counted instance reports a semver version ≥ `MinStoreVersion` (the release that ships T2, a constant in TrustGate). |
| `no_data_plane` | No instance counts. |
| `version_unknown` | At least one instance reports an empty version (no heartbeat, so older than v0.76.0) or one that is not semver (`dev`, a sha). |
| `data_plane_outdated` | At least one instance reports a semver version below the minimum. This only happens for planes in [v0.76.0, N). The minimum and the lowest version seen are returned. |

`version_unknown` wins over `data_plane_outdated`.

Hosted and dedicated gateways always resolve to `available`. A rollout with
mixed versions stays off until the last instance is recent enough. That
matches what a user would see, because the load balancer may send them to
either instance.

**What "not available" blocks.** It blocks only what a user would get as a 404:

- Portal key creation and listing (A7).
- An admin creating a user's key (A1 `:472`).

Models access, Everyone and bulk actions can always be configured on hybrid,
with a notice. That way access is already in place when the plane reaches N.

### D3 Group limits and key budgets stay off on hybrid

Enforcing them depends on two things we have not checked for hybrid planes:

- Usage records reaching UsageSystem.
- `UsageSnapshot` coming back.

The current skip stays in `syncGroupBudgets` and `llmStoreGroupLimitsActions`.
The panel says the limits are not available on this gateway yet.

`syncPersonalKeyGroups` is **not** a budget: it syncs the group attribution of
group-scoped keys. It runs on hybrid (A6b), otherwise attribution would drift.

The follow-up, outside this change, is to verify usage records from a hybrid
plane and then lift the skip.

### D4 What happens when the capability is lost

This covers a downgrade or a new old instance. Rows and keys stay, the
reconcile keeps writing (it is harmless), and nothing is revoked. The console
shows the reason from D2 on Access and in the Portal. Revoking keys because of
a temporary rollout state would be worse than a 404.

### D5 Store base URL on hybrid

The Store base URL is the operator-set proxy origin + `/store/v1`. The data
plane resolves the gateway before the Store route (`AuthMiddleware`, gateway
resolver), and a hybrid origin does not name it, so every call sends
`X-AG-Gateway-Slug: <slug>`, as the MCP Store already does on hybrid.

## TrustGate changes

| # | File | Change |
|---|---|---|
| T1 | `pkg/domain/gateway/gateway.go` | `AllowsPersonal()` returns true for hybrid, and the "predates" comment goes away. `ErrHybridPersonal` and its `FailedPrecondition` mapping in `configsync/grpc/personal_keys.go` are removed now: each binary checks `AllowsPersonal` locally, and an older plane calling a new control plane never receives `FailedPrecondition`, because the control plane deploys first. |
| T2 | `pkg/api/middleware/auth.go:125` | `serveStore` drops `gw.ServedByHybridDataPlane()`. The `HasPersonalConsumers` 404 stays as it is. |
| T3 | `pkg/app/mcp/store_*_tool.go`, `oauth/personal_key_page.go` | No logic change, because they follow `AllowsPersonal`. Their hybrid copy texts stay for older planes and become dead code on N. |
| T4 | `pkg/domain/dataplane` + `pkg/app/configsync` | `MinStoreVersion` and `StoreAvailability(gateway, connections, now)`, a pure function implementing D2 with a tolerant semver parser. |
| T5 | `GET /v1/gateways/{gateway_id}/store/llm-availability` (admin, Store group) | `{available, reason, min_version, lowest_version}`, read from `config_sync_connections` for hybrid gateways only. Hosted and dedicated gateways skip the query. A hybrid plane's config-sync scope is its gateway id: the console mints its token with `instanceId` = gateway id (`privateGateway.ts`). |
| T6 | Local QA (3.1, 3.2) | The functional suite's control plane accepts only the static global token, so a scoped hybrid plane is not part of it. F5 is covered by unit tests; the end-to-end path is QA. |
| T7 | `docs/llm-store.md`, `make docs` | Document hybrid support and the minimum version. Run `make docs` in its own commit (OpenAPI drift). |

## Console changes

The console gets one helper: `llmStoreAvailability(teamId, gatewayId)` in
`llm-store/lib/llmStoreStore.ts`. It returns `{available, reason, minVersion}`,
reading T5 for hybrid gateways and resolving to `available` for the rest.

| # | File (under `app/[locale]/v2/features`) | Today | After |
|---|---|---|---|
| A1 | `llm-store/actions/llmStoreAccessActions.ts:134,342,385,472,523` | `isSaasGateway` | `:385` (set access) no longer checks. `:342`, `:472` and `:523` (keys) require `available`, and the error names the reason (D2). |
| A2 | `llm-store/actions/llmStoreAccessRequestActions.ts:140` | `[]` on hybrid | `[]` only when not available. |
| A3 | `llm-store/lib/reconcileLlmStoreGateway.ts:331` | Returns early on hybrid | Runs on hybrid, whether available or not (the writes are harmless, D4), so access appears as soon as the plane upgrades. |
| A4 | `llm-store/lib/llmStoreStore.ts:346,471` (`listTeamSaasGatewayIds`, boot sweep) | SaaS only | All gateways. |
| A5 | `llm-store/lib/ownerLlmStoreAccess.ts:61` | No owner seed on hybrid | Seeds it. A one-off backfill of the owner's All on existing hybrid gateways rides the boot sweep. |
| A6 | `llm-store/lib/revokeIneligibleKeys.ts:109` | Skipped on hybrid | Runs: eligibility rules are the same. |
| A6b | `llm-store/lib/syncPersonalKeyGroups.ts:87` | Skipped on hybrid | Runs (D3). |
| A7 | `portal/actions/getPortalModelsAction.ts:61`, `getPortalPreviewModelKeysAction.ts:39`, `portalModelKeyActions.ts:64,94` | Disabled on hybrid | Disabled only when not available. The response carries the reason so the Portal can explain it. |
| A8 | `access/actions/everyoneActions.ts:80,106,118,156,193` | Models Everyone refused on hybrid | Always allowed. `hybrid` becomes `storeAvailability` (reason + versions) so the UI can show the notice. |
| A9 | `access/actions/groupBulkActions.ts:185` | Models refused on hybrid | Always allowed. |
| A10 | `portal/lib/portalStoreBaseUrl.ts`, `StoreConnectPanel.tsx`, `portalModelsSnippets.ts` | Hosted host only | The plane's operator-set origin + `/store/v1`, and every snippet and prompt sends `X-AG-Gateway-Slug` (D5). `settings/lib/storeLlmUrl.ts` stays empty for hybrid: a bare SDK base URL cannot carry the header. |
| A11 | Access › Models panel, Portal | Red "not available on hybrid gateways" | When not available, the selector stays usable and an informative notice explains the reason. The Portal shows the same notice instead of the key. One message per reason: `data_plane_outdated` "Your data plane runs vX; keys work from vN", `version_unknown` "Your data plane does not report its version; upgrade to vN or later", `no_data_plane` "No data plane is connected". |
| A12 | `llmStoreGroupLimitsActions.ts:152`, `syncGroupBudgets.ts:75` | Skipped on hybrid | Unchanged (D3). Message: "not available on this gateway yet". |

## Data flow (hybrid, after the change)

```
console ── PUT access / personal key ──▶ TrustGate CP ── scoped snapshot ──▶ hybrid DP ≥ N
   ▲                                         │                                   │
   └── GET /v1/gateways/{id}.llm_store ◀── config_sync_connections ◀─ heartbeat ─┘
user ── X-AG-API-Key ──▶ https://<operator origin>/store/v1 ──▶ hybrid DP ──▶ provider
hybrid DP ── metrics event (OwnerID, no raw) ──▶ enrolment ingest ──▶ ClickHouse ──▶ DataCore byUser
```

## Rejected

- **Stored flag:** D1, option B.
- **Gating access writes on version, in the control plane or the console:**
  the writes are harmless on an old plane. Gating them would leave access
  unwritten until the customer upgrades, and the Store would come up empty at
  the moment it turns on. Only key creation waits (D2).
- **Revoking when the capability is lost:** D4.
- **Opening group limits and key budgets now:** usage enforcement on hybrid is
  unverified (D3).

## Risks

- **A plane with non-semver versions:** it stays at `version_unknown`. The
  console says so, and support can see the version on Topology.
- **Instances that are disconnected but not cleaned up:** only `connected`
  instances with a recent heartbeat count.
- **A hybrid plane that does not export metrics** (enrolment ingest not
  configured): Cost by user shows nothing. This is the same as all of its
  other telemetry today, so it is not new.
