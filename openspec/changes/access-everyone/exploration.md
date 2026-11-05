# Exploration: ENG-3054 — backend for Everyone and bulk Assign / Remove

Read against `TrustGate@origin/develop` (`30ce3c07`) and `app` at the front-end
front-end branch for ENG-2929 (`193951e6`). That branch is 16 commits behind
`develop`. Nothing under `llm-store/` or `prisma/` differs, so those line
numbers hold for `develop`; `develop` did change `GroupAccessSidePanel.tsx`,
`LlmStoreAccessSection.tsx` and `LlmModelsAccessEditor.tsx`, so `access/`
line numbers may shift and the front branch needs a rebase. Paths without a prefix are in `app`;
`TrustGate/` paths are in TrustGate. This complements
`access-everyone-backend-brief.md` (D1–D7) and does not repeat it.

## Part 1 — Closed by the code

### Q1. Does D1-B (native TrustGate object) reach hybrid gateways? — Yes, if upgraded

- Grants and policies are gateway config that "ride the config snapshot to the
  data planes" (`TrustGate/pkg/domain/storeaccess/grant.go:22-24`). A hybrid
  gateway gets its own scoped snapshot carrying `StoreGrants` and
  `StorePolicies` (`TrustGate/pkg/app/configsnapshot/compiler.go:316-334, 560-561`);
  the data plane reads them in memory
  (`TrustGate/pkg/runtimeconfig/snapshot/adapters/store_grant_reader.go:37-45`).
- So an Everyone object added to the same snapshot reaches hybrid planes with
  no extra channel. Option A could not: the console skips hybrid gateways
  (`llm-store/lib/syncPersonalKeyGroups.ts:87`).
- **Risk:** a hybrid plane on an older TrustGate ignores the new field, so its
  users silently get no Everyone. See Risks.

**D1 is closed in favour of B.** A also fails group keys
(`StoreGroups()` = only the key's group, `TrustGate/pkg/domain/identity/principal.go:241-249`)
and external-IdP sessions (the directory push only applies to the default IdP,
`TrustGate/pkg/app/oauth/session_groups.go:67`).

### Q2. Where does Everyone sit in MCP mode precedence? — Rule below

Today (`TrustGate/pkg/domain/storeaccess/policy.go:144-175`, `TrustGate/pkg/app/store/mode.go:74-88`):

1. The caller's own user policy, if any, wins outright.
2. Else the most permissive **explicit** group policy among `StoreGroups()`
   (open 2 > curated 1 > none 0). A group without a policy is skipped; a group
   on `none` is a real vote.
3. Else (no policy named the caller) the fallback: legacy `store_access` claim →
   gateway `store_mode` (default curated).

Naive "Everyone = one more group vote" would **lower** access: a caller whose
groups have no policy today gets the fallback (say `open`); adding an Everyone
vote of `curated` makes step 2 return `curated` and the fallback is never read.

**Proposed rule.** Let `reached` = some group in `StoreGroups()` is not in
`excluded_groups` and has no own `none` policy (a group without a policy
passes). Then:

```
own user policy present           → own policy                         (unchanged)
explicit group policies present   → max(best group policy, Everyone if reached)
no explicit group policy          → max(fallback,          Everyone if reached)
```

Properties:

- No Everyone object → `reached` is false → every row is today's result.
- With one, every branch is `max(today, …)`, so no caller ever ends lower.
- Everyone's mode is only `open` or `curated` (`access/types.ts:69`,
  `EveryoneSectionMode = 'all' | 'selected'`), so it never contributes `none`.

| Caller | `StoreGroups()` | Reaches Everyone when |
| -- | -- | -- |
| Group key | its group only | that group is not excluded and not on `none` |
| Personal key | owner's directory groups | any of them passes |
| Default-IdP session | claim ∪ pushed directory groups | any of them passes |
| External-IdP session | IdP claim | any of them passes (group keys must match the claim) |
| User in no group | — | never |

Open product point inside this rule: a user's own `none` policy still blocks
Everyone (it beats groups today). See Part 2.

Note: the exclusion must be evaluated **per group**, not per caller. The
existing `ExceptGroups` in `TrustGate/pkg/domain/policy/mcp_scope.go:166-168`
rejects the caller if *any* of its groups is excepted. That would fail the QA
case "a user in an excluded group **and** a passing group gets Everyone", so it
is not reusable as-is.

### Q3. Do Everyone's MCP grants avoid Approvals under `curated`? — Only if every grant call site sees them

There is no cache: grants are re-checked live on every decision. The call sites
that decide "is this caller granted server X" are:

- `TrustGate/pkg/app/store/installer.go:772-810` (`decideAmong`, the install
  decision; ungranted → `StatusPendingApproval` at `:786-794`), `:434`;
- `TrustGate/pkg/app/store/scoper.go:286`;
- `TrustGate/pkg/app/mcp/store_tool.go:895, 971, 1013` (search, offer, shelf);
- `TrustGate/pkg/app/store/principal_connect.go:156`,
  `principal_configure.go:159, 220`;
- `TrustGate/pkg/app/store/approver.go:412-415`.

All of them go through the in-memory `storeaccess.Set`
(`grant.go:260-299`). The cheapest correct change is to make the `Set` itself
Everyone-aware (built from grants + Everyone + the caller's `reached`) rather
than patching ten call sites.

**Storage:** keep Everyone's grants out of `store_grants`. The panels PUT full
`groups` lists built in the browser (`access/actions/updateResourceAccessAction.ts:40-50`),
so a reserved group key inside those lists would be stripped by any ordinary
save. A separate table and endpoint, e.g.
`GET|PUT /v1/gateways/:id/store/everyone { mode, grants[{catalog_code, registry_id?}], excluded_groups[] }`,
next to `store/access-policies` (`TrustGate/pkg/server/router/admin_router.go:243-252`).
It follows the same pattern: Postgres table + outbox marker + snapshot field.

### Q4. Models Everyone: does a shared consumer break billing or limits? — No

- Group budgets are keyed by the **authenticated key's group**
  (`KeyGroupID`, `TrustGate/pkg/app/plugins/plugin.go:260-264`,
  `TrustGate/pkg/app/proxy/group_budget.go`); the console writes them per
  `group_id` (`llm-store/lib/llmStoreGateway.ts:440-451`). Not per consumer.
- Cost by group comes from TrustGate's key-groups cost endpoint
  (`analytics/actions/getAnalyticsKeyCostAction.ts:57`), keyed by key group.
- The only consumer-level budget policy is a leftover the planner now
  detaches and deletes (`planLlmStoreReconcile.ts:430-440`).
- A personal key already links to N consumers that complement each other, with
  levels `user` < `group` < `all` (TrustGate `openspec/changes/llm-store/proposal.md`
  B4–B7; `TrustGate/pkg/domain/consumer/auth_link.go:30`).

That opens an option the brief did not list:

- **(c) One shared consumer.** The `EVERYONE` row is a real row, gets one
  consumer `llm-store:everyone`, and the planner links it at level `all` to
  every key of a passing group, next to that group's own consumer. No
  synthetic rows, no per-group merge, one consumer whatever the number of
  groups, and the "consumer deleted each run" problem does not arise because
  a real row keeps it.
- **(a) Synthetic effective row per group** (the brief's leaning) still works
  but needs a consumer per Everyone-only group and a merge of selections.

What a shared consumer could lose, checked:

- Admin policies (guardrails, firewall) cannot target LLM Store consumers: the
  pickers hide `audience: 'personal'` (`consumers/lib/consumerAudience.ts:1-12`,
  `policies/types.ts:207-208`).
- Analytics already folds every `llm-store:` consumer into one "LLM Store" row
  (`analytics/lib/aggregateCostMetrics.ts:146-163`), so no per-consumer view is lost.
- UsageSystem has no reference to `consumer_id` / `consumerId` (`.go`, `.sql`, `.proto`).

**Leaning: (c).** It fits how links already work and loses nothing found.

### Q5. Which code must share the new eligibility predicate? — More than the brief lists

`group eligible = (own row is ALL|SELECTED) or (Everyone has models and the
group is not excluded and its own row is not NONE)`. It must replace the
current rule in **all** of these, or Everyone-only groups break:

| Site | What goes wrong without it |
| -- | -- |
| `llm-store/lib/planLlmStoreReconcile.ts:271-288` `desiredRowsForKey` | the group key is never linked to Everyone (also: "one row at most" becomes two) |
| `llm-store/lib/llmStoreKeys.ts:26-30` `eligibleGroupIds` | no group key can be created |
| `llm-store/lib/revokeIneligibleKeys.ts:52, 66-68` | **the sweep revokes every Everyone-only group key on each run** (`!row` = ineligible) |
| `llm-store/actions/llmStoreAccessActions.ts:326` `groupLosesModels` | clearing a group's own row asks to confirm and revokes keys although Everyone still covers it |
| `llm-store/actions/llmStoreAccessActions.ts:499-510` key counts | wrong counts in the confirmation |
| `planLlmStoreReconcile.ts:296-309` `reachableRowsForOwner`, `lib/llmStoreEffectiveModels.ts`, `lib/llmStoreReach.ts` | the Portal never shows Everyone's models |
| `lib/llmStoreKeyOptions.ts:28`, `llmStoreAccessActions.ts:452` | key options in Portal / admin key creation |
| `llmStoreGroupLimitsActions.ts:107`, `analytics/actions/getAnalyticsKeyCostAction.ts:81` | group limits / cost filter hide Everyone-only groups |
| `access/hooks/useLlmStoreAccessDraft.ts:146`, `GroupAccessSidePanel.tsx:549`, `LlmStoreAccessSection.tsx:80` | the UI repeats the rule client-side |

Also: a row with `scope: 'ALL'` and another `principalKey` would be read as the
gateway default (`planLlmStoreReconcile.ts:402`, last one wins), so Everyone
must be a new enum value (`schema.prisma:1446`), not an `ALL` row. Places that
enumerate the scope: `schema.prisma:1446`, `llm-store/types.ts:12`,
`llmStoreStore.ts:19, 37-41`, `llmStoreAccessInput.ts:26-30, 47-54`,
`planLlmStoreReconcile.ts:149` (`LINK_LEVEL_BY_SCOPE`, needs `EVERYONE → 'all'`),
`access/lib/llmStoreModels.ts:23-26`.

MCP side of the console, for comparison. Because Everyone is a separate
TrustGate object (Q3), the existing writers keep working untouched; only the
readers need to learn about it:

| Site | Effect of Everyone |
| -- | -- |
| `access/actions/listAccessResourcesAction.ts:46` (Access column, group panel) | reads only `store/grants`: needs to read `store/everyone` too to show what a group passes on |
| `access/actions/storeAccessPolicyActions.ts:88` `listStoreAccessPoliciesAction` | unchanged; the Everyone mode is shown separately |
| `app/server/lib/storeAccess/ownerStoreAccess.ts:47, 107` | writes the owner's own user policy — unaffected (own policy still wins) |
| `app/server/lib/platform/pendingStoreAccess.ts:87, 131` | invite: user policy + read-modify-write of user lists on grants — unaffected |
| `access/actions/updateResourceAccessAction.ts` | unaffected; bulk MCP items should use a new server-side action, not this one |

Hybrid: the Models reconcile does not run for hybrid gateways
(`reconcileLlmStoreGateway.ts:328`) and `/store/v1` returns 404 there, so
Models Everyone is SaaS-only, like Models today.

### Q6. D3 — identify groups by id or by grant key? — By id

- `groupGrantKey` = `externalId?.trim() || displayName` (`access/lib/groupGrantKey.ts:9-11`).
  `displayName` is not unique, so key → id is ambiguous; id → key is a function.
- Proposal: change the contract (`EveryoneAccess.excludedGroupKeys`,
  `GroupBulkAssignment.groupKeys`) to `DirectoryGroup.id`s. Store exclusions in
  the console by id (Models needs ids anyway); the server action maps ids → keys
  when it writes TrustGate's Everyone object and the MCP grants.
- Known cost: when a group without `externalId` (SCIM/IdP; NeuralTrust groups
  are keyed `nt:<uuid>` and do not change) is renamed, the key pushed to
  TrustGate goes stale. For grants that fails closed (the stale key
  grants nobody); for exclusions it fails open (the group stops being
  excluded), so the console must re-push Everyone when a grant key changes.

Where exclusions live and how the two copies stay in sync — **open design
point**, proposal:

- **Console is the source of truth.** One `AccessEveryone` row per
  (team, gateway) as in the brief's appendix, holding `excludedGroupIds` (by
  id), the MCP mode and the MCP items. Models' selection lives on the
  `EVERYONE` `LlmStoreAccess` row (it needs a consumer). Exclusions are shared
  by both, so they cannot live on the `LlmStoreAccess` row: an MCP-only
  Everyone has none.
- **Read back:** a new reader in `lib/reads/v2Readers.ts` returning
  `EveryoneAccess` from the console table (no TrustGate round-trip), which
  replaces `useEveryoneAccess`'s mock.
- **Push to TrustGate:** the save action writes the table, then PUTs
  `store/everyone` (ids mapped to keys) inline, like the MCP actions do today.
  If the PUT fails, the save reports it and a retry re-sends the full object
  (idempotent). It cannot ride `reconcileLlmStoreGateway`, which returns early
  for hybrid gateways (`reconcileLlmStoreGateway.ts:328`), and MCP Everyone
  must work there.
- Alternative: TrustGate as the source of truth for MCP (mode, items,
  exclusions by key) and the console only for Models. One fewer copy for MCP,
  but Models would have to read exclusions from TrustGate by key and map them
  to ids, the ambiguous direction.

### Q7. D4 / D6 — bulk writes and audit

- MCP writes today have no audit (`app/constants/audit.ts:442-501`, only
  `mcp_connection.revoked`). The Audit log shows `description` as the
  label (`telemetry/lib/mapAuditLogRecord.ts:157-166`), so the descriptions in
  the brief's §5 are what admins read. No label map is needed.
- Bulk Models: N upserts in one `$transaction` + one `scheduleLlmStoreReconcile`
  (debounced 2 s). Revocation counts come from the shared predicate (Q5),
  computed before vs after over all picked groups.
- Bulk MCP: one policy PUT per group, and one grant PUT per affected server
  computed server-side from a fresh read. Per-group `{ applied, failed }`; all
  writes are idempotent upserts, so a retry converges.
- `useEveryoneAccess.save` returns only `{ success }` today, not
  `{ success, error }` as the brief says (`access/hooks/useEveryoneAccess.ts:25`).

## Decisions taken (2026-11-05)

- **D7:** one backend owner for both repos; an agent writes the code, the owner reviews each PR.
- **Source of truth:** console. `AccessEveryone` table (by group id) + PUT
  `store/everyone` to TrustGate on save, ids mapped to keys, idempotent retry.
- **Old hybrid planes:** warning banner in Manage Everyone for hybrid gateways
  (minimum TrustGate version); saving is not blocked.
- **Models Everyone = the existing `ALL` row, not a new `EVERYONE` scope.**
  This supersedes Q4/Q5's new enum and the "Everyone vs `ALL` row" item. Why it fits:
  - the `ALL` row already has one consumer (`llm-store:all`) linked at level
    `all` (`planLlmStoreReconcile.ts:149`): that is option (c) as it stands;
  - the group panel already shows it as what a group without a row inherits
    (`llmStoreInheritance.ts:40-47`), and for legacy keys it already adds to the
    groups' rows (`llmStoreInheritance.ts:49-60`, `planLlmStoreReconcile.ts:262-263`);
  - what changes: group keys of passing groups get linked to it too, and the
    shared predicate counts it for eligibility (which also fixes today's
    "inherited but not key-eligible" inconsistency);
  - legacy keys keep their path, except that the `ALL` row is added only when
    the owner is reached (some group not excluded and not on NONE), so users
    in no group and fully excluded users get nothing from Everyone;
    `inheritedForUser` follows the same rule. No effect today: there are no
    `ALL` rows in production.
  - **Risk measured, none:** a gateway with an `ALL` row in ALL or SELECTED
    would start giving those models to every non-excluded group key. Production
    (read-only, 2026-11-05) has **no `ALL` rows at all**, in any mode, in either region. The change widens nobody's access on day one.
- MCP still needs the native `store/everyone` object: `store_mode` is a level
  with no list of servers, and it also reaches users in no group.

## Part 2 — Still open

Items 1, 2, 6 and 7 are closed above (item 3 by the `ALL` row decision, with the reach rule:
legacy keys keep their path otherwise). Items 4 and 5 are closed with the leanings as
defaults (own `none` blocks Everyone; bulk Remove skips groups on All and
reports them; Remove warns about key revocation, as the product rules already
require for any write that leaves a group without models).

**Conflict found while proposing:** "an emptied Selected list becomes None"
would also cut the group off Everyone, because a group on None does not pass
Everyone. Alternative: MCP stays `curated` with no own grants (Everyone's
grants still reach it); Models deletes the group's own row (no row = receives
Everyone), and asks for the revocation confirm only if the group ends with no
models at all. **Decided 2026-11-05: this alternative.**

1. **D7:** who builds the TrustGate part and the console part.
2. **Everyone vs the gateway default (`ALL` row).** The group panel already
   shows a group with no row as "inherited" from the `ALL` row
   (`llmStoreAccessActions.ts:282-287`), while that group is **not** key-eligible
   (`llmStoreKeys.ts:28`) and the sweep revokes its keys. With Everyone there
   would be two "defaults" on the same screen. Keep both, or make Everyone
   replace the `ALL` row's role in the UI?
3. **Legacy keys** (pre group keys, `desiredRowsForOwner`): do they get Everyone?
   The brief puts the Users side out of scope. Leaning: no.
4. **A user's own MCP `none` policy:** does it block Everyone? Today it beats
   every group policy. Leaning: yes, keep it.
5. **Bulk Remove** (from `access-everyone-and-bulk-assign.md:98-107`): removing
   the last item of a Selected list → stays Selected-empty or moves to None?
   Can Remove take items from a group on All? Does Remove warn about revoking
   model keys?
6. **Hybrid gateways on an old TrustGate:** gate or warn in the console, or accept?
7. **Source of truth for exclusions** (end of Q6): console table + push
   (leaning), or TrustGate for MCP.

## Recommendation

- D1 → **B**, with the precedence rule in Q2, a separate `store/everyone`
  object in the snapshot, and an Everyone-aware `storeaccess.Set`.
- D2 → new `EVERYONE` scope, **option (c)** (one shared consumer linked at
  level `all`), and one shared predicate applied to every site in Q5.
- D3 → ids in the contract and in console storage; map to keys on write.
- D4 → per-group results. D5 → later. D6 → the events in the brief's §5, per
  group, no summary event.
- Order: (1) Models Everyone (2) Models bulk (3) MCP audit events
  (4) TrustGate Everyone + console wiring (5) MCP bulk (6) front wiring and flag removal.

## Risks

- **Revocation sweep:** shipping the Everyone row without updating
  `revokeIneligibleKeys` revokes real keys. The predicate change and the row
  must land together.
- **Hybrid version skew:** older hybrid planes ignore Everyone silently.
- **Concurrent grant edits:** handled later with D5, as today.
- **Rename staleness** of grant keys (Q6): fails open for exclusions, so re-push on key change.

## Ready for proposal

Yes, once Part 2 items 1, 2 and 5 are answered. Items 3, 4, 6 and 7 have a
leaning that can go into the spec as defaults.
