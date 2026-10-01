# Proposal: MCP-wide placement for group-scoped policies (RUN-1746)

Linear: [RUN-1746](https://linear.app/neuraltrust/issue/RUN-1746/fixpolicy-a-policy-scoped-to-groups-from-the-console-runs-nowhere-mcp).
Repos: TrustGate (Go) and app (Next.js console). Base branch: `develop` in both.
Exploration: [`exploration.md`](./exploration.md).

## Intent

When an admin picks **Requests from → Groups** in the console, the policy is saved as a draft (`global=false`, no consumer links, `mcp_scope.groups`). TrustGate runs it nowhere, MCP Store included, but the admin believes it is enforced. The RUN-1621 product rule says a policy assigned to a group belongs to no consumer: the LLM gateway never sees it. What the admin wants is a policy that applies across MCP, limited to those groups. No placement can express that today.

## Scope

Add a third placement next to `global` and consumer attachments: **MCP-wide**. The policy runs on every MCP consumer of the gateway and on the MCP Store, gated by its `mcp_scope` (groups / except_groups / destinations). It never enters an LLM or A2A chain.

### In scope

**TrustGate**

- Domain: `Policy.MCPWide bool` (JSON `mcp_wide`). A policy is never `Global` and `MCPWide` at once. `Draft()` becomes `!Global && !MCPWide && len(ConsumerIDs)==0`. `IsGlobal()` keeps its meaning (gateway-wide on every plane).
- DB: column `policies.mcp_wide boolean NOT NULL DEFAULT false` plus `CHECK (NOT (global AND mcp_wide))`. In-code migration, idempotent up and down. In DB-less mode the field travels in the snapshot's domain JSON, so the proto does not change.
- API: dedicated `POST|DELETE /v1/gateways/{gw}/policies/{id}/mcp-wide`, mirroring `/global`, same handler and use-case shape. `PolicyResponse` gains `mcp_wide`.
- Load path (`pkg/app/consumer/data_finder.go`): `loadPolicies` returns a third bucket. MCP consumers and `data.StoreConsumer` take MCP-wide policies exactly as they take globals: composed with `composePolicies` and merged with `mergeScoped`, with the same override rules. LLM and A2A consumers never see the bucket: no `inertPolicies` and no `coalesceInert` for it. As with `global`, consumer links on an MCP-wide policy are ignored at load.
- Plugin state: an MCP-wide policy partitions its state gateway-wide, like a global one (`RuntimeScope.Global`). One budget for the gateway across its MCP consumers and the Store. Add a domain predicate (e.g. `GatewayWide()` = `Global || MCPWide`) and use it at `pkg/app/plugins/plan.go:90` and `chain.go:119`.
- Level guard: MCP-wide occupies the **same "all consumers" cell as global** (consumer=`*` × groups × destination). Two MCP-wide policies of one plugin with overlapping groups → 409. MCP-wide against global, same plugin, overlapping groups → 409. Occupancy is computed from the row alone, so no guard is needed on consumer create or type change. The 409 wording (`already runs plugin … at level …`) must not change, because the console matches on it.
- Promotion guard: `POST /mcp-wide` returns 422 when the plugin does not support the MCP protocol (`resolver.SupportedProtocols`).
- Warnings: an MCP-wide policy never gets `policy has no consumers and is not global: it runs nowhere`. `reach` and `sameSlugRunsWhere` (`warnings.go`) learn the placement. Drafts keep the current text; the console never reads `warnings[]`.
- Cache invalidation: reuse `withMarkedTx` + `invalidation.GatewayData` + `Signal`, as `/global` does. No new event.
- Docs and specs: the placement table in `docs/mcp-policy-scope.md` (~:120-135) and the rows at ~:256, :259, :514. Deltas for `openspec/specs/{mcp-policy-scope,mcp-policy-plan-selection}` and the RUN-1621 specs (`policy-inert-scope`, `policy-level-uniqueness`) wherever they live. OpenAPI via `make docs`, with an `openapi_test.go` assertion for the new route.

**app (console)**

- Types (`$P/types.ts`, `$P/lib/policyContract.ts`): `mcp_wide?: boolean` on the item, where absent means `false`. `PolicyScope` gains `'mcp-wide'`.
- `policyScopeOf`: `group` → `'mcp-wide'`. `policyConsumerIdsOf` keeps returning `[]` for it.
- `syncPolicyAssociations`: reconcile three placements with the new endpoint.
  - Into MCP-wide: `POST /mcp-wide`, which atomically clears `global`, then **detach every previous consumer link**. Links would be ignored at load anyway, but detaching keeps a rollback to an older TrustGate fail-closed.
  - Into gateway-wide: `POST /global`, which atomically clears `mcp_wide`; keep links, as today.
  - Into targeted: `DELETE` whichever flag is set, then attach and detach the difference.
  - The retry and error tagging (`PolicyAssociationError`) apply to the new writes too.
- Create and update actions: replace `previousGlobal: boolean` with the previous scope derived from the item. Create returns the **post-promotion** item, so the "create from consumer/application" flows skip their auto-attach for any promoted placement (`global || mcp_wide`).
- Read-back (`policyMapper.requestsFromOf`): `mcp_wide` → `group` with its groups, checked before `consumer_ids`.
- `policyLevelConflict.ts`: an MCP-wide placement takes levels with consumer key `*`, the same cell as global, so the client check matches TrustGate's. A group-only **draft** still takes no level.
- Validation: *Groups* with no group selected cannot be saved. Show a hint; do not promote MCP-wide with a null scope from the console.
- List and detail copy: row scope `mcp-wide`, coverage "All MCP traffic · <groups>" (or similar), the `PolicyScope` exhaustive switch, the security banner and the delete-modal text for MCP-wide, and partial-write error copy (e.g. `POLICY_NOT_RUNNING_MCP:` / `POLICY_STILL_MCP_WIDE:`). English only (`messages/en/v2Policies.json`, `messages/en/v2Gateway.json`).
- The UI label stays **"Groups"**; the issue's "Users" is the stale doc name. Fix the stale doc comment in `PolicyRequestsFromSection.tsx:56`.

### Out of scope

- Store-only policies (issue).
- A user principal in `mcp_scope` (issue).
- *Applications* + *Groups* combined (issue).
- Listing MCP-wide policies as applied (and non-detachable) on the consumer and application Policies tabs (~31 `item.global` call sites). Follow-up ticket.
- A `?mcp_wide=` filter on the list endpoint.
- A console affordance to promote existing group-only drafts. Handled by the rollout below.
- API-key callers on regular MCP consumers skip the group check. This is RUN-1621 behaviour for every group-scoped policy; document it, don't change it.
- An MCP-wide policy plus a same-plugin, same-group policy attached to an MCP consumer can both run there. Same gap as `global` + groups today; document only.

## Decisions on the exploration's open questions

| # | Question | Decision |
|---|---|---|
| TG1 / app4 | Must MCP-wide carry groups? | TrustGate accepts any `mcp_scope` (null = every MCP caller, which is meaningful). The console requires ≥1 group for *Groups*. |
| TG2 / app3 | Links on an MCP-wide policy | Ignored at load and in occupancy, like `global`. Attach is not refused. The console detaches on promotion. `validatePolicyProtocol` skips MCP-wide, as it skips global. |
| TG3 | Plugin state | Gateway-wide, like global. |
| TG4 / app2 | Switching placement | `POST /mcp-wide` and `POST /global` each clear the other flag in one UPDATE, guarded once. `DELETE` clears only its own flag and is idempotent. |
| TG5 | Warning text | Unchanged for drafts; MCP-wide does not get it. The console does not read warnings. |
| TG6 | Double-run warning | Documented only. |
| TG7 | List filter | Out of scope. |
| TG8 / app9 | Existing group-only drafts | No data migration. Run the rollout SQL per environment and record the decision on the issue. |
| app1 | Read field | `mcp_wide: bool`; `global` stays `false` for MCP-wide. |
| app5 | Levels | Same cell as global (consumer `*`). The 409 wording is unchanged. |
| app6 | Promote responses | `POST`/`DELETE /mcp-wide` and `/global` return `PolicyResponse` including `mcp_wide`. |
| app7 | Consumer/application tabs | Out of scope (follow-up). Only the create-from flows' auto-attach is fixed. |
| app8 | Label | "Groups". |
| app10 | Groups offered from a consumer/application modal | Unchanged. |

## Rollout

1. Ship TrustGate first. An older console never calls `/mcp-wide`, and an older TrustGate answers 404, which the console surfaces as not-running.
2. Before deploying the console, run this per environment and record the list on the issue. It also covers `except_groups`-only drafts, which the issue's query misses. **Do not promote anything to MCP-wide, whether by SQL or by the API, until the console PR (A1+A2) is deployed.** A console without A2 reads an MCP-wide row as targeted. If an admin then switches it to *Applications*, the console attaches links that TrustGate ignores and writes a scope with no groups, without demoting. The policy would then run for every MCP caller.

```sql
SELECT p.id, p.gateway_id, p.slug, p.name, p.mcp_scope
  FROM policies p
 WHERE NOT p.global AND NOT p.mcp_wide AND p.enabled
   AND (p.mcp_scope ? 'groups' OR p.mcp_scope ? 'except_groups')
   AND NOT EXISTS (SELECT 1 FROM consumer_policy cp WHERE cp.policy_id = p.id);
```

Rollback: an older TrustGate binary ignores `mcp_wide`. The policy then reads as a draft with no links and runs nowhere, so it fails closed. The down migration drops the column.

## Delivery

Expected to exceed the 400-line review budget. `sdd-tasks` forecasts it and proposes chained PRs: TrustGate before app.
