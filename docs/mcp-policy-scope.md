# MCP policy scope (`mcp_scope`)

A policy attached to an MCP consumer used to run on every `tools/call` of that
consumer. `mcp_scope` narrows it to a registry, a tool or a group, so
"DLP for Finance on Snowflake" or "only Finance may call `run_query`" is one
policy instead of one consumer per audience. The principal is always a group;
individual users are not a dimension. Without the field nothing changes:
the policy keeps running consumer-wide.

The field gates only on the MCP plane, but it is not a switch that takes the
policy off every other plane: the destination (`registry_ids`, `tools`) cannot
reach an LLM or A2A consumer at all, while the principal (`groups`) does reach
it and simply does not gate there. See
[Inertness is per dimension](#inertness-is-per-dimension).

## Worked example

`trustguard` DLP that only runs when someone in the Finance group calls a tool
of the Snowflake registry:

```json
POST /v1/gateways/{gateway_id}/policies
{
  "name": "DLP Finance on Snowflake",
  "slug": "trustguard",
  "enabled": true,
  "priority": 0,
  "stages": ["pre_request", "pre_response"],
  "settings": { "...": "..." },
  "mcp_scope": {
    "registry_ids": ["7c1e0d2a-9a4b-4c1e-9c5a-1f2e3d4c5b6a"],
    "groups": ["Finance"]
  }
}
```

Attach it to the consumer as usual (`POST .../consumers/{id}/policies/{pid}`).
Finance on Snowflake runs it; Finance on Jira and Marketing on Snowflake do not.

## The four dimensions

| Field | Selects | Key |
|---|---|---|
| (no `mcp_scope`) | all traffic of the consumers it is attached to, or of every consumer when `global` | — |
| `registry_ids` | calls to any tool of these registries | registry id (a Store shelf id also matches its per-user instances) |
| `tools[{registry_id, tool}]` | calls to one tool of one registry | the upstream's **native** tool name, never the exposed name (federated `mcp_<hash>_…`) nor a toolkit `expose_as` alias |
| `groups` | the caller | same key as a Store Access grant: the IdP `externalId` when the group has one, otherwise its display name; exact match after trimming |
| `except_groups` | callers to remove after a positive match | same key as `groups` |

Destination (`registry_ids` ∪ `tools`) and principal (`groups`) are combined
with **AND** inside one policy; an empty list means "any" on that dimension.
Across policies the result is the **union**: every policy that matches enters
the plan.

There is no `users` or `except_users`: a policy that has to reach one person
names a group that contains them. A request whose `mcp_scope` still carries
either key is rejected with 422 rather than accepted without it, because a
scope that lost its only principal would apply to every caller of its
destination.

## Inertness is per dimension

`mcp_scope` is not one thing that is either on or off outside MCP. It is a set
of dimensions with different fates:

> **The consumer dimension always gates, on both planes. Group, registry and
> tool only gate on MCP; on LLM and A2A they are inert.**

| Dimension | Where it lives | Gates on… | Outside MCP | Why |
|---|---|---|---|---|
| **Consumer** | `global` + the consumer attachments — **not part of `mcp_scope`** | **always**: MCP, LLM and A2A | gates the same | It is not scope, it is routing. It exists and means the same on all three planes |
| **Destination** (`registry_ids`, `tools`) | `mcp_scope` | MCP consumer | **never arrives**: 422 on attach, filtered out at load | The `(registry, native tool)` binding does not exist on LLM, and approximating it by name would be wrong |
| **Principal** (`groups`) | `mcp_scope` | MCP consumer | **inert**: arrives and does not gate | A policy attached to one consumer keeps running there even if its group only means something on MCP |

Two distinctions that are not interchangeable:

- **The destination is not inert, it is impossible.** A policy with
  `registry_ids` reaches no non-MCP plane by any route. "Inert" describes
  something that arrives and does not gate, and that is only the group.
- `except_groups` is **not** a separate dimension. It is a subtraction on the
  principal and shares its fate: on an LLM consumer, "everyone but Finance"
  becomes "everyone".

### What reaches an LLM or A2A chain

| Policy | Reaches a non-MCP consumer's chain? | Why |
|---|---|---|
| All traffic (`global`), no scope | Yes | — |
| Attached to consumer X, no scope | Yes, on X only | the consumer gates |
| **Only** group, no consumer and not `global` | **No** | with no consumers and no `global` it runs nowhere — already true today |
| **Only** registry or tool, no consumer and not `global` | **No** | same |
| Consumer X **+** group | **Yes**, on X | gates by consumer; the group is inert |
| Consumer X **+** registry or tool | **No** — the attach returns **422** | the destination does not cross |
| `global` **+** group | **Yes, everywhere** | gates by consumer (= all); the group is inert |
| `global` **+** registry or tool | **No** | the destination does not cross, not through `global` either |

Only one of those eight rows changes behaviour without anyone editing the
policy: **`global` + group**. It used to be skipped on every non-MCP consumer
and now runs on all the gateway's LLM and A2A traffic. Audit for it before
deploying:

```sql
SELECT p.id, p.gateway_id, p.name, p.slug, p.priority, p.mcp_scope
FROM policies p
WHERE p.global = true AND p.enabled = true
  AND p.mcp_scope IS NOT NULL AND p.mcp_scope <> '{}'::jsonb
  AND jsonb_array_length(COALESCE(NULLIF(p.mcp_scope->'registry_ids','null'::jsonb),'[]'::jsonb)) = 0
  AND jsonb_array_length(COALESCE(NULLIF(p.mcp_scope->'tools',       'null'::jsonb),'[]'::jsonb)) = 0
ORDER BY p.gateway_id, p.slug;
```

### Which plugins cross

A group-only scope reaches a non-MCP plane **only if its plugin declares it is
safe there**. The criterion: a plugin that gates on a tool or registry name —
it reads `mcp.tool` or `mcp.registry_id`, or carries tool names in its config —
does not cross. A plugin that does not say anything does not cross either:
the default is closed, so nothing becomes cross-plane by accident.

`tool_allowlist` is the worked example of why. `deny_tools: ["*"]` with
`mcp_scope: {"except_groups": ["Finance"]}` attached to an LLM consumer would
cross on the consumer dimension, then lose its exception to inertness, and deny
**every** function call of that consumer. Attaching it answers 422 instead, and
the message names the plugin rather than the dimension.

### Two same-slug policies collapsing onto one plane

Uniqueness is checked on the **stored** levels; inertness **collapses** them.
Two `trustguard` policies scoped to `groups: [finance]` and
`groups: [engineering]` on the same LLM consumer are two valid levels that both
fall to the same one once the group stops gating. The load resolves it, in this
order:

| Situation on the inert plane | Resolution |
|---|---|
| There is an unscoped policy of the same slug | The unscoped one runs, the collapsed ones are dropped, with a warning |
| No unscoped one and exactly **one** collapses | It runs |
| No unscoped one and **two or more** collapse | **None of them runs**, and the load logs a warning naming all of them |

The third row has a cost worth saying out loud: for a blocking plugin, running
none of them leaves that plane **without a guardrail** — not with one of the
two. It is the deliberate choice, because running one of two contradicting
configurations is worse, but it is only noisy for whoever reads the log.

### Ordering is flat outside MCP

Inside MCP a scoped policy outranks an unscoped one at equal `priority`.
Outside MCP every entry scores 0, so the order stays `priority` → `slug` →
`id` — exactly what it was before the policy had a scope. Adding
`groups: […]` to a policy attached to an LLM consumer must never move it ahead
of its peers, because that would change which plugin writes first.

## One plugin per level

Two **enabled** policies of the same plugin may not run at the same level of a
gateway. A policy does not occupy one level: it occupies the cartesian product
of its dimensions, with `∅` meaning "all".

```
level = (consumer, group, destination)        with ∅ = "all"
destination = registry_id | (registry_id, tool)
```

A policy with two consumers, two registries and one group occupies **four**
levels. `except_groups` is not part of the key — it is a subtraction, not a
level — so two policies with the same `groups` and different `except_groups`
do conflict.

The conflict is an **overlap**, not an exact match. `registry_ids: [a, b]`
against `registry_ids: [b, c]` conflicts, because a call on `b` would put both
in the plan. That is the frequent case: an operator adds a registry to an
existing policy instead of creating another one.

| | Behaviour |
|---|---|
| Checked on | create, update (including flipping `enabled` to true), attach, promotion to `global`, duplicate |
| Not checked on | detach, un-setting `global` — they only free levels |
| Answer | `409 {"error": "conflict"}`, with the conflicting policy and the level in the message |
| `enabled: false` | Does not occupy and does not conflict, so "create the replacement disabled, review it, then switch" still works. Enabling it is a write and goes through the check |
| `mcp_scope: {}` | Occupies zero levels: a dormant policy never conflicts and never causes one |

A 409 here is not a transient failure. Retrying it will not help; the level has
to change.

Different levels coexist on purpose: "strict TrustGuard for Finance, lax for
Engineering" is two policies at two levels, and that is legitimate — see the
collapse rules above for what happens to that pair on an LLM consumer.

**Duplicates that already exist are not rejected retroactively.** The rule only
applies to writes. Pre-existing duplicates keep their rows and simply do not
run on an inert plane. Run the duplicate audit before deploying anyway, to know
how many warnings to expect.

## Semantics that are easy to get wrong

| Case | Behaviour |
|---|---|
| `mcp_scope` absent or `null` | Applies to all traffic of its consumers, on every plane (unchanged). |
| `mcp_scope: {}` (present, empty) | A tombstone, not an empty filter. It matches nothing and the policy runs on **no** plane — not MCP, not LLM, not A2A — and occupies zero levels. The API refuses to create or update a policy to `{}` (422). It only appears when the last registry a scope referenced is deleted, or when the user-dimension migration resets a scope that had no group left: the prune writes `{}`, never `NULL`, so the policy goes dormant instead of silently widening to the whole consumer. Reading it back or updating it answers with a warning saying it runs nowhere and how to revive it. Renaming such a policy still works. |
| Caller without groups | An API key acting as the application runs as `app:<consumer_id>`; an `acts_for_users` consumer with source `app` runs as `app:<consumer_id>:<end_user>`. Neither carries a `groups` claim, so such a caller never matches `groups` and never falls in `except_groups`. "Everyone but Finance" therefore still applies to it. |
| `global: true` + scope | Allowed (`POST .../policies/{id}/global`). This is how a scoped policy reaches the MCP Store, whose consumer only sees global policies. What it does to the rest of the gateway depends on the dimension: with `registry_ids` or `tools` it stays MCP-only, exactly as before — promotion is not a back door. With **only** `groups` it now runs on every LLM and A2A consumer of the gateway too, with the group inert. Promotion also goes through the level check and can answer 409. |
| Same `slug` twice | On MCP, scoped policies are additive: they never replace a same-`slug` policy the way an unscoped consumer policy replaces an unscoped global one. A scoped `trustguard` next to an unscoped one runs both. The API returns non-blocking `warnings` (`consumer <id> already runs plugin <slug> without scope`) on create, update and `global`; attach answers `200 {"warnings": [...]}` when there are warnings and `204` otherwise. Two same-slug policies at the **same** level are a 409 instead, and on an inert plane same-slug policies collapse rather than stack. |
| LLM or A2A consumer | Depends on the dimension. With `registry_ids` or `tools`: 422, the destination does not cross. With only `groups`/`except_groups`: accepted if the plugin is cross-plane safe, and the policy runs there with the group inert; 422 naming the plugin if it is not. The two 422s have different messages. |
| Policy with no consumers and not `global` | Runs nowhere, on any plane, and always did. Nothing was added to make that true — it simply falls in neither the global nor the per-consumer bucket. Create and update answer with a warning (`policy has no consumers and is not global: it runs nowhere`). |

### Precedence at equal `priority`

Plans are still ordered by `priority` ascending. Ties are broken by
specificity, then `slug`, then `id`:

1. tool-scoped, with principal
2. tool-scoped
3. registry-scoped, with principal
4. registry-scoped
5. principal only
6. unscoped (consumer-wide)

Parallel batches keep grouping by equal `priority`; specificity only orders
inside a batch.

This ladder is the MCP plane's. On an LLM or A2A consumer every entry scores 0,
so ties fall straight through to `slug` and `id`.

## Where the scope is evaluated

Only `tools/call` against a real upstream selects a plan by scope. `tools/list`,
prompts, resources and the gateway's `trustgate_*` meta-tools run the unscoped
policies only.

```
tools/call
  1. rate limit
  2. gateway meta-tools (trustgate_connect_*, trustgate_list_tools, Store)   → short-circuit
  3. resolve the exposed name → (registry, native tool)
     unknown tool, toolkit denial, pending consent fail HERE, before any policy
  4. select the plan for (registry, native tool, caller)
  5. pre-request policies
  6. upstream call
  7. pre-response policies, same plan as step 5
```

**Policies decide execution; the toolkit and Access decide visibility.** A tool
a policy denies still appears in `tools/list`; the call fails with JSON-RPC
error `-32001` on HTTP 200, without reaching the upstream.

**The binding a plugin gates on is not rewritable.** Step 3 fixes the
destination before any policy runs and records it on the request context as
`RegistryID` and `MCPTool`. A plugin that rewrites the request body cannot
reroute the call, and neither can one that writes metadata: `mcp.tool`,
`mcp.registry_id`, `mcp.registry_name` and `mcp.exposed_tool` mirror the
binding for plugins that only read metadata, but metadata is merged back out of
the isolated requests of a parallel batch, so a plugin ordered ahead of another
can change what it sees there. Plugins that gate a call — `tool_allowlist` — read
`MCPTool`, never the metadata key.

## Deny pattern: "only group X may call this tool"

`tool_allowlist` now supports MCP and judges the native tool name. Combined
with a scope it is the deny primitive; the scope selects who the policy runs
for, the plugin denies.

```json
{
  "name": "run_query is Finance only",
  "slug": "tool_allowlist",
  "enabled": true,
  "mode": "enforce",
  "settings": { "deny_tools": ["*"] },
  "mcp_scope": {
    "tools": [{ "registry_id": "7c1e0d2a-9a4b-4c1e-9c5a-1f2e3d4c5b6a", "tool": "run_query" }],
    "except_groups": ["Finance"]
  }
}
```

Finance callers are excepted, so the policy is not in their plan and the call
proceeds. Everyone else, API keys included, gets `-32001`. In `mode: observe`
the call goes through and the event records the decision.

## Observability

When tracing is active, the `tools/call` event carries `policy_scope` inside
the MCP metadata:

```json
"policy_scope": {
  "evaluated": 3,
  "matched": ["<policy id>"],
  "skipped": [
    { "id": "<policy id>", "name": "Jira audit", "reason": "destination" },
    { "id": "<policy id>", "name": "Finance DLP", "reason": "principal" }
  ]
}
```

`reason` is `destination`, `principal` (the caller is not in `groups`) or
`except`. `evaluated` counts only
scoped policies; unscoped ones never appear. `policies[]` keeps listing the
plugins that actually ran. Without an active span nothing is computed.

## Admin API

| Call | Shape |
|---|---|
| `POST /v1/gateways/{gw}/policies` | `mcp_scope` object as in the example; omitted keeps the policy consumer-wide. 422 on: registry of another gateway or not MCP, empty `tool`/`groups` entries, duplicates, a registry both in `registry_ids` and `tools`, a scope without entries, a plugin without MCP support, a `users` or `except_users` key. 409 when the policy would occupy a level another enabled policy of the same plugin already occupies. |
| `PUT /v1/gateways/{gw}/policies/{id}` | Tri-state: `mcp_scope` **omitted** leaves the stored scope untouched, `null` clears it, an object replaces it. Same 409. Flipping `enabled` to true is a write and is checked too. |
| `GET /v1/gateways/{gw}/policies?registry_id=<uuid>` | Only policies whose scope names that registry, in `registry_ids` or in `tools`. A non-UUID value is a 400. |
| `POST .../policies/{id}/global` | Promotes the policy to the all-traffic level; the response may carry `warnings`, and it can answer 409. |
| `POST .../consumers/{id}/policies/{pid}` | `204`, or `200 {"warnings": [...]}` only when the consumer already runs the plugin without scope. 409 on a level conflict. On a non-MCP consumer, 422 for a destination scope or for a plugin that gates on tool names. |
| `GET .../registries/{id}/tools` | The registry's advertised tools, with the upstream's **native** names — the key `mcp_scope.tools[].tool` stores. 409 when the registry cannot be introspected without a principal (per-principal auth, or URL variables in the target): write the tool name by hand. 502 when the upstream is unreachable or `tools/list` fails: retry. |

Responses echo `mcp_scope` (absent when unset, `{}` when pruned) and, on
create/update/global, an optional `warnings: []string`.

## Removing the user dimension

`users` and `except_users` shipped with the first version of the field and were
dropped before the console exposed them. Migration
`20260917120000_drop_policy_mcp_scope_users` rewrites the stored scopes:

- a scope that still names `groups` or `except_groups` loses only its user
  entries, so it keeps running for the audience the groups describe;
- a scope left with no group at all is written as `{}` and goes **dormant**
  instead of keeping its destination and applying to every caller of it. This
  is the same fail-closed state a registry delete leaves behind, and it has to
  be rewritten in terms of groups by hand — a `PUT` with the new `mcp_scope`.

Find them with
`SELECT id, name FROM policies WHERE mcp_scope = '{}'::jsonb;` after the
migration. A running data plane keeps serving its snapshot until the next
publish, so a dormant policy stops running when the snapshot is rebuilt, not
the moment the migration lands.

## Rollout

- The column is additive (`policies.mcp_scope JSONB NULL`); the snapshot carries
  it inside the policy JSON, the proto does not change.
- **Deploy the data plane before the control plane.** An old data plane ignores
  `mcp_scope` and runs the policy consumer-wide. Do not create scoped policies
  until both are on the new version.
- Reverting the code restores the previous behaviour without touching any data.
- Before deploying, run the audits below. One of them is a gate; one of them,
  deliberately, is not.

### Deployment gates

**Gate — group-only global policies.** The query in
[What reaches an LLM or A2A chain](#what-reaches-an-llm-or-a2a-chain) lists the
policies that start running on all LLM and A2A traffic of their gateway without
anyone editing them. Do not deploy while it returns rows that have no written
decision each: let it into LLM, take `global` off it, or put it to sleep. It is
very likely empty — but *very likely empty* is something you check, not
something you assume.

**Not a gate — level duplicates that already exist.** Same-slug policies that
already occupy the same level cannot be rejected retroactively, and the runtime
leaves **all** of them unexecuted on an inert plane. Run the audit anyway, so
you know how many load warnings to expect and can go looking for them:

```sql
-- Run it three times: once with the group level as below, then substituting
-- the registry level and the (registry, tool) level, or destination
-- duplicates will not show up.
WITH lvl AS (
  SELECT p.id, p.gateway_id, p.slug,
         COALESCE(cp.consumer_id, '00000000-0000-0000-0000-000000000000'::uuid) AS consumer_lvl,
         COALESCE(p.mcp_scope->>'groups', '*') AS group_lvl
  FROM policies p
  LEFT JOIN consumer_policy cp ON cp.policy_id = p.id
  WHERE p.enabled = true AND (p.mcp_scope IS NULL OR p.mcp_scope <> '{}'::jsonb)
)
SELECT gateway_id, slug, consumer_lvl, group_lvl,
       count(*) AS n, array_agg(id) AS policy_ids
FROM lvl GROUP BY 1,2,3,4 HAVING count(*) > 1;
```

> **This is not a gate because TrustGate v2 has almost no production exposure**,
> so the set of real duplicates is expected to be tiny and resolving them as
> they show up costs less than resolving them first. **The reasoning depends on
> that fact and therefore expires with it: if the v2 population grows, this
> audit becomes a deployment gate again.** The argument is not "duplicates are
> harmless" — it is "there are almost none". Re-read this paragraph when that
> stops being true; do not inherit it.
>
> What is being accepted, unsoftened: for a blocking plugin — a TrustGuard, a
> prompt-injection guardrail — a pair of duplicates leaves that plane with **no
> guardrail at all**, not with one of the two, and the only trace is a warning
> in the load log.

### Observation window

After the data plane goes out, watch p95 latency on the LLM plane of the
gateways that had rows in the group-only global audit. The collapse rules
should keep it flat; if it rises, the coalescing is missing a slug.

## Emergency levers

Two writes change where a policy runs, with no deploy and no code change. They
are not the same lever and they are not opposites of "remove the scope" —
each one has an exact effect:

| Write | Exact effect |
|---|---|
| `PUT /v1/gateways/{gw}/policies/{id}` with `{"mcp_scope": {}}` | **Puts the policy to sleep on every plane.** It runs on no MCP consumer, no LLM consumer and no A2A consumer, whatever it is attached to and whether or not it is `global`. It also stops occupying any level, so it can no longer conflict with anything. Its settings, attachments and `global` flag are all preserved. |
| `PUT /v1/gateways/{gw}/policies/{id}` with `{"mcp_scope": null}` | **Makes the policy run on every plane.** The scope is cleared, so it behaves like a policy that never had one: it runs on all traffic of the consumers it is attached to, on all three planes, and on the whole gateway if it is `global`. It is the widening lever, not the off switch. |

Pick by what you want to happen:

- A policy is firing where it should not, or you want it out of the way while
  you investigate → `{}`.
- A policy is not firing where it should because its scope no longer describes
  anything reachable (its registry was deleted, or it was left dormant by the
  user-dimension migration) and you want coverage back **now**, accepting that
  it covers everything → `null`.

Neither lever is a rollback of the feature. Reverting the code is.

Two traps:

- `{}` is a state the API refuses to accept on create and on a normal update
  for a *new* policy — this lever is the deliberate exception, reached by
  writing the empty object on an existing one. The stored value is `{}`, never
  `NULL`, and the two mean opposite things.
- A running data plane keeps serving its snapshot until the next publish, so
  either lever takes effect when the snapshot is rebuilt, not the moment the
  `PUT` returns.

Find every policy currently asleep with:

```sql
SELECT id, gateway_id, name, slug FROM policies WHERE mcp_scope = '{}'::jsonb;
```
