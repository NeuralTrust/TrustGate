# MCP policy scope (`mcp_scope`)

A policy attached to an MCP consumer used to run on every `tools/call` of that
consumer. `mcp_scope` narrows it to a registry, a tool, a user or a group, so
"DLP for Finance on Snowflake" or "only Finance may call `run_query`" is one
policy instead of one consumer per audience. Without the field nothing changes:
the policy keeps running consumer-wide. The LLM plane never reads it.

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

## The six dimensions

| Field | Selects | Key |
|---|---|---|
| (no `mcp_scope`) | all traffic of the consumers it is attached to, or of every consumer when `global` | — |
| `registry_ids` | calls to any tool of these registries | registry id (a Store shelf id also matches its per-user instances) |
| `tools[{registry_id, tool}]` | calls to one tool of one registry | the upstream's **native** tool name, never the exposed name (federated `mcp_<hash>_…`) nor a toolkit `expose_as` alias |
| `users` | the caller | token `sub`, or email (case-insensitive; other subjects compared as written) |
| `groups` | the caller | same key as a Store Access grant: the IdP `externalId` when the group has one, otherwise its display name; exact match after trimming |
| `except_users`, `except_groups` | callers to remove after a positive match | same keys as `users` / `groups` |

Destination (`registry_ids` ∪ `tools`) and principal (`users` ∪ `groups`) are
combined with **AND** inside one policy; an empty list means "any" on that
dimension. Across policies the result is the **union**: every policy that
matches enters the plan.

## Semantics that are easy to get wrong

| Case | Behaviour |
|---|---|
| `mcp_scope` absent or `null` | Applies to all traffic of its consumers (unchanged). |
| `mcp_scope: {}` (present, empty) | Matches nothing. The API refuses to create or update a policy to `{}` (422). It only appears when the last registry a scope referenced is deleted: the prune writes `{}`, never `NULL`, so the policy goes dormant instead of silently widening to the whole consumer. Renaming such a policy still works. |
| Caller without a user identity | An API key acting as the application runs as `app:<consumer_id>`; an `acts_for_users` consumer with source `app` runs as `app:<consumer_id>:<end_user>`. Neither carries groups or an email claim, so such a caller never matches `groups`, never matches an email in `users`, and never falls in `except_groups`. "Everyone but Finance" therefore still applies to it. |
| `global: true` + scope | Allowed (`POST .../policies/{id}/global`). This is how a scoped policy reaches the MCP Store, whose consumer only sees global policies. |
| Same `slug` twice | Scoped policies are additive: they never replace a same-`slug` policy the way an unscoped consumer policy replaces an unscoped global one. A scoped `trustguard` next to an unscoped one runs both. The API returns non-blocking `warnings` (`consumer <id> already runs plugin <slug> without scope`) on create, update and `global`; attach answers `200 {"warnings": [...]}` when there are warnings and `204` otherwise. |
| LLM consumer | A policy with `mcp_scope` cannot be attached to an LLM consumer (422). |

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

`reason` is `destination`, `principal` or `except`. `evaluated` counts only
scoped policies; unscoped ones never appear. `policies[]` keeps listing the
plugins that actually ran. Without an active span nothing is computed.

## Admin API

| Call | Shape |
|---|---|
| `POST /v1/gateways/{gw}/policies` | `mcp_scope` object as in the example; omitted keeps the policy consumer-wide. 422 on: registry of another gateway or not MCP, empty `tool`/`users`/`groups` entries, duplicates, a registry both in `registry_ids` and `tools`, a scope without entries, a plugin without MCP support. |
| `PUT /v1/gateways/{gw}/policies/{id}` | Tri-state: `mcp_scope` **omitted** leaves the stored scope untouched, `null` clears it, an object replaces it. |
| `GET /v1/gateways/{gw}/policies?registry_id=<uuid>` | Only policies whose scope names that registry, in `registry_ids` or in `tools`. A non-UUID value is a 400. |
| `POST .../policies/{id}/global` | Promotes the policy; the response may carry `warnings`. |
| `POST .../consumers/{id}/policies/{pid}` | `204`, or `200 {"warnings": [...]}` only when the consumer already runs the plugin without scope. 422 on an LLM consumer. |

Responses echo `mcp_scope` (absent when unset, `{}` when pruned) and, on
create/update/global, an optional `warnings: []string`.

## Rollout

- The column is additive (`policies.mcp_scope JSONB NULL`); the snapshot carries
  it inside the policy JSON, the proto does not change.
- **Deploy the data plane before the control plane.** An old data plane ignores
  `mcp_scope` and runs the policy consumer-wide. Do not create scoped policies
  until both are on the new version.
- To turn the feature off without deploying, clear the scopes
  (`PUT ... {"mcp_scope": null}`). Reverting the dispatcher reorder restores the
  previous consumer-wide behaviour for any scope left in place.
