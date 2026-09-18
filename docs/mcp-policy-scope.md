# MCP policy scope (`mcp_scope`)

A policy attached to an MCP consumer used to run on every `tools/call` of that
consumer. `mcp_scope` narrows it to a registry, a tool or a group, so
"DLP for Finance on Snowflake" or "only Finance may call `run_query`" is one
policy instead of one consumer per audience. The principal is always a group;
individual users are not a dimension. Without the field nothing changes:
the policy keeps running consumer-wide. The LLM plane never reads it.

One limit before the examples: the group dimension does not gate a caller that
authenticates with an api key, so a policy scoped to `groups` also runs on the
consumer's api-key traffic. See
[Api-key callers and `groups`](#api-key-callers-and-groups).

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

## Semantics that are easy to get wrong

| Case | Behaviour |
|---|---|
| `mcp_scope` absent or `null` | Applies to all traffic of its consumers (unchanged). |
| `mcp_scope: {}` (present, empty) | Matches nothing. The API refuses to create or update a policy to `{}` (422). It only appears when the last registry a scope referenced is deleted: the prune writes `{}`, never `NULL`, so the policy goes dormant instead of silently widening to the whole consumer. Renaming such a policy still works. |
| Caller by api key | **The principal dimension does not gate for it.** An api key acting as the application runs as `app:<consumer_id>`, and an `acts_for_users` consumer with source `app` runs as `app:<consumer_id>:<end_user>`; the credential belongs to the application, not to a person, so the scope's `groups` are ignored and the policy runs. A policy written for one group therefore also runs on the consumer's api-key traffic, and `groups` can no longer keep a policy off it. See [Api-key callers and `groups`](#api-key-callers-and-groups). |
| Caller by token without a `groups` claim | Gates as before: it is not in `groups`, so a scope naming them skips it (`principal`), and it never falls in `except_groups` either. An identity provider that emits no groups does not make the principal inert — only the api key does. |
| `global: true` + scope | Allowed (`POST .../policies/{id}/global`). This is how a scoped policy reaches the MCP Store, whose consumer only sees global policies. **A scope also takes the policy off every non-MCP consumer of the gateway**: scoped policies never enter the plan of an LLM or A2A consumer. Giving a scope to a global policy that was covering LLM traffic silently stops it there, so create, update and `global` answer with a non-blocking warning (`policy is global and scoped to MCP: it no longer runs on <n> non-MCP consumer(s) of the gateway`). |
| Same `slug` twice | Scoped policies are additive: they never replace a same-`slug` policy the way an unscoped consumer policy replaces an unscoped global one. A scoped `trustguard` next to an unscoped one runs both. The API returns non-blocking `warnings` (`consumer <id> already runs plugin <slug> without scope`) on create, update and `global`; attach answers `200 {"warnings": [...]}` when there are warnings and `204` otherwise. |
| LLM consumer | A policy with `mcp_scope` cannot be attached to an LLM consumer (422). |

### Api-key callers and `groups`

A caller that authenticates with an api key has an **inert principal**: the
group dimension of the scope is not evaluated for it and the policy runs. This
is deliberate — with an api key the caller is the application, and no identity
provider is in the loop to say which groups it belongs to.

The relaxation is **asymmetric**, and only one direction moved:

| Scope | Caller by api key |
|---|---|
| `groups: [Finance]` | **Runs.** Previously it did not (`principal`). This is the change. |
| `except_groups: [Finance]` | Runs, as before. An api-key caller carries no groups, so it never fell in the exception. |

The direction that changed is the allow-list one. **`groups` no longer says
who a policy applies to — it says which token holders it applies to, plus
every api-key caller of the consumer.** Two consequences, and they point
opposite ways:

- A policy written as "this only concerns Finance" now also runs on the
  consumer's api-key traffic. On the MCP plane every plugin that can carry a
  scope is restrictive — `trustguard`, `tool_allowlist`, `rate_limiter`,
  `per_tool_rate_limiter`, `request_size` — so what api-key callers get is
  more enforcement, not less: calls that used to pass can start being denied,
  rate-limited or inspected, and they share the group's rate-limit buckets.
  Nobody has to edit anything for that to start happening.
- There is no longer any way to keep a policy off machine traffic by scoping
  it to a group. A scope that has to exclude api-key callers has to name a
  destination they do not reach, or the consumer has to stop accepting api
  keys.

The inert branch skips the principal dimension entirely, so a plugin whose
execution were permissive rather than restrictive would be granted, not
applied, to those callers. None of the MCP-capable plugins is permissive
today; that is a property of the plugin set, not of the rule.

Three things follow, and they are the safeguards, not decoration:

- The decision is an **allow-list of one method**. Only an api key makes the
  principal inert. A caller with no principal at all, mTLS, a bearer token
  whose issuer emits no `groups`, and the legacy undifferentiated `jwt` method
  all keep gating, so one misconfigured identity provider cannot turn into a
  gateway-wide bypass of every group check.
- Create, update and attach answer with a non-blocking warning naming every
  MCP consumer reached that accepts an api-key auth
  (`policy narrows to groups but consumer <id> accepts api-key auth: group
  checks do not apply to those callers`). Either drop the api-key auth from
  that consumer, or accept that the narrowing does not cover it.
- Auditing which policies this affects is a deploy gate, not a follow-up:
  every policy with `groups` whose consumers accept api keys has to be seen by
  its owner before the behaviour changes, because it changes without anyone
  editing anything.

To make a policy depend on the caller's group at all, the credential has to be
one that carries a group: attach a token-based auth to the consumer and remove
the api-key auth. There is no per-policy opt-out.

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
proceeds. Everyone else, api keys included, gets `-32001`. In `mode: observe`
the call goes through and the event records the decision.

Nothing about this changed with the inert principal: an api-key caller carries
no groups, so it was never excepted and still is not. The form that did change
is `groups`, which now also selects api-key callers — so a deny-all scoped
with `groups: ["Finance"]` denies them too.

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

A group-scoped policy that matched because the caller's principal was inert
appears in `matched` like any other match: the span does not yet say that the
group was not evaluated. Reading a trace, an api-key call and a call by a
member of the group look the same.

## Admin API

| Call | Shape |
|---|---|
| `POST /v1/gateways/{gw}/policies` | `mcp_scope` object as in the example; omitted keeps the policy consumer-wide. 422 on: registry of another gateway or not MCP, empty `tool`/`groups` entries, duplicates, a registry both in `registry_ids` and `tools`, a scope without entries, a plugin without MCP support, a `users` or `except_users` key. |
| `PUT /v1/gateways/{gw}/policies/{id}` | Tri-state: `mcp_scope` **omitted** leaves the stored scope untouched, `null` clears it, an object replaces it. |
| `GET /v1/gateways/{gw}/policies?registry_id=<uuid>` | Only policies whose scope names that registry, in `registry_ids` or in `tools`. A non-UUID value is a 400. |
| `POST .../policies/{id}/global` | Promotes the policy; the response may carry `warnings`. |
| `POST .../consumers/{id}/policies/{pid}` | `204`, or `200 {"warnings": [...]}` when the attach has something to warn about: the consumer already runs the plugin without scope, or the policy narrows to `groups` and the consumer accepts an api-key auth. 422 on an LLM consumer. |

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
- To turn the feature off without deploying, clear the scopes
  (`PUT ... {"mcp_scope": null}`). Reverting the dispatcher reorder restores the
  previous consumer-wide behaviour for any scope left in place.
