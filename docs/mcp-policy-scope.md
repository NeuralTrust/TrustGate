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
| (no `mcp_scope`) | all traffic of the consumers it is attached to, of every consumer when `global`, or of every MCP consumer and the Store when `mcp_wide` | — |
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

## The nearer destination wins

A policy attached to `(registry, tool)` **replaces** the registry-wide policy of
the same `slug` on that tool. Every other slug keeps running, and so does the
registry policy on every other tool of that registry.

Before, both ran. On a call to that tool the same plugin executed twice: two
`rate_limiter` policies meant two counters, each with its own budget, so the
limit an operator had written for the tool was not the limit the tool had.

The rule is per slug, never wholesale. A registry-wide `trustguard` is not
switched off because someone attached a `rate_limiter` to one of its tools.

Who wins can depend on the caller, because either policy may also narrow by
group:

| Registry policy | Tool policy | On that tool |
|---|---|---|
| applies to everyone | applies to everyone | the tool policy, alone |
| applies to everyone | narrowed by group | the tool policy for a caller in the group; the registry policy for everyone else |
| narrowed by group | applies to everyone | the tool policy, alone: it covers every caller |
| narrowed by group | narrowed by group | the tool policy only for callers it reaches; otherwise the registry policy, if *it* reaches them |

**A tool policy that does not reach a caller replaces nothing.** The registry
policy is not disabled by the existence of a narrower one; it stands down only
where the narrower one actually applies.

What this rule does **not** cover: a consumer-wide policy (scope with no
destination, or no scope at all) is not a destination, so it still stacks with
both. Only registry and tool are ranked against each other.

## Inertness is per dimension

`mcp_scope` is not one thing that is either on or off outside MCP. It is a set
of dimensions with different fates:

> **The consumer dimension always gates, on both planes. Group, registry and
> tool only gate on MCP; on LLM and A2A they are inert.**

| Dimension | Where it lives | Gates on… | Outside MCP | Why |
|---|---|---|---|---|
| **Consumer** | `global`, `mcp_wide` and the consumer attachments — **not part of `mcp_scope`** | **always**: MCP, LLM and A2A | gates the same | It is not scope, it is routing. It exists and means the same on all three planes |
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
| **Only** group, no consumer, neither `global` nor `mcp_wide` | **No** | a draft: it runs nowhere — already true today |
| **Only** registry or tool, no consumer, neither `global` nor `mcp_wide` | **No** | same |
| `mcp_wide`, any scope | **No** | it runs on MCP consumers and the Store only; the LLM and A2A load never sees it |
| Consumer X **+** group | **Yes**, on X | gates by consumer; the group is inert |
| Consumer X **+** registry or tool | **No** — the attach returns **422** | the destination does not cross |
| `global` **+** group | **Yes, everywhere** | gates by consumer (= all); the group is inert |
| `global` **+** registry or tool | **No** | the destination does not cross, not through `global` either |

Only one of those nine rows changes behaviour without anyone editing the
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

### Which plugins run where the scope is inert

The opt-in is per plugin and starts denied, so a plugin that says nothing keeps
a group-only policy off the LLM and A2A planes with a 422 that names it.

| Plugin | Runs on an inert plane | Why |
|---|---|---|
| `trustguard` | **yes** | inspects the content of the request or response; reads no tool or registry name |
| `request_size_limiter` | **yes** | measures the body; means the same thing on every plane |
| `rate_limiter` | no | would spend the group's budget on traffic that is not the group's |
| `per_tool_rate_limiter` | no | keyed by tool; outside MCP there is no tool to key on |
| `tool_allowlist` | no | gates by tool name; a deny-all narrowed to a group would widen to every function call |

For the two that opted in, the group stops selecting **who** the policy runs
for, so it covers all of that consumer's traffic. For a content guardrail and a
size ceiling that is a stricter bound, never a wider one — which is the whole
test a plugin has to pass before it may opt in.

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
| Checked on | create, update (including flipping `enabled` to true), attach, promotion to `global` or `mcp_wide`, duplicate |
| Not checked on | detach, un-setting `global` or `mcp_wide` — they only free levels, with one exception that predates `mcp_wide`: a global policy keeps its links, and demoting it puts them back on their consumers' levels unchecked. An MCP-wide policy holds no links, so its demotion only frees levels |
| Answer | `409 {"error": "conflict"}`, with the conflicting policy and the level in the message |
| `enabled: false` | Does not occupy and does not conflict, so "create the replacement disabled, review it, then switch" still works. Enabling it is a write and goes through the check |
| `mcp_scope: {}` | Occupies zero levels: a dormant policy never conflicts and never causes one |

A 409 here is not a transient failure. Retrying it will not help; the level has
to change. The one transient 409 is `placement changed`: the policy was updated
while it was being promoted, or promoted while it was being updated. Reload it
and retry.

An MCP-wide policy takes the levels a global policy of the same scope takes:
the consumer is "all", whatever is attached. Two MCP-wide policies of one
plugin with overlapping groups conflict, and so do an MCP-wide and a global one.
Swapping a policy between the two flags is checked once and never conflicts
with itself.

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
| Caller by api key | **The principal dimension does not gate for it.** An api key acting as the application runs as `app:<consumer_id>`, and one naming an end user in `X-NeuralTrust-End-User` runs as `app:<consumer_id>:<end_user>`; the credential belongs to the application, not to a person, so the scope's `groups` are ignored and the policy runs. A policy written for one group therefore also runs on the consumer's api-key traffic, and `groups` can no longer keep a policy off it. See [Api-key callers and `groups`](#api-key-callers-and-groups). |
| Caller by token without a `groups` claim | Gates as before: it is not in `groups`, so a scope naming them skips it (`principal`), and it never falls in `except_groups` either. An identity provider that emits no groups does not make the principal inert — only the api key does. |
| `global: true` + scope | Allowed (`POST .../policies/{id}/global`). This is one way a scoped policy reaches the MCP Store, whose consumer only sees global and MCP-wide policies. What it does to the rest of the gateway depends on the dimension: with `registry_ids` or `tools` it stays MCP-only, exactly as before — promotion is not a back door. With **only** `groups` it now runs on every LLM and A2A consumer of the gateway too, with the group inert; to reach MCP by group, the Store included, without touching LLM and A2A, use `mcp_wide`. Promotion also goes through the level check and can answer 409. |
| `mcp_wide: true` + scope | Allowed (`POST .../policies/{id}/mcp-wide`) for a plugin that supports MCP, 422 otherwise. Runs on every MCP consumer of the gateway and on the Store, narrowed by the scope, and never on LLM or A2A. A `null` scope means every MCP caller. It holds no consumer links: the promotion removes them in the same write, attaching a consumer answers 422 until the policy is demoted, and the demotion leaves a draft with nothing to revive. An unscoped policy attached to a consumer still overrides an unscoped MCP-wide one of the same slug. Plugin state is gateway-wide, as for `global`: one budget across every MCP consumer and the Store, reported with the dimension `global` (`exceeded_type: global`, Redis key `ratelimit:<policy>:global:<gateway>`). Api-key callers of a regular MCP consumer skip the group check, as for any group scope: see [Api-key callers and `groups`](#api-key-callers-and-groups). A same-plugin policy with the same groups attached to an MCP consumer holds that consumer's level, not the "all" one, so the level check lets it through and both run there; nothing warns about it, and `global` + groups has the same gap. |
| Same `slug` twice | On MCP, scoped policies are additive **except between a registry and one of its tools**, where the nearer destination wins — see [The nearer destination wins](#the-nearer-destination-wins). A scoped `trustguard` next to an unscoped one still runs both. The API returns non-blocking `warnings` (`consumer <id> already runs plugin <slug> without scope`) on create, update and the promotions (`global`, `mcp_wide`); attach answers `200 {"warnings": [...]}` when there are warnings and `204` otherwise. Two same-slug policies at the **same** level are a 409 instead, and on an inert plane same-slug policies collapse rather than stack. |
| LLM or A2A consumer | Depends on the dimension. With `registry_ids` or `tools`: 422, the destination does not cross. With only `groups`/`except_groups`: accepted if the plugin is cross-plane safe, and the policy runs there with the group inert; 422 naming the plugin if it is not. The two 422s have different messages. |
| Policy with no consumers, neither `global` nor `mcp_wide` (a draft) | Runs nowhere, on any plane, and always did. Nothing was added to make that true — it simply falls in none of the global, MCP-wide or per-consumer buckets. Create and update answer with a warning (`policy has no consumers and is not global: it runs nowhere`); an MCP-wide policy never gets it. |

### Api-key callers and `groups`

A caller that authenticates with an api key has an **inert principal**: the
group dimension of the scope is not evaluated for it and the policy runs. This
is deliberate — with an api key the caller is the application, and no identity
provider is in the loop to say which groups it belongs to.

**The Store is outside this by construction.** Groups carry the most meaning on
the MCP Store, and the Store cannot be reached by an api key at all: it is
synthetic, never persisted, and `BuildStoreConsumer` gives it no auths of its
own, so platform login is the only way in. The inert branch never fires there.

What is left is the narrower case the rule is really about: a regular MCP
consumer carrying **both** an api-key auth **and** a token auth whose identity
provider emits a `groups` claim. Nothing in the gateway reserves groups for the
Store — `Principal.Groups()` reads the claim off whatever token authenticated
the caller — so this is a convention of how the platform issues tokens, not an
invariant the code enforces. The warning below names exactly that intersection,
and on a deployment where only the Store emits groups it will stay silent.

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

**Rewriters run before readers within a priority.** A parallel batch runs on
isolated copies of the request and writes a rewrite back only when it ends, so a
policy that reads content would otherwise score the original text next to a
masker at the same priority. The planner therefore splits such a run into the
rewriters first and then the plugins that opted in as content readers:
`openai_moderation`, `azure_content_safety` and `semantic_cache` (at
`pre_request`). Readers stay parallel among themselves, and a run with no
rewriter, no reader, or a different priority is planned as before. If an earlier
rewriter blocks, or short-circuits at a request stage (a cache hit), the readers
after it do not run. The cost is latency: the rewriter and the slowest reader
now add up instead of overlapping. `semantic_cache` counts as a rewriter at the
response stages, so nothing is moved after it there.

**Local rewriters run before the rewriters that call a third party.** Among the
rewriters of such a run, the ones that opted in as local (their rewrite never
leaves the gateway: `regex_replace`, `prompt_template`, `prompt_compression`,
`model_allowlist`, `tool_allowlist`, `tool_injection`, `token_rate_limiter`,
`per_tool_rate_limiter`) take the rewriter slots first, and the rewriters that
send the content to a provider (`bedrock_guardrail`, `google_model_armor`,
`trustguard`) follow. So AWS, Google and TrustGuard receive the text with
`regex_replace`'s masks applied, never the raw values the client will not see.
Entries that neither rewrite nor read keep their exact place. A rewriter that
does not declare itself local is treated as remote, so forgetting the opt-in
can only move a plugin later. Two remote rewriters keep their order between
themselves: whichever runs first still sees the text the other one masks. Two
rewriters of one body were already sequential, so this adds no latency.

**A buffered response rewrite is handed on.** At `pre_response` a plugin
rewrites the upstream body by returning the new one with a 2xx status. That
used to end the stage, so a mask at one priority silently skipped every later
guard, at any later priority, and dropped every later rewriter's masks. The
chain now goes on over the rewritten body: later guards judge what the client
will receive, a later rewrite builds on the earlier one, and the last body
written is the one sent. A block after a rewrite still blocks, and a non-2xx
short-circuit is a denial that still ends the stage, so nothing can overwrite
it. Request stages are unchanged: a short-circuit there (a cache hit) still
ends the stage.

**Streamed responses follow the same rule.** A streamed segment does not use
batches: the chain walks the streaming entries one at a time. The walk is now
ordered like a batch (local rewriters, then remote rewriters, then opted-in
readers at the same priority; other entries keep their place, priorities are
never crossed), and a rewrite is handed on. When an enforcing entry masks a
segment, the entries behind it receive the masked text, so `openai_moderation`,
`bedrock_guardrail`, `google_model_armor` or `trustguard` at the same priority
as `regex_replace` never sends the unmasked text to its provider. Consequences:

- The last transform wins, and it already contains the earlier ones, because
  each rewriter transforms the previous rewriter's output. Before, only the first
  transform in the chain was kept and the others were dropped.
- An `observe` entry's transform is never applied to the client, so it is not
  handed on: the entries behind it judge the text the client will actually get.
- A block still ends the chain and discards any transform of the same segment.
- If a guardrail fails on an availability failure after an earlier entry masked
  the segment, the failure fails open and the chain goes on with the masked
  text: what is released is the masked text, never the raw text. A failure that
  depends on the content of the block cuts the stream in a mode that blocks, and
  so does a mask that cannot be applied.
- Masks can stack within a block: a wide pattern in a later rewriter may match
  inside the placeholder an earlier one wrote (`[MASKED_*]`). Only placeholders
  change, never raw data. Across blocks they do not: `regex_replace` replaces
  only matches that reach into the block's new text, so a placeholder already
  released, even one matching its own pattern (`[SSN]` under `(?i)ssn`), is
  left alone instead of cutting the stream. The same rule keeps `^` and `\b`
  from matching where a tail window starts once a response passes
  `max_accumulated_bytes`. A match that starts in released text and ends in the
  new block still cuts: its first part is already with the client.
- The rule applies only within consecutive `parallel` entries of the same
  priority. A reader with `parallel: false`, or at another priority, is not
  moved; the console always writes `parallel: true`.
- If the composed mask cannot be applied to the held text, the stream is cut, as
  for a single rewriter.

**Each streaming entry is sent its own window.** One stream has one head gate
and one cadence, taken from the first entry that owns them, usually
`trustguard`. The stream's own `on_error` is `fail_open` when a guardrail takes
part, because no guardrail has a setting for it, and a passive rewriter
(`regex_replace`) does not change that: a guardrail's availability failure is
absorbed per entry and fails open, and one that depends on the content of the
block arrives as a cut verdict. The stream keeps the largest
`max_accumulated_bytes` of its participants, and each entry is handed only the
tail of the text that its own `streaming.max_accumulated_bytes` allows. So a
policy's setting bounds what its provider receives whatever policy owns the
stream, and a provider with a small limit never shrinks what another policy
inspects. A rewrite over that tail is put back behind the text the entry did
not see. The one exception is a block whose new text alone is larger than the
window: that text is about to reach the client, so it is screened in full, in
chunks of the window (at most 8 per block, four in flight, one for
`bedrock_guardrail`) that share an
overlap of 4,096 bytes where the window is 32 KiB or more, and an eighth of the
window below that, so a long secret lies whole in one chunk. A block that would
need more than 8 chunks is a failure of the content: a mode that blocks cuts the
stream (`input_too_large` / `chunk_limit`) and observe releases the block. The
chunks are read through the same rules as a buffered evaluation: a chunk that
blocks wins, a failure that is the content's cuts, a throttle on any piece but the
first is the content's too when the first piece answered without a throttle (the block's own pieces beside or before it may have
caused it; one on the first piece is the provider's load, which makes every throttle of the block fail open, and so
is every throttle on `bedrock_guardrail`, whose pieces are spaced so a throttle is attributed to traffic outside the block). A throttled piece of the first round is sent once more after a short backoff. A mask from any chunk is applied, and an
availability failure releases the block unless a mask or a finding can still be
used. A block is held for at most one piece timeout per round of pieces and never
more than four, whatever the provider does. A piece that was not started or was
cut by that deadline is availability only when some piece's call took more than
half of its timeout (the provider was slow), and otherwise the block's own size
used the time: it is cut in a mode that blocks as `input_too_large` /
`chunk_budget`. `trustguard` is not split: it bounds its own payload and is sent the block
whole, and a block of more than 65,536 bytes is refused before any call with the
failure reason `stream_block_too_large` (`input_too_large` / `chunk_limit`; a cut
in a mode that blocks, recorded in observe). The gateway does not split what the
upstream sends in one server-sent event, so a single upstream event of more than
64 KiB (the provider's own framing) is such a block and cuts a TrustGuard stream
in Enforce. Every other evaluation sends at most the entry's window, which a provider
ceiling caps whatever the setting asks for, so the time of a block does not grow
with the response and a long preamble cannot push the blocks that follow past
the per-block deadline. The
ceilings follow the providers' per-request limits and deadlines, and a larger
`streaming.max_accumulated_bytes` is capped to them:

- `google_model_armor`: 56 KiB (57,344 bytes), and never more. Model Armor
  skips its filters above 65,536 tokens, which the plugin counts as a filter
  that did not run, so a larger payload would release the block uninspected. The
  stream sends an 8 KiB correlation prompt with each block, and 57,344 bytes
  plus that prompt is 65,536. Google does not raise this limit, so a higher
  setting is treated as 56 KiB.
- `bedrock_guardrail` (streaming is opt-in): 8 KiB, and never more. AWS bounds
  each `ApplyGuardrail` input per guardrail policy in text units of up to 1,000
  characters, at a number of units per second that goes as low as 25 (for
  example in eu-west-3, eu-south-1 and sa-east-1). A block of 8 KiB is at most
  9 units, so it leaves room for concurrent blocks and for the retry a
  throttled call gets within the block's deadline; a larger setting is treated
  as 8 KiB. A throttled block that is still throttled after its retries is
  released as an availability failure and does not count toward retiring the
  guardrail for the rest of the stream. A buffered Bedrock request is different:
  its chunks are sent one at a time and spaced under the region's quota, so a
  throttle there is always availability. The pieces of one streamed block larger
  than the window are sent one at a time and spaced by the same per-block spacer,
  so a throttle on a piece is other traffic and availability too; the block is
  held for at most four times the 2 s guard timeout.
- `openai_moderation`: 32 KiB, and never more. OpenAI documents no per-request
  input limit for moderations, so the window is fitted to the 1.5 second block
  deadline.
- `trustguard`: 64 KiB, and never more, fitted to the 2 second deadline that
  covers the token and the evaluate call.

A buffered request (the whole prompt or response, not a stream block) is split
too, and the text a guardrail screens is bounded by what half of its 30 second
evaluation budget admits, which is separate from the timeout of each call (a
provider that hangs fails open after about one call, not after the budget). A
text above the ceiling is refused before any call as `input_too_large` /
`chunk_limit` in a mode that blocks. The ceilings, in characters or bytes and
in tokens at about four characters a token:

| Guardrail | Chunks | Text | Tokens |
|---|---|---|---|
| `azure_content_safety` | 60 | about 482,000 UTF-16 units | about 120,000 |
| `openai_moderation` | 28 | about 807,000 bytes | about 200,000 |
| `bedrock_guardrail` | 10 | about 203,000 bytes | about 50,000 |
| `google_model_armor` | 16 | about 856,000 bytes | about 210,000 |

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
| `POST /v1/gateways/{gw}/policies` | `mcp_scope` object as in the example; omitted keeps the policy consumer-wide. 422 on: registry of another gateway or not MCP, empty `tool`/`groups` entries, duplicates, a registry both in `registry_ids` and `tools`, a scope without entries, a plugin without MCP support, a `users` or `except_users` key. 409 when the policy would occupy a level another enabled policy of the same plugin already occupies. |
| `PUT /v1/gateways/{gw}/policies/{id}` | Tri-state: `mcp_scope` **omitted** leaves the stored scope untouched, `null` clears it, an object replaces it. Same 409. Flipping `enabled` to true is a write and is checked too. Changing the slug of an MCP-wide policy to a plugin without MCP support is a 422. An update racing a promotion or demotion of the policy is a 409 `placement changed`: reload and retry. |
| `GET /v1/gateways/{gw}/policies?registry_id=<uuid>` | Only policies whose scope names that registry, in `registry_ids` or in `tools`. A non-UUID value is a 400. |
| `POST .../policies/{id}/global` | Promotes the policy to the all-traffic level and clears `mcp_wide` in the same write; the response may carry `warnings`, and it can answer 409. A retry that finds the policy already global answers 200 with it, including one whose first attempt landed while the retry was in flight. `DELETE` clears only `global`: on a policy that is not global it answers 200 and changes nothing. |
| `POST .../policies/{id}/mcp-wide` | Places the policy on every MCP consumer and the Store, clears `global` and removes the policy's consumer links, all in the same write; the response may carry `warnings` and never carries `consumer_ids`. 409 on a level conflict or a placement that changed meanwhile, 422 for a plugin without MCP support. A retry that finds the policy already MCP-wide answers 200 with it. `DELETE` clears only `mcp_wide`, is idempotent and never answers 409 or 422; the policy is then a draft. |
| `POST .../consumers/{id}/policies/{pid}` | `204`, or `200 {"warnings": [...]}` when the attach has something to warn about: the consumer already runs the plugin without scope, or the policy narrows to `groups` and the consumer accepts an api-key auth. 409 on a level conflict. 422 when the policy is MCP-wide, on any consumer: `consumer: policy is MCP-wide: it already runs on every MCP consumer; demote it before attaching a consumer`. On a non-MCP consumer, also 422 for a destination scope or for a plugin that gates on tool names. |
| `GET .../registries/{id}/tools` | The registry's advertised tools, with the upstream's **native** names — the key `mcp_scope.tools[].tool` stores. 409 when the registry cannot be introspected without a principal (per-principal auth, or URL variables in the target): write the tool name by hand. 502 when the upstream is unreachable or `tools/list` fails: retry. |

Responses echo `mcp_scope` (absent when unset, `{}` when pruned), `global` and
`mcp_wide` (always present, never both true) and, on create, update and the
promotions, an optional `warnings: []string`.

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

### MCP-wide placement (RUN-1746)

The `policies.mcp_wide` column is additive, exclusive with `global` through a
CHECK, and rides in the snapshot's policy JSON, so the proto does not change.

- **Ship TrustGate before the console, on every plane.** The admin, proxy and
  MCP planes (the MCP plane also serves the Store) must all run the new version
  before the console that promotes to MCP-wide ships. An older console never
  calls `/mcp-wide`; an older TrustGate answers it with 404. An older plane
  places a policy by its links alone, so it runs an MCP-wide policy nowhere,
  and an older admin does not refuse links on one.
- **Do not promote anything to MCP-wide, by SQL or by the API, before the
  console that reads `mcp_wide` is deployed.** An older console reads an
  MCP-wide policy as targeted: switching it to *Applications* there writes a
  scope with no groups without demoting it, and TrustGate then refuses the
  attaches with 422, so the policy runs for every MCP caller.
- Before deploying the console, list per environment the drafts whose scope
  names `groups` or `except_groups`, which is what the console used to save,
  and record the decision for each on the issue. Disabled drafts are listed
  too: the console promotes a group-only draft the next time it is saved,
  enabled or not.

```sql
SELECT p.id, p.gateway_id, p.slug, p.name, p.enabled, p.mcp_scope
  FROM policies p
 WHERE NOT p.global AND NOT p.mcp_wide
   AND (p.mcp_scope ? 'groups' OR p.mcp_scope ? 'except_groups')
   AND NOT EXISTS (SELECT 1 FROM consumer_policy cp WHERE cp.policy_id = p.id);
```

- **Rollback.** There is no down-migration runner: migrations only run up, on
  boot, so a binary rollback leaves the column, the CHECK and every flag as
  they are. Before rolling a binary back, list the MCP-wide rows and demote each
  one through the API, and keep the list to promote them again afterwards:

```sql
SELECT p.id, p.gateway_id, p.slug, p.name
  FROM policies p
 WHERE p.mcp_wide
 ORDER BY p.gateway_id, p.id;
```

  ```
  DELETE /v1/gateways/{gateway_id}/policies/{id}/mcp-wide
  ```

  A row left MCP-wide reads as a draft on the old binary, because it holds no
  links, so it runs nowhere. But the old admin answers 500 to `POST /global` on
  it (the CHECK refuses it), it does not refuse attaching a consumer to it, and
  on roll-forward the row runs MCP-wide again at once, on every MCP consumer
  and the Store, with whatever scope the old binary left.

  "Runs nowhere" is fail-closed only in one direction: the policy never runs
  wider than its groups, but for as long as the old binary runs it enforces
  nothing at all, for its groups included. Demoted or not, it protects nothing
  again until it is MCP-wide on the new version.

- **Roll-forward.** Links an old admin attached to an MCP-wide row survive the
  roll-forward, and an MCP-wide policy must hold none. List them:

```sql
SELECT p.gateway_id, p.id AS policy_id, cp.consumer_id
  FROM policies p
  JOIN consumer_policy cp ON cp.policy_id = p.id
 WHERE p.mcp_wide
 ORDER BY p.gateway_id, p.id, cp.consumer_id;
```

  Then detach each row with
  `DELETE /v1/gateways/{gateway_id}/consumers/{consumer_id}/policies/{policy_id}`,
  or run `DELETE` and then `POST .../policies/{id}/mcp-wide` on the policy: the
  promotion removes every link. The promotion goes through the level check
  again, so it can answer 409 if another policy took the level meanwhile. Then
  promote again the rows you demoted before the rollback.

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
| `PUT /v1/gateways/{gw}/policies/{id}` with `{"mcp_scope": {}}` | **Puts the policy to sleep on every plane.** It runs on no MCP consumer, no LLM consumer and no A2A consumer, whatever it is attached to and whether or not it is `global` or `mcp_wide`. It also stops occupying any level, so it can no longer conflict with anything. Its settings, attachments and placement flags are all preserved. |
| `PUT /v1/gateways/{gw}/policies/{id}` with `{"mcp_scope": null}` | **Makes the policy run on every plane.** The scope is cleared, so it behaves like a policy that never had one: it runs on all traffic of the consumers it is attached to, on all three planes, on the whole gateway if it is `global`. An `mcp_wide` policy runs for every caller of every MCP consumer and the Store, and still only there. It is the widening lever, not the off switch. |

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
