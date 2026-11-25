# Consolidated gateway tools

This page is for engineers working on the MCP plane. It describes the
gateway's own MCP tools, `trustgate_search`, `trustgate_call` and
`trustgate_access`, and how clients that fetched the earlier tools keep
working.

## Why

The gateway grew one meta-tool per need, and ended up with four ways to look
something up and three ways to call:

| Need | Earlier tools | Consolidated tool |
|---|---|---|
| Find | `trustgate_list_tools`, `trustgate_store_search`, `trustgate_list_agents`, `trustgate_store_models` | `trustgate_search` |
| Call | `trustgate_call_tool`, `trustgate_call_agent` | `trustgate_call` |
| Change what the user has | `trustgate_connect_<provider>`, `trustgate_store_install`, `trustgate_store_uninstall`, `trustgate_store_personal_key`, `trustgate_store_request_models` | `trustgate_access` |

The consolidated tools are the same three on applications and on the Store.
A gateway with [Code Mode](code-mode.md) on also offers `trustgate_query`, and
`trustgate_execute`, which run a program that calls the user's tools.
Their list never changes with what the user installs or connects, so a client
that keeps the list it fetched (Claude's hosted connectors do) is never left
without a tool. On an application, `trustgate_search` offers the `overview`
and `tool` kinds and `trustgate_access` only `connect`; on the Store they offer
everything their dependencies are wired for.

Code is in `pkg/app/mcp`: `gateway_tools.go` (definitions),
`search_tool.go`, `search_rank.go` and `ts_signature.go` (`trustgate_search`),
and `gateway_call_access.go` (`trustgate_call`, `trustgate_access`).

## Compatibility

Every connection is offered the three consolidated tools. The earlier tools
are not listed any more, and nothing switches them back on.

- **The earlier names still answer.** `tools/call` accepts
  `trustgate_list_tools`, `trustgate_call_tool`, `trustgate_connect_*`, the
  `trustgate_store_*` tools, `trustgate_list_agents` and `trustgate_call_agent`,
  and they answer exactly as before. Claude's hosted connectors keep the tool
  list they fetched when the person connected them, whatever the gateway
  announces, until the person reconnects; a connector that fetched the earlier
  list keeps working.
- **Instructions for both.** The `initialize` instructions name the
  consolidated tools, and close with a sentence for a client whose list still
  shows the earlier ones: those still work.
- **Text rewritten for the consolidated tools.** An answer the consolidated
  tools build on an earlier tool has the earlier tools' names in its text
  rewritten to the consolidated tool that does the same, because a client with
  the consolidated list does not have the earlier tools.
- **Readable faults.** A fault the earlier tools return as an internal error
  (-32603), such as a closed Store or a missing dependency, comes back from the
  consolidated tools as a tool error with a stable `error` code. Policy
  refusals (-32001), pending consent (-32003) and rate limits (-32004) stay
  protocol errors, as on a direct call.
- **Reserved names.** An upstream tool named like one of the gateway's tools
  (`trustgate_search`, `trustgate_query`, `trustgate_connect_*`,
  `trustgate_store_*`…) is not listed: a call to that name reaches the
  gateway, never the upstream.

## trustgate_search

It reads the same inventory `tools/list` and `tools/call` read, through the
consumer's toolkit, so it cannot offer a tool the caller could not call nor
hide one they could. Ranking runs per request over that answer; there is no
separate index to fall out of step with it.

| Arguments | Answer |
|---|---|
| none | `overview`: the user's servers, their state and cause, tool counts, and `next`, the call that fixes a server the user can fix. On the Store, also what they can install |
| `query` | the user's tools ranked, best first, with name, server, state, risk, description and TypeScript signature. On the Store, also matching catalog servers and agents |
| `kind: "tool"` without `query` | every tool, in surface order, page by page (`limit`, `cursor`) |
| `name` | one tool in full: description, signature, input schema, output schema when declared. An unknown name answers with the closest names |
| `kind: "catalog"`, `"agent"`, `"model"` | the Store's catalog search, agent listing and model listing |

Ranking is BM25 per field. Names weigh 3, titles 2, server name and code 1.5,
description and parameter names 1. Each field saturates on its own, and the
description counts each distinct word once, from its first 300 characters and
40 distinct words. A server that stuffs its descriptions with keywords cannot
outrank a tool whose name matches. On top of the words:

- **Synonyms** (issue/ticket/incidencia, meeting/event/reunión, refund/reembolso…)
  widen a query at 0.6 weight, both ways. **Implied words** go one way at 0.5:
  "move" reaches `update`, "schedule" `create`, "cancel" `delete`, "create"
  `save`, "reply" `comment`, but `update` never reaches "move".
- **Plurals and accents** fold, including Spanish `-iones` (reuniones →
  reunión). Two words a tool writes as one count joined ("on call" → oncall).
- **Intent.** The first verb or question word of the request (show, what, who,
  find, create, schedule, move, cancel, send, ver, qué, crear, borrar,
  avisar…) is matched against the first verb in the tool's name past its
  server's words. A tool that does what was asked counts up to 1.6×, one that
  does something else 0.7×, and a tool that removes or ends something 0.3× when
  the request only reads, so a read never gets a delete first.
- **Server named.** A tool counts 1.5× when the query names its server ("in
  linear", "on my calendar").

A query that scores nothing falls back to a substring match, so it never finds
less than the earlier tools did.

### Eval

`testdata/search_eval.json` holds about 170 requests as people write them, in
English and Spanish, with synonyms, vague and ambiguous asks, each with the
tools that answer it. `TestSearchEval` ranks them over the catalog's real tools
twice: a typical Store surface of 25 servers (about 620 tools) and the whole
catalog (about 2,850). It fails under a floor: recall@1 0.78, recall@10 0.98
and MRR 0.85 on the typical surface; 0.70, 0.93 and 0.78 on the whole catalog;
and any read request that gets a destructive tool first.

```sh
go test ./pkg/app/mcp -run TestSearchEval -v   # the report, with every miss
```

When a case fails because the ranking is wrong, fix the ranking; change a case
only when its expected tools are wrong. A ranking change that helps one case
must not lower the floors.

### Metrics

`trustgate.mcp.searches`, `trustgate.mcp.search.follow_ups` and
`trustgate.mcp.unknown_tool_calls` measure the ranking on real traffic: empty
searches, where the search put the tool the caller then called, calls to tools
the search did not return, calls to tools that do not exist. See
[operational metrics](../operational-metrics.md).

The ranking only orders. A listing without a query returns every tool, and a
call by exact name reaches a tool whether or not a search returned it.

Tools of a server that is not serving come from the catalog's snapshot, named
the way `tools/call` will name them once the server serves them.

## trustgate_call

`{"tool": <name>, "arguments": {…}}` runs the tool exactly as a direct call:
resolve, plan, policies, upstream, response policies. Activity, usage and
policies record the tool that ran (`GatewayCallTarget`). If the upstream
refuses the arguments, the answer carries the tool's input schema.

On the Store, `{"agent": <id>, "message": …}` or `{"agent", "task_id"}` calls
an agent, as `trustgate_call_agent` did.

## trustgate_access

`{"action", "target"}`; every action but `key` needs a target:

| Action | Target | Lands on |
|---|---|---|
| `install` | catalog code | the Store's install; `config`, and `registry_id` for the instance |
| `uninstall` | catalog code | the Store's uninstall; `installation_id` for the installation |
| `connect` | server name, code or provider | an application's connection tool for the provider; on the Store, the server's install, which answers its connect link |
| `key` | none | the Store's personal-key page, where the user creates, rotates or revokes the key their LLM models are called with. The key is shown to them there and never to the model. `connect` with target `personal_key`, the earlier spelling, still opens it |
| `request` | LLM provider | the Store's model request; `registry_id` for the registry |

The answer keeps every field the earlier tools answered with (a link keeps its
`action: "user_confirmation_required"`) and adds `status` (`installed`, `already_installed`, `requires_config`,
`requires_admin_setup`, `choose_instance`, `requires_request`, `disabled`,
`uninstalled`, `not_installed`, `choose_installation`, `link`, `connected`,
`has_access`, `already_requested`, `unknown_provider`, `choose_registry`,
`not_available`, `error`). An install or uninstall through it announces
`tools/list_changed` on the same terms as the Store tools.

## Not done yet

- Shadow comparison of the ranking on real traffic, beyond the funnel metrics.
