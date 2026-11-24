# Consolidated gateway tools

This page is for engineers working on the MCP plane. It describes the
gateway's own MCP tools, `trustgate_search`, `trustgate_call` and
`trustgate_access`, how a gateway switches to them, and how clients connected
before the switch keep working.

## Why

The gateway grew one meta-tool per need, and ended up with four ways to look
something up and three ways to call:

| Need | Earlier tools | Consolidated tool |
|---|---|---|
| Find | `trustgate_list_tools`, `trustgate_store_search`, `trustgate_list_agents`, `trustgate_store_models` | `trustgate_search` |
| Call | `trustgate_call_tool`, `trustgate_call_agent` | `trustgate_call` |
| Change what the user has | `trustgate_connect_<provider>`, `trustgate_store_install`, `trustgate_store_uninstall`, `trustgate_store_personal_key`, `trustgate_store_request_models` | `trustgate_access` |

The consolidated tools are the same three on applications and on the Store.
Their list never changes with what the user installs or connects, so a client
that keeps the list it fetched (Claude's hosted connectors do) is never left
without a tool. On an application, `trustgate_search` offers the `overview`
and `tool` kinds and `trustgate_access` only `connect`; on the Store they offer
everything their dependencies are wired for.

Code is in `pkg/app/mcp`: `surface.go` (which surface a request gets),
`gateway_tools.go` (definitions), `search_tool.go`, `search_rank.go` and
`ts_signature.go` (`trustgate_search`), and `gateway_call_access.go`
(`trustgate_call`, `trustgate_access`).

## Turning them on

A gateway serves the earlier tools until an admin turns the consolidated ones
on:

```http
PUT /v1/gateways/{id}
{"mcp_gateway_tools": true}
```

The server stamps the time in the reserved metadata key
`mcp_gateway_tools_since` and returns it as `mcp_gateway_tools_since`. A
client cannot write the key, so the start can never be set in the past.
Turning the tools on again keeps the first start. `false` removes it and
returns every client to the earlier tools: that is the kill switch. The surface
fingerprint does not include the switch, so a client is not sent
`tools/list_changed` when it flips; it needs none, because every name keeps
answering on every connection.

## Who gets which tools

`appmcp.SurfaceFor` decides per request:

| Caller | Tools off | Tools on |
|---|---|---|
| Gateway session (`token_use: mcp_session`) opened after the start | earlier | consolidated |
| Gateway session opened before the start, or before sessions carried their start | earlier | earlier |
| Api key, personal key, certificate, a customer identity provider's token | earlier | consolidated |

A gateway session carries `mcp_session_start`: the login that opened it, in
Unix seconds, the same on every token refreshed from it
(`pkg/app/oauth/proxy.go`, `mintSession`). Claude's hosted connectors fetch the
tool list when the person connects them, which is that login, and keep it
until the person reconnects, which opens a new session. So a connector that
fetched the earlier list keeps being offered it.

Credentials without a connection time belong to clients that re-list on start.

## Compatibility

- **Every name answers on every connection.** `tools/call` accepts the earlier
  names and the consolidated ones whatever surface the connection was
  offered, so a client holding either list keeps working, including across a
  kill switch.
- **The earlier tools answer exactly as before.** They run unchanged; the
  consolidated tools call into the same implementations.
- **Text rewritten for the consolidated surface.** An answer the consolidated
  tools build on an earlier tool has the earlier tools' names in its text
  rewritten to the consolidated tool that does the same, because a client on
  the consolidated surface does not have the earlier tools in its list.
- **Readable faults.** A fault the earlier tools return as an internal error
  (-32603), such as a closed Store or a missing dependency, comes back from the
  consolidated tools as a tool error with a stable `error` code. Policy
  refusals (-32001), pending consent (-32003) and rate limits (-32004) stay
  protocol errors, as on a direct call.
- **`initialize` instructions** name the tools the connection is offered.

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
outrank a tool whose name matches. A small synonym list (issue/ticket,
email/mail, create/new, English/Spanish pairs) widens a query at 0.6 weight.
A query that scores nothing falls back to a substring match, so it never finds
less than the earlier tools did.

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

`{"action", "target"}`:

| Action | Target | Lands on |
|---|---|---|
| `install` | catalog code | the Store's install; `config`, and `registry_id` for the instance |
| `uninstall` | catalog code | the Store's uninstall; `installation_id` for the installation |
| `connect` | server name, code or provider | an application's connection tool for the provider; on the Store, the server's install, which answers its connect link |
| `connect` | `personal_key` | the Store's personal-key page |
| `request` | LLM provider | the Store's model request; `registry_id` for the registry |

The answer keeps the fields the earlier tools answered with and adds `action`
and `status` (`installed`, `already_installed`, `requires_config`,
`requires_admin_setup`, `choose_instance`, `requires_request`, `disabled`,
`uninstalled`, `not_installed`, `choose_installation`, `link`, `connected`,
`has_access`, `already_requested`, `unknown_provider`, `choose_registry`,
`not_available`, `error`). An install or uninstall through it announces
`tools/list_changed` on the same terms as the Store tools.

## Not done yet

- Shadow comparison of the ranking on real traffic before switching a gateway.
- A console control for the switch: it is set through the admin API.
- A per-connection choice of surface (for example a URL parameter).
- Code Mode (`trustgate_query`, `trustgate_execute`).
