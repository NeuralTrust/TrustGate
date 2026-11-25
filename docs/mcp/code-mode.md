# MCP Code Mode

This page is for engineers working on the MCP plane and for admins deciding
whether to turn Code Mode on. It describes `trustgate_query` and
`trustgate_execute`: tools that run a short JavaScript program, written by the
model, that calls the user's tools inside the gateway and returns one result.

## Why

A task that takes several tool calls, such as listing issues, reading each
one's comments and counting the unanswered ones, costs the model one call per
step. Every intermediate result goes through its context. With Code Mode the
model writes the steps as a program, the gateway runs it, and only what the
program returns reaches the model. Models write code against a typed API well,
and `trustgate_search` already gives each tool's TypeScript signature.

```js
const { issues } = await tools.linear_list_issues({ assignee: "me", state: "started" });
const comments = await Promise.all(
  issues.slice(0, 10).map(i => tools.linear_list_comments({ issueId: i.id }))
);
return issues.slice(0, 10).map((i, k) => ({ id: i.identifier, comments: comments[k].comments.length }));
```

## Turning it on

Code Mode is a gateway setting, off by default:

```http
PUT /v1/gateways/{id}
{"mcp_code_mode": "read_only"}
```

| `mcp_code_mode` | Offered tools |
|---|---|
| `off` | none |
| `read_only` | `trustgate_query` |
| `full` | `trustgate_query` and `trustgate_execute` |

The gateway response always carries `mcp_code_mode`. The value is stored in
reserved gateway metadata (`mcp_code_mode`). A client cannot set or remove it
through `metadata`.

Clients see the tools in `tools/list` on their next listing. Claude's hosted
connectors keep the list they fetched until the person reconnects. A call to a
tool the gateway does not offer answers a readable tool error (`not_enabled`).

### Listing only the gateway's tools

With the user's tools in its list, a model takes the obvious path and calls
them one at a time, even when a program would do the task in one call. A gateway
can list only its own tools instead:

```http
PUT /v1/gateways/{id}
{"mcp_tool_listing": "gateway"}
```

`tools/list` then answers with `trustgate_search`, `trustgate_call`,
`trustgate_access` and the Code Mode tools, without asking the upstreams for
their lists. The model finds the user's tools with `trustgate_search` and calls
one with `trustgate_call`, or several from a program. A direct call to a tool
the client already knows still works. The default, `all`, lists both.

The trade-offs:
- **A single call costs a search first.**
- **Client permissions get coarser.** A client approves `trustgate_call` once
  instead of each tool. The gateway's policies still apply to every call.
- **Per-tool toggles disappear.** Clients that let the user switch tools on and
  off one by one only see the gateway's.

## How the model knows to write a program

The client does not need anything new: for it, a Code Mode tool is an MCP tool
whose one argument, `code`, is a string. The model learns to use it from three
places:

1. **The tool's description**, the one place every client passes on. It says
   when to use the tool (several calls, loops, filtering, joining, counting),
   how to call a tool (`await tools.<name>(args)`), what a call returns, and the
   limits.
2. **The `initialize` instructions.** The sentences that depend on the
   gateway's settings (where the user's tools are, when to write a program)
   come right after the opening one, since clients cut long instructions.
3. **`trustgate_search` answers**, which give each tool's TypeScript signature
   and, with Code Mode on, close with a line saying those signatures are the
   API a program calls.

### Clients that kept an earlier tool list

A client that fetched its tool list before Code Mode was turned on has no
`trustgate_query` in it. Claude's hosted connectors keep theirs until the
person reconnects. Both call-throughs run a program for it:
`trustgate_call {"tool": "trustgate_query", "arguments": {"code": …}}` and the
earlier `trustgate_call_tool {"name": "trustgate_query", …}`. The gateway's
mode applies the same way.

Such a client learns this from two places it still reads live: the
`initialize` instructions, and the answer of the earlier `trustgate_list_tools`,
which closes with how to run a program.

## What a program can do

- **Call a tool.** `tools.<name>(args)` calls the user's tool `<name>` (its
  exact exposed name, as `trustgate_search` gives it) and returns a promise:
  - The tool's `structuredContent` when it has one.
  - Otherwise its one text block, parsed when it is a JSON object or array.
  - Otherwise its text, or for several blocks an array of their texts, with
    other block types marked `{"type", "omitted": true}`.
- **Catch failed calls.** A failed call throws a `ToolError`. Its `name` is
  one of:

  | Name | Why the call failed |
  |---|---|
  | `ToolError` | The tool answered `isError`, or the upstream failed |
  | `PolicyError` | A request policy refused it |
  | `NotAllowedError` | The read-only rule, or the toolkit |
  | `NotFoundError` | No such tool; the message names the closest ones |

  The program can catch it.
- **Run calls in parallel.** `Promise.all` works. The runner owns the event
  loop and runs a program's pending calls together, four at a time.
- **Log.** `console.log`, `info`, `warn`, `error` and `debug` lines come back
  with the result.
- **Return.** The program's return value, as JSON, is the tool's result.
  Calls a program did not await before returning are not made.

It cannot reach anything else:

- No filesystem, network, environment, timers, real sleep or modules.
- No gateway tools (`trustgate_*`), so programs do not nest.

## Every call is a direct call

Each call a program makes goes through the same path as a `tools/call` naming
that tool:

- **Resolution:** the consumer's toolkit and the Store scoper.
- **Rate limit:** one check per call.
- **Plan:** the policy plan of that destination.
- **Policies:** request policies, then the upstream, then response policies.

Then:

- **Ends the program.** A consent the user must give, or a rate limit. The
  client gets the protocol error a direct call would have got, so it can show
  the consent link.
- **Can be caught.** A policy refusal or an upstream failure.

The program's answer passes the consumer's response policies once more as a
whole. Each call's result already passed them, but the program can decode,
join or reshape what it read, and the guard has to see what actually reaches
the model.

The request policies do not inspect the program's code itself: a code-injection
detector would flag every program. They inspect each call it makes.

## The read-only rule

`trustgate_query` calls a tool only when the tool reads. That means one of:

- Its server annotates it `readOnlyHint: true`, and does not declare
  `openWorldHint: true`. An open-world tool, such as a web search or a fetch,
  could carry what the program read out in its arguments.
- An admin lists it in the server's `mcp_target.read_only_tools`, by the name
  the server gives the tool (`list_issues`, not `linear_list_issues`). The
  list covers servers that do not annotate their tools, and open-world tools
  the admin trusts. It changes nothing else: a listed tool is called and
  guarded like any other.

```http
PUT /v1/registries/{id}
{"mcp_target": {"read_only_tools": ["list_issues", "get_issue"]}}
```

The list is kept when an update omits it, and cleared by an empty list. The
server trims, deduplicates and sorts it; at most 500 names.

An unannotated tool that no admin lists is refused, with a message that points
to `trustgate_call`. Annotations are the server's own claim. The list is the
admin's.

`trustgate_execute` calls any tool the user can call. Its definition is
annotated `destructiveHint: true`, so clients ask the user before running it,
showing the program.

## The sandbox

Programs run in QuickJS compiled to WebAssembly, under wazero, without cgo.
The engine is a patched copy of fastschema/qjs in `third_party/qjs`; its
README lists the patches. The runner is `pkg/infra/jsrun`.

- **Isolation.**
  - Every program gets a fresh runtime, discarded afterwards: nothing one
    program leaves behind is seen by the next.
  - No directory is mounted. QuickJS's `std` and `os` modules are removed from
    the global object. `import("qjs:std")` still loads them, but the
    filesystem they see is empty, and there are no sockets, environment or
    processes.
  - The runner's own functions are read-only.
- **Memory.** Each runtime's WebAssembly memory is capped at 64 MiB.
  QuickJS's own allocations are capped at 48 MiB. A program that allocates
  without end gets an out-of-memory error, not the gateway's memory.
- **Time.** A program's context ends its runtime wherever it is, including
  an infinite loop. There is no real sleep: a timer spins inside
  WebAssembly, where the context can stop it.
- **Crashes.** A recursion deep enough to overflow the engine's stack traps
  inside WebAssembly. The program fails with `crashed` and the runtime is
  discarded.
- **Concurrency.** At most 8 programs run at once per process. Past that a
  program waits for a slot until its request ends (`busy`).
- **Warm-up.** The engine is compiled once per process, about half a second,
  in the background when the MCP plane starts.

| Limit | Default |
|---|---|
| Run time, calls included | 30 s (lower when the server's write timeout × ¾ is) |
| Tool calls | 50 |
| Calls at once | 4 |
| Program size | 20,000 bytes |
| Result | 25,000 bytes of JSON |
| One call's result handed to the program | 4 MiB |
| Log lines | 100, of 1,000 bytes |

A program that does not finish returns a tool error. The answer carries:

- `error`: the kind, one of `thrown`, `timeout`, `memory`, `call_limit`,
  `output_limit`, `code_limit`, `stalled`, `crashed` or `busy`.
- A message written for the model to fix the program.
- The calls the program made before it stopped, and its logs.

## Answer

```json
{
  "content": [{"type": "text", "text": "<the result as JSON>\n\nLogs:\n…"}],
  "structuredContent": {
    "result": "…",
    "calls": [{"tool": "linear_list_issues", "ok": true, "ms": 120}],
    "logs": ["…"]
  }
}
```

## Activity, usage and metrics

The program's own request names the servers its calls went to: one server as
a direct call names it, several by their names joined. That is what Activity's
Provider shows for it.

- **Activity.** The program's request is one event, `mcp.tool` =
  `trustgate_query` or `trustgate_execute`. Each call the program made is in
  `mcp.calls[]`:
  - `tool`, `upstream_tool`, `server_name`, `registry_id`, `catalog_code`
  - `upstream_status`, `rpc_error_code`, `latency_ms`, `tool_risk`, `decision`
  - `error`, the error's name only: never what its message quoted.

  The request also carries what the program read and what it returned:
  - `program_bytes_read`: what its calls handed it, each result as the
    program saw it (or the error's message and data).
  - `program_bytes_returned`: the text the client got back, the result and
    logs, or why it failed.

  The model read the second instead of the first. The console estimates the
  tokens kept out of the model's context from the difference, at 4 bytes a
  token. That is a floor: each direct call's result also comes wrapped in its
  MCP envelope, and whatever enters the conversation is sent again on every
  later turn.

  On OTLP it carries `trustgate.mcp.program_calls`,
  `trustgate.mcp.program_tools`, `trustgate.mcp.program_bytes_read` and
  `trustgate.mcp.program_bytes_returned` (see
  [the OTLP contract](../telemetry/otlp-metadata-contract.md)). Each call has
  its own MCP span, marked with the program (`trace.MCPAttrs.Program`).
- **Usage.** The program's own request is the gateway's and is not billed.
  Each call that reached its tool is a request: resolved to a server and
  answered, with a result or a tool error. Calls refused by a policy, by the
  read-only rule or for a name nobody serves are not counted.
- **Metrics** (see [operational metrics](../operational-metrics.md)):
  - `trustgate.mcp.code.programs` by `surface`, `tool` and `result`
  - `trustgate.mcp.code.program_duration`
  - `trustgate.mcp.code.program_calls`
  - `trustgate.mcp.code.bytes_read` and `trustgate.mcp.code.bytes_returned`

  A program's first call after a search counts as that search's follow-up in
  `trustgate.mcp.search.follow_ups`, with `via` naming the program's tool.

## Code

| Where | What |
|---|---|
| `pkg/infra/jsrun` | the runner: limits, the batched event loop, the prelude |
| `third_party/qjs` | the engine, patched |
| `pkg/app/mcp/code_mode.go` | the tools, each call's path, the read-only rule, result shaping |
| `pkg/app/mcp/code_mode_metrics.go` | the metrics |
| `pkg/domain/gateway` | `MCPCodeMode`, the setting |
| `pkg/domain/registry` | `MCPTarget.ReadOnlyTools` |
| `pkg/app/metrics/builder.go`, `pkg/app/usage` | Activity and usage of a program's calls |

Tests: `go test ./pkg/infra/jsrun/ ./pkg/app/mcp/ -run 'Run|CodeMode'`. The
runner's tests try each escape and each limit.

## Measuring whether models use it

Whether a model writes a program when one helps depends on how the tools and
instructions are worded, as search depended on its ranking. The agent eval
measures it. It runs by hand, because it calls a model API and costs money:

```sh
EVAL_MODEL=<model id> go test -tags agenteval ./pkg/app/mcp -run TestCodeModeAgentEval -v -timeout 30m
```

It gives a model the gateway's real tool list, Code Mode sentence and
dispatcher, over fake Linear, GitHub and Calendar servers with fixed data
(`pkg/app/mcp/code_mode_eval_world_test.go`), and ten tasks, eight of them
multi-step. For each gateway mode it reports:

- correct answers,
- tool calls per task,
- input and output tokens,
- how many multi-step tasks got a program,
- how many first programs ran.

`EVAL_MODES` picks the modes (default `off,read_only`, so a run compares
Code Mode with calling tools one at a time), `EVAL_TASKS` a subset of tasks,
and `EVAL_REPORT` a JSON file for the results. Run it before and after
changing a tool's description or the instructions.

A reference program solves each task through `trustgate_query`, without a
model. That test runs in CI: it checks the data and the graded answers agree,
and exercises Code Mode end to end over several servers.
