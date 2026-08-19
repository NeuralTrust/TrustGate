# MCP tasks extension

TrustGate mediates the `io.modelcontextprotocol/tasks` draft extension
(SEP-2663) on the modern northbound plane. A long-running `tools/call` may answer
with a task the client then polls, answers, and cancels. TrustGate stores **no**
task state: the upstream `taskId` travels northbound only inside a signed handle,
and every `tasks/*` POST is a full policy pass.

The extension is off by default. It turns on when `MCP_TASK_HANDLE_SECRET` is
set.

## Controls

| Env var | Default | Effect |
|---------|---------|--------|
| `MCP_TASK_HANDLE_SECRET` | empty | HMAC key for task handles. Empty disables task mediation entirely. |
| `MCP_TASK_HANDLE_SECRET_PREV` | empty | Previous key, accepted for verification only (`kid=p`), so rotation does not invalidate live handles. |
| `MCP_TASK_HANDLE_TTL` | `1h` | Handle lifetime. Clamped to a hard `24h` ceiling; the effective expiry is the lower of this and the upstream's own `ttlMs`. |
| `MCP_TASK_POLL_INTERVAL_FLOOR_MS` | `1000` | Floor applied to `pollIntervalMs` northbound, so an upstream cannot tell a client to hammer the gateway. |
| `MCP_TASK_HANDLE_MAX_BYTES` | `1024` | Size bound at mint. Exceeding it fails closed with `-32603`. |

Rotation: move the live value to `MCP_TASK_HANDLE_SECRET_PREV`, set the new value
in `MCP_TASK_HANDLE_SECRET`, and drop `_PREV` once the longest TTL has elapsed.

## What the client sees

`server/discover` advertises
`capabilities.extensions["io.modelcontextprotocol/tasks"] = {}` only when the
request is modern, the secret is set, at least one bound registry is not
`protocol_mode=legacy`, and tools are visible to that consumer. Discovery never
dials an upstream to decide, so advertisement means *TrustGate can mediate
tasks* — never that a particular upstream supports them.

A client must declare the extension in
`params._meta["io.modelcontextprotocol/clientCapabilities"].extensions` on every
request that relies on it. A `tasks/*` request without that declaration is
refused with `-32025` and
`data.requiredCapabilities: ["io.modelcontextprotocol/tasks"]`.

The `taskId` a client receives is a TrustGate handle (`tg1k.<kid>.…`), not the
upstream's id. It is stable for the task's life: `tasks/*` responses echo the
inbound handle rather than minting a new one.

Every handle refusal answers `-32602` with one constant message and no `data`.
Tamper, expiry, a registry detached from the consumer, a toolkit change, a
principal change, an unknown or purged upstream task, and a credential failure
are deliberately indistinguishable, so a handle cannot be used to probe for
existence.

## Policy coverage

The tool output a completed task carries is inspected on `tasks/get`, under the
tool's exposed name, by the same response stage a plain `tools/call` takes. A
denial withholds the content; a masking rewrite is spliced back into the task
envelope. Long-running output therefore cannot bypass TrustGuard by arriving
through a task.

`tasks/update` answers take the request stage, also under the exposed name.
Polling is metered on the consumer's existing MCP rate-limit bucket — a task does
not grant a second, unmetered budget.

## Rollback without redeploy

Unset `MCP_TASK_HANDLE_SECRET`. The gateway then behaves exactly as it did before
the feature: the extension is no longer advertised, a client's declaration is
dropped at the capability boundary, `tasks/*` answers `-32025`, and a
task-shaped upstream answer degrades to an ordinary `resultType: "complete"`
result rather than handing the client a `taskId` it cannot poll.

**Orphaned tasks:** because TrustGate keeps no task record, disabling the feature
(or rotating both secrets at once, or a handle simply expiring) leaves any
in-flight upstream task running, unreachable through the gateway. The upstream's
own `ttlMs` reaps it. Cancel outstanding tasks before a rollback when the
upstream work is expensive.

## Dashboards

Require `OPS_METRICS_ENABLED=true`:
`mcp.northbound.tasks.outcome_total{operation,outcome,era}` — see
[operational metrics](../operational-metrics.md). Handles, upstream task ids, and
task payloads are never labels and never logged.

## Not in this change

`notifications/tasks` and `tasks/list` are not exposed. TrustGate keeps no task
record, so there is nothing to enumerate and no channel to push task progress on.
Bounded list-change streaming is a separate, independently gated feature — see
[MCP subscriptions](subscriptions.md).
