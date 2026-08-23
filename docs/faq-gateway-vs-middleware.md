# FAQ: gateway plane vs in-process middleware

Contributors and evaluators often ask how an agent gateway differs from
wrapping an SDK with middleware. This is a risk-placement note, not a
feature list.

## When does a gateway plane beat in-process middleware?

Use an edge / gateway plane when tool calls, identity, and policy must
hold for every egress path — not only the ones that remember to wrap the
SDK. Middleware is still reasonable when a single app owns every tool
call, identities stay app-local, and you do not need a shared
break-glass or audit trail across agents.

| Concern | In-process middleware | Edge / gateway plane |
|---|---|---|
| Rogue tool call after model emit | Can be bypassed if another path hits the tool | Enforced for every egress identity |
| Short-lived per-invocation identity | Usually app-owned cookies/keys | Mint + expire at the edge |
| Break-glass for destructive verbs | Scattered in app code | One policy surface |
| Audit (decision + upstream response) | Per-service logs | Correlated across apps |

The four rows are the usual failure modes of “just wrap the SDK”:

- **Tool egress.** After the model emits a tool call, any other path
  that can reach the tool skips in-process middleware. A gateway
  plane sits on every egress identity.
- **Identity.** Per-invocation credentials are usually minted and
  stored by the app. At the edge they can be minted and expired in
  one place.
- **Break-glass.** Destructive verbs (`delete`, `send`, `pay`, …)
  otherwise pick up whatever allowlist each service copied. One
  policy surface is the cut that makes emergency deny/allow
  coherent.
- **Audit.** Decision plus upstream response correlated across apps
  needs a shared control point; per-service logs do not join
  themselves.

## Docker sandboxes are orthogonal

Docker sandboxes contain *execution* (what a tool process can do once
it runs). They do not answer *who is allowed to call what*.
Authorization, identity lifetime, and audit still need a control point
on the call path — in-process or at the gateway.

## Related reading

- [Discussion #518](https://github.com/NeuralTrust/TrustGate/discussions/518) — show and tell
- [Consumers and registries: the MCP aggregation plane agents actually need](https://neuraltrust-victor.hashnode.dev/consumers-and-registries-the-mcp-aggregation-plane-agents-actually-need)
- Community Q&A on this cut: [issue #519](https://github.com/NeuralTrust/TrustGate/issues/519)
