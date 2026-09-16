# Design FAQ: tools/list Filtering ≠ Tool Egress Control

A common pattern when securing LLM-based agent systems is filtering `tools/list` responses before passing tool definitions to the model. While this helps optimize prompt token usage and guides model selection, it is not an egress security boundary.

## The Core Difference

- **`tools/list` filtering** controls what tools the LLM *knows about* in its prompt context.
- **Tool egress control** controls what requests *actually leave the system* across the network wire.

Relying solely on `tools/list` filtering assumes the LLM prompt is the only pathway to execute tool operations.

## Layer Comparison

| Layer | What it sees | What it misses | Security property |
|---|---|---|---|
| **Prompt / Tool-Choice Filtering** | What the model was offered in context | Direct invocations, out-of-band requests, bypassed prompts | UX & token optimization |
| **In-App Allowlist** | Calls processed through that specific application runtime | Sidecars, background scripts, helper workers, reused SDKs | Cooperative application-level guard |
| **Gateway / Edge Egress** | Every network call and egress identity traversing the gateway | Nothing (provided egress is routed through gateway) | Hard security boundary |

## Practical Architectural Rule

1. **Treat `tools/list` filtering as UX and token hygiene**: Reduce prompt bloat, eliminate unrelated tools from context, and guide model decision-making.
2. **Treat egress controls as the security boundary**:
   - Enforce egress allowlists at the gateway level.
   - Use short-lived, scoped consumer credentials for agents.
   - Audit both the authorization decision (allow/deny) and the actual upstream execution and response.

## Related Resources

- [Design FAQ: Gateway Plane vs In-Process Middleware](faq-gateway-vs-middleware.md) (Issue [#519](https://github.com/NeuralTrust/TrustGate/issues/519))
- [Discussion #521](https://github.com/NeuralTrust/TrustGate/issues/521)
- [Consumers and Registries: The MCP Aggregation Plane Agents Actually Need](https://neuraltrust-victor.hashnode.dev/consumers-and-registries-the-mcp-aggregation-plane-agents-actually-need)
