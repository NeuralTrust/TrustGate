# Design FAQ: MCP and Provider Secrets Belong on the Gateway, Not in the Agent Runtime

A common shortcut when assembling LLM agent workflows is dumping upstream MCP server URLs and long-lived API keys directly into agent runtimes (`.env` files, local editor configurations, container environment variables, or shared orchestrator configs). While convenient for demos and rapid prototyping, this pattern becomes a major security and operational liability in multi-agent and production deployments.

This note clarifies **where secrets should live**, complementing architectural discussions on gateway planes vs in-process middleware ([#519](https://github.com/NeuralTrust/TrustGate/issues/519)) and `tools/list` filtering vs tool egress control ([#521](https://github.com/NeuralTrust/TrustGate/issues/521)).

---

## Architectural Comparison: Where Secrets Live

| Where MCP/Provider Secret Lives | What Actually Happens | Security & Operational Impact |
|---|---|---|
| **Agent process / developer machine / CI job** | Every replica, worker fork, stack trace, and crash dump contains raw production credentials. Credential rotation requires updating and restarting every agent deployment. | High risk of credential exfiltration; secret sprawl; slow and brittle rotation. |
| **Per-server OAuth in each agent's MCP config** | Agents hold long-lived tokens or refresh tokens. If a runtime is compromised via prompt injection or dependency vulnerability, attackers can act directly as the organization. | Broad blast radius; delegated authority cannot be revoked centrally across heterogeneous tools. |
| **Gateway-held upstream + short-lived consumer credentials** | The agent presents a short-lived, scoped consumer identity to the gateway. The gateway validates policy, injects upstream MCP/provider credentials on the wire, and routes the request. | Strict credential isolation; instant rotation at the gateway/vault without restarting agents; granular auditability. |

---

## Sandboxing Does Not Prevent Credential Abuse

A common misconception is that running agents inside containers (Docker, gVisor, or microVMs) protects secrets stored in the runtime environment.

While sandboxing successfully contains **execution** (preventing filesystem tampering and host escapes), it does **not** prevent a process from reading environment variables or configuration files within its sandbox. If an agent process is steered by malicious prompt injection or compromised code, it can easily exfiltrate or directly invoke upstream APIs using the ambient secrets granted to it.

Sandboxing protects the host from the agent; gateway secret isolation protects upstream services and organizational credentials from a compromised agent.

---

## Practical Architectural Rules

1. **Centralize Upstream Secrets on the Gateway**:
   Store provider API keys (OpenAI, Anthropic, etc.) and upstream MCP authentication tokens exclusively on the gateway or in a centralized vault/secret manager read directly by the gateway.
2. **Issue Scoped, Short-Lived Consumer Identities**:
   Agents authenticate to the gateway using short-lived consumer tokens scoped strictly to the specific models, MCP tools, and routes they are authorized to invoke.
3. **Audit Both Policy Decisions and Upstream Calls**:
   Record audit logs that capture both the policy evaluation (consumer ID, allowed/blocked action, timestamp) and the upstream tool call details, rather than relying solely on user-facing prompt logs.

---

## Related Resources

- [Design FAQ: Gateway Plane vs In-Process Middleware](https://github.com/NeuralTrust/TrustGate/issues/519)
- [Design FAQ: tools/list Filtering ≠ Tool Egress Control](https://github.com/NeuralTrust/TrustGate/issues/521)
- [Discussion #523](https://github.com/NeuralTrust/TrustGate/issues/523)
- [Consumers and Registries: The MCP Aggregation Plane Agents Actually Need](https://neuraltrust-victor.hashnode.dev/consumers-and-registries-the-mcp-aggregation-plane-agents-actually-need)
