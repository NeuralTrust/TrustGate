# Vendor outreach: TrustGate as an MCP client

Production OAuth client name: **TrustGate MCP Gateway**  
Production callback origin: `https://gateway-mcp.neuraltrust.ai`  
Callback pattern: `https://gateway-mcp.neuraltrust.ai/oauth/callback/{catalog-code}`

AWS Sign-In is already allowlisted. Do not re-request it.

## What to ask each vendor

| Vendor | Catalog | Ask |
|--------|---------|-----|
| Figma | *(not in catalog; `https://mcp.figma.com/mcp`)* | Add TrustGate to the [Figma MCP Catalog](https://www.figma.com/mcp-catalog/) so DCR is allowed (`mcp:connect`). Today `POST /v1/oauth/mcp/register` returns 403. |
| Dropbox | `com.dropbox/mcp` | Add TrustGate as a trusted MCP DCR partner (same path as Claude, ChatGPT, Cursor). |
| Vercel | `com.vercel/mcp` | Allowlist the TrustGate redirect (or issue an approved MCP `client_id`). |
| Vanta | `com.vanta/mcp` | Mark TrustGate as an official Vanta MCP client and allowlist the redirect. DCR already succeeds; consent fails with “Unrecognized redirect URL” / “Uh oh, something went wrong”. |
| Cal.com | `com.cal/mcp` | Allowlist the TrustGate callback host for MCP DCR. |
| Checkr | `com.checkr/mcp` | Allowlist the TrustGate redirect URI for MCP DCR. |
| Intercom | `com.intercom/mcp` | Allowlist the TrustGate redirect URI (Intercom Customer Support). |
| Semrush | `com.semrush/mcp` | Allowlist the TrustGate redirect URI. |
| Shortcut | `com.shortcut/mcp` | Approve the TrustGate redirect URI. |
| Square | `com.squareup/mcp` | Allowlist the TrustGate callback domain for MCP DCR. |
| Prismic | `io.prismic/mcp` | Allowlist the TrustGate redirect URI. |
| Slack | `com.slack/mcp` | Enable Slack MCP on NeuralTrust’s Slack app (standard apps get an enablement error). |
| Google | `com.google.workspace/*`, `com.google.cloud/*` | Complete Google Cloud OAuth verification for the TrustGate client (restricted Workspace / Cloud scopes). No DCR. |
| Jotform | `com.jotform/mcp` | Approve the TrustGate OAuth callback for Jotform MCP. |

Redirect to quote in every email:

`https://gateway-mcp.neuraltrust.ai/oauth/callback/<catalog-code>`

Replace `<catalog-code>` with the row above (for Figma use a stable code such as `com.figma/mcp` once listed).

---

## Email to send

**To:** vendor MCP / partner / support alias (Vanta: `support@vanta.com`)  
**Subject:** Request to allowlist TrustGate as an enterprise MCP client

Hello,

We are **NeuralTrust**, a cybersecurity company. Our product **TrustGate** is an enterprise MCP gateway: we sit in front of the MCP catalog our customers use (Figma, Vanta, productivity, cloud, security tools, and the rest of the remote MCP ecosystem) and give them a **governance and security layer** over those connections — centralized auth, policy, audit, and least-privilege tool access — instead of each employee wiring SaaS MCP servers straight into an IDE.

Enterprise customers connect TrustGate once. TrustGate then acts as the OAuth client to each upstream MCP server (`client_name`: **TrustGate MCP Gateway**).

We need you to allow our production client so those customers can authorize **[Vendor] MCP** through TrustGate the same way they already can from Claude, Cursor, or other first-party MCP hosts.

**Please:**  
**[ASK — paste the “Ask” cell for this vendor]**

**OAuth client**  
- Client name: TrustGate MCP Gateway  
- Grant: authorization code + PKCE (S256), public client (`token_endpoint_auth_method: none`)  
- Redirect URI: `https://gateway-mcp.neuraltrust.ai/oauth/callback/[catalog-code]`  
- Product: https://neuraltrust.ai  

Happy to complete any security review you require for enterprise MCP clients. We already operate this pattern with other vendors (including AWS Sign-In for AWS MCP).

Thank you,  
[Name]  
NeuralTrust  
[email] · [calendar link]
