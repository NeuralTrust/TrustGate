# MCP catalog: vendor approval of the TrustGate OAuth client

TrustGate connects to remote MCP servers as **one OAuth client**
(`client_name`: `TrustGate MCP Gateway`, redirect
`{gatewayOrigin}/oauth/callback/{catalogCode}`). Most vendors let that
client self-register (RFC 7591 DCR) and the user just consents. A smaller
set only authorizes a **pre-approved MCP client list** or a **pre-approved
redirect host**. Those are the Figma / Vanta-class failures.

Probed 2026-09-10 against `seed/mcp-catalog/enterprise-servers.json`
(200 servers, 146 OAuth). DCR was posted as TrustGate with
`https://connect.neuraltrust.ai/oauth/callback/{code}`. Loopback-only
success (`http://localhost`) does **not** mean a hosted gateway works.

## 1. Needs provider approval before TrustGate can authorize

### 1a. Client allowlist (must apply to be an approved MCP client)

| Catalog code | Vendor | Live DCR | What to request |
|--------------|--------|----------|-----------------|
| *(not in catalog)* | **Figma** (`https://mcp.figma.com/mcp`) | `POST https://api.figma.com/v1/oauth/mcp/register` → **403 Forbidden** | Join the [Figma MCP Catalog](https://www.figma.com/mcp-catalog/) waitlist / account team. Only listed clients (Claude, Cursor, VS Code, …) may use `mcp:connect`. |
| `com.dropbox/mcp` | Dropbox | **403** `registration_not_supported`: “Only pre-registered MCP trusted partners are allowed.” | [Get Help](https://help.dropbox.com/integrations/connect-dropbox-mcp-server) to add TrustGate as a trusted DCR client (today: Claude, ChatGPT, Cursor). Other clients can still use a **manual** Dropbox app. |
| `com.vanta/mcp` | Vanta | DCR **201**; consent then **Uh oh, something went wrong** for unofficial redirects | Ask Vanta to allowlist `{gateway}/oauth/callback/com.vanta/mcp` as an official MCP client. See §2. |

Figma is the same failure mode as the 403 vendor-allowlist mentioned in
`docs/mcp/testing-guide.md`. It is **not** seeded; adding it as
`registration: auto` would show a one-click Connect that cannot succeed.

### 1b. Redirect-host allowlist (DCR exists, hosted HTTPS callback rejected)

These advertise `registration_endpoint` and accept `http://localhost`, but
reject TrustGate’s HTTPS callback until the vendor allowlists the gateway
host.

| Catalog code | Vendor | Live error | Ask them to allowlist |
|--------------|--------|------------|------------------------|
| `com.amazon.aws/mcp` | AWS | `The redirection URI … is not allowed by this server.` (us-east-1) | Already noted in the seed: AWS Sign-In DCR is redirect-allowlisted. |
| `com.cal/mcp` | Cal.com | `redirect_uri host '…' is not in the allowed list` | Cal.com MCP redirect host list |
| `com.checkr/mcp` | Checkr | `Redirect URI '…' is not allowed.` | Checkr MCP DCR redirect allowlist |
| `com.intercom/mcp` | Intercom | `Redirect URI … is not in the allowlist, reach out to Intercom Customer Support` | Intercom Customer Support ([community thread](https://community.intercom.com/apps-integrations-25/requesting-redirect-uri-allowlist-for-mcp-dcr-14501)) |
| `com.semrush/mcp` | Semrush | `redirect URI … is not allowed` | Semrush MCP redirect allowlist |
| `com.shortcut/mcp` | Shortcut | `must be an approved redirect URI` | Shortcut OAuth redirect approval |
| `com.squareup/mcp` | Square | `domain not in allowlist` | Square MCP domain allowlist |
| `io.prismic/mcp` | Prismic | `Redirect URI not allowed` | Prismic MCP redirect allowlist |

Once the **production** connect origin (`MCP_OAUTH_PUBLIC_BASE_URL` or each
gateway host) is on that list, `registration: auto` works. Every extra
customer host is another allowlist request unless a single public callback
origin is used.

### 1c. Manual OAuth apps that the vendor still has to enable/verify

These are `registration: manual` (no DCR). The operator creates an OAuth
app, **and** the vendor often must flip a flag or complete a review before
that app can call MCP:

| Catalog code | Vendor | Extra vendor gate |
|--------------|--------|-------------------|
| `com.slack/mcp` | Slack | Slack MCP must be enabled on the app; ordinary Slack apps get an enablement error. |
| `com.google.workspace/gmail` `…/calendar` `…/drive` | Google | No DCR. Shared TrustGate client still needs Google Cloud verification / restricted-scope review for production. See `docs/mcp/google-workspace-oauth.md`. |
| `com.google.cloud/*` | Google Cloud | Same Google OAuth client model; no MCP DCR. |
| `com.jotform/mcp` | Jotform | Seed says unapproved DCR callbacks are rejected (hence manual). Live `register-public-client` **did** mint a TrustGate HTTPS client on this probe — treat as flaky; keep manual until confirmed in product. |
| `com.github/copilot-mcp` | GitHub | Org MCP policy can block the connection even after OAuth. |
| `com.asana/mcp` `com.box/mcp` `com.frontapp/mcp` `com.hubspot/mcp` `us.zoom/*` `com.pagerduty/mcp` `com.salesforce/mcp` `com.snowflake/mcp` `com.servicenow/mcp` `com.microsoft/*` `com.netsuite/ai-connector` | various | Operator must register a first-party OAuth app (and often pass that vendor’s app review / tenant admin consent). Not a TrustGate-specific allowlist, but Connect is not zero-config. |

## 2. Vanta (`com.vanta/mcp`) — DCR works; consent treats TrustGate as unofficial

Vanta is **not** Figma: DCR succeeds. The failure is on Vanta's **Authorize
App** page after the user is signed in.

Live production (`https://gateway-mcp.neuraltrust.ai/oauth/callback/com.vanta/mcp`):

1. `POST https://api.vanta.com/oauth/register` returns **201** and a `vci_…`
   client (TrustGate `client_name` + hosted HTTPS callback).
2. Discovery: PRM `https://mcp.vanta.com/.well-known/oauth-protected-resource`
   → AS `https://api.vanta.com/mcp` →
   `authorization_endpoint` `https://api.vanta.com/oauth/authorize` (302 to
   `https://app.vanta.com/oauth/authorize`). Token URL
   `https://api.vanta.com/oauth/token`.
3. Consent renders **TrustGate MCP Gateway** plus:
   - **Unrecognized redirect URL** — the callback is not an “official Vanta
     supported MCP” (their allowlist is localhost, `cursor://` / `vscode://`,
     and `https://claude.ai/api/mcp/auth_callback`). Docs say unofficial tools
     show a warning and the user can continue.
   - **Link your US Vanta instance to TrustGate MCP Gateway** — unofficial
     clients go through an extra tenant-link step that official Cursor/Claude
     skip.
   - Hard fail: **Uh oh, something went wrong! Contact support@vanta.com**.
     That toast is Vanta's SPA/API, not TrustGate. Allow never completes, so
     no `code` reaches `/oauth/callback/com.vanta/mcp`.

Ask Vanta (support@vanta.com / account team) to add TrustGate as an official
MCP client with redirect
`https://gateway-mcp.neuraltrust.ai/oauth/callback/com.vanta/mcp`
(and any extra gateway hosts). Until then Connect cannot finish.

Also required: the signer must be a **Vanta Organization Admin**. The catalog
tile is US (`mcp.vanta.com`); EU/AUS tenants need
`mcp.eu.vanta.com` / `mcp.aus.vanta.com` as Custom MCP.

## 3. Open DCR for a hosted TrustGate callback (no vendor pre-approval)

Live DCR **minted** a client for the TrustGate HTTPS URI (86 catalog
servers). These do **not** need NeuralTrust to be pre-approved as an MCP
client. User consent at the vendor still applies.

Includes (non-exhaustive): Airtable, Amplitude, Atlassian, Attio, Canva,
ClickUp, Cloudflare, GitLab, Grafana, Linear, Miro, Monday, Notion, PostHog,
Stripe, Supabase, Wix, and **Vanta** (see §2).

ClickUp is on this list despite older third-party audits calling it
redirect-allowlisted; this probe’s TrustGate HTTPS registration returned 201.

## 4. How to re-run

```bash
# Reachability of MCP URLs (401 vs 403 allowlist), not OAuth DCR:
make mcp-catalog-probe ARGS='-out /tmp/mcp-catalog-probe.jsonl'

# OAuth discovery + DCR as TrustGate (do not mint clients in production
# against customer tenants; this is a vendor-metadata probe):
python3 /tmp/mcp-oauth-audit.py   # if the helper is still around
```

Signals:

| Live DCR result | Meaning for TrustGate |
|-----------------|------------------------|
| 201/200 with hosted `https://{gateway}/oauth/callback/…` | Open; no vendor client approval |
| 201 only for `http://localhost` | Redirect allowlist; request host approval |
| 403 `registration_not_supported` / plaintext `Forbidden` | Client allowlist (Figma / Dropbox) |
| No `registration_endpoint` | Manual OAuth app (`registration: manual` in seed) |

## 5. Product implications

- Catalog `registration: auto` currently implies zero-config Connect.
  Servers in §1a/§1b will fail at DCR until NeuralTrust is allowlisted.
- Prefer a **single** `MCP_OAUTH_PUBLIC_BASE_URL` so each vendor only has to
  allowlist one callback origin.
- Figma should stay out of the one-click catalog (or be `hidden`) until
  TrustGate is on the MCP Catalog.
- Dropbox / Vercel can stay seeded but need the same partnership as Figma,
  or a documented manual-app fallback (Dropbox already documents that path).
