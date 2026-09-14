#!/usr/bin/env python3
"""Write 3 Portal “What you can do” lines onto every catalog server.

Empty-tool servers get curated copy. Everyone else uses the catalog
description first, then tool descriptions, then vendor-specific fallbacks.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

CATALOG = Path(__file__).resolve().parents[1] / "seed/mcp-catalog/enterprise-servers.json"
CAP_COUNT = 3
CAP_MAX = 72
SKIP_TOOL = re.compile(r"^(ping|health|echo|noop|whoami|get_me|read_me)\b", re.I)
SKIP_DESC = re.compile(r"\bping the mcp\b", re.I)
SKIP_META_NAME = re.compile(
    r"(mcp_server_version|report_missing_tool|proxy_tool_call|get_me|read_me)$",
    re.I,
)
PAREN = re.compile(r"\([^)]*\)")
URL = re.compile(r"https?://\S+")
MCP_JARGON = re.compile(r"\b(?:remote |hosted |official )?(?:MCP(?: Gateway| server| servers)?)\b", re.I)
TRAILING_PREP = re.compile(r"\b(?:via|on|in|for|from|across|including)\s+.+$", re.I)
JUNK_CLAUSE = re.compile(
    r"https?://|token passed|query parameter|per-site|regional host|other sites|"
    r"us-region|docs also|sandbox|append your|enable in|streamable|oauth|api key|"
    r"endpoint |optional \?",
    re.I,
)
OPENAPI_NOISE = re.compile(
    r"^(gets?|lists?|creates?|deletes?|retrieves?|returns?|shows|starts|disable|change)\b",
    re.I,
)
TOOL_PREFIXES = (
    "notion ",
    "github ",
    "figma ",
    "slack ",
    "jira ",
    "google ",
    "microsoft ",
    "aws ",
)
PREFERRED = (
    "search",
    "query",
    "create",
    "send",
    "manage",
    "read",
    "write",
    "update",
    "run",
    "book",
    "generate",
    "analyze",
    "monitor",
    "fetch",
    "add",
    "find",
    "list",
    "get",
    "delete",
    "cancel",
    "upload",
    "scrape",
    "issue",
)

CATEGORY_VERB = {
    "AI & Audio": "Look up",
    "AI & ML": "Work with",
    "Analytics": "Analyze",
    "Automation": "Run",
    "Billing & Payments": "Manage",
    "Browser Automation": "Automate",
    "Cloud Platform": "Manage",
    "Communication": "Send and read",
    "CRM": "Manage",
    "Customer Support": "Manage",
    "Data & Analytics": "Query",
    "Data Governance": "Explore",
    "Database": "Query",
    "Design": "Create and edit",
    "Dev & APIs": "Call",
    "Development": "Manage",
    "E-signature & Legal": "Manage",
    "ERP": "Query",
    "Feature Flags & Experimentation": "Manage",
    "File Management": "Search and manage",
    "Finance": "Manage",
    "HR & Recruiting": "Manage",
    "ITSM": "Manage",
    "Marketing": "Analyze",
    "Media & Video": "Manage",
    "Observability": "Monitor",
    "Payments": "Process",
    "Product Management": "Manage",
    "Productivity & Docs": "Work with",
    "Project Management": "Manage",
    "Sales": "Manage",
    "Sales & CRM": "Manage",
    "Sales Intelligence": "Research",
    "Scheduling": "Manage",
    "Search": "Search",
    "Search & Observability": "Search and monitor",
    "Security": "Review",
    "Security & Identity": "Manage",
    "Web & CMS": "Manage",
    "Web Scraping & Data": "Scrape",
}

# Servers the catalog could not probe (empty tools[]). Written for the Portal
# side panel from each server's description — not setup/auth notes.
CURATED: dict[str, list[str]] = {
    "com.apify/mcp": [
        "Run scrapers",
        "Run crawlers",
        "Automate data collection",
    ],
    "com.canva/mcp": [
        "Generate designs",
        "Edit assets",
        "Manage brand kits",
    ],
    "com.cloudflare/ai-gateway": [
        "Search AI Gateway logs",
        "Configure gateways",
        "Inspect request traces",
    ],
    "com.cloudflare/api-mcp": [
        "Search the Cloudflare API",
        "Call Cloudflare endpoints",
        "Manage account resources",
    ],
    "com.coinbase/bazaar": [
        "Discover paid endpoints",
        "Call x402 payment APIs",
        "Run agent payments",
    ],
    "com.databricks/mcp": [
        "Ask Genie spaces",
        "Search vector indexes",
        "Run SQL",
    ],
    "com.deepwiki/mcp": [
        "Read repository docs",
        "Ask questions about GitHub wikis",
        "Browse documentation topics",
    ],
    "com.digitalocean/droplets": [
        "Create and manage Droplets",
        "Resize and rebuild compute",
        "Control backups and kernels",
    ],
    "com.digitalocean/kubernetes": [
        "Manage Kubernetes clusters",
        "Scale node pools",
        "Inspect cluster options",
    ],
    "dev.firecrawl/mcp": [
        "Scrape web pages",
        "Crawl sites",
        "Extract structured data",
    ],
    "com.google.workspace/gmail": [
        "Search threads",
        "Read messages",
        "Create drafts",
    ],
    "io.pinecone/assistant": [
        "Retrieve assistant context",
        "Search uploaded files",
        "Read relevant snippets",
    ],
    "com.storyblok/mcp": [
        "Search content and spaces",
        "Manage components and assets",
        "Work with workflows and releases",
    ],
    "io.aha/mcp": [
        "View product roadmaps",
        "Capture ideas and features",
        "Manage Aha! records",
    ],
    "com.ahrefs/mcp": [
        "Analyze SEO performance",
        "Research backlinks",
        "Compare keywords and competitors",
    ],
    "ai.airbyte/agents": [
        "Query connected data",
        "Act across business apps",
        "Work with synced sources",
    ],
    "com.algolia/mcp": [
        "Search application indices",
        "Get recommendations",
        "Browse indexed content",
    ],
    "io.apollo/mcp": [
        "Prospect accounts and contacts",
        "Enrich sales records",
        "Search buyer intelligence",
    ],
    "dev.arcade/mcp": [
        "Call tools across integrations",
        "Run automation actions",
        "Connect business apps",
    ],
    "com.betterstack/mcp": [
        "Monitor uptime",
        "Investigate incidents and logs",
        "Manage on-call and status pages",
    ],
    "io.builder/cms-mcp": [
        "Publish site content",
        "Edit CMS entries",
        "Manage Builder spaces",
    ],
    "com.clickup/mcp": [
        "Manage tasks and lists",
        "Work with docs",
        "Track projects",
    ],
    "io.coda/mcp": [
        "Read docs and tables",
        "Write pages and rows",
        "Search workspace content",
    ],
    "dev.cube/mcp": [
        "Query the semantic layer",
        "Explore Cube metrics",
        "Analyze workspace data",
    ],
    "com.egnyte/mcp": [
        "Search files",
        "Upload and manage documents",
        "Work with secure folders",
    ],
    "co.elastic/agent-builder-mcp": [
        "Search Elastic data",
        "Query observability signals",
        "Use Agent Builder tools",
    ],
    "com.freshworks/mcp": [
        "Manage tickets",
        "Look up assets",
        "Search the knowledge base",
    ],
    "com.slack/mcp": [
        "Search messages, files, and people",
        "Read channels and threads",
        "Send messages and update canvases",
    ],
    "com.gorgias/mcp": [
        "Manage helpdesk tickets",
        "Look up customers",
        "Work with support conversations",
    ],
    "com.grafana/mcp": [
        "Browse dashboards",
        "Query datasources",
        "Manage alerts",
    ],
    "com.holded/mcp": [
        "Create and manage invoices",
        "Update contacts and products",
        "Track payments and stock",
    ],
    "com.haloitsm/mcp": [
        "Manage tickets",
        "Search the knowledge base",
        "Work with assets and runbooks",
    ],
    "co.huggingface/mcp": [
        "Search models",
        "Browse datasets",
        "Discover Spaces",
    ],
    "com.infobip/mcp": [
        "Send SMS and RCS",
        "Message WhatsApp and Viber",
        "Run omnichannel campaigns",
    ],
    "com.make/mcp": [
        "Build automation workflows",
        "Run scenarios",
        "Manage workflow connections",
    ],
    "com.netsuite/ai-connector": [
        "Query records and transactions",
        "Run saved searches and reports",
        "Execute SuiteQL",
    ],
    "io.n8n/mcp": [
        "Search workflows",
        "Run automations",
        "Build workflows for agents",
    ],
    "com.pandadoc/mcp": [
        "Manage documents",
        "Work with templates",
        "Update contacts and webhooks",
    ],
    "com.pipedream/mcp": [
        "Call tools across connected apps",
        "Run hosted automations",
        "Connect 3,000+ services",
    ],
    "com.salesforce/mcp": [
        "Query Salesforce records",
        "Update CRM objects",
        "Search accounts and opportunities",
    ],
    "com.sectigo/mcp": [
        "Issue and renew certificates",
        "Revoke certificates",
        "Search and report on certificates",
    ],
    "com.servicenow/mcp": [
        "Manage incidents and requests",
        "Search the knowledge base",
        "Work with ServiceNow records",
    ],
    "com.snowflake/mcp": [
        "Query Cortex data",
        "Explore database schemas",
        "Analyze warehouse results",
    ],
    "com.statsig/mcp": [
        "Manage feature flags",
        "Review experiments",
        "Analyze product metrics",
    ],
    "com.vimeo/mcp": [
        "Manage videos",
        "Query the video library",
        "Update Vimeo content",
    ],
    "com.workato/developer-api": [
        "Manage workspace assets",
        "Work with projects",
        "Run Workato automations",
    ],
    "us.zoom/revenue-accelerator": [
        "Review sales insights",
        "Analyze deal intelligence",
        "Work with conversation data",
    ],
}


def sentence(text: str) -> str:
    text = " ".join(text.split())
    for sep in ".!?":
        i = text.find(sep)
        if 0 <= i < len(text) - 1:
            text = text[:i].strip()
            break
    return text.rstrip(".: ").strip()


def format_line(text: str) -> str:
    text = sentence(text)
    if not text:
        return ""
    text = text[0].upper() + text[1:]
    if len(text) <= CAP_MAX:
        return text
    cut = text[: CAP_MAX - 1]
    if " " in cut:
        cut = cut.rsplit(" ", 1)[0]
    return cut + "…"


def humanize_tool(name: str) -> str:
    name = name.replace("_", " ").replace("-", " ").strip()
    lower = name.lower()
    for prefix in TOOL_PREFIXES:
        if lower.startswith(prefix):
            name = name[len(prefix) :].strip()
            break
    if not name:
        return ""
    return name[0].upper() + name[1:]


def is_bad_label(line: str) -> bool:
    if not line or " " not in line:
        return True
    if re.search(r"[a-z][A-Z]", line):
        return True
    lower = line.lower()
    if lower.startswith(
        (
            "get me",
            "read me",
            "cio ",
            "mcp ",
            "genie ",
            "fireflies ",
            "firecrawl ",
            "tavily ",
            "vonage ",
            "browserbase ",
            "plaid ",
        )
    ):
        return True
    return False


def clean_description(desc: str, vendor: str) -> str:
    text = URL.sub("", desc)
    text = PAREN.sub("", text)
    text = MCP_JARGON.sub("", text)
    text = re.sub(rf"\b{re.escape(vendor)}\b", "", text, flags=re.I)
    text = " ".join(text.split()).strip(" -:;")
    if ":" in text:
        _, right = text.split(":", 1)
        if len(right.strip()) >= 10:
            text = right.strip()
    text = TRAILING_PREP.sub("", text)
    return " ".join(text.split()).strip(" -:;")


def is_junk_clause(text: str) -> bool:
    return bool(JUNK_CLAUSE.search(text))


def join_verb_noun(verb: str, noun: str) -> str:
    words = noun.split()
    if words and words[0][:1].isupper() and words[0][1:].islower() and words[0] not in {
        "Jira",
        "Confluence",
        "Compass",
        "Postgres",
        "Kafka",
        "Cortex",
        "OAuth",
    }:
        words[0] = words[0].lower()
    return format_line(f"{verb} {' '.join(words)}")


def from_description(desc: str, vendor: str, category: str) -> list[str]:
    text = clean_description(desc, vendor)
    if not text:
        return []
    if ";" in text:
        lines = []
        for part in text.split(";"):
            if is_junk_clause(part):
                continue
            line = format_line(part)
            if line and not is_bad_label(line):
                lines.append(line)
        return lines[:CAP_COUNT]

    verb_list = re.match(
        r"^((?:[A-Za-z]+,\s*)+[A-Za-z]+,\s*and\s+[A-Za-z]+)\s+(.+)$",
        text,
    )
    if verb_list:
        verbs = [v.strip() for v in re.split(r",\s*(?:and\s+)?|\s+and\s+", verb_list.group(1)) if v.strip()]
        if verbs and verbs[0].lower() in set(PREFERRED):
            objects = [o.strip() for o in re.split(r",\s*(?:and\s+)?|\s+and\s+", verb_list.group(2)) if o.strip()]
            obj = objects[0] if objects else "content"
            out: list[str] = []
            if verbs:
                out.append(join_verb_noun(verbs[0], obj))
            if len(verbs) >= 3:
                out.append(join_verb_noun(f"{verbs[1]} and {verbs[2]}", obj))
            elif len(verbs) == 2:
                out.append(join_verb_noun(verbs[1], obj))
            if len(objects) > 1:
                extra = objects[1] if len(objects) == 2 else f"{objects[1]} and {objects[2]}"
                out.append(join_verb_noun("Work with", extra))
            return [line for line in out if line and not is_bad_label(line)][:CAP_COUNT]

    parts = [p.strip() for p in re.split(r",\s*(?:and\s+)?|\s+and\s+", text) if p.strip() and not is_junk_clause(p)]
    verb = CATEGORY_VERB.get(category, "Work with")
    out = []
    for part in parts:
        first = part.split()[0].lower()
        line = format_line(part) if first in set(PREFERRED) else join_verb_noun(verb, part)
        if line and not is_bad_label(line):
            out.append(line)
        if len(out) == CAP_COUNT:
            break
    return out


def is_noisy(desc: str) -> bool:
    text = desc.strip()
    lower = text.lower()
    if lower.startswith(("step ", "always ")):
        return True
    if "lists all api paths" in lower or "code mode" in lower:
        return True
    if OPENAPI_NOISE.match(text) and any(
        token in lower for token in ("given", "specified", "signed-in", "paginated")
    ):
        return True
    return False


def tool_rank(name: str) -> int:
    n = name.lower().replace("-", "_")
    for i, prefix in enumerate(PREFERRED):
        if n == prefix or n.startswith(prefix + "_") or n.startswith(prefix + " "):
            return i
    return len(PREFERRED) + 1


def from_tools(tools: list[dict]) -> list[str]:
    ranked = sorted(tools, key=lambda t: tool_rank(t.get("name") or ""))
    out: list[str] = []
    seen: set[str] = set()
    for tool in ranked:
        name = tool.get("name") or ""
        desc = tool.get("description") or ""
        if (
            SKIP_TOOL.match(name)
            or SKIP_META_NAME.search(name)
            or SKIP_TOOL.match(desc)
            or SKIP_DESC.search(desc)
        ):
            continue
        line = ""
        if desc and not is_noisy(desc):
            candidate = format_line(desc)
            first = candidate.split()[0].lower() if candidate else ""
            if candidate and first in set(PREFERRED) | {
                "search",
                "list",
                "create",
                "read",
                "write",
                "update",
                "send",
                "query",
                "manage",
                "look",
                "browse",
                "retrieve",
                "check",
                "navigate",
                "semantic",
                "full-text",
                "full",
                "real-time",
                "ai-powered",
                "ai-related",
                "workspace",
            }:
                line = candidate
        if not line:
            line = format_line(humanize_tool(name))
        if is_bad_label(line):
            continue
        key = line.lower()
        if not line or key in seen:
            continue
        seen.add(key)
        out.append(line)
        if len(out) == CAP_COUNT:
            break
    return out


def vendor_fallbacks(vendor: str, category: str) -> list[str]:
    topic = (category.split("&")[0] if category else "workspace").strip().lower()
    return [
        format_line(f"Search and read {vendor} {topic}"),
        format_line(f"Create and update {vendor} records"),
        format_line(f"Take actions in {vendor}"),
    ]


def unique(lines: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for line in lines:
        key = line.lower()
        if not line or key in seen:
            continue
        seen.add(key)
        out.append(line)
    return out


def capabilities_for(server: dict) -> list[str]:
    code = server["name"]
    if code in CURATED:
        return CURATED[code][:CAP_COUNT]
    vendor = server.get("vendor") or "this server"
    category = server.get("category") or ""
    lines = unique(
        from_description(server.get("description") or "", vendor, category)
        + from_tools(server.get("tools") or [])
        + vendor_fallbacks(vendor, category)
    )
    if len(lines) < CAP_COUNT:
        raise SystemExit(f"{code}: expected 3 capabilities, got {lines}")
    return lines[:CAP_COUNT]


def inject(raw: str, code: str, caps: list[str], offset: int) -> tuple[str, int]:
    needle = f'"name": {json.dumps(code)}'
    idx = raw.find(needle, offset)
    if idx < 0:
        raise SystemExit(f"could not find {code} in catalog JSON")
    desc_key = raw.find('"description":', idx)
    line_end = raw.find("\n", desc_key)
    pretty = '      "capabilities": [\n'
    for i, line in enumerate(caps):
        comma = "," if i < len(caps) - 1 else ""
        pretty += f"        {json.dumps(line, ensure_ascii=False)}{comma}\n"
    pretty += "      ],\n"
    raw = raw[: line_end + 1] + pretty + raw[line_end + 1 :]
    return raw, line_end + 1 + len(pretty)


def main() -> None:
    raw = CATALOG.read_text()
    data = json.loads(raw)
    if any(server.get("capabilities") for server in data["servers"]):
        raise SystemExit("catalog already has capabilities; restore the seed and rerun")
    offset = 0
    for server in data["servers"]:
        caps = capabilities_for(server)
        raw, offset = inject(raw, server["name"], caps, offset)
    parsed = json.loads(raw)
    if any(len(s.get("capabilities") or []) != CAP_COUNT for s in parsed["servers"]):
        raise SystemExit("injection produced a server without 3 capabilities")
    CATALOG.write_text(raw)
    print(f"wrote {len(parsed['servers'])} servers")
    for server in parsed["servers"]:
        print(f"{server['vendor']:28} | {server['capabilities']}")


if __name__ == "__main__":
    main()
