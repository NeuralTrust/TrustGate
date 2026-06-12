package catalog

import (
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/catalog"
)

type MCPServerCatalog interface {
	ListMCPServers() []domain.MCPServer
}

var _ MCPServerCatalog = (*mcpServerCatalog)(nil)

type mcpServerCatalog struct{}

func NewMCPServerCatalog() MCPServerCatalog {
	return &mcpServerCatalog{}
}

func (c *mcpServerCatalog) ListMCPServers() []domain.MCPServer {
	return curatedMCPServers
}

const curatedSource = "curated"

var curatedMCPServers = []domain.MCPServer{
	{
		Code:        "github",
		DisplayName: "GitHub",
		URL:         "https://api.githubcopilot.com/mcp/",
		Transport:   "streamable-http",
		AuthHint:    "oauth",
		Metadata:    map[string]any{"docs": "https://github.com/github/github-mcp-server"},
		Source:      curatedSource,
	},
	{
		Code:        "linear",
		DisplayName: "Linear",
		URL:         "https://mcp.linear.app/mcp",
		Transport:   "streamable-http",
		AuthHint:    "oauth",
		Metadata:    map[string]any{"docs": "https://linear.app/docs/mcp"},
		Source:      curatedSource,
	},
	{
		Code:        "notion",
		DisplayName: "Notion",
		URL:         "https://mcp.notion.com/mcp",
		Transport:   "streamable-http",
		AuthHint:    "oauth",
		Metadata:    map[string]any{"docs": "https://developers.notion.com/docs/mcp"},
		Source:      curatedSource,
	},
	{
		Code:        "sentry",
		DisplayName: "Sentry",
		URL:         "https://mcp.sentry.dev/mcp",
		Transport:   "streamable-http",
		AuthHint:    "oauth",
		Metadata:    map[string]any{"docs": "https://docs.sentry.io/product/sentry-mcp/"},
		Source:      curatedSource,
	},
	{
		Code:        "atlassian",
		DisplayName: "Atlassian (Jira / Confluence)",
		URL:         "https://mcp.atlassian.com/v1/mcp",
		Transport:   "streamable-http",
		AuthHint:    "oauth",
		Metadata:    map[string]any{"docs": "https://www.atlassian.com/platform/remote-mcp-server"},
		Source:      curatedSource,
	},
	{
		Code:        "stripe",
		DisplayName: "Stripe",
		URL:         "https://mcp.stripe.com",
		Transport:   "streamable-http",
		AuthHint:    "static",
		Metadata:    map[string]any{"docs": "https://docs.stripe.com/mcp"},
		Source:      curatedSource,
	},
	{
		Code:        "context7",
		DisplayName: "Context7",
		URL:         "https://mcp.context7.com/mcp",
		Transport:   "streamable-http",
		AuthHint:    "static",
		Metadata:    map[string]any{"docs": "https://context7.com"},
		Source:      curatedSource,
	},
	{
		Code:        "deepwiki",
		DisplayName: "DeepWiki",
		URL:         "https://mcp.deepwiki.com/mcp",
		Transport:   "streamable-http",
		AuthHint:    "none",
		Metadata:    map[string]any{"docs": "https://docs.devin.ai/work-with-devin/deepwiki-mcp"},
		Source:      curatedSource,
	},
	{
		Code:        "hugging-face",
		DisplayName: "Hugging Face",
		URL:         "https://huggingface.co/mcp",
		Transport:   "streamable-http",
		AuthHint:    "static",
		Metadata:    map[string]any{"docs": "https://huggingface.co/docs/hub/mcp"},
		Source:      curatedSource,
	},
}
