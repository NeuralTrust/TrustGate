package catalog

import (
	"encoding/json"
	"fmt"
	"sort"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/catalog"
	mcpcatalog "github.com/NeuralTrust/AgentGateway/seed/mcp-catalog"
)

type MCPServerCatalog interface {
	ListMCPServers() []domain.MCPServer
}

var _ MCPServerCatalog = (*mcpServerCatalog)(nil)

type mcpServerCatalog struct {
	servers []domain.MCPServer
}

// NewMCPServerCatalog loads the curated catalog of remote MCP servers embedded
// at build time. The embedded JSON is a validated build asset, so a parse
// failure is a programming error and surfaces at startup.
func NewMCPServerCatalog() (MCPServerCatalog, error) {
	servers, err := loadCuratedMCPServers()
	if err != nil {
		return nil, fmt.Errorf("loading curated mcp catalog: %w", err)
	}
	return &mcpServerCatalog{servers: servers}, nil
}

func (c *mcpServerCatalog) ListMCPServers() []domain.MCPServer {
	out := make([]domain.MCPServer, len(c.servers))
	copy(out, c.servers)
	return out
}

const curatedSource = "curated"

// authHintNone/Static/OAuth are the coarse auth classifications surfaced to the
// UI so it can prefill the right registry auth mode.
const (
	authHintNone   = "none"
	authHintStatic = "static"
	authHintOAuth  = "oauth"
)

// registrationAuto marks OAuth servers whose client self-registers (DCR), so no
// operator configuration is needed before connecting.
const registrationAuto = "auto"

// rawCatalog mirrors the schema of seed/mcp-catalog/enterprise-servers.json.
type rawCatalog struct {
	Servers []rawServer `json:"servers"`
}

type rawServer struct {
	Name         string                  `json:"name"`
	Vendor       string                  `json:"vendor"`
	Category     string                  `json:"category"`
	Description  string                  `json:"description"`
	Transport    string                  `json:"transport"`
	ServerURL    string                  `json:"server_url"`
	URLVariables []domain.MCPURLVariable `json:"url_variables"`
	RequiresAuth bool                    `json:"requires_auth"`
	AuthHeaders  []domain.MCPAuthHeader  `json:"auth_headers"`
	OAuth        *domain.MCPOAuth        `json:"oauth"`
	Relevance    int                     `json:"relevance"`
}

func loadCuratedMCPServers() ([]domain.MCPServer, error) {
	var raw rawCatalog
	if err := json.Unmarshal(mcpcatalog.EnterpriseServersJSON, &raw); err != nil {
		return nil, err
	}
	servers := make([]domain.MCPServer, 0, len(raw.Servers))
	for _, s := range raw.Servers {
		servers = append(servers, domain.MCPServer{
			Code:           s.Name,
			DisplayName:    s.Vendor,
			Vendor:         s.Vendor,
			Category:       s.Category,
			Description:    s.Description,
			URL:            s.ServerURL,
			Transport:      s.Transport,
			AuthHint:       authHint(s),
			RequiresAuth:   s.RequiresAuth,
			RequiresConfig: requiresConfig(s),
			Relevance:      s.Relevance,
			URLVariables:   s.URLVariables,
			AuthHeaders:    s.AuthHeaders,
			OAuth:          s.OAuth,
			Source:         curatedSource,
		})
	}
	// Most relevant first; ties broken alphabetically so the order is stable.
	sort.SliceStable(servers, func(i, j int) bool {
		if servers[i].Relevance != servers[j].Relevance {
			return servers[i].Relevance > servers[j].Relevance
		}
		if servers[i].DisplayName != servers[j].DisplayName {
			return servers[i].DisplayName < servers[j].DisplayName
		}
		return servers[i].Code < servers[j].Code
	})
	return servers, nil
}

// authHint classifies the upstream's auth model so the UI can prefill the
// registry auth mode: OAuth when an OAuth block is present, static when a
// credential must be supplied (headers or a token in a URL variable), else none.
func authHint(s rawServer) string {
	switch {
	case s.OAuth != nil && s.OAuth.Required:
		return authHintOAuth
	case len(s.AuthHeaders) > 0:
		return authHintStatic
	case s.RequiresAuth:
		return authHintStatic
	default:
		return authHintNone
	}
}

// requiresConfig reports whether the operator must supply input before the
// server can be connected, so the UI can connect zero-config servers by default
// and only surface a setup step for the rest. Config is required when a URL
// variable must be filled (e.g. a tenant host), when a static secret is needed,
// or when OAuth needs a manual/tenant client. OAuth servers that self-register
// (registration "auto") need nothing at creation — the user logs in at runtime.
func requiresConfig(s rawServer) bool {
	for _, v := range s.URLVariables {
		if v.Required {
			return true
		}
	}
	switch authHint(s) {
	case authHintNone:
		return false
	case authHintStatic:
		return true
	case authHintOAuth:
		return s.OAuth.Registration != registrationAuto
	default:
		return true
	}
}
