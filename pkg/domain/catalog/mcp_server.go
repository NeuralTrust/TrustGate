package catalog

// MCPServer is a single entry in the curated catalog of remote MCP servers,
// used to prefill MCP registry creation.
type MCPServer struct {
	Code         string `json:"code"`
	DisplayName  string `json:"display_name"`
	Vendor       string `json:"vendor,omitempty"`
	Category     string `json:"category,omitempty"`
	Description  string `json:"description,omitempty"`
	URL          string `json:"url"`
	Transport    string `json:"transport"`
	AuthHint     string `json:"auth_hint"` // none | static | oauth
	RequiresAuth bool   `json:"requires_auth"`
	// Relevance ranks how broadly relevant a server is for enterprises
	// (higher = more relevant). Used to sort the catalog; 0 means unranked.
	Relevance    int              `json:"relevance"`
	Scopes       []string         `json:"scopes,omitempty"`
	URLVariables []MCPURLVariable `json:"url_variables,omitempty"`
	AuthHeaders  []MCPAuthHeader  `json:"auth_headers,omitempty"`
	OAuth        *MCPOAuth        `json:"oauth,omitempty"`
	Metadata     map[string]any   `json:"metadata,omitempty"`
	Source       string           `json:"source"`
}

// MCPURLVariable describes a templated segment of an MCP server URL (e.g. a
// tenant subdomain or region) that the operator must supply.
type MCPURLVariable struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required"`
}

// MCPAuthHeader describes a header the upstream MCP server expects for
// authentication (API key / bearer token / custom header).
type MCPAuthHeader struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required"`
	Secret      bool   `json:"secret"`
}

// MCPOAuth describes the OAuth 2.1 capabilities advertised by an MCP server.
type MCPOAuth struct {
	Required         bool `json:"required"`
	ResourceMetadata bool `json:"resource_metadata"`
}
