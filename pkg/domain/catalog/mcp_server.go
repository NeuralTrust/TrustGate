package catalog

// MCPServer is one curated remote MCP server entry. The catalog feeds the
// admin UI pick-list so creating an MCP registry starts from a known server
// (URL, transport, auth hint) instead of a blank form.
type MCPServer struct {
	Code        string         `json:"code"`
	DisplayName string         `json:"display_name"`
	URL         string         `json:"url"`
	Transport   string         `json:"transport"`
	AuthHint    string         `json:"auth_hint"` // none | static | oauth
	Scopes      []string       `json:"scopes,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	Source      string         `json:"source"`
}
