package catalog

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
