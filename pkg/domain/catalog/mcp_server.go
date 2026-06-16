// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	// RequiresConfig reports whether the operator must supply input before the
	// server can be connected (a required URL variable, a static secret, or a
	// manual/tenant OAuth client). When false the UI can connect it by default
	// without a configuration step: public servers, and OAuth servers whose
	// client self-registers (registration "auto") where the user simply logs in
	// at runtime.
	RequiresConfig bool `json:"requires_config"`
	// Relevance ranks how broadly relevant a server is for enterprises
	// (higher = more relevant). Used to sort the catalog; 0 means unranked.
	Relevance    int              `json:"relevance"`
	Scopes       []string         `json:"scopes,omitempty"`
	URLVariables []MCPURLVariable `json:"url_variables,omitempty"`
	AuthHeaders  []MCPAuthHeader  `json:"auth_headers,omitempty"`
	OAuth        *MCPOAuth        `json:"oauth,omitempty"`
	// Tools is a snapshot of the server's advertised tools, captured by an
	// unauthenticated tools/list where the server allows it. It is a preview for
	// the catalog UI; the authoritative per-connection tool set is discovered at
	// runtime by the gateway's introspector (and may be tenant/user-specific).
	// Empty when the server requires auth to list tools.
	Tools    []MCPTool      `json:"tools,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
	Source   string         `json:"source"`
}

// MCPTool is a single tool advertised by an MCP server (name + description),
// used as a catalog preview of the server's capabilities.
type MCPTool struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// MCPURLVariable describes a templated segment of an MCP server URL (e.g. a
// tenant subdomain or region) that the operator must supply.
type MCPURLVariable struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required"`
	// Secret marks a variable that carries a credential (e.g. a token passed in
	// the query string) so the UI/secret store treats it as sensitive.
	Secret bool `json:"secret,omitempty"`
	// In is where the variable is substituted: "path" (default) or "query".
	In string `json:"in,omitempty"`
}

// MCPAuthHeader describes a header the upstream MCP server expects for
// authentication (API key / bearer token / custom header).
type MCPAuthHeader struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required"`
	Secret      bool   `json:"secret"`
	// Scheme is the credential prefix the gateway prepends to the supplied
	// secret when building the header value: Bearer | Token | Basic | ApiKey |
	// App | raw (raw = send the value verbatim, no prefix).
	Scheme string `json:"scheme,omitempty"`
}

// MCPOAuth describes the OAuth 2.1 capabilities advertised by an MCP server.
// These fields tell the gateway how to drive the "forwarded" auth mode: when
// DCR is supported it can self-register (registration: auto); otherwise the
// operator must pre-register a client and the gateway needs AuthorizeURL/
// TokenURL/Scopes to complete the flow.
type MCPOAuth struct {
	Required         bool `json:"required"`
	ResourceMetadata bool `json:"resource_metadata"`
	// Registration is the recommended gateway registration mode derived from
	// DCR support: "auto" when the server supports Dynamic Client Registration
	// (the gateway self-registers and the user just logs in at runtime),
	// "manual" when an operator must pre-register a client. Empty means the
	// server is tenant-hosted and discovery happens per-instance at connect time.
	Registration string `json:"registration,omitempty"`
	// DCR reports whether the server supports OAuth Dynamic Client Registration
	// (RFC 7591). A nil pointer means it could not be determined (e.g. a
	// tenant-templated host that must be probed per-instance).
	DCR *bool `json:"dcr,omitempty"`
	// PKCE reports whether the authorization server supports PKCE (S256). A nil
	// pointer means it could not be determined.
	PKCE *bool `json:"pkce,omitempty"`
	// AuthorizeURL / TokenURL are required for manual registration
	// (Registration == "manual"), where the operator supplies a pre-registered
	// client_id/secret; they also serve as a discovery fallback otherwise.
	AuthorizeURL string `json:"authorize_url,omitempty"`
	TokenURL     string `json:"token_url,omitempty"`
	// Scopes are the default/required OAuth scopes for the server.
	Scopes []string `json:"scopes,omitempty"`
	// Resource is the RFC 8707 resource indicator / expected token audience.
	Resource string `json:"resource,omitempty"`
}
