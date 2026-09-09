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

import "strings"

// MCPServer is a single entry in the curated catalog of remote MCP servers,
// used to prefill MCP registry creation.
type MCPServer struct {
	Code        string `json:"code"`
	DisplayName string `json:"display_name"`
	Vendor      string `json:"vendor,omitempty"`
	Category    string `json:"category,omitempty"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url"`
	Transport   string `json:"transport"`
	AuthHint    string `json:"auth_hint"` // none | static | oauth
	// AuthMethods lists every auth method an operator may pick when installing
	// this server: "static" (API key / header) and/or "oauth". It is the
	// authoritative declaration the UI uses to decide whether to offer a choice
	// of auth (both present) or a single fixed method. AuthHint stays the coarse
	// default/prefill; AuthMethods is the full menu. Empty ⇒ derive from AuthHint.
	AuthMethods  []string `json:"auth_methods,omitempty"`
	RequiresAuth bool     `json:"requires_auth"`
	// RequiresConfig reports whether the operator must supply input before the
	// server can be connected (a required URL variable, a static secret, or a
	// manual/tenant OAuth client). When false the UI can connect it by default
	// without a configuration step: public servers, and OAuth servers whose
	// client self-registers (registration "auto") where the user simply logs in
	// at runtime.
	RequiresConfig bool `json:"requires_config"`
	PlatformClient bool `json:"platform_client,omitempty"`
	// SelfService reports whether a user can install this server from the Store
	// with nothing configured by an admin: OAuth with dynamic client registration
	// or a platform-held client, a public server, or a static server whose only
	// credential is a per-user secret URL variable. False means an admin must
	// connect an instance first (a shared API key, a manual OAuth client, or a
	// client_credentials grant). Computed from the entry (see IsSelfService).
	SelfService bool `json:"self_service"`
	// MultiInstance reports whether more than one registry of this server is
	// meaningful on one gateway. Computed from the entry (see SupportsInstances).
	MultiInstance bool `json:"multi_instance"`
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
// TokenURL/Scopes to complete the flow. When GrantType is "client_credentials",
// the gateway instead uses machine-to-machine auth (no per-user consent).
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
	// TokenURL is also required for GrantType "client_credentials".
	AuthorizeURL string `json:"authorize_url,omitempty"`
	TokenURL     string `json:"token_url,omitempty"`
	// Scopes are the default/required OAuth scopes for the server.
	Scopes []string `json:"scopes,omitempty"`
	// Resource is the RFC 8707 resource indicator / expected token audience.
	Resource string `json:"resource,omitempty"`
	// GrantType selects the OAuth grant. Empty / omitted means authorization
	// code (forwarded). "client_credentials" is machine-to-machine.
	GrantType string `json:"grant_type,omitempty"`
	// TokenEndpointAuthMethod is used with client_credentials:
	// client_secret_basic (default) or client_secret_post.
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
}

// SupportedAuthMethods reports which install methods the entry offers: an
// explicit AuthMethods list wins; otherwise the coarse AuthHint plus the
// presence of an OAuth spec / auth headers decide.
func (s MCPServer) SupportedAuthMethods() (static, oauth bool) {
	if len(s.AuthMethods) > 0 {
		for _, m := range s.AuthMethods {
			switch strings.ToLower(strings.TrimSpace(m)) {
			case "static":
				static = true
			case "oauth":
				oauth = true
			}
		}
		return static, oauth
	}
	hint := strings.ToLower(strings.TrimSpace(s.AuthHint))
	oauth = hint == "oauth" || s.OAuth != nil
	static = hint == "static" || len(s.AuthHeaders) > 0
	return static, oauth
}

// IsSelfService reports whether the entry can be installed without an admin
// connecting it first:
//
//   - an OAuth server whose client the gateway can obtain itself — dynamic
//     registration (auto) or a platform-held client; not a client_credentials
//     grant nor a manual registration without a platform client;
//   - a public server (no auth);
//   - a static server whose only credential is a per-user secret URL variable
//     (each user enters their own value through the hosted form).
//
// A static-only server whose credential is a shared header value (an API key)
// the catalog does not carry is NOT self-service: only an admin can add it.
func (s MCPServer) IsSelfService() bool {
	static, oauth := s.SupportedAuthMethods()
	if oauth {
		return s.oauthSelfServiceable()
	}
	if !static {
		return true
	}
	return len(s.AuthHeaders) == 0 && s.hasSecretURLVariable()
}

func (s MCPServer) oauthSelfServiceable() bool {
	o := s.OAuth
	if o == nil {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(o.GrantType), "client_credentials") {
		return false
	}
	if s.PlatformClient {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(o.Registration)) {
	case "auto":
		return true
	case "":
		return !o.Required
	default:
		return false
	}
}

// SupportsInstances reports whether more than one registry of this server is
// meaningful on one gateway. Two registries of the same server can only differ
// in what an operator configures, so where there is nothing to configure the
// second one is a byte-for-byte copy of the first and buys nothing but
// ambiguity: an instance to pick on every install and uninstall, every tool
// name qualified by its instance (see naming.go's perInstance), and two Access
// rows granting the same thing.
//
// Something to configure means a templated URL — Snowflake's account, database
// and schema; Aha!'s domain — or a credential the operator supplies: a static
// header, an OAuth client they register themselves, a client_credentials grant.
// What does not count is which user signs in: a fixed URL behind per-user OAuth
// that registers itself (or whose client the platform holds) serves every user
// from one instance, and so does a public server.
//
// Registration "" is the tenant-hosted case, where discovery happens per
// instance at connect time; on its own that says nothing about what an operator
// would configure, so it counts only through the URL variables such a server
// declares.
func (s MCPServer) SupportsInstances() bool {
	if len(s.URLVariables) > 0 {
		return true
	}
	static, oauth := s.SupportedAuthMethods()
	if static {
		return true
	}
	if !oauth || s.OAuth == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(s.OAuth.GrantType), "client_credentials") {
		return true
	}
	if s.PlatformClient {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(s.OAuth.Registration), "manual")
}

func (s MCPServer) hasSecretURLVariable() bool {
	for _, v := range s.URLVariables {
		if v.Secret {
			return true
		}
	}
	return false
}
