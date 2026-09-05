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

package registry

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
)

type Type string

const (
	TypeLLM Type = "LLM"
	TypeMCP Type = "MCP"
)

type MCPTransport string

const MCPTransportStreamableHTTP MCPTransport = "streamable-http"

type MCPSource string

const (
	MCPSourceRemote  MCPSource = "mcp"
	MCPSourceOpenAPI MCPSource = "openapi"
)

type OpenAPITarget struct {
	SpecURL string `json:"spec_url"`
}

type MCPAuthMode string

const (
	MCPAuthModeNone              MCPAuthMode = "none"
	MCPAuthModeStatic            MCPAuthMode = "static"
	MCPAuthModePassthrough       MCPAuthMode = "passthrough"
	MCPAuthModeExchange          MCPAuthMode = "exchange"
	MCPAuthModeForwarded         MCPAuthMode = "forwarded"
	MCPAuthModeClientCredentials MCPAuthMode = "client_credentials"
)

// Token endpoint auth methods for MCPAuthModeClientCredentials (RFC 6749).
const (
	TokenEndpointAuthClientSecretBasic = "client_secret_basic"
	TokenEndpointAuthClientSecretPost  = "client_secret_post"
)

type MCPClientRegistration string

const (
	RegistrationManual MCPClientRegistration = "manual"
	RegistrationAuto   MCPClientRegistration = "auto"
)

type MCPExchangePattern string

const (
	ExchangeImpersonation MCPExchangePattern = "impersonation"
	ExchangeDelegation    MCPExchangePattern = "delegation"
	ExchangeOBO           MCPExchangePattern = "obo"
	ExchangeTokenExchange MCPExchangePattern = "token_exchange"
)

type MCPAuth struct {
	Mode   MCPAuthMode `json:"mode"`
	Header string      `json:"header,omitempty"`
	Value  string      `json:"value,omitempty"` // #nosec G117 -- upstream credential

	ExpectedAudience string             `json:"expected_audience,omitempty"`
	Pattern          MCPExchangePattern `json:"pattern,omitempty"`
	Audience         string             `json:"audience,omitempty"`
	Scope            string             `json:"scope,omitempty"`
	Actor            string             `json:"actor,omitempty"`

	Provider     string                `json:"provider,omitempty"`
	Registration MCPClientRegistration `json:"registration,omitempty"`
	ClientID     string                `json:"client_id,omitempty"`
	ClientSecret string                `json:"client_secret,omitempty"`
	AuthorizeURL string                `json:"authorize_url,omitempty"`
	TokenURL     string                `json:"token_url,omitempty"`
	Scopes       []string              `json:"scopes,omitempty"`
	Resource     string                `json:"resource,omitempty"`
	// TokenEndpointAuthMethod selects how client_id/secret are presented to the
	// token endpoint for client_credentials: client_secret_basic (default) or
	// client_secret_post.
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
}

type MCPTarget struct {
	// Code is the catalog entry this connection was created from (the MCP
	// catalog's stable server code, e.g. "com.asana/mcp"). It is the canonical
	// join key the UI uses to tell whether a catalog server is already
	// connected, mirroring how an LLM registry stores its provider code. Empty
	// for custom servers added by raw URL.
	Code      string            `json:"code,omitempty"`
	Source    MCPSource         `json:"source,omitempty"`
	URL       string            `json:"url,omitempty"`
	Transport MCPTransport      `json:"transport,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Auth      *MCPAuth          `json:"auth,omitempty"`
	OpenAPI   *OpenAPITarget    `json:"openapi,omitempty"`
	// Store is the MCP Store governance for this server: whether users may
	// self-install it, whether that needs approval, and which roles may. It rides
	// in the mcp_target JSONB, so it needs no schema change and is read wherever
	// the registry is loaded. Nil means "not offered in the Store".
	Store *MCPStoreConfig `json:"store,omitempty"`
	// URLVariables declares the per-user placeholders in URL (e.g. {account_url},
	// {instance}) that each principal fills at install time. It is copied verbatim
	// from the catalog entry when a registry is materialised, so the dial path is
	// self-contained: it knows which placeholders to substitute, which are
	// required, and which are secret (vault) vs plain (installation config) —
	// without re-reading the catalog. Empty for servers whose URL is fully
	// determined (the common case). See ResolveURL.
	URLVariables []MCPURLVariable `json:"url_variables,omitempty"`
}

// MCPURLVariable declares one per-user placeholder in an MCPTarget URL template.
// It is the registry-side mirror of the catalog's url_variable: the shared
// registry carries the declaration, each principal's installation carries the
// value (a plain value in installation.Config, or a secret in the vault).
type MCPURLVariable struct {
	// Name is the placeholder token: {Name} in the URL template.
	Name string `json:"name"`
	// Description is human help shown when collecting the value.
	Description string `json:"description,omitempty"`
	// Required fails the install if the principal does not supply the value.
	Required bool `json:"required,omitempty"`
	// Secret routes the value to the vault instead of installation config, and
	// keeps it out of the model context (collected via the connect link, never as
	// a chat argument).
	Secret bool `json:"secret,omitempty"`
	// In is where the placeholder sits: "" (a host or path segment, validated to a
	// structure-safe charset) or "query" (a query-string value, percent-escaped).
	In string `json:"in,omitempty"`
}

// URLVariableIn values.
const (
	URLVariableInQuery = "query"
)

// HasURLVariables reports whether this target's URL carries per-user
// placeholders that must be resolved from a principal's install before dialing.
func (t *MCPTarget) HasURLVariables() bool {
	return t != nil && len(t.URLVariables) > 0
}

// RequiredURLVariables returns the names of the placeholders a principal must
// supply. SecretURLVariables returns those that route to the vault.
func (t *MCPTarget) RequiredURLVariables() []string {
	if t == nil {
		return nil
	}
	var out []string
	for _, v := range t.URLVariables {
		if v.Required {
			out = append(out, v.Name)
		}
	}
	return out
}

// MCPStoreConfig is the admin's Store access grant for one MCP server, edited
// from the Access side panel. Groups and Users are the two subject axes matched
// against the caller's token: Groups against the token's group claim, Users
// against the token subject.
type MCPStoreConfig struct {
	// Available exposes the server for self-service install in the Store.
	Available bool `json:"available,omitempty"`
	// RequiresApproval routes an install through an approver instead of granting
	// it immediately.
	RequiresApproval bool `json:"requires_approval,omitempty"`
	// Groups, when non-empty, restricts self-install to principals carrying one of
	// these IdP/NeuralTrust groups (matched against the token's group claim).
	Groups []string `json:"groups,omitempty"`
	// Users, when non-empty, additionally admits these individual principals
	// (matched against the token subject). A caller is allowed if their groups
	// intersect Groups OR their subject is in Users. Both empty means "any".
	Users []string `json:"users,omitempty"`
}

// UnmarshalJSON reads MCPStoreConfig, accepting the legacy "roles" key as an
// alias for "groups" so registries stored (in the DB or the config-sync
// snapshot) before the rename keep working. "groups" wins when both are present.
func (c *MCPStoreConfig) UnmarshalJSON(data []byte) error {
	type alias MCPStoreConfig
	aux := struct {
		*alias
		LegacyRoles []string `json:"roles,omitempty"`
	}{alias: (*alias)(c)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if len(c.Groups) == 0 && len(aux.LegacyRoles) > 0 {
		c.Groups = aux.LegacyRoles
	}
	return nil
}

// StoreAvailable reports whether the server is offered for self-install.
func (t *MCPTarget) StoreAvailable() bool {
	return t != nil && t.Store != nil && t.Store.Available
}

// StoreRequiresApproval reports whether self-install needs approval.
func (t *MCPTarget) StoreRequiresApproval() bool {
	return t != nil && t.Store != nil && t.Store.RequiresApproval
}

// StoreGroups returns the groups allowed to self-install, or nil for "any".
func (t *MCPTarget) StoreGroups() []string {
	if t == nil || t.Store == nil {
		return nil
	}
	return t.Store.Groups
}

// StoreUsers returns the individual principal subjects allowed to self-install,
// or nil for "any".
func (t *MCPTarget) StoreUsers() []string {
	if t == nil || t.Store == nil {
		return nil
	}
	return t.Store.Users
}

func (t *MCPTarget) Normalize() {
	if t == nil {
		return
	}
	if t.Source == "" {
		t.Source = MCPSourceRemote
	}
	if t.Source == MCPSourceRemote && t.Transport == "" {
		t.Transport = MCPTransportStreamableHTTP
	}
	if t.Auth == nil {
		t.Auth = &MCPAuth{Mode: MCPAuthModeNone}
	}
}

// targetURLValid reports whether the target URL is a valid http(s) URL, treating
// declared URL-variable placeholders as already filled. A template such as
// https://{instance}.service-now.com/mcp is legitimate even though "{" is not a
// legal host character until a principal's value replaces it at dial time, so the
// placeholders are substituted with a benign sentinel before the check. Servers
// with no URL variables are validated verbatim, unchanged from before.
func (t *MCPTarget) targetURLValid() bool {
	u := t.URL
	if len(t.URLVariables) > 0 {
		u = urlTemplateToken.ReplaceAllString(u, "x")
	}
	return isHTTPURL(u)
}

func (t *MCPTarget) Validate() error {
	if t == nil {
		return fmt.Errorf("%w: mcp_target is required", ErrInvalidMCPTarget)
	}
	source := t.Source
	if source == "" {
		source = MCPSourceRemote
	}
	switch source {
	case MCPSourceRemote:
		if strings.TrimSpace(t.URL) == "" {
			return fmt.Errorf("%w: url is required", ErrInvalidMCPTarget)
		}
		if !t.targetURLValid() {
			return fmt.Errorf("%w: url must be a valid http(s) URL", ErrInvalidMCPTarget)
		}
		if t.Transport != "" && t.Transport != MCPTransportStreamableHTTP {
			return fmt.Errorf("%w: unsupported transport %q", ErrInvalidMCPTarget, t.Transport)
		}
		if t.OpenAPI != nil {
			return fmt.Errorf("%w: openapi is only valid for openapi sources", ErrInvalidMCPTarget)
		}
	case MCPSourceOpenAPI:
		if t.OpenAPI == nil || !isHTTPURL(t.OpenAPI.SpecURL) {
			return fmt.Errorf("%w: openapi.spec_url must be a valid http(s) URL", ErrInvalidMCPTarget)
		}
		if t.URL != "" && !t.targetURLValid() {
			return fmt.Errorf("%w: url must be a valid http(s) URL", ErrInvalidMCPTarget)
		}
		if t.Transport != "" {
			return fmt.Errorf("%w: transport is not valid for openapi sources", ErrInvalidMCPTarget)
		}
	default:
		return fmt.Errorf("%w: unsupported source %q", ErrInvalidMCPTarget, t.Source)
	}
	if t.Auth != nil {
		if err := t.Auth.Validate(); err != nil {
			return err
		}
		if source == MCPSourceOpenAPI &&
			t.Auth.Mode != "" &&
			t.Auth.Mode != MCPAuthModeNone &&
			t.Auth.Mode != MCPAuthModeStatic &&
			t.Auth.Mode != MCPAuthModeClientCredentials {
			return fmt.Errorf("%w: auth mode %q is not supported for openapi sources", ErrInvalidMCPTarget, t.Auth.Mode)
		}
	}
	return nil
}

func (a *MCPAuth) Validate() error {
	switch a.Mode {
	case MCPAuthModeNone, "":
		if a.Header != "" || a.Value != "" {
			return fmt.Errorf("%w: auth mode none does not accept header/value", ErrInvalidMCPTarget)
		}
	case MCPAuthModeStatic:
		if strings.TrimSpace(a.Header) == "" || strings.TrimSpace(a.Value) == "" {
			return fmt.Errorf("%w: auth mode static requires header and value", ErrInvalidMCPTarget)
		}
		if secret.IsMasked(a.Value) {
			return fmt.Errorf("%w: secret cannot be a masked value; omit the field to keep the stored value",
				ErrInvalidMCPTarget)
		}
	case MCPAuthModePassthrough:
		if strings.TrimSpace(a.ExpectedAudience) == "" {
			return fmt.Errorf("%w: passthrough requires expected_audience (unconstrained passthrough is forbidden)",
				ErrInvalidMCPTarget)
		}
	case MCPAuthModeExchange:
		switch a.Pattern {
		case ExchangeImpersonation:
			if strings.TrimSpace(a.Audience) == "" {
				return fmt.Errorf("%w: exchange/impersonation requires audience", ErrInvalidMCPTarget)
			}
		case ExchangeDelegation:
			if strings.TrimSpace(a.Audience) == "" || strings.TrimSpace(a.Actor) == "" {
				return fmt.Errorf("%w: exchange/delegation requires audience and actor", ErrInvalidMCPTarget)
			}
		case ExchangeOBO:
			if strings.TrimSpace(a.Scope) == "" {
				return fmt.Errorf("%w: exchange/obo requires scope (e.g. resource/.default)", ErrInvalidMCPTarget)
			}
		case ExchangeTokenExchange:
			if strings.TrimSpace(a.Audience) == "" {
				return fmt.Errorf("%w: exchange/token_exchange requires audience", ErrInvalidMCPTarget)
			}
		default:
			return fmt.Errorf("%w: exchange requires pattern (impersonation|delegation|obo|token_exchange)",
				ErrInvalidMCPTarget)
		}
	case MCPAuthModeForwarded:
		if strings.TrimSpace(a.Provider) == "" {
			return fmt.Errorf("%w: forwarded requires provider", ErrInvalidMCPTarget)
		}
		switch a.Registration {
		case RegistrationAuto:
			if a.ClientID != "" || a.ClientSecret != "" {
				return fmt.Errorf("%w: registration auto does not accept client_id/client_secret", ErrInvalidMCPTarget)
			}
		case RegistrationManual, "":
			if strings.TrimSpace(a.ClientID) == "" || strings.TrimSpace(a.AuthorizeURL) == "" || strings.TrimSpace(a.TokenURL) == "" {
				return fmt.Errorf("%w: forwarded with manual registration requires client_id, authorize_url and token_url (or set registration: auto)",
					ErrInvalidMCPTarget)
			}
			if !isHTTPURL(a.AuthorizeURL) || !isHTTPURL(a.TokenURL) {
				return fmt.Errorf("%w: authorize_url and token_url must be valid http(s) URLs", ErrInvalidMCPTarget)
			}
			if secret.IsMasked(a.ClientSecret) {
				return fmt.Errorf("%w: secret cannot be a masked value; omit the field to keep the stored value",
					ErrInvalidMCPTarget)
			}
		default:
			return fmt.Errorf("%w: unknown registration mode %q", ErrInvalidMCPTarget, a.Registration)
		}
	case MCPAuthModeClientCredentials:
		if strings.TrimSpace(a.ClientID) == "" || strings.TrimSpace(a.ClientSecret) == "" {
			return fmt.Errorf("%w: client_credentials requires client_id and client_secret", ErrInvalidMCPTarget)
		}
		if strings.TrimSpace(a.TokenURL) == "" || !isHTTPURL(a.TokenURL) {
			return fmt.Errorf("%w: client_credentials requires a valid http(s) token_url", ErrInvalidMCPTarget)
		}
		if secret.IsMasked(a.ClientSecret) {
			return fmt.Errorf("%w: secret cannot be a masked value; omit the field to keep the stored value",
				ErrInvalidMCPTarget)
		}
		switch a.TokenEndpointAuthMethod {
		case "", TokenEndpointAuthClientSecretBasic, TokenEndpointAuthClientSecretPost:
		default:
			return fmt.Errorf("%w: unknown token_endpoint_auth_method %q", ErrInvalidMCPTarget, a.TokenEndpointAuthMethod)
		}
	default:
		return fmt.Errorf("%w: unknown auth mode %q", ErrInvalidMCPTarget, a.Mode)
	}
	return nil
}

func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func (t *MCPTarget) ResolveSecretsFrom(prev *MCPTarget) {
	if t == nil || prev == nil || t.Auth == nil || prev.Auth == nil {
		return
	}
	if t.Auth.Mode != prev.Auth.Mode {
		return
	}
	switch t.Auth.Mode {
	case MCPAuthModeStatic:
		t.Auth.Value = secret.Resolve(t.Auth.Value, prev.Auth.Value)
	case MCPAuthModeForwarded, MCPAuthModeClientCredentials:
		t.Auth.ClientSecret = secret.Resolve(t.Auth.ClientSecret, prev.Auth.ClientSecret)
	}
}
