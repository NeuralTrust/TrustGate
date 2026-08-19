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

type MCPProtocolMode string

const (
	MCPProtocolModeAuto   MCPProtocolMode = "auto"
	MCPProtocolModeModern MCPProtocolMode = "modern"
	MCPProtocolModeLegacy MCPProtocolMode = "legacy"
)

func (m MCPProtocolMode) Validate() error {
	switch m {
	case "", MCPProtocolModeAuto, MCPProtocolModeModern, MCPProtocolModeLegacy:
		return nil
	default:
		return fmt.Errorf("%w: unsupported protocol_mode %q", ErrInvalidMCPTarget, m)
	}
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
	Code         string            `json:"code,omitempty"`
	URL          string            `json:"url"`
	Transport    MCPTransport      `json:"transport,omitempty"`
	ProtocolMode MCPProtocolMode   `json:"protocol_mode,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Auth         *MCPAuth          `json:"auth,omitempty"`
}

func (t *MCPTarget) Normalize() {
	if t == nil {
		return
	}
	if t.Transport == "" {
		t.Transport = MCPTransportStreamableHTTP
	}
	if t.ProtocolMode == "" {
		t.ProtocolMode = MCPProtocolModeAuto
	}
	if t.Auth == nil {
		t.Auth = &MCPAuth{Mode: MCPAuthModeNone}
	}
}

func (t *MCPTarget) UnmarshalJSON(data []byte) error {
	type targetAlias MCPTarget
	var decoded targetAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	target := MCPTarget(decoded)
	target.Normalize()
	if err := target.Validate(); err != nil {
		return err
	}
	*t = target
	return nil
}

func (t *MCPTarget) Validate() error {
	if t == nil {
		return fmt.Errorf("%w: mcp_target is required", ErrInvalidMCPTarget)
	}
	t.Normalize()
	if strings.TrimSpace(t.URL) == "" {
		return fmt.Errorf("%w: url is required", ErrInvalidMCPTarget)
	}
	u, err := url.Parse(t.URL)
	if err != nil {
		return fmt.Errorf("%w: url must be a valid http(s) URL", ErrInvalidMCPTarget)
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Host == "" {
		return fmt.Errorf("%w: url must be a valid http(s) URL", ErrInvalidMCPTarget)
	}
	if t.Transport != "" && t.Transport != MCPTransportStreamableHTTP {
		return fmt.Errorf("%w: unsupported transport %q", ErrInvalidMCPTarget, t.Transport)
	}
	if err := t.ProtocolMode.Validate(); err != nil {
		return err
	}
	if t.Auth != nil {
		if err := t.Auth.Validate(); err != nil {
			return err
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
