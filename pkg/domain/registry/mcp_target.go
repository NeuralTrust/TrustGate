package registry

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/NeuralTrust/AgentGateway/pkg/common/secret"
)

type Type string

const (
	TypeLLM Type = "LLM"
	TypeMCP Type = "MCP"
)

type MCPTransport string

const MCPTransportStreamableHTTP MCPTransport = "streamable-http"

type MCPAuthMode string

const (
	MCPAuthModeNone        MCPAuthMode = "none"
	MCPAuthModeStatic      MCPAuthMode = "static"
	MCPAuthModePassthrough MCPAuthMode = "passthrough"
	MCPAuthModeExchange    MCPAuthMode = "exchange"
	MCPAuthModeForwarded   MCPAuthMode = "forwarded"
)

type MCPClientRegistration string

const (
	RegistrationManual MCPClientRegistration = "manual"
	RegistrationAuto   MCPClientRegistration = "auto"
)

type MCPExchangePattern string

const (
	ExchangeImpersonation   MCPExchangePattern = "impersonation"
	ExchangeDelegation      MCPExchangePattern = "delegation"
	ExchangeOBO             MCPExchangePattern = "obo"
	ExchangeTokenExchange   MCPExchangePattern = "token_exchange"
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
}

type MCPTarget struct {
	URL       string            `json:"url"`
	Transport MCPTransport      `json:"transport,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Auth      *MCPAuth          `json:"auth,omitempty"`
}

func (t *MCPTarget) Normalize() {
	if t == nil {
		return
	}
	if t.Transport == "" {
		t.Transport = MCPTransportStreamableHTTP
	}
	if t.Auth == nil {
		t.Auth = &MCPAuth{Mode: MCPAuthModeNone}
	}
}

func (t *MCPTarget) Validate() error {
	if t == nil {
		return fmt.Errorf("%w: mcp_target is required", ErrInvalidMCPTarget)
	}
	if strings.TrimSpace(t.URL) == "" {
		return fmt.Errorf("%w: url is required", ErrInvalidMCPTarget)
	}
	u, err := url.Parse(t.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%w: url must be a valid http(s) URL", ErrInvalidMCPTarget)
	}
	if t.Transport != "" && t.Transport != MCPTransportStreamableHTTP {
		return fmt.Errorf("%w: unsupported transport %q", ErrInvalidMCPTarget, t.Transport)
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
		if strings.TrimSpace(a.Header) == "" || a.Value == "" {
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
	case MCPAuthModeForwarded:
		t.Auth.ClientSecret = secret.Resolve(t.Auth.ClientSecret, prev.Auth.ClientSecret)
	}
}
