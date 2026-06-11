package registry

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/NeuralTrust/AgentGateway/pkg/common/secret"
)

// Type discriminates what kind of upstream a Registry fronts.
type Type string

const (
	TypeLLM Type = "LLM"
	TypeMCP Type = "MCP"
)

// MCPTransport is the wire protocol used to reach an upstream MCP server.
type MCPTransport string

// MCPTransportStreamableHTTP is the only supported transport in v1 (remote
// Streamable HTTP; stdio upstreams are out of scope).
const MCPTransportStreamableHTTP MCPTransport = "streamable-http"

// MCPAuthMode selects how the gateway authenticates to the upstream MCP server.
type MCPAuthMode string

const (
	// MCPAuthModeNone connects with no Authorization header (public upstream).
	MCPAuthModeNone MCPAuthMode = "none"
	// MCPAuthModeStatic injects a fixed header/value pair (the gateway's own
	// shared credential for that upstream).
	MCPAuthModeStatic MCPAuthMode = "static"
	// MCPAuthModePassthrough re-injects the principal's inbound JWT.
	// Guardrail: only allowed when expected_audience matches the inbound aud
	// (unconstrained passthrough is the MCP confused-deputy anti-pattern).
	MCPAuthModePassthrough MCPAuthMode = "passthrough"
	// MCPAuthModeExchange obtains a downstream token from the STS (mint or
	// external IdP exchange) per the configured pattern.
	MCPAuthModeExchange MCPAuthMode = "exchange"
	// MCPAuthModeForwarded injects a vaulted third-party token obtained
	// through one-time user consent (OAuth broker).
	MCPAuthModeForwarded MCPAuthMode = "forwarded"
)

// MCPClientRegistration selects how the gateway identifies itself to the
// third-party OAuth provider in forwarded mode.
type MCPClientRegistration string

const (
	// RegistrationManual uses an admin pre-registered OAuth app
	// (client_id/client_secret + explicit endpoints).
	RegistrationManual MCPClientRegistration = "manual"
	// RegistrationAuto discovers the upstream's authorization server via its
	// MCP protected-resource metadata (RFC 9728/8414) and registers the
	// gateway as a client via Dynamic Client Registration (RFC 7591).
	// No per-provider OAuth app or secret needs to be configured.
	RegistrationAuto MCPClientRegistration = "auto"
)

// MCPExchangePattern selects the STS exchange flavour for mode=exchange.
type MCPExchangePattern string

const (
	// ExchangeImpersonation mints a TrustGate-signed JWT, same sub, aud=target.
	ExchangeImpersonation MCPExchangePattern = "impersonation"
	// ExchangeDelegation mints a TrustGate-signed JWT with sub=user + act=agent.
	ExchangeDelegation MCPExchangePattern = "delegation"
	// ExchangeOBO delegates to the IdP: Microsoft Entra On-Behalf-Of.
	ExchangeOBO MCPExchangePattern = "obo"
	// ExchangeTokenExchange is generic RFC 8693 token exchange (Okta et al).
	ExchangeTokenExchange MCPExchangePattern = "token_exchange"
)

// MCPAuth is the downstream credential configuration for an MCP target.
type MCPAuth struct {
	Mode   MCPAuthMode `json:"mode"`
	Header string      `json:"header,omitempty"`
	Value  string      `json:"value,omitempty"` // #nosec G117 -- upstream credential

	// ExpectedAudience gates passthrough: the inbound token aud must match.
	ExpectedAudience string `json:"expected_audience,omitempty"`

	// Exchange settings (mode=exchange).
	Pattern  MCPExchangePattern `json:"pattern,omitempty"`
	Audience string             `json:"audience,omitempty"` // target aud / RFC 8693 audience
	Scope    string             `json:"scope,omitempty"`    // e.g. Entra "resource/.default"
	Actor    string             `json:"actor,omitempty"`    // act claim for delegation

	// Forwarded settings (mode=forwarded). With registration=auto only
	// provider is required: endpoints come from the upstream's MCP
	// protected-resource discovery and the client from DCR. With manual
	// registration the admin supplies the pre-registered OAuth app.
	Provider     string                `json:"provider,omitempty"` // "github", "linear", ...
	Registration MCPClientRegistration `json:"registration,omitempty"`
	ClientID     string                `json:"client_id,omitempty"`
	ClientSecret string                `json:"client_secret,omitempty"`
	AuthorizeURL string                `json:"authorize_url,omitempty"`
	TokenURL     string                `json:"token_url,omitempty"`
	Scopes       []string              `json:"scopes,omitempty"`
	// Resource is the RFC 8707 resource indicator sent on authorize/token
	// requests (auto mode defaults it to the upstream MCP URL).
	Resource string `json:"resource,omitempty"`
}

// MCPTarget describes how to reach one upstream MCP server.
type MCPTarget struct {
	URL       string            `json:"url"`
	Transport MCPTransport      `json:"transport,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Auth      *MCPAuth          `json:"auth,omitempty"`
}

// Normalize fills defaults: transport and auth mode.
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
			// Endpoints and client come from upstream discovery + DCR; a
			// pre-registered client must not be mixed in.
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

// ResolveSecretsFrom keeps the previously stored credentials when the
// incoming update omits them (empty or the redaction placeholder). It only
// merges when the auth mode is unchanged.
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
