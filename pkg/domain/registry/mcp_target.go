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
)

// MCPAuth is the downstream credential configuration for an MCP target.
type MCPAuth struct {
	Mode   MCPAuthMode `json:"mode"`
	Header string      `json:"header,omitempty"`
	Value  string      `json:"value,omitempty"` // #nosec G117 -- upstream credential
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
	default:
		return fmt.Errorf("%w: unknown auth mode %q", ErrInvalidMCPTarget, a.Mode)
	}
	return nil
}

// ResolveSecretsFrom keeps the previously stored static credential when the
// incoming update omits it (empty or the redaction placeholder). It only
// merges when the auth mode is unchanged.
func (t *MCPTarget) ResolveSecretsFrom(prev *MCPTarget) {
	if t == nil || prev == nil || t.Auth == nil || prev.Auth == nil {
		return
	}
	if t.Auth.Mode != prev.Auth.Mode {
		return
	}
	if t.Auth.Mode == MCPAuthModeStatic {
		t.Auth.Value = secret.Resolve(t.Auth.Value, prev.Auth.Value)
	}
}
