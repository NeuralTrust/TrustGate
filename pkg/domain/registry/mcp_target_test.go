package registry

import (
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

func validMCPTarget() *MCPTarget {
	return &MCPTarget{
		URL: "https://mcp.example.com/mcp",
		Auth: &MCPAuth{
			Mode:   MCPAuthModeStatic,
			Header: "Authorization",
			Value:  "Bearer tok",
		},
	}
}

func TestNewMCPRegistry_HappyPath(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	b, err := NewMCPRegistry(gwID, "github-mcp", "GitHub MCP server", validMCPTarget())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b.Type != TypeMCP {
		t.Fatalf("Type = %q, want MCP", b.Type)
	}
	if !b.IsMCP() {
		t.Fatal("IsMCP() = false, want true")
	}
	if b.MCPTarget.Transport != MCPTransportStreamableHTTP {
		t.Fatalf("Transport = %q, want default streamable-http", b.MCPTarget.Transport)
	}
}

func TestNewMCPRegistry_Rejects(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	tests := []struct {
		name   string
		mutate func(*MCPTarget) *MCPTarget
	}{
		{"nil target", func(*MCPTarget) *MCPTarget { return nil }},
		{"empty url", func(m *MCPTarget) *MCPTarget { m.URL = ""; return m }},
		{"non-http url", func(m *MCPTarget) *MCPTarget { m.URL = "ftp://x"; return m }},
		{"unsupported transport", func(m *MCPTarget) *MCPTarget { m.Transport = "stdio"; return m }},
		{"static without header", func(m *MCPTarget) *MCPTarget { m.Auth = &MCPAuth{Mode: MCPAuthModeStatic, Value: "v"}; return m }},
		{"static without value", func(m *MCPTarget) *MCPTarget { m.Auth = &MCPAuth{Mode: MCPAuthModeStatic, Header: "X"}; return m }},
		{"none with value", func(m *MCPTarget) *MCPTarget { m.Auth = &MCPAuth{Mode: MCPAuthModeNone, Value: "v"}; return m }},
		{"unknown mode", func(m *MCPTarget) *MCPTarget { m.Auth = &MCPAuth{Mode: "oauth"}; return m }},
		{"passthrough without expected_audience", func(m *MCPTarget) *MCPTarget {
			m.Auth = &MCPAuth{Mode: MCPAuthModePassthrough}
			return m
		}},
		{"exchange without pattern", func(m *MCPTarget) *MCPTarget {
			m.Auth = &MCPAuth{Mode: MCPAuthModeExchange}
			return m
		}},
		{"impersonation without audience", func(m *MCPTarget) *MCPTarget {
			m.Auth = &MCPAuth{Mode: MCPAuthModeExchange, Pattern: ExchangeImpersonation}
			return m
		}},
		{"delegation without actor", func(m *MCPTarget) *MCPTarget {
			m.Auth = &MCPAuth{Mode: MCPAuthModeExchange, Pattern: ExchangeDelegation, Audience: "aud"}
			return m
		}},
		{"obo without scope", func(m *MCPTarget) *MCPTarget {
			m.Auth = &MCPAuth{Mode: MCPAuthModeExchange, Pattern: ExchangeOBO}
			return m
		}},
		{"forwarded without provider", func(m *MCPTarget) *MCPTarget {
			m.Auth = &MCPAuth{Mode: MCPAuthModeForwarded, ClientID: "id", AuthorizeURL: "https://x/a", TokenURL: "https://x/t"}
			return m
		}},
		{"forwarded without client_id", func(m *MCPTarget) *MCPTarget {
			m.Auth = &MCPAuth{Mode: MCPAuthModeForwarded, Provider: "github", AuthorizeURL: "https://x/a", TokenURL: "https://x/t"}
			return m
		}},
		{"forwarded with bad token_url", func(m *MCPTarget) *MCPTarget {
			m.Auth = &MCPAuth{Mode: MCPAuthModeForwarded, Provider: "github", ClientID: "id", AuthorizeURL: "https://x/a", TokenURL: "not-a-url"}
			return m
		}},
		{"forwarded auto with pre-registered client", func(m *MCPTarget) *MCPTarget {
			m.Auth = &MCPAuth{Mode: MCPAuthModeForwarded, Provider: "linear", Registration: RegistrationAuto, ClientID: "id"}
			return m
		}},
		{"forwarded with unknown registration mode", func(m *MCPTarget) *MCPTarget {
			m.Auth = &MCPAuth{Mode: MCPAuthModeForwarded, Provider: "linear", Registration: "magic"}
			return m
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewMCPRegistry(gwID, "x", "", tc.mutate(validMCPTarget()))
			if !errors.Is(err, commonerrors.ErrValidation) {
				t.Fatalf("error = %v, want validation error", err)
			}
		})
	}
}

func TestMCPAuth_ForwardedAutoNeedsNoClient(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	target := validMCPTarget()
	target.Auth = &MCPAuth{Mode: MCPAuthModeForwarded, Provider: "linear", Registration: RegistrationAuto}
	if _, err := NewMCPRegistry(gwID, "linear-mcp", "", target); err != nil {
		t.Fatalf("auto registration without client_id should be valid, got %v", err)
	}
}

func TestRegistry_Validate_TypeCrossChecks(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()

	t.Run("LLM rejects mcp_target", func(t *testing.T) {
		t.Parallel()
		b, _ := NewLLMRegistry(gwID, "openai-1", "", &LLMTarget{Provider: "openai", Auth: NewAPIKeyAuth("sk-1")})
		b.MCPTarget = validMCPTarget()
		if err := b.Validate(); !errors.Is(err, commonerrors.ErrValidation) {
			t.Fatalf("error = %v, want validation error", err)
		}
	})

	t.Run("MCP rejects llm_target", func(t *testing.T) {
		t.Parallel()
		b, _ := NewMCPRegistry(gwID, "mcp-1", "", validMCPTarget())
		b.LLMTarget = &LLMTarget{Provider: "openai", Auth: NewAPIKeyAuth("sk-1")}
		if err := b.Validate(); !errors.Is(err, commonerrors.ErrValidation) {
			t.Fatalf("error = %v, want validation error", err)
		}
	})

	t.Run("empty type defaults to LLM", func(t *testing.T) {
		t.Parallel()
		b, _ := NewLLMRegistry(gwID, "openai-1", "", &LLMTarget{Provider: "openai", Auth: NewAPIKeyAuth("sk-1")})
		b.Type = ""
		if err := b.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if b.Type != TypeLLM {
			t.Fatalf("Type = %q, want LLM", b.Type)
		}
	})
}

func TestMCPTarget_ResolveSecretsFrom(t *testing.T) {
	t.Parallel()
	prev := validMCPTarget()
	next := validMCPTarget()
	next.Auth.Value = ""
	next.ResolveSecretsFrom(prev)
	if next.Auth.Value != "Bearer tok" {
		t.Fatalf("Value = %q, want previous secret kept", next.Auth.Value)
	}

	changedMode := validMCPTarget()
	changedMode.Auth = &MCPAuth{Mode: MCPAuthModeNone}
	changedMode.ResolveSecretsFrom(prev)
	if changedMode.Auth.Value != "" {
		t.Fatalf("Value = %q, want empty after mode change", changedMode.Auth.Value)
	}
}

func TestMCPAuth_Validate_NewModes(t *testing.T) {
	t.Parallel()
	valid := []*MCPAuth{
		{Mode: MCPAuthModePassthrough, ExpectedAudience: "api://upstream"},
		{Mode: MCPAuthModeExchange, Pattern: ExchangeImpersonation, Audience: "https://up.example.com"},
		{Mode: MCPAuthModeExchange, Pattern: ExchangeDelegation, Audience: "https://up.example.com", Actor: "agent-1"},
		{Mode: MCPAuthModeExchange, Pattern: ExchangeOBO, Scope: "api://target/.default"},
		{Mode: MCPAuthModeExchange, Pattern: ExchangeTokenExchange, Audience: "https://up.example.com"},
		{Mode: MCPAuthModeForwarded, Provider: "github", ClientID: "id",
			AuthorizeURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token"},
	}
	for _, a := range valid {
		if err := a.Validate(); err != nil {
			t.Fatalf("Validate(%s/%s) = %v, want nil", a.Mode, a.Pattern, err)
		}
	}
}

func TestMCPTarget_ResolveSecretsFrom_ForwardedClientSecret(t *testing.T) {
	t.Parallel()
	forwarded := func() *MCPTarget {
		return &MCPTarget{
			URL: "https://mcp.example.com/mcp",
			Auth: &MCPAuth{
				Mode: MCPAuthModeForwarded, Provider: "github", ClientID: "id", ClientSecret: "s3cret",
				AuthorizeURL: "https://x/a", TokenURL: "https://x/t",
			},
		}
	}
	prev := forwarded()
	next := forwarded()
	next.Auth.ClientSecret = ""
	next.ResolveSecretsFrom(prev)
	if next.Auth.ClientSecret != "s3cret" {
		t.Fatalf("ClientSecret = %q, want previous secret kept", next.Auth.ClientSecret)
	}
}
