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
	b, err := NewMCPRegistry(gwID, "github-mcp", "GitHub MCP server", 0, validMCPTarget())
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
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewMCPRegistry(gwID, "x", "", 0, tc.mutate(validMCPTarget()))
			if !errors.Is(err, commonerrors.ErrValidation) {
				t.Fatalf("error = %v, want validation error", err)
			}
		})
	}
}

func TestRegistry_Validate_TypeCrossChecks(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()

	t.Run("LLM rejects mcp_target", func(t *testing.T) {
		t.Parallel()
		b, _ := NewRegistry(gwID, "openai-1", "openai", nil, "", 1, NewAPIKeyAuth("sk-1"), nil)
		b.MCPTarget = validMCPTarget()
		if err := b.Validate(); !errors.Is(err, commonerrors.ErrValidation) {
			t.Fatalf("error = %v, want validation error", err)
		}
	})

	t.Run("MCP rejects provider", func(t *testing.T) {
		t.Parallel()
		b, _ := NewMCPRegistry(gwID, "mcp-1", "", 0, validMCPTarget())
		b.Provider = "openai"
		if err := b.Validate(); !errors.Is(err, commonerrors.ErrValidation) {
			t.Fatalf("error = %v, want validation error", err)
		}
	})

	t.Run("MCP rejects target auth", func(t *testing.T) {
		t.Parallel()
		b, _ := NewMCPRegistry(gwID, "mcp-1", "", 0, validMCPTarget())
		b.Auth = NewAPIKeyAuth("sk-1")
		if err := b.Validate(); !errors.Is(err, commonerrors.ErrValidation) {
			t.Fatalf("error = %v, want validation error", err)
		}
	})

	t.Run("empty type defaults to LLM", func(t *testing.T) {
		t.Parallel()
		b, _ := NewRegistry(gwID, "openai-1", "openai", nil, "", 1, NewAPIKeyAuth("sk-1"), nil)
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
