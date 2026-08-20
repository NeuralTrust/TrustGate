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
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
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
	if b.MCPTarget.ProtocolMode != MCPProtocolModeAuto {
		t.Fatalf("ProtocolMode = %q, want auto", b.MCPTarget.ProtocolMode)
	}
}

func TestMCPTarget_ProtocolModeValidation(t *testing.T) {
	t.Parallel()
	for _, mode := range []MCPProtocolMode{MCPProtocolModeAuto, MCPProtocolModeModern, MCPProtocolModeLegacy} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			target := validMCPTarget()
			target.ProtocolMode = mode
			if err := target.Validate(); err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}

	target := validMCPTarget()
	target.ProtocolMode = "future"
	if err := target.Validate(); !errors.Is(err, ErrInvalidMCPTarget) {
		t.Fatalf("Validate() = %v, want ErrInvalidMCPTarget", err)
	}
}

func TestMCPTarget_AcceptsUppercaseHTTPS(t *testing.T) {
	t.Parallel()

	target := validMCPTarget()
	target.URL = "HTTPS://MCP.EXAMPLE.COM/mcp"
	if err := target.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestMCPTarget_JSONRoundTripDefaultsAndValidatesProtocolMode(t *testing.T) {
	t.Parallel()
	var old MCPTarget
	if err := json.Unmarshal([]byte(`{"url":"https://mcp.example.com/mcp"}`), &old); err != nil {
		t.Fatalf("Unmarshal old target: %v", err)
	}
	if old.ProtocolMode != MCPProtocolModeAuto {
		t.Fatalf("old ProtocolMode = %q, want auto", old.ProtocolMode)
	}

	want := validMCPTarget()
	want.ProtocolMode = MCPProtocolModeLegacy
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got MCPTarget
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.ProtocolMode != MCPProtocolModeLegacy {
		t.Fatalf("round-trip ProtocolMode = %q, want legacy", got.ProtocolMode)
	}

	if err := json.Unmarshal([]byte(`{"url":"https://mcp.example.com/mcp","protocol_mode":"future"}`), &got); !errors.Is(err, ErrInvalidMCPTarget) {
		t.Fatalf("invalid Unmarshal error = %v, want ErrInvalidMCPTarget", err)
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
		{"client_credentials without client_id", func(m *MCPTarget) *MCPTarget {
			m.Auth = &MCPAuth{Mode: MCPAuthModeClientCredentials, ClientSecret: "s", TokenURL: "https://idp/token"}
			return m
		}},
		{"client_credentials without token_url", func(m *MCPTarget) *MCPTarget {
			m.Auth = &MCPAuth{Mode: MCPAuthModeClientCredentials, ClientID: "id", ClientSecret: "s"}
			return m
		}},
		{"client_credentials with bad auth method", func(m *MCPTarget) *MCPTarget {
			m.Auth = &MCPAuth{
				Mode: MCPAuthModeClientCredentials, ClientID: "id", ClientSecret: "s",
				TokenURL: "https://idp/token", TokenEndpointAuthMethod: "private_key_jwt",
			}
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
		{Mode: MCPAuthModeClientCredentials, ClientID: "id", ClientSecret: "s",
			TokenURL: "https://auth.example.com/token", TokenEndpointAuthMethod: TokenEndpointAuthClientSecretBasic},
		{Mode: MCPAuthModeClientCredentials, ClientID: "id", ClientSecret: "s",
			TokenURL: "https://auth.example.com/token", TokenEndpointAuthMethod: TokenEndpointAuthClientSecretPost},
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

func TestMCPTarget_ResolveSecretsFrom_ClientCredentialsSecret(t *testing.T) {
	t.Parallel()
	prev := &MCPTarget{
		URL: "https://mcp.example.com/mcp",
		Auth: &MCPAuth{
			Mode: MCPAuthModeClientCredentials, ClientID: "id", ClientSecret: "s3cret",
			TokenURL: "https://idp/token",
		},
	}
	next := &MCPTarget{
		URL: "https://mcp.example.com/mcp",
		Auth: &MCPAuth{
			Mode: MCPAuthModeClientCredentials, ClientID: "id", ClientSecret: "",
			TokenURL: "https://idp/token",
		},
	}
	next.ResolveSecretsFrom(prev)
	if next.Auth.ClientSecret != "s3cret" {
		t.Fatalf("ClientSecret = %q, want previous secret kept", next.Auth.ClientSecret)
	}
}
