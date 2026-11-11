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
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const agentCoreARNValue = "arn:aws:bedrock-agentcore:eu-west-1:123456789012:runtime/travel-abc"

func pinnedGeneric(t *testing.T) *A2ATarget {
	t.Helper()
	target := &A2ATarget{CardURL: "https://travel.example.com"}
	target.Normalize()
	require.NoError(t, target.Pin("https://travel.example.com/.well-known/agent-card.json", []byte(card10), time.Now()))
	return target
}

func validate(target *A2ATarget) error {
	target.Normalize()
	return target.Validate()
}

func TestNewA2ARegistryMinimal(t *testing.T) {
	t.Parallel()
	b, err := NewA2ARegistry(ids.New[ids.GatewayKind](), "Travel planner", "", pinnedGeneric(t))
	require.NoError(t, err)
	assert.Equal(t, TypeA2A, b.Type)
	assert.Equal(t, A2AVersion10, b.A2ATarget.ProtocolVersion)
	assert.Equal(t, MCPAuthModeNone, b.A2ATarget.Auth.Mode)
	assert.Equal(t, A2AProviderGeneric, b.A2ATarget.Provider)
	assert.Equal(t, "https://travel.example.com/a2a", b.A2ATarget.Endpoint())
	assert.NotEmpty(t, b.A2ATarget.CardDigest)
	assert.False(t, b.A2ATarget.CardPinnedAt.IsZero())
}

func TestRegistryRefusesForeignTargets(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	a2a := &Registry{Name: "a", GatewayID: gw, Type: TypeA2A, A2ATarget: pinnedGeneric(t), MCPTarget: validMCPTarget()}
	assert.ErrorIs(t, a2a.Validate(), ErrInvalidRegistry)

	mcp := &Registry{Name: "m", GatewayID: gw, Type: TypeMCP, MCPTarget: validMCPTarget(), A2ATarget: pinnedGeneric(t)}
	assert.ErrorIs(t, mcp.Validate(), ErrInvalidRegistry)

	missing := &Registry{Name: "a", GatewayID: gw, Type: TypeA2A}
	assert.ErrorIs(t, missing.Validate(), ErrInvalidRegistry)
}

func TestA2ATargetValidateRefuses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		target A2ATarget
		want   string
	}{
		{"reserved header", A2ATarget{CardURL: "https://a.example.com", Headers: map[string]string{"Authorization": "Bearer x"}}, `"Authorization"`},
		{"gateway header", A2ATarget{CardURL: "https://a.example.com", Headers: map[string]string{"x-ag-trace-id": "1"}}, `"x-ag-trace-id"`},
		{"a2a-version header", A2ATarget{CardURL: "https://a.example.com", Headers: map[string]string{"a2a-version": "1.0"}}, "reserved"},
		{"passthrough", A2ATarget{CardURL: "https://a.example.com", Auth: &MCPAuth{Mode: MCPAuthModePassthrough, ExpectedAudience: "x"}}, "never reaches an agent"},
		{"forwarded", A2ATarget{CardURL: "https://a.example.com", Auth: &MCPAuth{Mode: MCPAuthModeForwarded, Provider: "x"}}, "never reaches an agent"},
		{"impersonation", A2ATarget{CardURL: "https://a.example.com", Auth: &MCPAuth{Mode: MCPAuthModeExchange, Pattern: ExchangeImpersonation, Audience: "a"}}, "which application acts"},
		{"cloud on generic", A2ATarget{CardURL: "https://a.example.com", Auth: &MCPAuth{Mode: A2AAuthModeCloud}}, "only valid for agents hosted"},
		{"no card url", A2ATarget{}, "card_url"},
		{"http url override", A2ATarget{CardURL: "https://a.example.com", URL: "http://a.example.com/rpc"}, "https"},
		{"bad version", A2ATarget{CardURL: "https://a.example.com", ProtocolVersion: "0.2"}, "protocol_version"},
		{"method of other version", A2ATarget{CardURL: "https://a.example.com", ProtocolVersion: A2AVersion10, AllowedMethods: []string{"message/send"}}, "allowed_methods"},
		{"same without credential", A2ATarget{CardURL: "https://a.example.com", CardAuth: A2ACardAuthSame}, "static or client_credentials"},
		{"same over http", A2ATarget{CardURL: "http://a.example.com", CardAuth: A2ACardAuthSame, Auth: &MCPAuth{Mode: MCPAuthModeStatic, Header: "X-Key", Value: "k"}}, "https"},
		{"obo without scope", A2ATarget{CardURL: "https://a.example.com", Auth: &MCPAuth{Mode: MCPAuthModeExchange, Pattern: ExchangeOBO}}, "scope"},
		{"agentcore with card_url", A2ATarget{Provider: A2AProviderBedrockAgentCore, CardURL: "https://a.example.com",
			BedrockAgentCore: &AgentCoreLocator{RuntimeARN: agentCoreARNValue}}, "runtime_arn"},
		{"foundry with card_url", A2ATarget{Provider: A2AProviderAzureFoundry, CardURL: "https://a.example.com",
			AzureFoundry: &FoundryLocator{ProjectEndpoint: "https://acct.services.ai.azure.com/api/projects/p", AgentName: "travel"}}, "project_endpoint, agent_name"},
		{"foundry foreign host", A2ATarget{Provider: A2AProviderAzureFoundry,
			AzureFoundry: &FoundryLocator{ProjectEndpoint: "https://evil.example.com/api/projects/x", AgentName: "travel"}}, "services.ai.azure.com"},
		{"agentcore arn of another service", A2ATarget{Provider: A2AProviderBedrockAgentCore,
			BedrockAgentCore: &AgentCoreLocator{RuntimeARN: "arn:aws:bedrock:eu-west-1:123456789012:agent/x"}}, "runtime_arn"},
		{"foundry static", A2ATarget{Provider: A2AProviderAzureFoundry, Auth: &MCPAuth{Mode: MCPAuthModeStatic, Header: "X", Value: "v"},
			AzureFoundry: &FoundryLocator{ProjectEndpoint: "https://acct.services.ai.azure.com/api/projects/p", AgentName: "travel"}}, "only Microsoft Entra ID"},
		{"foundry without cloud_auth", A2ATarget{Provider: A2AProviderAzureFoundry, Auth: &MCPAuth{Mode: A2AAuthModeCloud},
			AzureFoundry: &FoundryLocator{ProjectEndpoint: "https://acct.services.ai.azure.com/api/projects/p", AgentName: "travel"}}, "even to read its card"},
		{"foundry obo without card_auth", A2ATarget{Provider: A2AProviderAzureFoundry, Auth: &MCPAuth{Mode: MCPAuthModeExchange, Pattern: ExchangeOBO},
			AzureFoundry: &FoundryLocator{ProjectEndpoint: "https://acct.services.ai.azure.com/api/projects/p", AgentName: "travel"}}, "card_auth cloud"},
		{"agentcore delegation", A2ATarget{Provider: A2AProviderBedrockAgentCore, Auth: &MCPAuth{Mode: MCPAuthModeExchange, Pattern: ExchangeDelegation},
			BedrockAgentCore: &AgentCoreLocator{RuntimeARN: agentCoreARNValue}}, "signed by TrustGate"},
		{"agentcore obo without card_auth", A2ATarget{Provider: A2AProviderBedrockAgentCore, Auth: &MCPAuth{Mode: MCPAuthModeExchange, Pattern: ExchangeOBO, Scope: "s"},
			BedrockAgentCore: &AgentCoreLocator{RuntimeARN: agentCoreARNValue}}, "card_auth client_credentials"},
		{"agentcore with azure", A2ATarget{Provider: A2AProviderBedrockAgentCore, Auth: &MCPAuth{Mode: A2AAuthModeCloud},
			CloudAuth:        &A2ACloudAuth{Azure: &AzureAuth{UseManagedIdentity: true}},
			BedrockAgentCore: &AgentCoreLocator{RuntimeARN: agentCoreARNValue}}, "cloud_auth.aws"},
		{"vertex client credentials", A2ATarget{Provider: A2AProviderVertexAgentEngine,
			Auth:              &MCPAuth{Mode: MCPAuthModeClientCredentials, ClientID: "c", ClientSecret: "s", TokenURL: "https://idp.example.com/token"},
			VertexAgentEngine: &VertexLocator{Project: "my-project", Location: "us-central1", ReasoningEngineID: "123"}}, "Google tokens"},
		{"vertex 1.0", A2ATarget{Provider: A2AProviderVertexAgentEngine, ProtocolVersion: A2AVersion10, Auth: &MCPAuth{Mode: A2AAuthModeCloud},
			CloudAuth:         &A2ACloudAuth{GCP: &A2AGCPAuth{}},
			VertexAgentEngine: &VertexLocator{Project: "my-project", Location: "us-central1", ReasoningEngineID: "123"}}, "0.3"},
		{"azure api key", A2ATarget{Provider: A2AProviderAzureFoundry, Auth: &MCPAuth{Mode: A2AAuthModeCloud},
			CloudAuth:    &A2ACloudAuth{Azure: &AzureAuth{APIKey: "k"}},
			AzureFoundry: &FoundryLocator{ProjectEndpoint: "https://acct.services.ai.azure.com/api/projects/p", AgentName: "travel"}}, "not an api key"},
		{"masked cloud secret", A2ATarget{Provider: A2AProviderBedrockAgentCore, Auth: &MCPAuth{Mode: A2AAuthModeCloud},
			CloudAuth:        &A2ACloudAuth{AWS: &A2AAWSAuth{AWSAuth: AWSAuth{AccessKeyID: "AKIA", SecretAccessKey: secret.Mask("secretvalue")}}},
			BedrockAgentCore: &AgentCoreLocator{RuntimeARN: agentCoreARNValue}}, "masked"},
		{"cloud_auth without cloud mode", A2ATarget{CardURL: "https://a.example.com", CloudAuth: &A2ACloudAuth{GCP: &A2AGCPAuth{}}}, "cloud_auth is only valid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			target := tt.target
			err := validate(&target)
			require.Error(t, err)
			assert.ErrorContains(t, err, tt.want)
		})
	}
}

func TestA2ATargetValidateAccepts(t *testing.T) {
	t.Parallel()
	foundry := &FoundryLocator{ProjectEndpoint: "https://acct.services.ai.azure.com/api/projects/p", AgentName: "travel"}
	tests := []struct {
		name   string
		target A2ATarget
	}{
		{"delegation without audience", A2ATarget{CardURL: "https://a.example.com", Auth: &MCPAuth{Mode: MCPAuthModeExchange, Pattern: ExchangeDelegation}}},
		{"token exchange", A2ATarget{CardURL: "https://a.example.com", Auth: &MCPAuth{Mode: MCPAuthModeExchange, Pattern: ExchangeTokenExchange}}},
		{"same with static", A2ATarget{CardURL: "https://a.example.com", CardAuth: A2ACardAuthSame, Auth: &MCPAuth{Mode: MCPAuthModeStatic, Header: "X-Key", Value: "k"}}},
		{"agentcore pod role", A2ATarget{Provider: A2AProviderBedrockAgentCore, Auth: &MCPAuth{Mode: A2AAuthModeCloud},
			CloudAuth: &A2ACloudAuth{AWS: &A2AAWSAuth{}}, BedrockAgentCore: &AgentCoreLocator{RuntimeARN: agentCoreARNValue}}},
		{"agentcore obo with client credentials", A2ATarget{Provider: A2AProviderBedrockAgentCore, CardAuth: A2ACardAuthClientCredentials,
			Auth:             &MCPAuth{Mode: MCPAuthModeExchange, Pattern: ExchangeOBO, Scope: "api://x/.default", ClientID: "c", ClientSecret: "s", TokenURL: "https://idp.example.com/token"},
			BedrockAgentCore: &AgentCoreLocator{RuntimeARN: agentCoreARNValue}}},
		{"foundry service principal", A2ATarget{Provider: A2AProviderAzureFoundry, Auth: &MCPAuth{Mode: A2AAuthModeCloud},
			CloudAuth: &A2ACloudAuth{Azure: &AzureAuth{TenantID: "t", ClientID: "c", ClientSecret: "s"}}, AzureFoundry: foundry}},
		{"foundry obo with card cloud", A2ATarget{Provider: A2AProviderAzureFoundry, CardAuth: A2ACardAuthCloud,
			Auth:      &MCPAuth{Mode: MCPAuthModeExchange, Pattern: ExchangeOBO},
			CloudAuth: &A2ACloudAuth{Azure: &AzureAuth{UseManagedIdentity: true}}, AzureFoundry: foundry}},
		{"vertex impersonation", A2ATarget{Provider: A2AProviderVertexAgentEngine, Auth: &MCPAuth{Mode: A2AAuthModeCloud},
			CloudAuth:         &A2ACloudAuth{GCP: &A2AGCPAuth{ImpersonateServiceAccount: "agent@my-project.iam.gserviceaccount.com"}},
			VertexAgentEngine: &VertexLocator{Project: "my-project", Location: "us-central1", ReasoningEngineID: "123"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			target := tt.target
			require.NoError(t, validate(&target))
		})
	}
}

func TestA2ATargetNormalizeDropsActorAndFillsDefaults(t *testing.T) {
	t.Parallel()
	target := &A2ATarget{
		Provider:         A2AProviderBedrockAgentCore,
		BedrockAgentCore: &AgentCoreLocator{RuntimeARN: agentCoreARNValue},
		Auth:             &MCPAuth{Mode: A2AAuthModeCloud, Actor: "someone"},
	}
	target.Normalize()
	assert.Empty(t, target.Auth.Actor)
	assert.Equal(t, "DEFAULT", target.BedrockAgentCore.Qualifier)

	foundry := &A2ATarget{Provider: A2AProviderAzureFoundry, Auth: &MCPAuth{Mode: MCPAuthModeExchange, Pattern: ExchangeOBO}}
	foundry.Normalize()
	assert.Equal(t, "https://ai.azure.com/.default", foundry.Auth.Scope)
}

func TestA2ATargetDerivedURLs(t *testing.T) {
	t.Parallel()
	agentcore := &A2ATarget{Provider: A2AProviderBedrockAgentCore, BedrockAgentCore: &AgentCoreLocator{RuntimeARN: agentCoreARNValue}}
	agentcore.Normalize()
	assert.Equal(t, "https://bedrock-agentcore.eu-west-1.amazonaws.com/runtimes/arn%3Aaws%3Abedrock-agentcore%3Aeu-west-1%3A123456789012%3Aruntime%2Ftravel-abc/invocations/.well-known/agent-card.json?qualifier=DEFAULT",
		agentcore.CardLocation())
	assert.Equal(t, "https://bedrock-agentcore.eu-west-1.amazonaws.com/runtimes/arn%3Aaws%3Abedrock-agentcore%3Aeu-west-1%3A123456789012%3Aruntime%2Ftravel-abc/invocations/?qualifier=DEFAULT",
		agentcore.Endpoint())
	assert.Equal(t, "eu-west-1", agentcore.BedrockAgentCore.Region())

	foundry := &A2ATarget{Provider: A2AProviderAzureFoundry, AzureFoundry: &FoundryLocator{ProjectEndpoint: "https://acct.services.ai.azure.com/api/projects/p/", AgentName: "travel"}}
	assert.Equal(t, "https://acct.services.ai.azure.com/api/projects/p/agents/travel/endpoint/protocols/a2a/agentCard/v1.0", foundry.CardLocation())
	foundry.ProtocolVersion = A2AVersion03
	assert.Equal(t, "https://acct.services.ai.azure.com/api/projects/p/agents/travel/endpoint/protocols/a2a/agentCard/v0.3", foundry.CardLocation())
	assert.Equal(t, "https://acct.services.ai.azure.com/api/projects/p/agents/travel/endpoint/protocols/a2a", foundry.Endpoint())

	vertex := &A2ATarget{Provider: A2AProviderVertexAgentEngine, VertexAgentEngine: &VertexLocator{Project: "my-project", Location: "us-central1", ReasoningEngineID: "123"}}
	base := "https://us-central1-aiplatform.googleapis.com/v1beta1/projects/my-project/locations/us-central1/reasoningEngines/123/a2a"
	assert.Equal(t, base+"/v1/card", vertex.CardLocation())
	assert.Equal(t, base, vertex.Endpoint())
}

func TestA2ATargetPin(t *testing.T) {
	t.Parallel()
	now := time.Now()

	both := &A2ATarget{CardURL: "https://travel.example.com", ProtocolVersion: A2AVersion03}
	require.NoError(t, both.Pin("https://travel.example.com/card.json", []byte(cardBoth), now))
	assert.Equal(t, A2AVersion03, both.ProtocolVersion)
	assert.Equal(t, "https://travel.example.com/rpc", both.Endpoint())

	only03 := &A2ATarget{CardURL: "https://travel.example.com", ProtocolVersion: A2AVersion10}
	err := only03.Pin("https://travel.example.com/card.json", []byte(card03), now)
	require.ErrorIs(t, err, ErrAgentVersionUnsupported)
	assert.ErrorContains(t, err, `["0.3"]`)
	assert.Empty(t, only03.CardDigest)

	grpc := &A2ATarget{CardURL: "https://travel.example.com"}
	assert.ErrorContains(t, grpc.Pin("https://travel.example.com/card.json", []byte(cardGRPC), now), "[]")

	foundry := &A2ATarget{Provider: A2AProviderAzureFoundry, AzureFoundry: &FoundryLocator{ProjectEndpoint: "https://acct.services.ai.azure.com/api/projects/p", AgentName: "travel"}}
	require.NoError(t, foundry.Pin("https://x", []byte(`{"name":"f"}`), now))
	assert.Equal(t, A2AVersion10, foundry.ProtocolVersion)

	otherHost := &A2ATarget{CardURL: "https://cards.example.com", CardAuth: A2ACardAuthSame, URL: "https://agent.example.com/rpc"}
	assert.ErrorContains(t, otherHost.Pin("https://cards.example.com/card.json", []byte(card10), now), "own host")
}

func TestValidateSharedDataPlane(t *testing.T) {
	t.Parallel()
	role := &A2ATarget{CloudAuth: &A2ACloudAuth{AWS: &A2AAWSAuth{AWSAuth: AWSAuth{UseRole: true, Role: "arn:aws:iam::123456789012:role/tg"}}}}
	err := role.ValidateSharedDataPlane()
	require.ErrorIs(t, err, ErrInvalidRegistry)
	assert.ErrorContains(t, err, "external_id")

	role.CloudAuth.AWS.ExternalID = "nt-7f3a"
	assert.NoError(t, role.ValidateSharedDataPlane())
	assert.NoError(t, (&A2ATarget{CloudAuth: &A2ACloudAuth{AWS: &A2AAWSAuth{}}}).ValidateSharedDataPlane())
}

func TestA2ATargetResolveSecretsFrom(t *testing.T) {
	t.Parallel()
	prev := &A2ATarget{
		Headers:   map[string]string{"X-Tenant": "acme-secret"},
		Auth:      &MCPAuth{Mode: MCPAuthModeStatic, Header: "X-Key", Value: "stored-key"},
		CloudAuth: &A2ACloudAuth{GCP: &A2AGCPAuth{ServiceAccountJSON: `{"type":"service_account"}`}},
	}
	next := &A2ATarget{
		Headers:   map[string]string{"X-Tenant": secret.Mask("acme-secret")},
		Auth:      &MCPAuth{Mode: MCPAuthModeStatic, Header: "X-Key", Value: secret.Mask("stored-key")},
		CloudAuth: &A2ACloudAuth{GCP: &A2AGCPAuth{ServiceAccountJSON: secret.Mask(`{"type":"service_account"}`)}},
	}
	next.ResolveSecretsFrom(prev)
	assert.Equal(t, "acme-secret", next.Headers["X-Tenant"])
	assert.Equal(t, "stored-key", next.Auth.Value)
	assert.Equal(t, `{"type":"service_account"}`, next.CloudAuth.GCP.ServiceAccountJSON)

	changed := &A2ATarget{Auth: &MCPAuth{Mode: MCPAuthModeClientCredentials}}
	changed.ResolveSecretsFrom(prev)
	assert.Empty(t, changed.Auth.ClientSecret)
}
