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

package response

import (
	"encoding/json"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// A2ATargetResponse is an A2A registry's target with its secrets masked.
// Endpoint is the URL the gateway calls, derived from the locator or the card.
type A2ATargetResponse struct {
	Provider          string                   `json:"provider"`
	CardURL           string                   `json:"card_url,omitempty"`
	ResolvedCardURL   string                   `json:"resolved_card_url,omitempty"`
	ProtocolVersion   string                   `json:"protocol_version"`
	URL               string                   `json:"url,omitempty"`
	Endpoint          string                   `json:"endpoint"`
	BedrockAgentCore  *domain.AgentCoreLocator `json:"bedrock_agentcore,omitempty"`
	AzureFoundry      *domain.FoundryLocator   `json:"azure_foundry,omitempty"`
	VertexAgentEngine *domain.VertexLocator    `json:"vertex_agent_engine,omitempty"`
	AgentCoreHarness  *domain.HarnessLocator    `json:"agentcore_harness,omitempty"`
	Databricks        *domain.DatabricksLocator `json:"databricks_agent,omitempty"`
	Headers           map[string]string        `json:"headers,omitempty"`
	Auth              *MCPAuthResponse         `json:"auth,omitempty"`
	CloudAuth         *A2ACloudAuthResponse    `json:"cloud_auth,omitempty"`
	CardAuth          string                   `json:"card_auth,omitempty"`
	AllowedMethods    []string                 `json:"allowed_methods"`
	Card              json.RawMessage          `json:"card,omitempty" swaggertype:"object"`
	CardDigest        string                   `json:"card_digest,omitempty"`
	CardPinnedAt      time.Time                `json:"card_pinned_at,omitzero"`
}

func fromA2ATarget(t *domain.A2ATarget) *A2ATargetResponse {
	if t == nil {
		return nil
	}
	methods := t.AllowedMethods
	if methods == nil {
		methods = []string{}
	}
	return &A2ATargetResponse{
		Provider:          string(t.Provider),
		CardURL:           t.CardURL,
		ResolvedCardURL:   t.ResolvedCardURL,
		ProtocolVersion:   string(t.ProtocolVersion),
		URL:               t.URL,
		Endpoint:          t.Endpoint(),
		BedrockAgentCore:  t.BedrockAgentCore,
		AzureFoundry:      t.AzureFoundry,
		VertexAgentEngine: t.VertexAgentEngine,
		AgentCoreHarness:  t.AgentCoreHarness,
		Databricks:        t.Databricks,
		Headers:           maskHeaders(t.Headers),
		Auth:              fromMCPAuth(t.Auth),
		CloudAuth:         fromA2ACloudAuth(t.CloudAuth),
		CardAuth:          string(t.CardAuth),
		AllowedMethods:    methods,
		Card:              t.Card,
		CardDigest:        t.CardDigest,
		CardPinnedAt:      t.CardPinnedAt,
	}
}
