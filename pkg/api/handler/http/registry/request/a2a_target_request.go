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

package request

import (
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// A2ATargetRequest is the agent an A2A registry points at. The pinned card
// fields are read-only and never taken from a request.
type A2ATargetRequest struct {
	Provider          string                   `json:"provider,omitempty" enums:"generic,bedrock_agentcore,azure_foundry,vertex_agent_engine"`
	CardURL           string                   `json:"card_url,omitempty"`
	ProtocolVersion   string                   `json:"protocol_version,omitempty" enums:"0.3,1.0"`
	URL               string                   `json:"url,omitempty"`
	BedrockAgentCore  *domain.AgentCoreLocator `json:"bedrock_agentcore,omitempty"`
	AzureFoundry      *domain.FoundryLocator   `json:"azure_foundry,omitempty"`
	VertexAgentEngine *domain.VertexLocator    `json:"vertex_agent_engine,omitempty"`
	Headers           map[string]string        `json:"headers,omitempty"`
	Auth              *MCPAuthRequest          `json:"auth,omitempty"`
	CloudAuth         *A2ACloudAuthRequest     `json:"cloud_auth,omitempty"`
	CardAuth          string                   `json:"card_auth,omitempty" enums:"same,client_credentials,cloud"`
	AllowedMethods    []string                 `json:"allowed_methods,omitempty"`
}

// A2ACloudAuthRequest is the cloud credential of a hosted agent; set the one
// its provider accepts.
type A2ACloudAuthRequest struct {
	AWS   *A2AAWSAuthRequest `json:"aws,omitempty"`
	Azure *AzureAuthRequest  `json:"azure,omitempty"`
	GCP   *A2AGCPAuthRequest `json:"gcp,omitempty"`
}

// A2AAWSAuthRequest is AWSAuthRequest plus the external id of an assumed role.
type A2AAWSAuthRequest struct {
	AWSAuthRequest
	ExternalID string `json:"external_id,omitempty"`
}

// A2AGCPAuthRequest takes a service-account key or a service account to
// impersonate; with neither the pod's Application Default Credentials apply.
type A2AGCPAuthRequest struct {
	ServiceAccountJSON        GCPServiceAccountJSON `json:"service_account_json,omitempty" swaggertype:"string"`
	ImpersonateServiceAccount string                `json:"impersonate_service_account,omitempty"`
}

func (t *A2ATargetRequest) ToDomain() *domain.A2ATarget {
	if t == nil {
		return nil
	}
	return &domain.A2ATarget{
		Provider:          domain.A2AProvider(t.Provider),
		CardURL:           t.CardURL,
		ProtocolVersion:   domain.A2AProtocolVersion(t.ProtocolVersion),
		URL:               t.URL,
		BedrockAgentCore:  t.BedrockAgentCore,
		AzureFoundry:      t.AzureFoundry,
		VertexAgentEngine: t.VertexAgentEngine,
		Headers:           t.Headers,
		Auth:              t.Auth.ToDomain(),
		CloudAuth:         t.CloudAuth.toDomain(),
		CardAuth:          domain.A2ACardAuth(t.CardAuth),
		AllowedMethods:    t.AllowedMethods,
	}
}

func (c *A2ACloudAuthRequest) toDomain() *domain.A2ACloudAuth {
	if c == nil {
		return nil
	}
	out := &domain.A2ACloudAuth{Azure: c.Azure.ToDomain()}
	if c.AWS != nil {
		out.AWS = &domain.A2AAWSAuth{AWSAuth: *c.AWS.ToDomain(), ExternalID: c.AWS.ExternalID}
	}
	if c.GCP != nil {
		out.GCP = &domain.A2AGCPAuth{
			ServiceAccountJSON:        string(c.GCP.ServiceAccountJSON),
			ImpersonateServiceAccount: c.GCP.ImpersonateServiceAccount,
		}
	}
	return out
}
