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
	"sort"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type ConsumerResponse struct {
	ID              ids.ConsumerID           `json:"id"`
	GatewayID       ids.GatewayID            `json:"gateway_id"`
	Name            string                   `json:"name"`
	Type            string                   `json:"type"`
	Slug            string                   `json:"slug"`
	RoutingMode     string                   `json:"routing_mode"`
	LBConfig        *LBConfigResponse        `json:"lb_config,omitempty"`
	Headers         map[string]string        `json:"headers,omitempty"`
	Active          bool                     `json:"active"`
	RegistryIDs     []ids.RegistryID         `json:"registry_ids"`
	RegistryWeights []RegistryWeightResponse `json:"registry_weights,omitempty"`
	RoleIDs         []ids.RoleID             `json:"role_ids"`
	AuthIDs         []ids.AuthID             `json:"auth_ids"`
	Fallback        *FallbackResponse        `json:"fallback,omitempty"`
	ModelPolicies   []ModelPolicyResponse    `json:"model_policies,omitempty"`
	Toolkit         []ToolkitEntryResponse   `json:"toolkit,omitempty"`
	FailMode        string                   `json:"fail_mode,omitempty"`
	CreatedAt       time.Time                `json:"created_at"`
	UpdatedAt       time.Time                `json:"updated_at"`
}

type RegistryWeightResponse struct {
	RegistryID ids.RegistryID `json:"registry_id"`
	Weight     int            `json:"weight"`
}

type ToolkitEntryResponse struct {
	RegistryID ids.RegistryID `json:"registry_id"`
	Tool       string         `json:"tool,omitempty"`
	Prompt     string         `json:"prompt,omitempty"`
	Resource   string         `json:"resource,omitempty"`
	ExposeAs   string         `json:"expose_as,omitempty"`
}

type ModelPolicyResponse struct {
	RegistryID ids.RegistryID `json:"registry_id"`
	Allowed    []string       `json:"allowed,omitempty"`
	Default    string         `json:"default,omitempty"`
}

type LBConfigResponse struct {
	Enabled         bool                     `json:"enabled"`
	Algorithm       string                   `json:"algorithm,omitempty"`
	PoolAlias       string                   `json:"pool_alias,omitempty"`
	Members         []LBPoolMemberResponse   `json:"members,omitempty"`
	EmbeddingConfig *EmbeddingConfigResponse `json:"embedding_config,omitempty"`
}

type LBPoolMemberResponse struct {
	RegistryID ids.RegistryID `json:"registry_id"`
	Models     []string       `json:"models,omitempty"`
}

type EmbeddingConfigResponse struct {
	Provider string                 `json:"provider"`
	Model    string                 `json:"model"`
	Auth     *EmbeddingAuthResponse `json:"auth,omitempty"`
}

type EmbeddingAuthResponse struct {
	APIKey        string `json:"api_key,omitempty"` // #nosec G117
	HeaderName    string `json:"header_name,omitempty"`
	HeaderValue   string `json:"header_value,omitempty"`
	ParamName     string `json:"param_name,omitempty"`
	ParamValue    string `json:"param_value,omitempty"`
	ParamLocation string `json:"param_location,omitempty"`
}

type FallbackResponse struct {
	Enabled  bool                   `json:"enabled"`
	Triggers []string               `json:"triggers,omitempty"`
	Budget   FallbackBudgetResponse `json:"budget"`
	Chain    []ids.RegistryID       `json:"chain"`
}

type FallbackBudgetResponse struct {
	MaxAttempts       int   `json:"max_attempts"`
	MaxTotalLatencyMs int64 `json:"max_total_latency_ms,omitempty"`
}

func FromConsumer(c *domain.Consumer) ConsumerResponse {
	if c == nil {
		return ConsumerResponse{}
	}
	registryIDs := []ids.RegistryID(c.RegistryIDs)
	if registryIDs == nil {
		registryIDs = []ids.RegistryID{}
	}
	authIDs := c.AuthIDs
	if authIDs == nil {
		authIDs = []ids.AuthID{}
	}
	roleIDs := c.RoleIDs
	if roleIDs == nil {
		roleIDs = []ids.RoleID{}
	}
	return ConsumerResponse{
		ID:              c.ID,
		GatewayID:       c.GatewayID,
		Name:            c.Name,
		Type:            string(c.Type),
		Slug:            c.Slug,
		RoutingMode:     string(c.RoutingMode),
		LBConfig:        fromLBConfig(c.LBConfig),
		Headers:         c.Headers,
		Active:          c.Active,
		RegistryIDs:     registryIDs,
		RegistryWeights: fromRegistryWeights(c.RegistryWeights),
		RoleIDs:         roleIDs,
		AuthIDs:         authIDs,
		Fallback:        fromFallback(c.Fallback),
		ModelPolicies:   fromModelPolicies(c.ModelPolicies),
		Toolkit:         fromToolkit(c.Toolkit()),
		FailMode:        string(c.FailMode()),
		CreatedAt:       c.CreatedAt,
		UpdatedAt:       c.UpdatedAt,
	}
}

func fromRegistryWeights(weights map[ids.RegistryID]int) []RegistryWeightResponse {
	if len(weights) == 0 {
		return nil
	}
	out := make([]RegistryWeightResponse, 0, len(weights))
	for registryID, weight := range weights {
		out = append(out, RegistryWeightResponse{RegistryID: registryID, Weight: weight})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RegistryID.String() < out[j].RegistryID.String()
	})
	return out
}

func fromLBConfig(config *domain.LBConfig) *LBConfigResponse {
	if config == nil {
		return nil
	}
	members := make([]LBPoolMemberResponse, 0, len(config.Members))
	for _, member := range config.Members {
		members = append(members, LBPoolMemberResponse{
			RegistryID: member.RegistryID,
			Models:     member.Models,
		})
	}
	var embedding *EmbeddingConfigResponse
	if config.EmbeddingConfig != nil {
		embedding = &EmbeddingConfigResponse{
			Provider: config.EmbeddingConfig.Provider,
			Model:    config.EmbeddingConfig.Model,
			Auth:     fromEmbeddingAuth(config.EmbeddingConfig.Auth),
		}
	}
	return &LBConfigResponse{
		Enabled:         config.Enabled,
		Algorithm:       config.Algorithm,
		PoolAlias:       config.PoolAlias,
		Members:         members,
		EmbeddingConfig: embedding,
	}
}

func fromToolkit(t domain.Toolkit) []ToolkitEntryResponse {
	if len(t) == 0 {
		return nil
	}
	out := make([]ToolkitEntryResponse, 0, len(t))
	for _, e := range t {
		out = append(out, ToolkitEntryResponse{
			RegistryID: e.RegistryID,
			Tool:       e.Tool,
			Prompt:     e.Prompt,
			Resource:   e.Resource,
			ExposeAs:   e.ExposeAs,
		})
	}
	return out
}

func fromEmbeddingAuth(a *registrydomain.APIKeyAuth) *EmbeddingAuthResponse {
	if a == nil {
		return nil
	}
	return &EmbeddingAuthResponse{
		APIKey:        secret.Mask(a.APIKey),
		HeaderName:    a.HeaderName,
		HeaderValue:   secret.Mask(a.HeaderValue),
		ParamName:     a.ParamName,
		ParamValue:    secret.Mask(a.ParamValue),
		ParamLocation: a.ParamLocation,
	}
}

func fromModelPolicies(m domain.ModelPolicies) []ModelPolicyResponse {
	if len(m) == 0 {
		return nil
	}
	out := make([]ModelPolicyResponse, 0, len(m))
	for backendID, policy := range m {
		out = append(out, ModelPolicyResponse{
			RegistryID: backendID,
			Allowed:    policy.Allowed,
			Default:    policy.Default,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RegistryID.String() < out[j].RegistryID.String()
	})
	return out
}

func fromFallback(f *domain.Fallback) *FallbackResponse {
	if f == nil {
		return nil
	}
	triggers := make([]string, 0, len(f.Triggers))
	for _, t := range f.Triggers {
		triggers = append(triggers, string(t))
	}
	chain := []ids.RegistryID(f.Chain)
	if chain == nil {
		chain = []ids.RegistryID{}
	}
	return &FallbackResponse{
		Enabled:  f.Enabled,
		Triggers: triggers,
		Budget: FallbackBudgetResponse{
			MaxAttempts:       f.Budget.MaxAttempts,
			MaxTotalLatencyMs: f.Budget.MaxTotalLatency.Milliseconds(),
		},
		Chain: chain,
	}
}
