package response

import (
	"sort"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/common/secret"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

type ConsumerResponse struct {
	ID              ids.ConsumerID           `json:"id"`
	GatewayID       ids.GatewayID            `json:"gateway_id"`
	Name            string                   `json:"name"`
	Type            string                   `json:"type"`
	Path            string                   `json:"path"`
	Algorithm       string                   `json:"algorithm"`
	EmbeddingConfig *EmbeddingConfigResponse `json:"embedding_config,omitempty"`
	Headers         map[string]string        `json:"headers,omitempty"`
	Active          bool                     `json:"active"`
	RegistryIDs     []ids.RegistryID         `json:"registry_ids"`
	AuthIDs         []ids.AuthID             `json:"auth_ids"`
	Fallback        *FallbackResponse        `json:"fallback,omitempty"`
	ModelPolicies   []ModelPolicyResponse    `json:"model_policies,omitempty"`
	CreatedAt       time.Time                `json:"created_at"`
	UpdatedAt       time.Time                `json:"updated_at"`
}

type ModelPolicyResponse struct {
	RegistryID ids.RegistryID `json:"registry_id"`
	Allowed    []string       `json:"allowed,omitempty"`
	Default    string         `json:"default,omitempty"`
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
	MaxAttempts       int     `json:"max_attempts"`
	MaxTotalLatencyMs int64   `json:"max_total_latency_ms,omitempty"`
	MaxCostUSD        float64 `json:"max_cost_usd,omitempty"`
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
	var embedding *EmbeddingConfigResponse
	if c.EmbeddingConfig != nil {
		embedding = &EmbeddingConfigResponse{
			Provider: c.EmbeddingConfig.Provider,
			Model:    c.EmbeddingConfig.Model,
			Auth:     fromEmbeddingAuth(c.EmbeddingConfig.Auth),
		}
	}
	return ConsumerResponse{
		ID:              c.ID,
		GatewayID:       c.GatewayID,
		Name:            c.Name,
		Type:            string(c.Type),
		Path:            c.Path,
		Algorithm:       c.Algorithm,
		EmbeddingConfig: embedding,
		Headers:         c.Headers,
		Active:          c.Active,
		RegistryIDs:     registryIDs,
		AuthIDs:         authIDs,
		Fallback:        fromFallback(c.Fallback),
		ModelPolicies:   fromModelPolicies(c.ModelPolicies),
		CreatedAt:       c.CreatedAt,
		UpdatedAt:       c.UpdatedAt,
	}
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
			MaxCostUSD:        f.Budget.MaxCostUSD,
		},
		Chain: chain,
	}
}
