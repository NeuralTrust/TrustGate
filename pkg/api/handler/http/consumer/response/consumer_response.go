package response

import (
	"time"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/google/uuid"
)

type ConsumerResponse struct {
	ID              uuid.UUID                `json:"id"`
	GatewayID       uuid.UUID                `json:"gateway_id"`
	Name            string                   `json:"name"`
	Type            string                   `json:"type"`
	Path            string                   `json:"path"`
	Algorithm       string                   `json:"algorithm"`
	EmbeddingConfig *EmbeddingConfigResponse `json:"embedding_config,omitempty"`
	Headers         map[string]string        `json:"headers,omitempty"`
	Active          bool                     `json:"active"`
	BackendIDs      []uuid.UUID              `json:"backend_ids"`
	PolicyIDs       []uuid.UUID              `json:"policy_ids"`
	AuthIDs         []uuid.UUID              `json:"auth_ids"`
	Fallback        *FallbackResponse        `json:"fallback,omitempty"`
	CreatedAt       time.Time                `json:"created_at"`
	UpdatedAt       time.Time                `json:"updated_at"`
}

type EmbeddingConfigResponse struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

type FallbackResponse struct {
	Enabled  bool                   `json:"enabled"`
	Triggers []string               `json:"triggers,omitempty"`
	Budget   FallbackBudgetResponse `json:"budget"`
	Chain    []uuid.UUID            `json:"chain"`
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
	backendIDs := c.BackendIDs
	if backendIDs == nil {
		backendIDs = []uuid.UUID{}
	}
	policyIDs := c.PolicyIDs
	if policyIDs == nil {
		policyIDs = []uuid.UUID{}
	}
	authIDs := c.AuthIDs
	if authIDs == nil {
		authIDs = []uuid.UUID{}
	}
	var embedding *EmbeddingConfigResponse
	if c.EmbeddingConfig != nil {
		embedding = &EmbeddingConfigResponse{
			Provider: c.EmbeddingConfig.Provider,
			Model:    c.EmbeddingConfig.Model,
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
		BackendIDs:      backendIDs,
		PolicyIDs:       policyIDs,
		AuthIDs:         authIDs,
		Fallback:        fromFallback(c.Fallback),
		CreatedAt:       c.CreatedAt,
		UpdatedAt:       c.UpdatedAt,
	}
}

func fromFallback(f *domain.Fallback) *FallbackResponse {
	if f == nil {
		return nil
	}
	triggers := make([]string, 0, len(f.Triggers))
	for _, t := range f.Triggers {
		triggers = append(triggers, string(t))
	}
	chain := f.Chain
	if chain == nil {
		chain = []uuid.UUID{}
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
