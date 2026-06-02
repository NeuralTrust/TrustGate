package request

import (
	"fmt"
	"strings"
	"time"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	backenddomain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/google/uuid"
)

type CreateConsumerRequest struct {
	Name            string                  `json:"name"`
	Type            string                  `json:"type,omitempty"`
	Path            string                  `json:"path"`
	Algorithm       string                  `json:"algorithm,omitempty"`
	EmbeddingConfig *EmbeddingConfigRequest `json:"embedding_config,omitempty"`
	Headers         map[string]string       `json:"headers,omitempty"`
	Active          *bool                   `json:"active,omitempty"`
	BackendIDs      []string                `json:"backend_ids"`
	PolicyIDs       []string                `json:"policy_ids,omitempty"`
	AuthIDs         []string                `json:"auth_ids,omitempty"`
	Fallback        *FallbackRequest        `json:"fallback,omitempty"`
	ModelPolicies   []ModelPolicyRequest    `json:"model_policies,omitempty"`
}

type ModelPolicyRequest struct {
	BackendID string   `json:"backend_id"`
	Allowed   []string `json:"allowed,omitempty"`
	Default   string   `json:"default,omitempty"`
}

type FallbackRequest struct {
	Enabled  bool                   `json:"enabled"`
	Triggers []string               `json:"triggers,omitempty"`
	Budget   *FallbackBudgetRequest `json:"budget,omitempty"`
	Chain    []string               `json:"chain,omitempty"`
}

type FallbackBudgetRequest struct {
	MaxAttempts       int     `json:"max_attempts,omitempty"`
	MaxTotalLatencyMs int     `json:"max_total_latency_ms,omitempty"`
	MaxCostUSD        float64 `json:"max_cost_usd,omitempty"`
}

func (r *FallbackRequest) ToFallback() (*domain.Fallback, error) {
	if r == nil {
		return nil, nil
	}
	chain, err := parseUUIDList(r.Chain, "fallback.chain")
	if err != nil {
		return nil, err
	}
	triggers := make([]domain.FallbackTrigger, 0, len(r.Triggers))
	for _, t := range r.Triggers {
		triggers = append(triggers, domain.FallbackTrigger(t))
	}
	budget := domain.FallbackBudget{}
	if r.Budget != nil {
		budget.MaxAttempts = r.Budget.MaxAttempts
		budget.MaxTotalLatency = time.Duration(r.Budget.MaxTotalLatencyMs) * time.Millisecond
		budget.MaxCostUSD = r.Budget.MaxCostUSD
	}
	return &domain.Fallback{
		Enabled:  r.Enabled,
		Triggers: triggers,
		Budget:   budget,
		Chain:    chain,
	}, nil
}

type EmbeddingConfigRequest struct {
	Provider string             `json:"provider"`
	Model    string             `json:"model"`
	Auth     *APIKeyAuthRequest `json:"auth,omitempty"`
}

type APIKeyAuthRequest struct {
	APIKey        string `json:"api_key,omitempty"` // #nosec G117
	HeaderName    string `json:"header_name,omitempty"`
	HeaderValue   string `json:"header_value,omitempty"`
	ParamName     string `json:"param_name,omitempty"`
	ParamValue    string `json:"param_value,omitempty"`
	ParamLocation string `json:"param_location,omitempty"`
}

func (e *EmbeddingConfigRequest) ToDomain() *backenddomain.EmbeddingConfig {
	if e == nil {
		return nil
	}
	out := &backenddomain.EmbeddingConfig{
		Provider: e.Provider,
		Model:    e.Model,
	}
	if e.Auth != nil {
		out.Auth = &backenddomain.APIKeyAuth{
			APIKey:        e.Auth.APIKey,
			HeaderName:    e.Auth.HeaderName,
			HeaderValue:   e.Auth.HeaderValue,
			ParamName:     e.Auth.ParamName,
			ParamValue:    e.Auth.ParamValue,
			ParamLocation: e.Auth.ParamLocation,
		}
	}
	return out
}

func (r CreateConsumerRequest) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
	}
	if len(r.Name) > 255 {
		return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
	}
	if strings.TrimSpace(r.Path) == "" {
		return fmt.Errorf("path is required: %w", commonerrors.ErrValidation)
	}
	if len(r.BackendIDs) == 0 {
		return fmt.Errorf("at least one backend_id is required: %w", commonerrors.ErrValidation)
	}
	return nil
}

func (r CreateConsumerRequest) ToType() domain.Type {
	return domain.Type(r.Type)
}

func (r CreateConsumerRequest) ToEmbeddingConfig() *backenddomain.EmbeddingConfig {
	return r.EmbeddingConfig.ToDomain()
}

func (r CreateConsumerRequest) ToBackendIDs() ([]uuid.UUID, error) {
	return parseUUIDList(r.BackendIDs, "backend_ids")
}

func (r CreateConsumerRequest) ToPolicyIDs() ([]uuid.UUID, error) {
	return parseUUIDList(r.PolicyIDs, "policy_ids")
}

func (r CreateConsumerRequest) ToAuthIDs() ([]uuid.UUID, error) {
	return parseUUIDList(r.AuthIDs, "auth_ids")
}

func (r CreateConsumerRequest) ToFallback() (*domain.Fallback, error) {
	return r.Fallback.ToFallback()
}

func (r CreateConsumerRequest) ToModelPolicies() (domain.ModelPolicies, error) {
	return parseModelPolicies(r.ModelPolicies)
}

func parseModelPolicies(raw []ModelPolicyRequest) (domain.ModelPolicies, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make(domain.ModelPolicies, len(raw))
	for i, mp := range raw {
		id, err := uuid.Parse(mp.BackendID)
		if err != nil {
			return nil, fmt.Errorf("model_policies[%d]: invalid backend_id %q: %w", i, mp.BackendID, commonerrors.ErrValidation)
		}
		if _, dup := out[id]; dup {
			return nil, fmt.Errorf("model_policies[%d]: duplicate backend_id %q: %w", i, mp.BackendID, commonerrors.ErrValidation)
		}
		out[id] = domain.ModelPolicy{Allowed: mp.Allowed, Default: mp.Default}
	}
	return out, nil
}

func parseUUIDList(raw []string, field string) ([]uuid.UUID, error) {
	out := make([]uuid.UUID, 0, len(raw))
	for i, s := range raw {
		id, err := uuid.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: invalid uuid %q: %w", field, i, s, commonerrors.ErrValidation)
		}
		out = append(out, id)
	}
	return out, nil
}
