package forwarding_rule

import (
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/google/uuid"
)

type CreateParams struct {
	GatewayID     uuid.UUID
	ServiceID     uuid.UUID
	Name          string
	Path          string
	Paths         domain.PathsJSON
	Type          Type
	Methods       domain.MethodsJSON
	Headers       domain.HeadersJSON
	StripPath     bool
	PreserveHost  bool
	RetryAttempts int
	PluginChain   domain.PluginChainJSON
	TrustLens     *domain.TrustLensJSON
	SessionConfig *SessionConfig
}

func New(params CreateParams) (*ForwardingRule, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID: %w", err)
	}

	ruleType := params.Type
	if ruleType == "" {
		ruleType = EndpointRuleType
	}

	now := time.Now()
	return &ForwardingRule{
		ID:            id,
		GatewayID:     params.GatewayID,
		ServiceID:     params.ServiceID,
		Name:          params.Name,
		Path:          params.Path,
		Paths:         params.Paths,
		Type:          ruleType,
		Methods:       params.Methods,
		Headers:       params.Headers,
		StripPath:     params.StripPath,
		PreserveHost:  params.PreserveHost,
		RetryAttempts: params.RetryAttempts,
		PluginChain:   params.PluginChain,
		Active:        true,
		Public:        false,
		TrustLens:     params.TrustLens,
		SessionConfig: params.SessionConfig,
		CreatedAt:     now,
		UpdatedAt:     now,
	}, nil
}
