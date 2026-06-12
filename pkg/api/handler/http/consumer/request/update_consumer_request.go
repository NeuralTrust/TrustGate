package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
)

type UpdateConsumerRequest struct {
	Name          *string                `json:"name,omitempty"`
	Type          *string                `json:"type,omitempty"`
	RoutingMode   *string                `json:"routing_mode,omitempty"`
	LBConfig      *LBConfigRequest       `json:"lb_config,omitempty"`
	Headers       *map[string]string     `json:"headers,omitempty"`
	Active        *bool                  `json:"active,omitempty"`
	Fallback      *FallbackRequest       `json:"fallback,omitempty"`
	ModelPolicies *[]ModelPolicyRequest  `json:"model_policies,omitempty"`
	Toolkit       *[]ToolkitEntryRequest `json:"toolkit,omitempty"`
	FailMode      *string                `json:"fail_mode,omitempty"`
}

func (r UpdateConsumerRequest) Validate() error {
	if r.Name != nil {
		if strings.TrimSpace(*r.Name) == "" {
			return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
		}
		if len(*r.Name) > 255 {
			return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
		}
	}
	return nil
}

func (r UpdateConsumerRequest) ToType() *domain.Type {
	if r.Type == nil || strings.TrimSpace(*r.Type) == "" {
		return nil
	}
	t := domain.Type(strings.ToUpper(strings.TrimSpace(*r.Type)))
	return &t
}

func (r UpdateConsumerRequest) ToRoutingMode() *domain.RoutingMode {
	if r.RoutingMode == nil || strings.TrimSpace(*r.RoutingMode) == "" {
		return nil
	}
	mode := domain.RoutingMode(*r.RoutingMode)
	return &mode
}

func (r UpdateConsumerRequest) ToLBConfig() (*domain.LBConfig, error) {
	return r.LBConfig.ToDomain()
}

func (r UpdateConsumerRequest) ToFallback() (*domain.Fallback, error) {
	return r.Fallback.ToFallback()
}

func (r UpdateConsumerRequest) ToModelPolicies() (*domain.ModelPolicies, error) {
	if r.ModelPolicies == nil {
		return nil, nil
	}
	mp, err := parseModelPolicies(*r.ModelPolicies)
	if err != nil {
		return nil, err
	}
	return &mp, nil
}

func (r UpdateConsumerRequest) ToToolkit() (*domain.Toolkit, error) {
	if r.Toolkit == nil {
		return nil, nil
	}
	tk, err := parseToolkit(*r.Toolkit)
	if err != nil {
		return nil, err
	}
	return &tk, nil
}

func (r UpdateConsumerRequest) ToFailMode() *domain.FailMode {
	if r.FailMode == nil || strings.TrimSpace(*r.FailMode) == "" {
		return nil
	}
	m := domain.FailMode(*r.FailMode)
	return &m
}
