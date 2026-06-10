package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

type UpdateConsumerRequest struct {
	Name            *string                   `json:"name,omitempty"`
	Type            *string                   `json:"type,omitempty"`
	Path            *string                   `json:"path,omitempty"`
	Algorithm       *string                   `json:"algorithm,omitempty"`
	EmbeddingConfig *EmbeddingConfigRequest   `json:"embedding_config,omitempty"`
	Headers         *map[string]string        `json:"headers,omitempty"`
	Active          *bool                     `json:"active,omitempty"`
	Fallback        *FallbackRequest          `json:"fallback,omitempty"`
	Registries      *[]RegistryBindingRequest `json:"registries,omitempty"`
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
	if r.Path != nil && strings.TrimSpace(*r.Path) == "" {
		return fmt.Errorf("path is required: %w", commonerrors.ErrValidation)
	}
	return nil
}

func (r UpdateConsumerRequest) ToType() *domain.Type {
	if r.Type == nil || strings.TrimSpace(*r.Type) == "" {
		return nil
	}
	t := domain.Type(*r.Type)
	return &t
}

func (r UpdateConsumerRequest) ToAlgorithm() *string {
	if r.Algorithm == nil || strings.TrimSpace(*r.Algorithm) == "" {
		return nil
	}
	return r.Algorithm
}

func (r UpdateConsumerRequest) ToEmbeddingConfig() *registrydomain.EmbeddingConfig {
	return r.EmbeddingConfig.ToDomain()
}

func (r UpdateConsumerRequest) ToFallback() (*domain.Fallback, error) {
	return r.Fallback.ToFallback()
}

func (r UpdateConsumerRequest) ToModelPolicies() (*domain.ModelPolicies, error) {
	if r.Registries == nil {
		return nil, nil
	}
	_, mp, err := parseRegistryBindings(*r.Registries)
	if err != nil {
		return nil, err
	}
	if mp == nil {
		mp = domain.ModelPolicies{}
	}
	return &mp, nil
}
