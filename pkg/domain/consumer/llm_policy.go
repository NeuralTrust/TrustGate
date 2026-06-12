package consumer

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/algorithm"
)

type LLMPolicy struct {
	Algorithm       string                    `json:"algorithm,omitempty"`
	EmbeddingConfig *registry.EmbeddingConfig `json:"embedding_config,omitempty"`
	ModelPolicies   ModelPolicies             `json:"model_policies,omitempty"`
	Fallback        *Fallback                 `json:"fallback,omitempty"`
}

func (p *LLMPolicy) Validate(known map[ids.RegistryID]struct{}) error {
	if p.Algorithm == "" {
		p.Algorithm = algorithm.RoundRobin
	}
	if !algorithm.IsValid(p.Algorithm) {
		return fmt.Errorf("%w: %q", ErrInvalidAlgorithm, p.Algorithm)
	}
	if p.Algorithm == algorithm.Semantic {
		if p.EmbeddingConfig == nil {
			return fmt.Errorf("%w: embedding_config required for semantic algorithm", ErrInvalidEmbeddingConfig)
		}
		if err := p.EmbeddingConfig.Validate(); err != nil {
			return err
		}
	} else if p.EmbeddingConfig != nil {
		return fmt.Errorf("%w: embedding_config is only valid for the semantic algorithm", ErrInvalidEmbeddingConfig)
	}
	if err := p.Fallback.Validate(); err != nil {
		return err
	}
	return p.ModelPolicies.Validate(known)
}
