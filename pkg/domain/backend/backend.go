package backend

import (
	"fmt"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/algorithm"
	"github.com/google/uuid"
)

const (
	AlgorithmRoundRobin         = algorithm.RoundRobin
	AlgorithmWeightedRoundRobin = algorithm.WeightedRoundRobin
	AlgorithmRandom             = algorithm.Random
	AlgorithmLeastConnections   = algorithm.LeastConnections
	AlgorithmSemantic           = algorithm.Semantic
)

type Backend struct {
	ID              uuid.UUID        `json:"id"`
	GatewayID       uuid.UUID        `json:"gateway_id"`
	Name            string           `json:"name"`
	Algorithm       string           `json:"algorithm"`
	Targets         Targets          `json:"targets"`
	EmbeddingConfig *EmbeddingConfig `json:"embedding_config,omitempty"`
	HealthChecks    *HealthChecks    `json:"health_checks,omitempty"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

func Rehydrate(
	id, gatewayID uuid.UUID,
	name, algorithm string,
	targets Targets,
	embedding *EmbeddingConfig,
	healthChecks *HealthChecks,
	createdAt, updatedAt time.Time,
) *Backend {
	return &Backend{
		ID:              id,
		GatewayID:       gatewayID,
		Name:            name,
		Algorithm:       algorithm,
		Targets:         targets,
		EmbeddingConfig: embedding,
		HealthChecks:    healthChecks,
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
	}
}

func (b *Backend) Validate() error {
	if b.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidTarget)
	}
	if b.GatewayID == uuid.Nil {
		return ErrInvalidGatewayID
	}
	if b.Algorithm == "" {
		b.Algorithm = AlgorithmRoundRobin
	}
	if !algorithm.IsValid(b.Algorithm) {
		return fmt.Errorf("%w: %q", ErrInvalidAlgorithm, b.Algorithm)
	}
	if len(b.Targets) == 0 {
		return ErrNoTargets
	}
	if b.HealthChecks != nil {
		if err := b.HealthChecks.Validate(); err != nil {
			return err
		}
	}

	if b.Algorithm == AlgorithmSemantic {
		if b.EmbeddingConfig == nil {
			return fmt.Errorf("%w: embedding_config required for semantic algorithm", ErrInvalidEmbeddingConfig)
		}
		if err := b.EmbeddingConfig.Validate(); err != nil {
			return err
		}
	}

	for i := range b.Targets {
		t := &b.Targets[i]
		if t.ID == "" {
			t.ID = fmt.Sprintf("%s-%s-%d", b.ID, t.Provider, i)
		}
		if err := t.Validate(); err != nil {
			return fmt.Errorf("target %d: %w", i, err)
		}
		if b.Algorithm == AlgorithmSemantic && t.Description == "" {
			return fmt.Errorf("%w: target %d description is required for semantic algorithm", ErrInvalidTarget, i)
		}
	}

	return nil
}
