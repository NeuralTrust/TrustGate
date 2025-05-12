package upstream

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/sirupsen/logrus"
)

type DescriptionEmbeddingCreator interface {
	Process(ctx context.Context, upstream *upstream.Upstream) error
}

type descriptionEmbeddingCreator struct {
	embeddingServiceLocator *factory.EmbeddingServiceLocator
	embeddingRepository     embedding.Repository
	logger                  *logrus.Logger
}

func NewDescriptionEmbeddingCreator(
	embeddingServiceLocator *factory.EmbeddingServiceLocator,
	embeddingRepository embedding.Repository,
	logger *logrus.Logger,
) DescriptionEmbeddingCreator {
	return &descriptionEmbeddingCreator{
		embeddingServiceLocator: embeddingServiceLocator,
		embeddingRepository:     embeddingRepository,
		logger:                  logger,
	}
}

func (s *descriptionEmbeddingCreator) Process(ctx context.Context, upstream *upstream.Upstream) error {
	if upstream.Algorithm != common.SemanticStrategyName {
		return nil
	}

	if upstream.EmbeddingConfig == nil {
		return fmt.Errorf("embedding configuration is required for semantic algorithm")
	}

	embeddingService, err := s.embeddingServiceLocator.GetService(upstream.EmbeddingConfig.Provider)
	if err != nil {
		return fmt.Errorf("failed to get embedding service: %w", err)
	}

	embeddingConfig := &embedding.Config{
		Provider:    upstream.EmbeddingConfig.Provider,
		Model:       upstream.EmbeddingConfig.Model,
		Credentials: upstream.EmbeddingConfig.Credentials,
	}

	for _, target := range upstream.Targets {
		if target.Description == "" {
			s.logger.Warnf("target %s has no description, skipping embedding generation", target.ID)
			continue
		}
		embData, err := embeddingService.Generate(
			ctx,
			target.Description,
			upstream.EmbeddingConfig.Model,
			embeddingConfig,
		)
		if err != nil {
			s.logger.WithError(err).Errorf("Failed to generate embedding for target %s", target.ID)
			continue
		}

		err = s.embeddingRepository.Store(ctx, target.ID, embData, "")
		if err != nil {
			s.logger.WithError(err).Errorf("Failed to store embedding for target %s", target.ID)
			continue
		}
	}

	return nil
}
