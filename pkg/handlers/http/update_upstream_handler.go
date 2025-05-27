package http

import (
	"fmt"

	appUpstream "github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type updateUpstreamHandler struct {
	logger                      *logrus.Logger
	repo                        upstream.Repository
	publisher                   infraCache.EventPublisher
	descriptionEmbeddingCreator appUpstream.DescriptionEmbeddingCreator
	cache                       *cache.Cache
	cfg                         *config.Config
}

func NewUpdateUpstreamHandler(
	logger *logrus.Logger,
	repo upstream.Repository,
	publisher infraCache.EventPublisher,
	cache *cache.Cache,
	descriptionEmbeddingCreator appUpstream.DescriptionEmbeddingCreator,
	cfg *config.Config,
) Handler {
	return &updateUpstreamHandler{
		logger:                      logger,
		repo:                        repo,
		publisher:                   publisher,
		descriptionEmbeddingCreator: descriptionEmbeddingCreator,
		cache:                       cache,
		cfg:                         cfg,
	}
}

// Handle @Summary Update an Upstream
// @Description Updates an existing upstream
// @Tags Upstreams
// @Accept json
// @Produce json
// @Param Authorization header string true "Authorization token"
// @Param gateway_id path string true "Gateway ID"
// @Param upstream_id path string true "Upstream ID"
// @Param upstream body request.UpstreamRequest true "Updated upstream data"
// @Success 200 {object} upstream.Upstream "Upstream updated successfully"
// @Router /api/v1/gateways/{gateway_id}/upstreams/{upstream_id} [put]
func (s *updateUpstreamHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	upstreamID := c.Params("upstream_id")

	var req request.UpstreamRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	if err := req.Validate(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	if req.Embedding != nil && req.Embedding.Provider != "" {
		if req.Embedding.Provider != factory.OpenAIProvider {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("embedding provider '%s' is not allowed", req.Embedding.Provider)})
		}
	}

	id, err := uuid.Parse(upstreamID)
	if err != nil {
		s.logger.WithError(err).Error("failed to parse upstream ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid upstream ID"})
	}

	gatewayUUID, err := uuid.Parse(gatewayID)
	if err != nil {
		s.logger.WithError(err).Error("failed to parse gateway ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway ID"})
	}

	var targets []upstream.Target
	for _, target := range req.Targets {
		targets = append(targets, upstream.Target{
			ID:           target.ID,
			Weight:       target.Weight,
			Priority:     target.Priority,
			Tags:         target.Tags,
			Headers:      target.Headers,
			Path:         target.Path,
			Host:         target.Host,
			Port:         target.Port,
			Protocol:     target.Protocol,
			Provider:     target.Provider,
			Models:       target.Models,
			DefaultModel: target.DefaultModel,
			Description:  target.Description,
			Stream:       target.Stream,
			Credentials:  domain.CredentialsJSON(target.Credentials),
		})
	}

	var healthCheck *upstream.HealthCheck
	if req.HealthChecks != nil {
		healthCheck = &upstream.HealthCheck{
			Passive:   req.HealthChecks.Passive,
			Path:      req.HealthChecks.Path,
			Headers:   req.HealthChecks.Headers,
			Threshold: req.HealthChecks.Threshold,
			Interval:  req.HealthChecks.Interval,
		}
	}

	var embedding *upstream.EmbeddingConfig
	if req.Embedding != nil {
		embedding = &upstream.EmbeddingConfig{
			Provider:    req.Embedding.Provider,
			Model:       req.Embedding.Model,
			Credentials: domain.CredentialsJSON(req.Embedding.Credentials),
		}
	}

	entity := upstream.Upstream{
		ID:              id,
		GatewayID:       gatewayUUID,
		Name:            req.Name,
		Algorithm:       req.Algorithm,
		Targets:         targets,
		EmbeddingConfig: embedding,
		HealthChecks:    healthCheck,
		Tags:            req.Tags,
	}

	if err := s.repo.UpdateUpstream(c.Context(), &entity); err != nil {
		s.logger.WithError(err).Error("failed to update upstream")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	err = s.publisher.Publish(c.Context(), channel.GatewayEventsChannel, event.UpdateUpstreamCacheEvent{
		UpstreamID: upstreamID,
		GatewayID:  gatewayID,
	})
	if err != nil {
		s.logger.WithError(err).Error("failed to publish update upstream event")
	}

	if err := s.descriptionEmbeddingCreator.Process(c.Context(), &entity); err != nil {
		s.logger.WithError(err).Error("Failed to process embeddings for upstream targets")
	}

	return c.Status(fiber.StatusOK).JSON(entity)
}
