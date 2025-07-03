package http

import (
	"fmt"
	"time"

	appUpstream "github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type createUpstreamHandler struct {
	logger                      *logrus.Logger
	cache                       *cache.Cache
	descriptionEmbeddingCreator appUpstream.DescriptionEmbeddingCreator
	repo                        upstream.Repository
	cfg                         *config.Config
}

func NewCreateUpstreamHandler(
	logger *logrus.Logger,
	repo upstream.Repository,
	cache *cache.Cache,
	descriptionEmbeddingCreator appUpstream.DescriptionEmbeddingCreator,
	cfg *config.Config,
) Handler {
	return &createUpstreamHandler{
		logger:                      logger,
		repo:                        repo,
		cache:                       cache,
		descriptionEmbeddingCreator: descriptionEmbeddingCreator,
		cfg:                         cfg,
	}
}

// Handle @Summary Create a new Upstream
// @Description Adds a new upstream under a gateway
// @Tags Upstreams
// @Accept json
// @Produce json
// @Param Authorization header string true "Authorization token"
// @Param gateway_id path string true "Gateway ID"
// @Param upstream body request.UpstreamRequest true "Upstream data"
// @Success 201 {object} upstream.Upstream "Upstream created successfully"
// @Router /api/v1/gateways/{gateway_id}/upstreams [post]
func (s *createUpstreamHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")

	var req request.UpstreamRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	if err := req.Validate(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	if req.Embedding != nil && req.Embedding.Provider != "" {
		if req.Embedding.Provider != factory.OpenAIProvider {
			return c.Status(fiber.StatusBadRequest).
				JSON(fiber.Map{"error": fmt.Sprintf("embedding provider '%s' is not allowed", req.Embedding.Provider)})
		}
	}

	entity, err := s.createUpstreamEntity(req, gatewayID)
	if err != nil {
		if err.Error() == "invalid gateway uuid" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	if err := s.repo.CreateUpstream(c.Context(), entity); err != nil {
		s.logger.WithError(err).Error("Failed to create upstream")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	if err := s.cache.SaveUpstream(c.Context(), gatewayID, entity); err != nil {
		s.logger.WithError(err).Error("Failed to cache upstream")
	}

	if err := s.descriptionEmbeddingCreator.Process(c.Context(), entity); err != nil {
		s.logger.WithError(err).Error("Failed to process embeddings for upstream targets")
	}

	return c.Status(fiber.StatusCreated).JSON(entity)
}

func (s *createUpstreamHandler) createUpstreamEntity(
	req request.UpstreamRequest,
	gatewayID string,
) (*upstream.Upstream, error) {
	now := time.Now()
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
			InsecureSSL:  target.InsecureSSL,
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

	gatewayUUID, err := uuid.Parse(gatewayID)
	if err != nil {
		return nil, fmt.Errorf("invalid gateway uuid")
	}

	id, err := uuid.NewV6()
	if err != nil {
		s.logger.WithError(err).Error("failed to generate UUID")
		return nil, fmt.Errorf("failed to generate UUID")
	}

	var embedding *upstream.EmbeddingConfig
	if req.Embedding != nil {
		embedding = &upstream.EmbeddingConfig{
			Provider:    req.Embedding.Provider,
			Model:       req.Embedding.Model,
			Credentials: domain.CredentialsJSON(req.Embedding.Credentials),
		}
	}

	var websocket *upstream.WebsocketConfig
	if req.WebhookConfig != nil {
		websocket = &upstream.WebsocketConfig{
			EnableDirectCommunication: req.WebhookConfig.EnableDirectCommunication,
			ReturnErrorDetails:        req.WebhookConfig.ReturnErrorDetails,
			PingPeriod:                req.WebhookConfig.PingPeriod,
			PongWait:                  req.WebhookConfig.PongWait,
			HandshakeTimeout:          req.WebhookConfig.HandshakeTimeout,
			ReadBufferSize:            req.WebhookConfig.ReadBufferSize,
			WriteBufferSize:           req.WebhookConfig.WriteBufferSize,
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
		Websocket:       websocket,
		Tags:            req.Tags,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	return &entity, nil
}
