package http

import (
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type createUpstreamHandler struct {
	logger *logrus.Logger
	repo   *database.Repository
	cache  *cache.Cache
}

func NewCreateUpstreamHandler(logger *logrus.Logger, repo *database.Repository, cache *cache.Cache) Handler {
	return &createUpstreamHandler{
		logger: logger,
		repo:   repo,
		cache:  cache,
	}
}

// Handle @Summary Create a new Upstream
// @Description Adds a new upstream under a gateway
// @Tags Upstreams
// @Accept json
// @Produce json
// @Param gateway_id path string true "Gateway ID"
// @Param upstream body types.UpstreamRequest true "Upstream data"
// @Success 201 {object} upstream.Upstream "Upstream created successfully"
// @Router /api/v1/gateways/{gateway_id}/upstreams [post]
func (s *createUpstreamHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")

	var req types.UpstreamRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	now := time.Now()

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
			Credentials:  domain.CredentialsJSON(target.Credentials),
		})
	}
	gatewayUUID, err := uuid.Parse(gatewayID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway uuid"})
	}

	id, err := uuid.NewV6()
	if err != nil {
		s.logger.WithError(err).Error("failed to generate UUID")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "dailed to generate UUID"})
	}

	entity := upstream.Upstream{
		ID:           id,
		GatewayID:    gatewayUUID,
		Name:         req.Name,
		Algorithm:    req.Algorithm,
		Targets:      targets,
		HealthChecks: healthCheck,
		Tags:         req.Tags,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.repo.CreateUpstream(c.Context(), &entity); err != nil {
		s.logger.WithError(err).Error("Failed to create upstream")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Cache the upstream
	if err := s.cache.SaveUpstream(c.Context(), gatewayID, &entity); err != nil {
		s.logger.WithError(err).Error("Failed to cache upstream")
	}

	return c.Status(fiber.StatusCreated).JSON(entity)
}
