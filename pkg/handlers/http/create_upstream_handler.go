package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/gofiber/fiber/v2"
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
// @Param upstream body object true "Upstream data"
// @Success 201 {object} upstream.Upstream "Upstream created successfully"
// @Router /api/v1/gateways/{gateway_id}/upstreams [post]
func (s *createUpstreamHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")

	var entity upstream.Upstream
	if err := c.BodyParser(&entity); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	entity.GatewayID = gatewayID

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
