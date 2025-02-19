package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/NeuralTrust/TrustGate/pkg/models"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type updateUpstreamHandler struct {
	logger *logrus.Logger
	repo   *database.Repository
	cache  *cache.Cache
}

func NewUpdateUpstreamHandler(logger *logrus.Logger, repo *database.Repository, cache *cache.Cache) Handler {
	return &updateUpstreamHandler{
		logger: logger,
		repo:   repo,
		cache:  cache,
	}
}

func (s *updateUpstreamHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	upstreamID := c.Params("upstream_id")

	var entity models.Upstream
	if err := c.BodyParser(&entity); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	entity.ID = upstreamID
	entity.GatewayID = gatewayID

	if err := s.repo.UpdateUpstream(c.Context(), &entity); err != nil {
		s.logger.WithError(err).Error("Failed to update upstream")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	if err := s.cache.SaveUpstream(c.Context(), gatewayID, &entity); err != nil {
		s.logger.WithError(err).Error("Failed to cache upstream")
	}

	return c.Status(fiber.StatusOK).JSON(entity)
}
