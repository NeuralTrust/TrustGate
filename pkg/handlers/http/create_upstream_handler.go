package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/NeuralTrust/TrustGate/pkg/models"
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

func (s *createUpstreamHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")

	var entity models.Upstream
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
