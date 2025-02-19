package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/NeuralTrust/TrustGate/pkg/models"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type createServiceHandler struct {
	logger *logrus.Logger
	repo   *database.Repository
	cache  *cache.Cache
}

func NewCreateServiceHandler(logger *logrus.Logger, repo *database.Repository, cache *cache.Cache) Handler {
	return &createServiceHandler{
		logger: logger,
		repo:   repo,
		cache:  cache,
	}
}

func (s *createServiceHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")

	var service models.Service
	if err := c.BodyParser(&service); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	service.GatewayID = gatewayID

	if err := s.repo.CreateService(c.Context(), &service); err != nil {
		s.logger.WithError(err).Error("Failed to create service")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Cache the service
	if err := s.cache.SaveService(c.Context(), gatewayID, &service); err != nil {
		s.logger.WithError(err).Error("Failed to cache service")
	}

	return c.Status(fiber.StatusCreated).JSON(service)
}
