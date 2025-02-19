package http

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type deleteServiceHandler struct {
	logger *logrus.Logger
	repo   *database.Repository
	cache  *cache.Cache
}

func NewDeleteServiceHandler(logger *logrus.Logger, repo *database.Repository, cache *cache.Cache) Handler {
	return &deleteServiceHandler{
		logger: logger,
		repo:   repo,
		cache:  cache,
	}
}

func (s *deleteServiceHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	serviceID := c.Params("service_id")

	if err := s.repo.DeleteService(c.Context(), serviceID); err != nil {
		if strings.Contains(err.Error(), "being used by") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		s.logger.WithError(err).Error("Failed to delete service")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Invalidate cache
	serviceKey := fmt.Sprintf(cache.ServiceKeyPattern, gatewayID, serviceID)
	servicesKey := fmt.Sprintf(cache.ServicesKeyPattern, gatewayID)
	if err := s.cache.Delete(c.Context(), serviceKey); err != nil {
		s.logger.WithError(err).Error("Failed to invalidate service cache")
	}
	if err := s.cache.Delete(c.Context(), servicesKey); err != nil {
		s.logger.WithError(err).Error("Failed to invalidate services list cache")
	}

	return c.SendStatus(http.StatusNoContent)
}
