package http

import (
	"encoding/json"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	"github.com/NeuralTrust/TrustGate/pkg/models"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type getServiceHandler struct {
	logger *logrus.Logger
	repo   service.Repository
	cache  *cache.Cache
}

func NewGetServiceHandler(logger *logrus.Logger, repo service.Repository, cache *cache.Cache) Handler {
	return &getServiceHandler{
		logger: logger,
		repo:   repo,
		cache:  cache,
	}
}

func (s *getServiceHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	serviceID := c.Params("service_id")

	// Try to get from cache first
	serviceKey := fmt.Sprintf(cache.ServiceKeyPattern, gatewayID, serviceID)
	if serviceJSON, err := s.cache.Get(c.Context(), serviceKey); err == nil {
		var entity models.Service
		if err := json.Unmarshal([]byte(serviceJSON), &entity); err == nil {
			return c.Status(fiber.StatusOK).JSON(entity)
		}
	}

	// If not in cache, get from database
	entity, err := s.repo.GetService(c.Context(), serviceID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Service not found"})
	}

	// Cache the service
	if err := s.cache.SaveService(c.Context(), gatewayID, entity); err != nil {
		s.logger.WithError(err).Error("Failed to cache service")
	}

	return c.Status(fiber.StatusOK).JSON(entity)
}
