package http

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type deleteAPIKeyHandler struct {
	logger *logrus.Logger
	cache  *cache.Cache
}

func NewDeleteAPIKeyHandler(logger *logrus.Logger, cache *cache.Cache) Handler {
	return &deleteAPIKeyHandler{
		logger: logger,
		cache:  cache,
	}
}

func (s *deleteAPIKeyHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	keyID := c.Params("key_id")

	// Delete API key from cache
	key := fmt.Sprintf("apikey:%s:%s", gatewayID, keyID)
	if err := s.cache.Delete(c.Context(), key); err != nil {
		s.logger.WithError(err).Error("Failed to delete API key")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete API key"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "API key deleted successfully"})
}
