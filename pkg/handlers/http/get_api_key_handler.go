package http

import (
	"encoding/json"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/apikey"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type getAPIKeyHandler struct {
	logger *logrus.Logger
	cache  *cache.Cache
}

func NewGetAPIKeyHandler(logger *logrus.Logger, cache *cache.Cache) Handler {
	return &getAPIKeyHandler{
		logger: logger,
		cache:  cache,
	}
}

// Handle @Summary Retrieve an API Key by ID
// @Description Returns details of a specific API key
// @Tags API Keys
// @Produce json
// @Param gateway_id path string true "Gateway ID"
// @Param key_id path string true "API Key ID"
// @Success 200 {object} apikey.APIKey "API Key details"
// @Failure 404 {object} map[string]interface{} "API Key not found"
// @Router /api/v1/gateways/{gateway_id}/keys/{key_id} [get]
func (s *getAPIKeyHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	keyID := c.Params("key_id")

	key := fmt.Sprintf("apikey:%s:%s", gatewayID, keyID)
	apiKeyJSON, err := s.cache.Get(c.Context(), key)
	if err != nil {
		if err.Error() == "redis: nil" {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "API key not found"})
		}
		s.logger.WithError(err).Error("failed to get API key")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get API key"})
	}

	var apiKey domain.APIKey
	if err := json.Unmarshal([]byte(apiKeyJSON), &apiKey); err != nil {
		s.logger.WithError(err).Error("failed to unmarshal API key")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get API key"})
	}

	// Don't expose the actual key
	apiKey.Key = ""

	return c.Status(fiber.StatusOK).JSON(apiKey)
}
