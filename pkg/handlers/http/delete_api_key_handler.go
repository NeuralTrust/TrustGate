package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/database"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type deleteAPIKeyHandler struct {
	logger    *logrus.Logger
	repo      *database.Repository
	publisher infraCache.EventPublisher
}

func NewDeleteAPIKeyHandler(
	logger *logrus.Logger,
	repo *database.Repository,
	publisher infraCache.EventPublisher,
) Handler {
	return &deleteAPIKeyHandler{
		logger:    logger,
		publisher: publisher,
		repo:      repo,
	}
}

// Handle @Summary Delete an API Key
// @Description Removes an API key from a gateway
// @Tags API Keys
// @Param gateway_id path string true "Gateway ID"
// @Param key_id path string true "API Key ID"
// @Success 204 "API Key deleted successfully"
// @Failure 404 {object} map[string]interface{} "API Key not found"
// @Router /api/v1/gateways/{gateway_id}/keys/{key_id} [delete]
func (s *deleteAPIKeyHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	keyID := c.Params("key_id")

	err := s.repo.DeleteAPIKey(c.Context(), keyID, gatewayID)

	if err != nil {
		s.logger.WithError(err).Error("Failed to delete API key")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete API key"})
	}

	err = s.publisher.Publish(c.Context(), channel.GatewayEventsChannel, event.DeleteKeyCacheEvent{
		ApiKeyID:  keyID,
		GatewayID: gatewayID,
	})

	if err != nil {
		s.logger.WithError(err).Error("failed to publish apiKey cache invalidation")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "API key deleted successfully"})
}
