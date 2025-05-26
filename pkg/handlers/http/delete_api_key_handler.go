package http

import (
	"errors"

	"github.com/NeuralTrust/TrustGate/pkg/domain/apikey"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/errors"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type deleteAPIKeyHandler struct {
	logger     *logrus.Logger
	apiKeyRepo apikey.Repository
	publisher  infraCache.EventPublisher
}

func NewDeleteAPIKeyHandler(
	logger *logrus.Logger,
	apiKeyRepo apikey.Repository,
	publisher infraCache.EventPublisher,
) Handler {
	return &deleteAPIKeyHandler{
		logger:     logger,
		publisher:  publisher,
		apiKeyRepo: apiKeyRepo,
	}
}

// Handle @Summary Delete an API Key
// @Description Removes an API key from a gateway
// @Tags API Keys
// @Param Authorization header string true "Authorization token"
// @Param gateway_id path string true "Gateway ID"
// @Param key_id path string true "API Key ID"
// @Success 204 "API Key deleted successfully"
// @Failure 404 {object} map[string]interface{} "API Key not found"
// @Router /api/v1/gateways/{gateway_id}/keys/{key_id} [delete]
func (s *deleteAPIKeyHandler) Handle(c *fiber.Ctx) error {
	gatewayUUID, err := uuid.Parse(c.Params("gateway_id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway ID"})
	}
	keyUUID, err := uuid.Parse(c.Params("key_id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway ID"})
	}
	key, err := s.apiKeyRepo.GetByID(c.Context(), keyUUID)
	if err != nil {
		if errors.Is(err, domain.ErrEntityNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "API key not found"})
		}
		s.logger.WithError(err).Error("Failed to fetch API key")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch API key"})
	}
	err = s.apiKeyRepo.Delete(c.Context(), keyUUID, gatewayUUID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to delete API key")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete API key"})
	}

	err = s.publisher.Publish(c.Context(), channel.GatewayEventsChannel, event.DeleteKeyCacheEvent{
		ApiKey:   key.Key,
		ApiKeyID: keyUUID.String(),
	})
	if err != nil {
		s.logger.WithError(err).Error("failed to publish apiKey cache invalidation")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "API key deleted successfully"})
}
