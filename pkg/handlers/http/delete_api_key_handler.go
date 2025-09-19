package http

import (
	"errors"
	"net/http"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/iam/apikey"
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

// Handle
// @Summary Delete an API Key
// @Description Removes an API key. If the key is scoped to a gateway (GatewayType), provide ?subject_id=<gateway_uuid>.
// @Tags API Keys
// @Param Authorization header string true "Authorization token"
// @Param key_id path string true "API Key ID"
// @Success 204 "No Content"
// @Failure 400 {object} map[string]interface{} "Bad Request"
// @Failure 404 {object} map[string]interface{} "Not Found"
// @Failure 500 {object} map[string]interface{} "Internal Error"
// @Router /api/v1/iam/api-key/{key_id} [delete]
func (s *deleteAPIKeyHandler) Handle(c *fiber.Ctx) error {
	keyID := c.Params("key_id")
	keyUUID, err := uuid.Parse(keyID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid key_id"})
	}

	ctx := c.UserContext()

	key, err := s.apiKeyRepo.GetByID(ctx, keyUUID)
	if err != nil {
		if errors.Is(err, domain.ErrEntityNotFound) {
			return c.SendStatus(http.StatusNotFound)
		}
		s.logger.WithError(err).WithField("key_id", keyID).Error("failed to fetch API key")
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch API key"})
	}

	if err := s.apiKeyRepo.Delete(ctx, key.ID); err != nil {
		if errors.Is(err, domain.ErrEntityNotFound) {
			return c.SendStatus(http.StatusNotFound)
		}
		s.logger.WithError(err).WithFields(logrus.Fields{
			"key_id": keyID,
		}).Error("failed to delete API key with subject")
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete API key"})
	}

	if err := s.publisher.Publish(ctx, channel.GatewayEventsChannel, event.DeleteKeyCacheEvent{
		ApiKey:   key.Key,
		ApiKeyID: keyUUID.String(),
	}); err != nil {
		s.logger.WithError(err).WithField("key_id", keyID).Warn("failed to publish apiKey cache invalidation")
	}

	return c.SendStatus(http.StatusNoContent)
}
