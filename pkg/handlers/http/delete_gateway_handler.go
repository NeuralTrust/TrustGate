package http

import (
	"net/http"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type deleteGatewayHandler struct {
	logger    *logrus.Logger
	repo      domain.Repository
	publisher infraCache.EventPublisher
}

func NewDeleteGatewayHandler(
	logger *logrus.Logger,
	repo domain.Repository,
	publisher infraCache.EventPublisher,
) Handler {
	return &deleteGatewayHandler{
		logger:    logger,
		repo:      repo,
		publisher: publisher,
	}
}

// Handle @Summary Delete a Gateway
// @Description Removes a gateway from the system
// @Tags Gateways
// @Param Authorization header string true "Authorization token"
// @Param gateway_id path string true "Gateway ID"
// @Success 204
// @Failure 404 {object} map[string]interface{} "Gateway not found"
// @Router /api/v1/gateways/{gateway_id} [delete]
func (s *deleteGatewayHandler) Handle(c *fiber.Ctx) error {
	id := c.Params("gateway_id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "gateway_id is required"})
	}
	parsedId, err := uuid.Parse(id)
	if err != nil {
		s.logger.WithError(err).Error("failed to parse gateway id")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway_id"})
	}

	if err := s.repo.Delete(parsedId); err != nil {
		s.logger.WithError(err).Error("Failed to delete gateway")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	if err := s.publisher.Publish(
		c.Context(),
		channel.GatewayEventsChannel,
		event.DeleteGatewayCacheEvent{
			GatewayID: id,
		},
	); err != nil {
		s.logger.WithError(err).Error("failed to publish gateway event")
	}
	return c.SendStatus(http.StatusNoContent)
}
