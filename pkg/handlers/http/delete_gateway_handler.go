package http

import (
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/database"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type deleteGatewayHandler struct {
	logger    *logrus.Logger
	repo      *database.Repository
	publisher infraCache.EventPublisher
}

func NewDeleteGatewayHandler(
	logger *logrus.Logger,
	repo *database.Repository,
	publisher infraCache.EventPublisher,
) Handler {
	return &deleteGatewayHandler{
		logger:    logger,
		repo:      repo,
		publisher: publisher,
	}
}

func (s *deleteGatewayHandler) Handle(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id is required"})
	}
	if err := s.repo.DeleteGateway(id); err != nil {
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
