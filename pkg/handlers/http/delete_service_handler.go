package http

import (
	"net/http"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/database"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type deleteServiceHandler struct {
	logger    *logrus.Logger
	repo      *database.Repository
	publisher infraCache.EventPublisher
}

func NewDeleteServiceHandler(
	logger *logrus.Logger,
	repo *database.Repository,
	publisher infraCache.EventPublisher,
) Handler {
	return &deleteServiceHandler{
		logger:    logger,
		repo:      repo,
		publisher: publisher,
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

	err := s.publisher.Publish(
		c.Context(),
		channel.GatewayEventsChannel,
		event.DeleteServiceCacheEvent{
			GatewayID: gatewayID,
			ServiceID: serviceID,
		},
	)

	if err != nil {
		s.logger.WithError(err).Error("failed to publish service cache invalidation")
	}

	return c.SendStatus(http.StatusNoContent)
}
