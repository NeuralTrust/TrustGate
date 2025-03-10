package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type updateServiceHandler struct {
	logger    *logrus.Logger
	repo      *database.Repository
	publisher infraCache.EventPublisher
}

func NewUpdateServiceHandler(logger *logrus.Logger, repo *database.Repository, publisher infraCache.EventPublisher) Handler {
	return &updateServiceHandler{
		logger:    logger,
		repo:      repo,
		publisher: publisher,
	}
}

func (s *updateServiceHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	serviceID := c.Params("service_id")

	var service service.Service
	if err := c.BodyParser(&service); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Ensure IDs match
	service.ID = serviceID
	service.GatewayID = gatewayID

	if err := s.repo.UpdateService(c.Context(), &service); err != nil {
		s.logger.WithError(err).Error("Failed to update service")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Cache the updated service
	err := s.publisher.Publish(c.Context(), channel.GatewayEventsChannel, event.UpdateServiceCacheEvent{
		ServiceID: service.ID,
		GatewayID: service.GatewayID,
	})
	if err != nil {
		s.logger.WithError(err).Error("failed to publish update service cache event")
	}

	return c.Status(fiber.StatusOK).JSON(service)
}
