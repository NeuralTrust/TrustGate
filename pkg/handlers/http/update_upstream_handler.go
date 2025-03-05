package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/database"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/NeuralTrust/TrustGate/pkg/models"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type updateUpstreamHandler struct {
	logger    *logrus.Logger
	repo      *database.Repository
	publisher infraCache.EventPublisher
}

func NewUpdateUpstreamHandler(
	logger *logrus.Logger,
	repo *database.Repository,
	publisher infraCache.EventPublisher,
) Handler {
	return &updateUpstreamHandler{
		logger:    logger,
		repo:      repo,
		publisher: publisher,
	}
}

func (s *updateUpstreamHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	upstreamID := c.Params("upstream_id")

	var entity models.Upstream
	if err := c.BodyParser(&entity); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	entity.ID = upstreamID
	entity.GatewayID = gatewayID

	if err := s.repo.UpdateUpstream(c.Context(), &entity); err != nil {
		s.logger.WithError(err).Error("Failed to update upstream")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	err := s.publisher.Publish(c.Context(), channel.GatewayEventsChannel, event.UpdateUpstreamCacheEvent{
		UpstreamID: upstreamID,
		GatewayID:  gatewayID,
	})
	if err != nil {
		s.logger.WithError(err).Error("failed to publish update upstream event")
	}

	return c.Status(fiber.StatusOK).JSON(entity)
}
