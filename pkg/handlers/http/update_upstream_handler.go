package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
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

// Handle @Summary Update an Upstream
// @Description Updates an existing upstream
// @Tags Upstreams
// @Accept json
// @Produce json
// @Param gateway_id path string true "Gateway ID"
// @Param upstream_id path string true "Upstream ID"
// @Param upstream body types.UpstreamRequest true "Updated upstream data"
// @Success 200 {object} upstream.Upstream "Upstream updated successfully"
// @Router /api/v1/gateways/{gateway_id}/upstreams/{upstream_id} [put]
func (s *updateUpstreamHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	upstreamID := c.Params("upstream_id")

	var entity upstream.Upstream
	if err := c.BodyParser(&entity); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	id, err := uuid.Parse(upstreamID)
	if err != nil {
		s.logger.WithError(err).Error("failed to parse upstream ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid upstream ID"})
	}

	gatewayUUID, err := uuid.Parse(gatewayID)
	if err != nil {
		s.logger.WithError(err).Error("failed to parse gateway ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid upstream ID"})
	}

	entity.ID = id
	entity.GatewayID = gatewayUUID

	if err := s.repo.UpdateUpstream(c.Context(), &entity); err != nil {
		s.logger.WithError(err).Error("failed to update upstream")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	err = s.publisher.Publish(c.Context(), channel.GatewayEventsChannel, event.UpdateUpstreamCacheEvent{
		UpstreamID: upstreamID,
		GatewayID:  gatewayID,
	})
	if err != nil {
		s.logger.WithError(err).Error("failed to publish update upstream event")
	}

	return c.Status(fiber.StatusOK).JSON(entity)
}
