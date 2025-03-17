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

// deleteUpstreamHandler struct
type deleteUpstreamHandler struct {
	logger    *logrus.Logger
	repo      *database.Repository
	publisher infraCache.EventPublisher
}

func NewDeleteUpstreamHandler(
	logger *logrus.Logger,
	repo *database.Repository,
	publisher infraCache.EventPublisher,
) Handler {
	return &deleteUpstreamHandler{
		logger:    logger,
		repo:      repo,
		publisher: publisher,
	}
}

// Handle @Summary Delete an Upstream
// @Description Removes an upstream from a gateway
// @Tags Upstreams
// @Param gateway_id path string true "Gateway ID"
// @Param upstream_id path string true "Upstream ID"
// @Success 204 "Upstream deleted successfully"
// @Router /api/v1/gateways/{gateway_id}/upstreams/{upstream_id} [delete]
func (s *deleteUpstreamHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	upstreamID := c.Params("upstream_id")

	if err := s.repo.DeleteUpstream(c.Context(), upstreamID); err != nil {
		if strings.Contains(err.Error(), "being used by") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		s.logger.WithError(err).Error("Failed to delete upstream")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	err := s.publisher.Publish(
		c.Context(),
		channel.GatewayEventsChannel,
		event.DeleteUpstreamCacheEvent{
			GatewayID:  gatewayID,
			UpstreamID: upstreamID,
		},
	)

	if err != nil {
		s.logger.WithError(err).Error("failed to publish upstream cache invalidation")
	}

	return c.SendStatus(http.StatusNoContent)
}
