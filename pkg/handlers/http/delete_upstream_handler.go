package http

import (
	"errors"
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auditlogs"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type deleteUpstreamHandler struct {
	logger       *logrus.Logger
	repo         upstream.Repository
	publisher    infraCache.EventPublisher
	auditService auditlogs.Service
}

func NewDeleteUpstreamHandler(
	logger *logrus.Logger,
	repo upstream.Repository,
	publisher infraCache.EventPublisher,
	auditService auditlogs.Service,
) Handler {
	return &deleteUpstreamHandler{
		logger:       logger,
		repo:         repo,
		publisher:    publisher,
		auditService: auditService,
	}
}

// Handle @Summary Delete an Upstream
// @Description Removes an upstream from a gateway
// @Tags Upstreams
// @Param Authorization header string true "Authorization token"
// @Param gateway_id path string true "Gateway ID"
// @Param upstream_id path string true "Upstream ID"
// @Success 204 "Upstream deleted successfully"
// @Router /api/v1/gateways/{gateway_id}/upstreams/{upstream_id} [delete]
func (s *deleteUpstreamHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	upstreamID := c.Params("upstream_id")

	if err := s.repo.DeleteUpstream(c.Context(), upstreamID); err != nil {
		if errors.Is(err, upstream.ErrUpstreamIsBeingUsed) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		s.logger.WithError(err).Error("Failed to delete upstream")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	err := s.publisher.Publish(
		c.Context(),
		event.DeleteUpstreamCacheEvent{
			GatewayID:  gatewayID,
			UpstreamID: upstreamID,
		},
	)

	if err != nil {
		s.logger.WithError(err).Error("failed to publish upstream cache invalidation")
	}

	s.emitAuditLog(c, upstreamID, "", auditlogs.StatusSuccess, "")

	return c.SendStatus(http.StatusNoContent)
}

func (s *deleteUpstreamHandler) emitAuditLog(c *fiber.Ctx, targetID, targetName, status, errMsg string) {
	if s.auditService == nil {
		return
	}
	s.auditService.Emit(c, auditlogs.Event{
		Event: auditlogs.EventInfo{
			Type:         auditlogs.EventTypeUpstreamDeleted,
			Category:     auditlogs.CategoryRunTimeSecurity,
			Status:       status,
			ErrorMessage: errMsg,
		},
		Target: auditlogs.Target{
			Type: auditlogs.TargetTypeUpstream,
			ID:   targetID,
			Name: targetName,
		},
		Context: auditlogs.Context{
			IPAddress: c.IP(),
			UserAgent: c.Get("User-Agent"),
			RequestID: c.Get("X-Request-ID"),
		},
	})
}
