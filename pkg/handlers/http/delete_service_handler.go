package http

import (
	"errors"
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auditlogs"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type deleteServiceHandler struct {
	logger       *logrus.Logger
	repo         service.Repository
	publisher    infraCache.EventPublisher
	auditService auditlogs.Service
}

func NewDeleteServiceHandler(
	logger *logrus.Logger,
	repo service.Repository,
	publisher infraCache.EventPublisher,
	auditService auditlogs.Service,
) Handler {
	return &deleteServiceHandler{
		logger:       logger,
		repo:         repo,
		publisher:    publisher,
		auditService: auditService,
	}
}

// Handle @Summary Delete a Service
// @Description Removes a service from a gateway
// @Tags Services
// @Param Authorization header string true "Authorization token"
// @Param gateway_id path string true "Gateway ID"
// @Param service_id path string true "Service ID"
// @Success 204 "Service deleted successfully"
// @Failure 404 {object} map[string]interface{} "Service not found"
// @Router /api/v1/gateways/{gateway_id}/services/{service_id} [delete]
func (s *deleteServiceHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	serviceID := c.Params("service_id")

	if err := s.repo.Delete(c.Context(), serviceID); err != nil {
		if errors.Is(err, service.ErrServiceIsBeingUsed) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		s.logger.WithError(err).Error("Failed to delete service")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	err := s.publisher.Publish(
		c.Context(),
		event.DeleteServiceCacheEvent{
			GatewayID: gatewayID,
			ServiceID: serviceID,
		},
	)

	if err != nil {
		s.logger.WithError(err).Error("failed to publish service cache invalidation")
	}

	s.emitAuditLog(c, serviceID, "", auditlogs.StatusSuccess, "")

	return c.SendStatus(http.StatusNoContent)
}

func (s *deleteServiceHandler) emitAuditLog(c *fiber.Ctx, targetID, targetName, status, errMsg string) {
	if s.auditService == nil {
		return
	}
	s.auditService.Emit(c, auditlogs.Event{
		Event: auditlogs.EventInfo{
			Type:         auditlogs.EventTypeServiceDeleted,
			Category:     auditlogs.CategoryRunTimeSecurity,
			Status:       status,
			ErrorMessage: errMsg,
		},
		Target: auditlogs.Target{
			Type: auditlogs.TargetTypeService,
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
