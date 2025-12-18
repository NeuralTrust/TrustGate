package http

import (
	"errors"
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type deleteServiceHandler struct {
	logger    *logrus.Logger
	repo      service.Repository
	publisher infraCache.EventPublisher
}

func NewDeleteServiceHandler(
	logger *logrus.Logger,
	repo service.Repository,
	publisher infraCache.EventPublisher,
) Handler {
	return &deleteServiceHandler{
		logger:    logger,
		repo:      repo,
		publisher: publisher,
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

	return c.SendStatus(http.StatusNoContent)
}
