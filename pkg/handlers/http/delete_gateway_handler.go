package http

import (
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auditlogs"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type deleteGatewayHandler struct {
	logger       *logrus.Logger
	deleter      gateway.Deleter
	auditService auditlogs.Service
}

func NewDeleteGatewayHandler(
	logger *logrus.Logger,
	deleter gateway.Deleter,
	auditService auditlogs.Service,
) Handler {
	return &deleteGatewayHandler{
		logger:       logger,
		deleter:      deleter,
		auditService: auditService,
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

	if err := s.deleter.Delete(c.Context(), parsedId); err != nil {
		if domain.IsNotFoundError(err) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "gateway not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	s.emitAuditLog(c, id, "", auditlogs.StatusSuccess, "")

	return c.SendStatus(http.StatusNoContent)
}

func (s *deleteGatewayHandler) emitAuditLog(c *fiber.Ctx, targetID, targetName, status, errMsg string) {
	if s.auditService == nil {
		return
	}
	s.auditService.Emit(c, auditlogs.Event{
		Event: auditlogs.EventInfo{
			Type:         auditlogs.EventTypeGatewayDeleted,
			Category:     auditlogs.CategoryRunTimeSecurity,
			Status:       status,
			ErrorMessage: errMsg,
		},
		Target: auditlogs.Target{
			Type: auditlogs.TargetTypeGateway,
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
