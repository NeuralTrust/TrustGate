package http

import (
	appService "github.com/NeuralTrust/TrustGate/pkg/app/service"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	req "github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auditlogs"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type updateServiceHandler struct {
	logger       *logrus.Logger
	updater      appService.Updater
	auditService auditlogs.Service
}

func NewUpdateServiceHandler(logger *logrus.Logger, updater appService.Updater, auditService auditlogs.Service) Handler {
	return &updateServiceHandler{
		logger:       logger,
		updater:      updater,
		auditService: auditService,
	}
}

// Handle @Summary Update a Service
// @Description Updates an existing service
// @Tags Services
// @Accept json
// @Produce json
// @Param Authorization header string true "Authorization token"
// @Param gateway_id path string true "Gateway ID"
// @Param service_id path string true "Service ID"
// @Param service body req.ServiceRequest true "Updated service data"
// @Success 200 {object} service.Service "Service updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Failure 404 {object} map[string]interface{} "Service not found"
// @Router /api/v1/gateways/{gateway_id}/services/{service_id} [put]
func (h *updateServiceHandler) Handle(c *fiber.Ctx) error {
	gatewayUUID, err := uuid.Parse(c.Params("gateway_id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway ID"})
	}

	serviceUUID, err := uuid.Parse(c.Params("service_id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid service ID"})
	}

	var r req.ServiceRequest
	if err := c.BodyParser(&r); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	if err := r.Validate(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	s, err := h.updater.Update(c.Context(), gatewayUUID, serviceUUID, &r)
	if err != nil {
		if domain.IsNotFoundError(err) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "service not found"})
		}
		h.logger.WithError(err).Error("failed to update service")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	h.emitAuditLog(c, s.ID.String(), s.Name, auditlogs.StatusSuccess, "")

	return c.Status(fiber.StatusOK).JSON(s)
}

func (h *updateServiceHandler) emitAuditLog(c *fiber.Ctx, targetID, targetName, status, errMsg string) {
	if h.auditService == nil {
		return
	}
	h.auditService.Emit(c, auditlogs.Event{
		Event: auditlogs.EventInfo{
			Type:         auditlogs.EventTypeServiceUpdated,
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
