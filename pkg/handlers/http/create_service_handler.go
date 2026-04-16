package http

import (
	appService "github.com/NeuralTrust/TrustGate/pkg/app/service"
	req "github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auditlogs"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type createServiceHandler struct {
	logger       *logrus.Logger
	creator      appService.Creator
	auditService auditlogs.Service
}

// NewCreateServiceHandler @Summary Create a new Service
// @Description Adds a new service under a gateway
// @Tags Services
// @Accept json
// @Produce json
// @Param Authorization header string true "Authorization token"
// @Param gateway_id path string true "Gateway ID"
// @Param service body req.ServiceRequest true "Service request body"
// @Success 201 {object} service.Service "Service created successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /api/v1/gateways/{gateway_id}/services [post]
func NewCreateServiceHandler(logger *logrus.Logger, creator appService.Creator, auditService auditlogs.Service) Handler {
	return &createServiceHandler{
		logger:       logger,
		creator:      creator,
		auditService: auditService,
	}
}

func (h *createServiceHandler) Handle(c *fiber.Ctx) error {
	gatewayUUID, err := uuid.Parse(c.Params("gateway_id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid gateway ID"})
	}

	var r req.ServiceRequest
	if err := c.BodyParser(&r); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	if err := r.Validate(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	s, err := h.creator.Create(c.Context(), gatewayUUID, &r)
	if err != nil {
		h.logger.WithError(err).Error("failed to create service")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	h.emitAuditLog(c, s.ID.String(), s.Name, auditlogs.StatusSuccess, "")

	return c.Status(fiber.StatusCreated).JSON(s)
}

func (h *createServiceHandler) emitAuditLog(c *fiber.Ctx, targetID, targetName, status, errMsg string) {
	if h.auditService == nil {
		return
	}
	h.auditService.Emit(c, auditlogs.Event{
		Event: auditlogs.EventInfo{
			Type:         auditlogs.EventTypeServiceCreated,
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
