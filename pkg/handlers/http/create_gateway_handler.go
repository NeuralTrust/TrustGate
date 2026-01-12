package http

import (
	"errors"

	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auditlogs"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type createGatewayHandler struct {
	logger       *logrus.Logger
	creator      gateway.Creator
	auditService auditlogs.Service
}

func NewCreateGatewayHandler(
	logger *logrus.Logger,
	creator gateway.Creator,
	auditService auditlogs.Service,
) Handler {
	return &createGatewayHandler{
		logger:       logger,
		creator:      creator,
		auditService: auditService,
	}
}

// Handle @Summary      Create a new GatewayDTO
// @Description  Creates a new gateway in the system
// @Tags         Gateways
// @Accept       json
// @Produce      json
// @Param        Authorization header string true "Authorization token"
// @Param        gateway body request.CreateGatewayRequest true "GatewayDTO data"
// @Success      201 {object} gateway.Gateway "GatewayDTO created successfully"
// @Failure      400 {object} map[string]interface{} "Invalid request data"
// @Router       /api/v1/gateways [post]
func (h *createGatewayHandler) Handle(c *fiber.Ctx) error {
	var req request.CreateGatewayRequest
	if err := c.BodyParser(&req); err != nil {
		h.logger.WithError(err).Error("Failed to bind request")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	if err := req.Validate(); err != nil {
		h.logger.WithError(err).Error("invalid request data")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	gatewayId, _ := c.Locals(common.GatewayContextKey).(string)

	entity, err := h.creator.Create(c.Context(), &req, gatewayId)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create gateway")
		if isValidationError(err) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	h.emitAuditLog(c, entity.ID.String(), entity.Name, auditlogs.StatusSuccess, "")

	return c.Status(fiber.StatusCreated).JSON(entity)
}

func (h *createGatewayHandler) emitAuditLog(c *fiber.Ctx, targetID, targetName, status, errMsg string) {
	if h.auditService == nil {
		return
	}
	h.auditService.Emit(c, auditlogs.Event{
		Event: auditlogs.EventInfo{
			Type:         auditlogs.EventTypeGatewayCreated,
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

func isValidationError(err error) bool {
	return errors.Is(err, types.ErrRequiredPluginNotFound) ||
		errors.Is(err, types.ErrDuplicateTelemetryExporter) ||
		errors.Is(err, types.ErrTelemetryValidation) ||
		errors.Is(err, types.ErrUnknownPlugin) ||
		errors.Is(err, types.ErrPluginChainValidation)
}
