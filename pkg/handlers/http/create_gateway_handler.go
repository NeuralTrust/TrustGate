package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type createGatewayHandler struct {
	logger   *logrus.Logger
	creator  gateway.Creator
}

func NewCreateGatewayHandler(
	logger *logrus.Logger,
	creator gateway.Creator,
) Handler {
	return &createGatewayHandler{
		logger:  logger,
		creator: creator,
	}
}

// Handle @Summary      Create a new Gateway
// @Description  Creates a new gateway in the system
// @Tags         Gateways
// @Accept       json
// @Produce      json
// @Param        Authorization header string true "Authorization token"
// @Param        gateway body request.CreateGatewayRequest true "Gateway data"
// @Success      201 {object} gateway.Gateway "Gateway created successfully"
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
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusCreated).JSON(entity)
}
