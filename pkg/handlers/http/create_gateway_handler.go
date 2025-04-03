package http

import (
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/app/plugin"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type createGatewayHandler struct {
	logger               *logrus.Logger
	repo                 domain.Repository
	updateGatewayCache   gateway.UpdateGatewayCache
	pluginChainValidator plugin.ValidatePluginChain
}

func NewCreateGatewayHandler(
	logger *logrus.Logger,
	repo domain.Repository,
	updateGatewayCache gateway.UpdateGatewayCache,
	pluginChainValidator plugin.ValidatePluginChain,
) Handler {
	return &createGatewayHandler{
		logger:               logger,
		repo:                 repo,
		updateGatewayCache:   updateGatewayCache,
		pluginChainValidator: pluginChainValidator,
	}
}

// Handle @Summary      Create a new Gateway
// @Description  Creates a new gateway in the system
// @Tags         Gateways
// @Accept       json
// @Produce      json
// @Param        gateway body types.CreateGatewayRequest true "Gateway data"
// @Success      201 {object} gateway.Gateway "Gateway created successfully"
// @Failure      400 {object} map[string]interface{} "Invalid request data"
// @Router       /api/v1/gateways [post]
func (h *createGatewayHandler) Handle(c *fiber.Ctx) error {

	var req types.CreateGatewayRequest
	if err := c.BodyParser(&req); err != nil {
		h.logger.WithError(err).Error("Failed to bind request")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	now := time.Now()
	req.CreatedAt = now
	req.UpdatedAt = now

	entity := domain.Gateway{
		ID:              uuid.New(),
		Name:            req.Name,
		Subdomain:       req.Subdomain,
		Status:          req.Status,
		RequiredPlugins: req.RequiredPlugins,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.UpdatedAt,
	}

	err := h.pluginChainValidator.Validate(entity.RequiredPlugins)
	if err != nil {
		h.logger.WithError(err).Error("failed to validate plugin chain")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	if err := h.repo.Save(c.Context(), &entity); err != nil {
		h.logger.WithError(err).Error("Failed to create gateway")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	if err := h.updateGatewayCache.Update(c.Context(), &entity); err != nil {
		h.logger.WithError(err).Error("Failed to update gateway cache")
	}

	return c.Status(fiber.StatusCreated).JSON(entity)
}
