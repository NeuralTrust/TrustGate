package http

import (
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/NeuralTrust/TrustGate/pkg/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type updateGatewayHandler struct {
	logger        *logrus.Logger
	repo          *database.Repository
	transformer   *gateway.OutputTransformer
	pluginManager *plugins.Manager
	publisher     infraCache.EventPublisher
}

func NewUpdateGatewayHandler(
	logger *logrus.Logger,
	repo *database.Repository,
	pluginManager *plugins.Manager,
	publisher infraCache.EventPublisher,
) Handler {
	return &updateGatewayHandler{
		logger:        logger,
		repo:          repo,
		transformer:   gateway.NewOutputTransformer(),
		pluginManager: pluginManager,
		publisher:     publisher,
	}
}

// Handle @Summary Update a Gateway
// @Description Updates an existing gateway
// @Tags Gateways
// @Accept json
// @Produce json
// @Param gateway_id path string true "Gateway ID"
// @Param gateway body object true "Updated gateway data"
// @Success 200 {object} gateway.Gateway "Gateway updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Router /api/v1/gateways/{gateway_id} [put]
func (h *updateGatewayHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")

	if err := h.validateGatewayID(gatewayID); err != nil {
		h.logger.WithError(err).WithField("gateway_id", gatewayID).Error("Invalid gateway ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	dbGateway, err := h.repo.GetGateway(c.Context(), gatewayID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get gateway")
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Gateway not found"})
	}

	var req types.UpdateGatewayRequest
	if err := c.BodyParser(&req); err != nil {
		h.logger.WithError(err).Error("Failed to bind request")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	if req.Name != nil {
		dbGateway.Name = *req.Name
	}
	if req.Status != nil {
		dbGateway.Status = *req.Status
	}

	if req.RequiredPlugins != nil {
		// Initialize plugins map
		if dbGateway.RequiredPlugins == nil {
			dbGateway.RequiredPlugins = []types.PluginConfig{}
		}

		// Convert and validate plugins
		for _, cfg := range req.RequiredPlugins {
			if err := h.pluginManager.ValidatePlugin(cfg.Name, cfg); err != nil {
				h.logger.WithError(err).WithField("plugin", cfg.Name).Error("Invalid plugin configuration")
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("Invalid plugin configuration: %v", err)})
			}
		}
	}

	dbGateway.UpdatedAt = time.Now()

	if err := h.repo.UpdateGateway(c.Context(), dbGateway); err != nil {
		h.logger.WithError(err).Error("Failed to update gateway")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update gateway"})
	}

	// Convert to response type
	apiGateway, err := h.transformer.Transform(dbGateway)
	if err != nil {
		h.logger.WithError(err).Error("Failed to convert gateway")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process gateway"})
	}

	response := types.Gateway{
		ID:              dbGateway.ID,
		Name:            dbGateway.Name,
		Subdomain:       dbGateway.Subdomain,
		Status:          dbGateway.Status,
		CreatedAt:       dbGateway.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       dbGateway.UpdatedAt.Format(time.RFC3339),
		RequiredPlugins: apiGateway.RequiredPlugins,
	}

	err = h.publisher.Publish(c.Context(), channel.GatewayEventsChannel, event.UpdateGatewayCacheEvent{
		GatewayID: dbGateway.ID,
	})
	if err != nil {
		h.logger.WithError(err).Error("Failed to publish update gateway cache event")
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

func (h *updateGatewayHandler) validateGatewayID(id string) error {
	if id == "" {
		return fmt.Errorf("gateway ID cannot be empty")
	}
	if _, err := uuid.Parse(id); err != nil {
		return fmt.Errorf("gateway ID must be a valid UUID: %v", err)
	}
	return nil
}
