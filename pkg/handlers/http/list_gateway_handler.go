package http

import (
	"context"
	"strconv"

	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type listGatewayHandler struct {
	logger             *logrus.Logger
	repo               *database.Repository
	updateGatewayCache gateway.UpdateGatewayCache
	transformer        *gateway.OutputTransformer
}

func NewListGatewayHandler(
	logger *logrus.Logger,
	repo *database.Repository,
	updateGatewayCache gateway.UpdateGatewayCache,
) Handler {
	return &listGatewayHandler{
		logger:             logger,
		repo:               repo,
		updateGatewayCache: updateGatewayCache,
		transformer:        gateway.NewOutputTransformer(),
	}
}

// Handle @Summary      List all Gateways
// @Description  Retrieves a list of all gateways in the system
// @Tags         Gateways
// @Param        Authorization header string true "Authorization token"
// @Produce      json
// @Success      200 {array} gateway.Gateway "List of gateways"
// @Failure      500 {object} map[string]interface{} "Internal server error"
// @Router       /api/v1/gateways [get]
func (h *listGatewayHandler) Handle(c *fiber.Ctx) error {
	offset := 0
	limit := 10

	if offsetStr := c.Query("offset"); offsetStr != "" {
		if val, err := strconv.Atoi(offsetStr); err == nil {
			offset = val
		}
	}
	if limitStr := c.Query("limit"); limitStr != "" {
		if val, err := strconv.Atoi(limitStr); err == nil && val > 0 && val <= 100 {
			limit = val
		}
	}

	dbGateways, err := h.repo.ListGateways(c.Context(), offset, limit)
	if err != nil {
		h.logger.WithError(err).Error("failed to list gateways")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list gateways"})
	}

	var gateways []types.Gateway
	for _, dbGateway := range dbGateways {
		output := h.transformer.Transform(&dbGateway)
		gateways = append(gateways, *output)
		go func(g domain.Gateway) {
			ctx := context.Background()
			if err := h.updateGatewayCache.Update(ctx, &g); err != nil {
				h.logger.WithError(err).Error("failed to update gateway cache")
			}
		}(dbGateway)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"gateways": gateways,
		"count":    len(gateways),
		"offset":   offset,
		"limit":    limit,
	})
}
