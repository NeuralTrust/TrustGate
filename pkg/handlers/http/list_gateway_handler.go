package http

import (
	"context"
	"strconv"

	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	gateway2 "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
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
		h.logger.WithError(err).Error("Failed to list gateways")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to list gateways"})
	}

	var gateways []types.Gateway
	for _, dbGateway := range dbGateways {
		output, err := h.transformer.Transform(&dbGateway)
		if err != nil {
			h.logger.WithError(err).Error("Failed to convert gateway")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process gateway configuration"})
		}
		gateways = append(gateways, *output)

		// Update cache in background
		go func(g gateway2.Gateway) {
			ctx := context.Background()
			if err := h.updateGatewayCache.Update(ctx, &g); err != nil {
				h.logger.WithError(err).Error("Failed to update gateway cache")
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
