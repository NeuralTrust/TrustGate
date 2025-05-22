package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type listAPIKeysHandler struct {
	logger *logrus.Logger
	repo   *database.Repository
}

func NewListAPIKeysHandler(logger *logrus.Logger, repo *database.Repository) Handler {
	return &listAPIKeysHandler{
		logger: logger,
		repo:   repo,
	}
}

// Handle @Summary Retrieve all API Keys
// @Description Returns a list of all API keys for a gateway
// @Tags API Keys
// @Param Authorization header string true "Authorization token"
// @Produce json
// @Param gateway_id path string true "Gateway ID"
// @Success 200 {array} apikey.APIKey "List of API Keys"
// @Failure 404 {object} map[string]interface{} "Gateway not found"
// @Router /api/v1/gateways/{gateway_id}/keys [get]
func (s *listAPIKeysHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	gatewayUUID, err := uuid.Parse(gatewayID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway_id"})
	}

	// Verify gateway exists
	if _, err := s.repo.GetGateway(c.Context(), gatewayUUID); err != nil {
		s.logger.WithError(err).Error("failed to get gateway")
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "gateway not found"})
	}

	apiKeys, err := s.repo.ListAPIKeys(c.Context(), gatewayUUID)
	if err != nil {
		s.logger.WithError(err).Error("failed to list API keys")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list API keys"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"api_keys": apiKeys,
		"count":    len(apiKeys),
	})
}
