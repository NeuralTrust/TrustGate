package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/gofiber/fiber/v2"
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

func (s *listAPIKeysHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")

	// Verify gateway exists
	if _, err := s.repo.GetGateway(c.Context(), gatewayID); err != nil {
		s.logger.WithError(err).Error("Failed to get gateway")
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Gateway not found"})
	}

	// Get API keys from database
	apiKeys, err := s.repo.ListAPIKeys(c.Context(), gatewayID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to list API keys")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to list API keys"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"api_keys": apiKeys,
		"count":    len(apiKeys),
	})
}
