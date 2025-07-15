package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/domain/apikey"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type listAPIKeysHandler struct {
	logger      *logrus.Logger
	gatewayRepo gateway.Repository
	apiKeyRepo  apikey.Repository
}

func NewListAPIKeysHandler(logger *logrus.Logger, gatewayRepo gateway.Repository, apiKeyRepo apikey.Repository) Handler {
	return &listAPIKeysHandler{
		logger:      logger,
		gatewayRepo: gatewayRepo,
		apiKeyRepo:  apiKeyRepo,
	}
}

func (s *listAPIKeysHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	gatewayUUID, err := uuid.Parse(gatewayID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway_id"})
	}

	// Verify gateway exists
	if _, err := s.gatewayRepo.Get(c.Context(), gatewayUUID); err != nil {
		s.logger.WithError(err).Error("failed to get gateway")
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "gateway not found"})
	}

	apiKeys, err := s.apiKeyRepo.List(c.Context(), gatewayUUID)
	if err != nil {
		s.logger.WithError(err).Error("failed to list API keys")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list API keys"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"api_keys": apiKeys,
		"count":    len(apiKeys),
	})
}
