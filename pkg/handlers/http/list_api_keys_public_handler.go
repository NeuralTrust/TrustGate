package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/iam/apikey"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type listAPIKeysPublicHandler struct {
	logger      *logrus.Logger
	gatewayRepo gateway.Repository
	apiKeyRepo  apikey.Repository
}

func NewListAPIKeysPublicHandler(logger *logrus.Logger, gatewayRepo gateway.Repository, apiKeyRepo apikey.Repository) Handler {
	return &listAPIKeysPublicHandler{
		logger:      logger,
		gatewayRepo: gatewayRepo,
		apiKeyRepo:  apiKeyRepo,
	}
}

// Handle @Summary Retrieve all API Keys with obfuscated keys
// @Description Returns a list of all API keys for a gateway with obfuscated key values
// @Tags API Keys
// @Param Authorization header string true "Authorization token"
// @Produce json
// @Param gateway_id path string true "Gateway ID"
// @Success 200 {array} apikey.APIKey "List of API Keys with obfuscated keys"
// @Failure 404 {object} map[string]interface{} "Gateway not found"
// @Router /api/v1/iam/api-key/public [get]
func (s *listAPIKeysPublicHandler) Handle(c *fiber.Ctx) error {
	subjectID := c.Query("subject_id")

	if subjectID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "subject_id query parameter is required"})
	}
	subjectUUID, err := uuid.Parse(subjectID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid subject_id"})
	}

	if _, err := s.gatewayRepo.Get(c.Context(), subjectUUID); err != nil {
		s.logger.WithError(err).Error("failed to get gateway")
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "gateway not found"})
	}

	apiKeys, err := s.apiKeyRepo.ListWithSubject(c.Context(), subjectUUID)
	if err != nil {
		s.logger.WithError(err).Error("failed to list API keys")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list API keys"})
	}

	obfuscatedAPIKeys := make([]apikey.APIKey, len(apiKeys))
	for i, key := range apiKeys {
		obfuscatedKey := key
		obfuscatedKey.Key = s.obfuscateKey(key.Key)
		obfuscatedAPIKeys[i] = obfuscatedKey
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"api_keys": obfuscatedAPIKeys,
		"count":    len(obfuscatedAPIKeys),
	})
}

func (s *listAPIKeysPublicHandler) obfuscateKey(key string) string {
	if len(key) <= 5 {
		return key // Return the original key if it's too short to obfuscate
	}

	return key[:2] + "..." + key[len(key)-3:]
}
