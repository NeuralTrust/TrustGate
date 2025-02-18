package middleware

import (
	"context"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/database"

	"github.com/sirupsen/logrus"
)

type AuthMiddleware struct {
	logger *logrus.Logger
	db     *database.Repository
}

func NewAuthMiddleware(logger *logrus.Logger, repo *database.Repository) *AuthMiddleware {
	return &AuthMiddleware{
		logger: logger,
		db:     repo,
	}
}

func (m *AuthMiddleware) ValidateAPIKey() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		// Skip validation for system endpoints
		if strings.HasPrefix(ctx.Path(), "/__/") {
			return ctx.Next()
		}

		// Extract API key from X-Api-Key header first, then fallback to Authorization header
		m.logger.WithField("headers", ctx.GetReqHeaders()).Debug("Extracting API key from headers")
		apiKey := ctx.Get("X-Api-Key")
		if apiKey == "" {
			authHeader := ctx.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				apiKey = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if apiKey == "" {
			m.logger.Debug("No API key provided")
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "API key required"})
		}

		// Get gateway ID from context
		gatewayID := ctx.Locals(common.GatewayContextKey).(string)
		if gatewayID == "" {
			return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway ID"})
		}

		// Validate API key
		valid, err := m.db.ValidateAPIKey(context.Background(), gatewayID, apiKey)
		if err != nil {
			m.logger.WithError(err).Error("Database error during API key validation")
			return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
		}

		if !valid {
			m.logger.Debug("Invalid API key")
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid API key"})
		}

		// Initialize metadata map
		metadata := map[string]interface{}{
			"api_key":    apiKey,
			"gateway_id": gatewayID,
		}

		// Store in context
		ctx.Locals("api_key", apiKey)
		ctx.Locals("metadata", metadata)

		return ctx.Next()
	}
}

// Add helper function for safe type assertions
func getContextValue[T any](ctx context.Context, key interface{}) (T, error) {
	value := ctx.Value(key)
	if value == nil {
		var zero T
		return zero, fmt.Errorf("value not found in context for key: %v", key)
	}
	result, ok := value.(T)
	if !ok {
		var zero T
		return zero, fmt.Errorf("invalid type assertion for key: %v", key)
	}
	return result, nil
}
