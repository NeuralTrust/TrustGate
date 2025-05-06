package middleware

import (
	"context"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/app/apikey"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/sirupsen/logrus"
)

const trustgateAuthHeader = "X-TG-API-Key"

type authMiddleware struct {
	skipAuthCheck bool
	logger        *logrus.Logger
	finder        apikey.Finder
}

func NewAuthMiddleware(logger *logrus.Logger, finder apikey.Finder, skipAuthCheck bool) Middleware {
	return &authMiddleware{
		skipAuthCheck: skipAuthCheck,
		logger:        logger,
		finder:        finder,
	}
}

func (m *authMiddleware) Middleware() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		if !m.skipAuthCheck {
			isPublic := m.isPublicRoute(ctx)
			if isPublic {
				return ctx.Next()
			}
		}
		// Skip validation for system endpoints
		if strings.HasPrefix(ctx.Path(), "/__/") {
			return ctx.Next()
		}

		// Extract API key from X-Api-Key header first, then fallback to Authorization header
		m.logger.WithField("headers", ctx.GetReqHeaders()).Debug("Extracting API key from headers")
		apiKey := ctx.Get(trustgateAuthHeader)
		if apiKey == "" {
			m.logger.Debug("No API key provided")
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "API key required"})
		}

		// Get gateway ID from context
		gatewayID, ok := ctx.Locals(common.GatewayContextKey).(string)
		if !ok || gatewayID == "" {
			m.logger.Error("missing or invalid gateway in context ID")
			return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid or missing gateway ID"})
		}

		// Validate API key
		key, err := m.finder.Find(ctx.Context(), gatewayID, apiKey)
		if err != nil {
			m.logger.WithError(err).Error("error retrieving apikey")
			return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "invalid API key"})
		}

		if !key.IsValid() {
			m.logger.Debug("Invalid API key")
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid API key"})
		}

		// Initialize metadata map
		metadata := map[string]interface{}{
			string(common.ApiKeyContextKey):  apiKey,
			string(common.GatewayContextKey): gatewayID,
		}

		// Store in context
		ctx.Locals(common.ApiKeyContextKey, apiKey)
		ctx.Locals(common.ApiKeyIdContextKey, key.ID.String())
		ctx.Locals(common.MetadataKey, metadata)

		c := context.WithValue(ctx.Context(), common.ApiKeyContextKey, apiKey)
		c = context.WithValue(c, common.MetadataKey, metadata)
		c = context.WithValue(c, common.ApiKeyIdContextKey, key.ID.String())

		ctx.SetUserContext(c)

		return ctx.Next()
	}
}

func (m *authMiddleware) isPublicRoute(ctx *fiber.Ctx) bool {
	path := ctx.Path()
	if strings.HasPrefix(path, "/__/") || path == "/health" {
		return true
	}
	// Get gateway data from context
	gatewayData := ctx.Locals(string(common.GatewayDataContextKey))
	if gatewayData == "" {
		return false
	}
	// Check if the route is marked as public in the gateway rules
	if data, ok := gatewayData.(*types.GatewayData); ok {
		for _, rule := range data.Rules {
			if rule.Path == path && rule.Public {
				return true
			}
		}
	}
	return false
}
