package middleware

import (
	"context"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/apikey"
	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/gofiber/fiber/v2"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/sirupsen/logrus"
)

const trustgateAuthHeader = "X-TG-API-Key"

type authMiddleware struct {
	logger        *logrus.Logger
	keyFinder     apikey.Finder
	gatewayFinder gateway.DataFinder
}

func NewAuthMiddleware(
	logger *logrus.Logger,
	keyFinder apikey.Finder,
	gatewayFinder gateway.DataFinder,
) Middleware {
	return &authMiddleware{
		logger:        logger,
		keyFinder:     keyFinder,
		gatewayFinder: gatewayFinder,
	}
}

func (m *authMiddleware) Middleware() fiber.Handler {
	return func(ctx *fiber.Ctx) error {

		apiKey := ctx.Get(trustgateAuthHeader)
		if apiKey == "" {
			m.logger.Debug("no api key provided")
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "API key required"})
		}
		// Validate API key
		key, err := m.keyFinder.Find(ctx.Context(), apiKey)
		if err != nil {
			m.logger.WithError(err).Error("error retrieving apikey")
			return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "invalid API key"})
		}

		if !key.IsValid() {
			m.logger.Debug("Invalid API key")
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid API key"})
		}

		ctx.Locals(common.LatencyContextKey, time.Now())
		c := context.WithValue(ctx.Context(), common.LatencyContextKey, time.Now())
		ctx.SetUserContext(c)

		gatewayData, err := m.gatewayFinder.Find(ctx.Context(), key.GatewayID)
		if err != nil {
			m.logger.WithError(err).Error("failed to fetch gateway data")
			return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch gateway data"})
		}

		// Initialize metadata map
		metadata := map[string]interface{}{
			string(common.ApiKeyContextKey):  apiKey,
			string(common.GatewayContextKey): key.GatewayID.String(),
		}

		// Store in context
		ctx.Locals(common.ApiKeyContextKey, apiKey)
		ctx.Locals(common.ApiKeyIdContextKey, key.ID.String())
		ctx.Locals(common.MetadataKey, metadata)
		ctx.Locals(common.GatewayContextKey, key.GatewayID.String())
		//nolint
		ctx.Locals(string(common.GatewayDataContextKey), gatewayData)

		c = context.WithValue(ctx.Context(), common.ApiKeyContextKey, apiKey)
		c = context.WithValue(c, common.MetadataKey, metadata)
		c = context.WithValue(c, common.ApiKeyIdContextKey, key.ID.String())
		c = context.WithValue(c, common.GatewayContextKey, key.GatewayID.String())
		//nolint
		c = context.WithValue(c, string(common.GatewayDataContextKey), gatewayData)

		ctx.SetUserContext(c)

		return ctx.Next()
	}
}
