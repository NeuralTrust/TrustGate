package middleware

import (
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type pluginMiddleware struct {
	logger *logrus.Logger
}

func NewPluginChainMiddleware(
	logger *logrus.Logger,
) Middleware {
	return &pluginMiddleware{
		logger: logger,
	}
}

func (m *pluginMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		gatewayData := c.Locals(common.GatewayDataContextKey)
		_, ok := gatewayData.(*types.GatewayData)
		if !ok {
			m.logger.Error("gateway data not found in context")
			return c.Status(fiber.StatusInternalServerError).JSON(
				fiber.Map{"error": "failed to get gateway data from context"},
			)
		}
		return c.Next()
	}

}
