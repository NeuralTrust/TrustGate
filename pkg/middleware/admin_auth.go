package middleware

import (
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

const authorizationHeader = "Authorization"
const bearerPrefix = "Bearer "

type adminAuthMiddleware struct {
	logger     *logrus.Logger
	jwtManager jwt.Manager
}

func NewAdminAuthMiddleware(
	logger *logrus.Logger,
	jwtManager jwt.Manager,
) Middleware {
	return &adminAuthMiddleware{
		logger:     logger,
		jwtManager: jwtManager,
	}
}

func (m *adminAuthMiddleware) Middleware() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		authHeader := ctx.Get(authorizationHeader)
		if authHeader == "" {
			m.logger.Debug("no authorization header provided")
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Authorization required"})
		}
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			m.logger.Debug("invalid authorization header format")
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid authorization format"})
		}

		tokenString := strings.TrimPrefix(authHeader, bearerPrefix)
		if tokenString == "" {
			m.logger.Debug("empty token provided")
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Empty token provided"})
		}

		err := m.jwtManager.ValidateToken(tokenString)
		if err != nil {
			m.logger.WithError(err).Debug("invalid token")
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"})
		}

		return ctx.Next()
	}
}
