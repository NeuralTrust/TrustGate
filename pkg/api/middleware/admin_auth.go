package middleware

import (
	"log/slog"
	"strings"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/auth/jwt"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
)

const (
	authorizationHeader = "Authorization"
	bearerPrefix        = "Bearer "
)

type AdminAuthMiddleware struct {
	logger     *slog.Logger
	jwtManager jwt.Manager
}

func NewAdminAuthMiddleware(logger *slog.Logger, jwtManager jwt.Manager) *AdminAuthMiddleware {
	return &AdminAuthMiddleware{logger: logger, jwtManager: jwtManager}
}

func (m *AdminAuthMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get(authorizationHeader)
		if authHeader == "" {
			return unauthorized(c, "Authorization required")
		}
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			return unauthorized(c, "Invalid authorization format")
		}

		tokenString := strings.TrimPrefix(authHeader, bearerPrefix)
		if tokenString == "" {
			return unauthorized(c, "Empty token provided")
		}

		if err := m.jwtManager.ValidateToken(tokenString); err != nil {
			m.logger.Debug("admin auth: invalid token", slog.String("error", err.Error()))
			return unauthorized(c, "Invalid token")
		}

		claims, err := m.jwtManager.DecodeToken(tokenString)
		if err != nil {
			m.logger.Debug("admin auth: failed to decode token", slog.String("error", err.Error()))
			return unauthorized(c, "Invalid token")
		}

		if claims.TeamID != "" {
			c.Locals(string(infracontext.TeamIDContextKey), claims.TeamID)
		}
		if claims.UserID != "" {
			c.Locals(string(infracontext.UserIDContextKey), claims.UserID)
		}
		if claims.UserEmail != "" {
			c.Locals(string(infracontext.UserEmailContextKey), claims.UserEmail)
		}

		return c.Next()
	}
}

func unauthorized(c *fiber.Ctx, message string) error {
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": message})
}
