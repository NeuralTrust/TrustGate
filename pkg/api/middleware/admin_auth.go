// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package middleware

import (
	"log/slog"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/helpers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
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
			return m.unauthorized(c, "Authorization required", nil)
		}
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			return m.unauthorized(c, "Invalid authorization format", nil)
		}

		tokenString := strings.TrimPrefix(authHeader, bearerPrefix)
		if tokenString == "" {
			return m.unauthorized(c, "Empty token provided", nil)
		}

		if err := m.jwtManager.ValidateToken(tokenString); err != nil {
			return m.unauthorized(c, "Invalid token", err)
		}

		claims, err := m.jwtManager.DecodeToken(tokenString)
		if err != nil {
			return m.unauthorized(c, "Invalid token", err)
		}

		// Purpose-tagged tokens (e.g. playground) are scoped to other planes
		// and must never grant admin access.
		if claims.Purpose != "" {
			return m.unauthorized(c, "Token not valid for admin API", nil)
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

func (m *AdminAuthMiddleware) unauthorized(c *fiber.Ctx, message string, err error) error {
	m.logAuthFailure(c, message, err)
	return c.Status(fiber.StatusUnauthorized).JSON(helpers.ErrorBody{
		Error:   "unauthorized",
		Message: message,
	})
}

func (m *AdminAuthMiddleware) logAuthFailure(c *fiber.Ctx, reason string, err error) {
	if m.logger == nil {
		return
	}
	attrs := []slog.Attr{
		slog.String("reason", reason),
		slog.String("method", c.Method()),
		slog.String("path", c.Path()),
		slog.String("request_id", c.Get(fiber.HeaderXRequestID)),
	}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	m.logger.LogAttrs(c.UserContext(), slog.LevelDebug, "admin auth failed", attrs...)
}
