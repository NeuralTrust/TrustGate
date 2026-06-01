package middleware

import (
	"context"
	"encoding/json"
	"log/slog"

	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type SessionMiddleware struct {
	logger *slog.Logger
	finder appgateway.Finder
}

func NewSessionMiddleware(logger *slog.Logger, finder appgateway.Finder) *SessionMiddleware {
	return &SessionMiddleware{logger: logger, finder: finder}
}

func (m *SessionMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		cfg := m.resolveConfig(c)
		if cfg == nil || !cfg.Enabled {
			return c.Next()
		}

		sessionID := ""
		if cfg.HeaderName != "" {
			sessionID = c.Get(cfg.HeaderName)
		}
		if sessionID == "" && cfg.BodyParamName != "" {
			sessionID = m.extractFromBody(c, cfg.BodyParamName)
		}
		if sessionID == "" {
			return c.Next()
		}

		c.Locals(string(infracontext.SessionContextKey), sessionID)
		ctx := context.WithValue(c.UserContext(), infracontext.SessionContextKey, sessionID)
		c.SetUserContext(ctx)

		return c.Next()
	}
}

func (m *SessionMiddleware) resolveConfig(c *fiber.Ctx) *domain.SessionConfig {
	rawID := c.Get(headerGatewayID)
	if rawID == "" {
		return nil
	}
	gatewayID, err := uuid.Parse(rawID)
	if err != nil {
		m.logger.Debug("session middleware: invalid gateway id header", slog.String("gateway_id", rawID))
		return nil
	}
	gw, err := m.finder.FindByID(c.UserContext(), gatewayID)
	if err != nil {
		m.logger.Debug("session middleware: gateway lookup failed", slog.String("error", err.Error()))
		return nil
	}
	if gw == nil {
		return nil
	}
	return gw.SessionConfig
}

func (m *SessionMiddleware) extractFromBody(c *fiber.Ctx, paramName string) string {
	body := c.Body()
	if len(body) == 0 {
		return ""
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		m.logger.Debug("session middleware: body is not valid JSON, skipping body param lookup")
		return ""
	}

	if v, ok := raw[paramName]; ok && v != nil {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}
