package middleware

import (
	"context"
	"encoding/json"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type sessionMiddleware struct {
	logger *logrus.Logger
}

func NewSessionMiddleware(logger *logrus.Logger) Middleware {
	return &sessionMiddleware{logger: logger}
}

func (m *sessionMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		rule := GetMatchedRuleFromFiber(c, m.logger)
		if rule == nil || rule.SessionConfig == nil {
			return c.Next()
		}

		cfg := rule.SessionConfig
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

		c.Locals(common.SessionContextKey, sessionID)
		ctx := context.WithValue(c.Context(), common.SessionContextKey, sessionID)
		c.SetUserContext(ctx)

		return c.Next()
	}
}

func (m *sessionMiddleware) extractFromBody(c *fiber.Ctx, paramName string) string {
	if paramName == "" {
		return ""
	}
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
