package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/domain/session"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type sessionMiddleware struct {
	logger     *logrus.Logger
	repository session.Repository
}

func NewSessionMiddleware(
	logger *logrus.Logger,
	repository session.Repository,
) Middleware {
	return &sessionMiddleware{
		logger:     logger,
		repository: repository,
	}
}

func (m *sessionMiddleware) Middleware() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		gatewayData, ok := ctx.Locals(string(common.GatewayDataContextKey)).(*types.GatewayData)
		if !ok {
			return ctx.Next()
		}

		if gatewayData.Gateway.SessionConfig == nil || !gatewayData.Gateway.SessionConfig.Enabled {
			return ctx.Next()
		}

		gatewayIDStr, ok := ctx.Locals(common.GatewayContextKey).(string)
		if !ok {
			return ctx.Next()
		}

		gatewayID, err := uuid.Parse(gatewayIDStr)
		if err != nil {
			m.logger.WithError(err).Error("failed to parse gateway ID")
			return ctx.Next()
		}

		sessionID := m.getSessionID(ctx, gatewayData.Gateway.SessionConfig)
		if sessionID == "" {
			return ctx.Next()
		}

		ctx.Locals(common.SessionContextKey, sessionID)
		c := context.WithValue(ctx.Context(), common.SessionContextKey, sessionID)
		ctx.SetUserContext(c)

		content := m.extractContent(ctx, gatewayData.Gateway.SessionConfig.Mapping)

		ttl := time.Duration(gatewayData.Gateway.SessionConfig.TTL) * time.Second
		sess := session.NewSession(sessionID, gatewayID, content, ttl)

		if err := m.repository.Save(ctx.Context(), sess); err != nil {
			m.logger.WithError(err).Error("failed to save session")
		}

		return ctx.Next()
	}
}

func (m *sessionMiddleware) getSessionID(ctx *fiber.Ctx, config *types.SessionConfig) string {
	if sessionID := ctx.Get(config.HeaderName); sessionID != "" {
		return sessionID
	}
	var body map[string]any
	if err := ctx.BodyParser(&body); err != nil {
		return ""
	}
	if id, ok := body[config.BodyParamName].(string); ok {
		return id
	}
	return ""
}

func (m *sessionMiddleware) extractContent(ctx *fiber.Ctx, mapping string) string {
	if mapping == "" {
		return string(ctx.Body())
	}

	var body map[string]interface{}
	if err := json.Unmarshal(ctx.Body(), &body); err != nil {
		m.logger.WithError(err).Debug("failed to parse request body")
		return string(ctx.Body())
	}

	if value, ok := body[mapping]; ok {
		switch v := value.(type) {
		case string:
			return v
		default:
			if jsonBytes, err := json.Marshal(v); err == nil {
				return string(jsonBytes)
			}
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}
