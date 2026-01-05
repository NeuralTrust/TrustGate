package middleware

import (
	"context"
	"net/url"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	infra "github.com/NeuralTrust/TrustGate/pkg/infra/websocket"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type websocketMiddleware struct {
	config    *config.Config
	logger    *logrus.Logger
	semaphore *infra.Semaphore
}

func NewWebsocketMiddleware(
	config *config.Config,
	logger *logrus.Logger,
) Middleware {
	semaphore := infra.NewSemaphore(infra.WithMaxConnections(config.WebSocket.MaxConnections))
	return &websocketMiddleware{
		config:    config,
		logger:    logger,
		semaphore: semaphore,
	}
}

func (m *websocketMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if strings.Contains(c.Path(), "/ws") {
			if websocket.IsWebSocketUpgrade(c) {
				if !m.semaphore.Acquire() {
					m.logger.Warn("maximum webSocket connections reached, rejecting connection")
					return fiber.ErrTooManyRequests
				}
				c.Locals("ws_semaphore", m.semaphore)

				gatewayID, ok := c.Locals(common.GatewayContextKey).(string)
				if !ok || gatewayID == "" {
					m.logger.Error("missing or invalid gateway in context ID")
					return fiber.ErrInternalServerError
				}

				reqCtx := &types.RequestContext{
					Context:   c.Context(),
					GatewayID: gatewayID,
					Headers:   make(map[string][]string),
					Method:    c.Method(),
					Path:      c.Path(),
					Query:     m.getQueryParams(c),
					Body:      c.Body(),
				}
				for key, values := range c.GetReqHeaders() {
					if strings.Contains(strings.ToLower(key), "sec-websocket") {
						continue
					}
					if strings.Contains(strings.ToLower(key), "connection") {
						continue
					}
					if strings.Contains(strings.ToLower(key), "upgrade") {
						continue
					}
					reqCtx.Headers[key] = values
				}
				if interactionId, ok := c.Locals(common.InteractionIDHeader).(string); ok && interactionId != "" {
					reqCtx.Headers[common.InteractionIDHeader] = []string{interactionId}
				}

				c.Locals(string(common.WsRequestContextContextKey), reqCtx)
				//nolint
				ctx := context.WithValue(c.Context(), string(common.GatewayContextKey), gatewayID)
				c.SetUserContext(ctx)

				return c.Next()
			}
			return fiber.ErrUpgradeRequired
		}
		return c.Next()
	}
}

func (m *websocketMiddleware) getQueryParams(c *fiber.Ctx) url.Values {
	queryParams := make(url.Values)
	c.Request().URI().QueryArgs().VisitAll(func(k, v []byte) {
		queryParams.Set(string(k), string(v))
	})
	return queryParams
}
