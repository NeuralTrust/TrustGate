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
	"context"
	"encoding/json"
	"log/slog"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

const defaultSessionHeader = "X-Session-Id"

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
		if !cfg.IsEnabled() {
			return c.Next()
		}

		headerName := defaultSessionHeader
		bodyParam := ""
		if cfg != nil {
			if cfg.HeaderName != "" {
				headerName = cfg.HeaderName
			}
			bodyParam = cfg.BodyParamName
		}

		sessionID := c.Get(headerName)
		if sessionID == "" && bodyParam != "" {
			sessionID = m.extractFromBody(c, bodyParam)
		}

		generated := false
		if sessionID == "" {
			sessionID = m.generateSessionID()
			generated = true
		}

		c.Locals(string(infracontext.SessionContextKey), sessionID)
		ctx := context.WithValue(c.UserContext(), infracontext.SessionContextKey, sessionID)
		if generated {
			c.Locals(string(infracontext.SessionGeneratedContextKey), true)
			ctx = context.WithValue(ctx, infracontext.SessionGeneratedContextKey, true)
		}
		c.SetUserContext(ctx)

		c.Set(defaultSessionHeader, sessionID)

		return c.Next()
	}
}

func (m *SessionMiddleware) generateSessionID() string {
	if id, err := uuid.NewV7(); err == nil {
		return id.String()
	}
	return uuid.New().String()
}

func (m *SessionMiddleware) resolveConfig(c *fiber.Ctx) *domain.SessionConfig {
	if gw, ok := appgateway.FromContext(c.UserContext()); ok {
		if gw == nil {
			return nil
		}
		return gw.SessionConfig
	}
	gatewayID, ok := appconsumer.GatewayIDFromContext(c.UserContext())
	if !ok {
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

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		m.logger.Debug("session middleware: body is not valid JSON, skipping body param lookup")
		return ""
	}

	value, ok := raw[paramName]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(value, &s); err != nil {
		return ""
	}
	return s
}
