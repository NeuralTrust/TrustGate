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
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/gofiber/fiber/v2"
)

type ConfigSyncAuthMiddleware struct {
	tokenDigest [32]byte
	configured  bool
	logger      *slog.Logger
}

func NewConfigSyncAuthMiddleware(cfg *config.Config, logger *slog.Logger) *ConfigSyncAuthMiddleware {
	m := &ConfigSyncAuthMiddleware{logger: logger}
	if cfg.ConfigSync.Token != "" {
		m.tokenDigest = sha256.Sum256([]byte(cfg.ConfigSync.Token))
		m.configured = true
	} else if logger != nil {
		logger.Warn("config-sync token is not configured; the snapshot endpoint will reject every pull and no data plane can converge",
			slog.String("component", "configsnapshot"))
	}
	return m
}

func (m *ConfigSyncAuthMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !m.configured {
			if m.logger != nil {
				m.logger.Warn("config-sync token is not configured; rejecting snapshot request",
					slog.String("component", "configsnapshot"))
			}
			return configSyncUnauthorized(c)
		}
		provided := configSyncBearerToken(c)
		if provided == "" {
			return configSyncUnauthorized(c)
		}
		providedDigest := sha256.Sum256([]byte(provided))
		if subtle.ConstantTimeCompare(providedDigest[:], m.tokenDigest[:]) != 1 {
			return configSyncUnauthorized(c)
		}
		return c.Next()
	}
}

func configSyncBearerToken(c *fiber.Ctx) string {
	header := c.Get(authorizationHeader)
	if !strings.HasPrefix(header, bearerPrefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, bearerPrefix))
}

func configSyncUnauthorized(c *fiber.Ctx) error {
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing or invalid config-sync token"})
}
