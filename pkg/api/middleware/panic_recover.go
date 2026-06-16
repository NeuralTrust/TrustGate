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

	"github.com/gofiber/fiber/v2"
)

type PanicRecoverMiddleware struct {
	logger *slog.Logger
}

func NewPanicRecoverMiddleware(logger *slog.Logger) *PanicRecoverMiddleware {
	return &PanicRecoverMiddleware{logger: logger}
}

func (m *PanicRecoverMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		defer func() {
			r := recover()
			if r == nil {
				return
			}
			m.logger.Error("HTTP server panic recovered",
				slog.Any("error", r),
				slog.String("path", c.Path()),
				slog.String("method", c.Method()),
				slog.String("request_id", c.Get(fiber.HeaderXRequestID)),
			)
			_ = c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Internal server error",
			})
		}()
		return c.Next()
	}
}
