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
	"errors"
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/logredact"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/requestid"
)

type AccessLogMiddleware struct {
	logger *slog.Logger
}

func NewAccessLogMiddleware(logger *slog.Logger) *AccessLogMiddleware {
	return &AccessLogMiddleware{logger: logger}
}

func (m *AccessLogMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		err := c.Next()
		requestID, _ := c.Locals(requestid.ConfigDefault.ContextKey).(string)
		if requestID == "" {
			requestID = c.Get(HeaderTraceID)
		}

		// For streamed responses the body is a lazy fasthttp body stream
		// (registered via SetBodyStreamWriter). Calling Response.Body() here
		// would force fasthttp to drain the whole stream into memory before it
		// is flushed to the socket, collapsing chunk-by-chunk SSE delivery into
		// a single burst at end-of-stream. Skip the byte count in that case.
		bytesOut := -1
		if !c.Response().IsBodyStream() {
			bytesOut = len(c.Response().Body())
		}

		// When a handler returns an error, the app error handler writes the
		// real status only after this middleware unwinds; the response still
		// reads 200 here. Derive the status from the error instead.
		status := c.Response().StatusCode()
		attrs := []any{
			slog.String("method", c.Method()),
			slog.String("path", c.Path()),
			slog.Duration("duration", time.Since(start)),
			slog.String("request_id", requestID),
			slog.String("ip", c.IP()),
			slog.Int("bytes_out", bytesOut),
		}
		if err != nil {
			status = fiber.StatusInternalServerError
			var fe *fiber.Error
			if errors.As(err, &fe) {
				status = fe.Code
			}
			attrs = append(attrs, slog.String("error", logredact.RedactLogString(err.Error())))
		}
		m.logger.Info("http access", append([]any{slog.Int("status", status)}, attrs...)...)
		return err
	}
}
