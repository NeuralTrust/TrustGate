package middleware

import (
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
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
		m.logger.Info("http access",
			slog.String("method", c.Method()),
			slog.String("path", c.Path()),
			slog.Int("status", c.Response().StatusCode()),
			slog.Duration("duration", time.Since(start)),
			slog.String("request_id", c.Get(fiber.HeaderXRequestID)),
			slog.String("ip", c.IP()),
			slog.Int("bytes_out", len(c.Response().Body())),
		)
		return err
	}
}
