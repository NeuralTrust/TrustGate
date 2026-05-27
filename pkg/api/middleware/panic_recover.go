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
