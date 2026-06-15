package middleware

import (
	"errors"
	"log/slog"
	"time"

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
			attrs = append(attrs, slog.String("error", err.Error()))
		}
		m.logger.Info("http access", append([]any{slog.Int("status", status)}, attrs...)...)
		return err
	}
}
