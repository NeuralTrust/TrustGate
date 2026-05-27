package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/requestid"
)

type RequestIDMiddleware struct{}

func NewRequestIDMiddleware() *RequestIDMiddleware { return &RequestIDMiddleware{} }

func (m *RequestIDMiddleware) Middleware() fiber.Handler {
	return requestid.New(requestid.Config{
		Header: fiber.HeaderXRequestID,
	})
}
