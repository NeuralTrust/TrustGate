package middleware

import "github.com/gofiber/fiber/v2"

type Middleware interface {
	Middleware() fiber.Handler
}

type Transport struct {
	AuthMiddleware    Middleware
	GatewayMiddleware Middleware
	MetricsMiddleware Middleware
	PluginMiddleware  Middleware
}
