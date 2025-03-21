package router

import (
	"net/http"
	"time"

	handlers "github.com/NeuralTrust/TrustGate/pkg/handlers/http"
	"github.com/NeuralTrust/TrustGate/pkg/middleware"
	"github.com/gofiber/fiber/v2"
)

const (
	HealthPath = "/health"
	PingPath   = "/__/ping"
	MirrorPath = "/__/mirror"
)

type proxyRouter struct {
	middlewareTransport *middleware.Transport
	handlerTransport    handlers.HandlerTransport
}

func NewProxyRouter(
	middlewareTransport *middleware.Transport,
	handlerTransport handlers.HandlerTransport,
) ServerRouter {
	return &proxyRouter{
		middlewareTransport: middlewareTransport,
		handlerTransport:    handlerTransport,
	}
}

func (r *proxyRouter) BuildRoutes(router *fiber.App) error {
	handlerTransport, ok := r.handlerTransport.GetTransport().(*handlers.HandlerTransportDTO)
	if !ok {
		return ErrInvalidHandlerTransport
	}
	router.Get(HealthPath, func(ctx *fiber.Ctx) error {
		return ctx.Status(http.StatusOK).JSON(fiber.Map{
			"status": "ok",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	router.Get(PingPath, func(ctx *fiber.Ctx) error {
		return ctx.Status(http.StatusOK).JSON(fiber.Map{
			"message": "pong",
		})
	})

	router.Post(PingPath, func(ctx *fiber.Ctx) error {
		return ctx.Status(http.StatusOK).JSON(fiber.Map{
			"message": "pong",
		})
	})

	router.Post(MirrorPath, func(ctx *fiber.Ctx) error {
		return ctx.Status(http.StatusOK).JSON(fiber.Map{
			"body": string(ctx.Body()),
		})
	})

	router.Use(r.middlewareTransport.GetMiddlewares()...)
	router.Use(handlerTransport.ForwardedHandler.Handle)

	return nil
}
