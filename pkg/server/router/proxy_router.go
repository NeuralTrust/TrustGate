package router

import (
	"net/http"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	handlers "github.com/NeuralTrust/TrustGate/pkg/handlers/http"
	wsHandlers "github.com/NeuralTrust/TrustGate/pkg/handlers/websocket"
	"github.com/NeuralTrust/TrustGate/pkg/server/middleware"
	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
)

const (
	HealthPath       = "/health"
	AdminHealthPath  = "/__/health"
	PingPath         = "/__/ping"
	MirrorPath       = "/__/mirror"
	MirrorParamsPath = "/:id/mirror"
	WebsocketPath    = "/ws/*"
)

type proxyRouter struct {
	middlewareTransport *middleware.Transport
	handlerTransport    handlers.HandlerTransport
	wsHandlerTransport  wsHandlers.HandlerTransport
	config              *config.Config
}

func NewProxyRouter(
	middlewareTransport *middleware.Transport,
	handlerTransport handlers.HandlerTransport,
	wsHandlerTransport wsHandlers.HandlerTransport,
	cfg *config.Config,
) ServerRouter {
	return &proxyRouter{
		middlewareTransport: middlewareTransport,
		handlerTransport:    handlerTransport,
		wsHandlerTransport:  wsHandlerTransport,
		config:              cfg,
	}
}

func (r *proxyRouter) BuildRoutes(router *fiber.App) error {

	handlerTransport, ok := r.handlerTransport.GetTransport().(*handlers.HandlerTransportDTO)
	if !ok {
		return ErrInvalidHandlerTransport
	}

	wsHandlerTransport, ok := r.wsHandlerTransport.GetTransport().(*wsHandlers.HandlerTransportDTO)
	if !ok {
		return ErrInvalidHandlerTransport
	}

	router.Get(HealthPath, func(ctx *fiber.Ctx) error {
		return ctx.Status(http.StatusOK).JSON(fiber.Map{
			"status": "ok",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	router.Get(AdminHealthPath, func(ctx *fiber.Ctx) error {
		return ctx.Status(http.StatusOK).JSON(fiber.Map{
			"status": "ok",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	router.Get(PingPath, func(ctx *fiber.Ctx) error {
		response := fiber.Map{
			"message": "pong",
		}
		if len(ctx.Queries()) > 0 {
			response["query_params"] = ctx.Queries()
		}
		return ctx.Status(http.StatusOK).JSON(response)
	})

	router.Post(PingPath, func(ctx *fiber.Ctx) error {
		response := fiber.Map{
			"message": "pong",
		}
		// Add query parameters if they exist
		if len(ctx.Queries()) > 0 {
			response["query_params"] = ctx.Queries()
		}
		return ctx.Status(http.StatusOK).JSON(response)
	})

	router.Post(MirrorPath, func(ctx *fiber.Ctx) error {
		return ctx.Status(http.StatusOK).JSON(fiber.Map{
			"body": string(ctx.Body()),
		})
	})

	router.Post(MirrorParamsPath, func(ctx *fiber.Ctx) error {
		return ctx.Status(http.StatusOK).JSON(fiber.Map{
			"body":   string(ctx.Body()),
			"params": ctx.Params("id"),
		})
	})

	router.Use(r.middlewareTransport.GetMiddlewares()...)

	router.Get(WebsocketPath, websocket.New(
		wsHandlerTransport.ForwardedHandler.Handle,
		websocket.Config{
			HandshakeTimeout: 15 * time.Second,
			ReadBufferSize:   1024,
			WriteBufferSize:  1024,
		},
	))

	router.Use(handlerTransport.ForwardedHandler.Handle)

	return nil
}
