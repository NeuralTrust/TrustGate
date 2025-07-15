package router

import (
	"errors"

	handlers "github.com/NeuralTrust/TrustGate/pkg/handlers/http"
	"github.com/NeuralTrust/TrustGate/pkg/middleware"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/swagger"
)

var (
	ErrInvalidHandlerTransport = errors.New("invalid handler transport")
)

type adminRouter struct {
	middlewareTransport *middleware.Transport
	handlerTransport    handlers.HandlerTransport
}

func NewAdminRouter(
	middlewareTransport *middleware.Transport,
	handlerTransport handlers.HandlerTransport,
) ServerRouter {
	return &adminRouter{
		middlewareTransport: middlewareTransport,
		handlerTransport:    handlerTransport,
	}
}

func (r *adminRouter) BuildRoutes(router *fiber.App) error {

	handlerTransport, ok := r.handlerTransport.GetTransport().(*handlers.HandlerTransportDTO)
	if !ok {
		return ErrInvalidHandlerTransport
	}

	router.Static("/swagger.json", "./docs/swagger.json")

	router.Get("/docs/*", swagger.New(swagger.Config{
		URL: "http://localhost:8080/swagger.json",
	}))

	router.Get("/version", handlerTransport.GetVersionHandler.Handle)
	router.Get("/plugins", handlerTransport.ListPluginsHandler.Handle)
	router.Post("/invalidate-cache", handlerTransport.InvalidateCacheHandler.Handle)

	v1 := router.Group("/api/v1")
	{
		if r.middlewareTransport.GetMiddlewares() != nil {
			v1.Use(r.middlewareTransport.GetMiddlewares()...)
		}

		// Gateway endpoints
		gateways := v1.Group("/gateways")
		{
			gateways.Post("", handlerTransport.CreateGatewayHandler.Handle)
			gateways.Get("", handlerTransport.ListGatewayHandler.Handle)
			gateways.Get("/:gateway_id", handlerTransport.GetGatewayHandler.Handle)
			gateways.Put("/:gateway_id", handlerTransport.UpdateGatewayHandler.Handle)
			gateways.Delete("/:gateway_id", handlerTransport.DeleteGatewayHandler.Handle)

			// Upstream management (scoped to gateway)
			upstreams := gateways.Group("/:gateway_id/upstreams")
			{
				upstreams.Post("", handlerTransport.CreateUpstreamHandler.Handle)
				upstreams.Get("", handlerTransport.ListUpstreamHandler.Handle)
				upstreams.Get("/:upstream_id", handlerTransport.GetUpstreamHandler.Handle)
				upstreams.Put("/:upstream_id", handlerTransport.UpdateUpstreamHandler.Handle)
				upstreams.Delete("/:upstream_id", handlerTransport.DeleteUpstreamHandler.Handle)
			}

			// Service management (scoped to gateway)
			services := gateways.Group("/:gateway_id/services")
			{
				services.Post("", handlerTransport.CreateServiceHandler.Handle)
				services.Get("", handlerTransport.ListServicesHandler.Handle)
				services.Get("/:service_id", handlerTransport.GetServiceHandler.Handle)
				services.Put("/:service_id", handlerTransport.UpdateServiceHandler.Handle)
				services.Delete("/:service_id", handlerTransport.DeleteServiceHandler.Handle)
			}

			// Rules management (already scoped to gateway)
			rules := gateways.Group("/:gateway_id/rules")
			{
				rules.Get("", handlerTransport.ListRulesHandler.Handle)
				rules.Post("", handlerTransport.CreateRuleHandler.Handle)
				rules.Put("/:rule_id", handlerTransport.UpdateRuleHandler.Handle)
				rules.Delete("/:rule_id", handlerTransport.DeleteRuleHandler.Handle)
			}

			// API key management
			keys := gateways.Group("/:gateway_id/keys")
			{
				keys.Post("", handlerTransport.CreateAPIKeyHandler.Handle)
				keys.Get("", handlerTransport.ListAPIKeysHandler.Handle)
				// keys.Get("/:key_id", handlerTransport.GetAPIKeyHandler.Handle)
				keys.Delete("/:key_id", handlerTransport.DeleteAPIKeyHandler.Handle)
			}

			// Public API key management (with obfuscated keys)
			publicKeys := gateways.Group("/:gateway_id/public-keys")
			{
				publicKeys.Get("", handlerTransport.ListAPIKeysPublicHandler.Handle)
			}
		}
	}
	return nil
}
