package server

import (
	"fmt"

	handlers "github.com/NeuralTrust/TrustGate/pkg/handlers/http"
	"github.com/NeuralTrust/TrustGate/pkg/middleware"
	"github.com/gofiber/fiber/v2"

	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/config"
)

type (
	AdminServerDI struct {
		MiddlewareTransport middleware.Transport
		HandlerTransport    handlers.HandlerTransport
		Config              *config.Config
		Cache               *cache.Cache
		Logger              *logrus.Logger
	}
	AdminServer struct {
		*BaseServer
		middlewareTransport middleware.Transport
		handlerTransport    handlers.HandlerTransport
	}
)

func NewAdminServer(di AdminServerDI) *AdminServer {
	return &AdminServer{
		BaseServer:          NewBaseServer(di.Config, di.Cache, di.Logger),
		middlewareTransport: di.MiddlewareTransport,
		handlerTransport:    di.HandlerTransport,
	}
}

func (s *AdminServer) Run() error {
	// Set up routes
	s.setupRoutes()
	s.setupHealthCheck()
	// Start the server
	addr := fmt.Sprintf(":%d", s.config.Server.AdminPort)
	s.logger.WithField("addr", addr).Info("Starting admin server")
	return s.router.Listen(addr)
}

func (s *AdminServer) setupRoutes() {
	baseRouter := s.router.Group("")
	s.addRoutes(baseRouter)
}

func (s *AdminServer) addRoutes(router fiber.Router) {
	v1 := router.Group("/api/v1")
	{
		gateways := v1.Group("/gateways")
		{
			gateways.Post("", s.handlerTransport.CreateGatewayHandler.Handle)
			gateways.Get("", s.handlerTransport.ListGatewayHandler.Handle)
			gateways.Get("/:gateway_id", s.handlerTransport.GetGatewayHandler.Handle)
			gateways.Put("/:gateway_id", s.handlerTransport.UpdateGatewayHandler.Handle)
			gateways.Delete("/:gateway_id", s.handlerTransport.DeleteGatewayHandler.Handle)

			// Upstream management (scoped to gateway)
			upstreams := gateways.Group("/:gateway_id/upstreams")
			{
				upstreams.Post("", s.handlerTransport.CreateUpstreamHandler.Handle)
				upstreams.Get("", s.handlerTransport.ListUpstreamHandler.Handle)
				upstreams.Get("/:upstream_id", s.handlerTransport.GetUpstreamHandler.Handle)
				upstreams.Put("/:upstream_id", s.handlerTransport.UpdateUpstreamHandler.Handle)
				upstreams.Delete("/:upstream_id", s.handlerTransport.DeleteUpstreamHandler.Handle)
			}

			// Service management (scoped to gateway)
			services := gateways.Group("/:gateway_id/services")
			{
				services.Post("", s.handlerTransport.CreateServiceHandler.Handle)
				services.Get("", s.handlerTransport.ListServicesHandler.Handle)
				services.Get("/:service_id", s.handlerTransport.GetServiceHandler.Handle)
				services.Put("/:service_id", s.handlerTransport.UpdateServiceHandler.Handle)
				services.Delete("/:service_id", s.handlerTransport.DeleteServiceHandler.Handle)
			}

			// Rules management (already scoped to gateway)
			rules := gateways.Group("/:gateway_id/rules")
			{
				rules.Get("", s.handlerTransport.ListRulesHandler.Handle)
				rules.Post("", s.handlerTransport.CreateRuleHandler.Handle)
				rules.Put("/:rule_id", s.handlerTransport.UpdateRuleHandler.Handle)
				rules.Delete("/:rule_id", s.handlerTransport.DeleteRuleHandler.Handle)
			}

			// API key management
			keys := gateways.Group("/:gateway_id/keys")
			{
				keys.Post("", s.handlerTransport.CreateAPIKeyHandler.Handle)
				keys.Get("", s.handlerTransport.ListAPIKeysHandler.Handle)
				keys.Get("/:key_id", s.handlerTransport.GetAPIKeyHandler.Handle)
				keys.Delete("/:key_id", s.handlerTransport.DeleteAPIKeyHandler.Handle)
			}
		}
	}
}

func (s *AdminServer) Shutdown() error {
	return s.router.Shutdown()
}
