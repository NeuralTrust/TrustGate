package modules

import (
	"fmt"
	"log/slog"

	apihandler "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http"
	authhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/auth"
	cataloghttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/catalog"
	consumerhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/consumer"
	gatewayhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/gateway"
	policyhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/policy"
	registryhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	"github.com/NeuralTrust/AgentGateway/pkg/server"
	"github.com/NeuralTrust/AgentGateway/pkg/server/router"
	"go.uber.org/dig"
)

type adminMiddlewares struct {
	dig.In
	RequestID       *middleware.RequestIDMiddleware
	PanicRecover    *middleware.PanicRecoverMiddleware
	AccessLog       *middleware.AccessLogMiddleware
	CORS            *middleware.CORSMiddleware
	SecurityHeaders *middleware.SecurityHeadersMiddleware
}

func adminTransport(m adminMiddlewares) *middleware.Transport {
	return middleware.NewTransport(
		m.RequestID,
		m.SecurityHeaders,
		m.CORS,
		m.PanicRecover,
		m.AccessLog,
	)
}

type adminRouterParams struct {
	dig.In
	Transport      *middleware.Transport `name:"admin"`
	AdminAuth      *middleware.AdminAuthMiddleware
	HealthHandler  *apihandler.HealthHandler
	VersionHandler *apihandler.VersionHandler

	CreateGateway *gatewayhttp.CreateGatewayHandler
	GetGateway    *gatewayhttp.GetGatewayHandler
	ListGateway   *gatewayhttp.ListGatewayHandler
	UpdateGateway *gatewayhttp.UpdateGatewayHandler
	DeleteGateway *gatewayhttp.DeleteGatewayHandler

	CreateRegistry *registryhttp.CreateRegistryHandler
	GetRegistry    *registryhttp.GetRegistryHandler
	ListRegistry   *registryhttp.ListRegistryHandler
	UpdateRegistry *registryhttp.UpdateRegistryHandler
	DeleteRegistry *registryhttp.DeleteRegistryHandler

	CreatePolicy *policyhttp.CreatePolicyHandler
	GetPolicy    *policyhttp.GetPolicyHandler
	ListPolicy   *policyhttp.ListPolicyHandler
	UpdatePolicy *policyhttp.UpdatePolicyHandler
	DeletePolicy *policyhttp.DeletePolicyHandler
	GlobalPolicy *policyhttp.GlobalPolicyHandler

	CreateConsumer      *consumerhttp.CreateConsumerHandler
	GetConsumer         *consumerhttp.GetConsumerHandler
	ListConsumer        *consumerhttp.ListConsumerHandler
	UpdateConsumer      *consumerhttp.UpdateConsumerHandler
	DeleteConsumer      *consumerhttp.DeleteConsumerHandler
	ConsumerAssociation *consumerhttp.AssociationHandler

	CreateAuth *authhttp.CreateAuthHandler
	GetAuth    *authhttp.GetAuthHandler
	ListAuth   *authhttp.ListAuthHandler
	UpdateAuth *authhttp.UpdateAuthHandler
	DeleteAuth *authhttp.DeleteAuthHandler

	ListProvidersCatalog *cataloghttp.ListProvidersHandler
	ListModelsCatalog    *cataloghttp.ListModelsHandler
	ListPoliciesCatalog  *cataloghttp.ListPolicyCatalogHandler
}

type adminServerParams struct {
	dig.In
	Cfg    *config.Config
	Logger *slog.Logger
	Router router.ServerRouter `name:"admin"`
}

func ServerAdmin(c *container.Container) error {
	if err := c.Provide(adminTransport, dig.Name("admin")); err != nil {
		return err
	}
	if err := c.Provide(
		func(p adminRouterParams) router.ServerRouter {
			return router.NewAdminRouter(router.AdminRouterDeps{
				MiddlewareTransport: p.Transport,
				AdminAuth:           p.AdminAuth,
				HealthHandler:       p.HealthHandler,
				VersionHandler:      p.VersionHandler,
				CreateGateway:       p.CreateGateway,
				GetGateway:          p.GetGateway,
				ListGateway:         p.ListGateway,
				UpdateGateway:       p.UpdateGateway,
				DeleteGateway:       p.DeleteGateway,
				CreateRegistry:      p.CreateRegistry,
				GetRegistry:         p.GetRegistry,
				ListRegistry:        p.ListRegistry,
				UpdateRegistry:      p.UpdateRegistry,
				DeleteRegistry:      p.DeleteRegistry,
				CreatePolicy:        p.CreatePolicy,
				GetPolicy:           p.GetPolicy,
				ListPolicy:          p.ListPolicy,
				UpdatePolicy:        p.UpdatePolicy,
				DeletePolicy:        p.DeletePolicy,
				GlobalPolicy:        p.GlobalPolicy,
				CreateConsumer:      p.CreateConsumer,
				GetConsumer:         p.GetConsumer,
				ListConsumer:        p.ListConsumer,
				UpdateConsumer:      p.UpdateConsumer,
				DeleteConsumer:      p.DeleteConsumer,
				ConsumerAssociation: p.ConsumerAssociation,
				CreateAuth:          p.CreateAuth,
				GetAuth:             p.GetAuth,
				ListAuth:            p.ListAuth,
				UpdateAuth:          p.UpdateAuth,
				DeleteAuth:          p.DeleteAuth,

				ListProvidersCatalog: p.ListProvidersCatalog,
				ListModelsCatalog:    p.ListModelsCatalog,
				ListPoliciesCatalog:  p.ListPoliciesCatalog,
			})
		},
		dig.Name("admin"),
	); err != nil {
		return err
	}
	return c.Provide(
		func(p adminServerParams) server.Server {
			addr := fmt.Sprintf(":%d", p.Cfg.Server.AdminPort)
			return server.NewHTTPServer("admin", addr, p.Cfg.Server, p.Logger, []router.ServerRouter{p.Router})
		},
		dig.Name("admin"),
	)
}
