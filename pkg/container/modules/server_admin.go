// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package modules

import (
	"fmt"
	"log/slog"

	apihandler "github.com/NeuralTrust/TrustGate/pkg/api/handler/http"
	authhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/auth"
	cataloghttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/catalog"
	configsynchttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/configsync"
	consumerhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/consumer"
	gatewayhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/gateway"
	playgroundhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/playground"
	policyhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/policy"
	registryhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry"
	rolehttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/role"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	configsyncconnrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/configsyncconn"
	"github.com/NeuralTrust/TrustGate/pkg/server"
	"github.com/NeuralTrust/TrustGate/pkg/server/router"
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

	CreateRegistry         *registryhttp.CreateRegistryHandler
	GetRegistry            *registryhttp.GetRegistryHandler
	ListRegistry           *registryhttp.ListRegistryHandler
	UpdateRegistry         *registryhttp.UpdateRegistryHandler
	DeleteRegistry         *registryhttp.DeleteRegistryHandler
	TestRegistryConnection *registryhttp.TestConnectionHandler
	ListRegistryTools      *registryhttp.ListRegistryToolsHandler

	CreatePolicy    *policyhttp.CreatePolicyHandler
	GetPolicy       *policyhttp.GetPolicyHandler
	ListPolicy      *policyhttp.ListPolicyHandler
	UpdatePolicy    *policyhttp.UpdatePolicyHandler
	DeletePolicy    *policyhttp.DeletePolicyHandler
	GlobalPolicy    *policyhttp.GlobalPolicyHandler
	DuplicatePolicy *policyhttp.DuplicatePolicyHandler

	CreateConsumer      *consumerhttp.CreateConsumerHandler
	GetConsumer         *consumerhttp.GetConsumerHandler
	ListConsumer        *consumerhttp.ListConsumerHandler
	UpdateConsumer      *consumerhttp.UpdateConsumerHandler
	DeleteConsumer      *consumerhttp.DeleteConsumerHandler
	ConsumerAssociation *consumerhttp.AssociationHandler

	CreateRole      *rolehttp.CreateRoleHandler
	GetRole         *rolehttp.GetRoleHandler
	ListRole        *rolehttp.ListRoleHandler
	UpdateRole      *rolehttp.UpdateRoleHandler
	DeleteRole      *rolehttp.DeleteRoleHandler
	RoleAssociation *rolehttp.AssociationHandler

	CreateAuth *authhttp.CreateAuthHandler
	GetAuth    *authhttp.GetAuthHandler
	ListAuth   *authhttp.ListAuthHandler
	UpdateAuth *authhttp.UpdateAuthHandler
	DeleteAuth *authhttp.DeleteAuthHandler

	ListProvidersCatalog  *cataloghttp.ListProvidersHandler
	ListModelsCatalog     *cataloghttp.ListModelsHandler
	ListPoliciesCatalog   *cataloghttp.ListPolicyCatalogHandler
	ListMCPServersCatalog *cataloghttp.ListMCPServersHandler

	GetTrace *playgroundhttp.GetTraceHandler

	ListConfigSyncConnections *configsynchttp.ListConnectionsHandler
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
	if err := c.Provide(func(repo *configsyncconnrepo.Repository) *configsynchttp.ListConnectionsHandler {
		return configsynchttp.NewListConnectionsHandler(repo)
	}); err != nil {
		return err
	}
	if err := c.Provide(
		func(p adminRouterParams) router.ServerRouter {
			return router.NewAdminRouter(router.AdminRouterDeps{
				MiddlewareTransport:    p.Transport,
				AdminAuth:              p.AdminAuth,
				HealthHandler:          p.HealthHandler,
				VersionHandler:         p.VersionHandler,
				CreateGateway:          p.CreateGateway,
				GetGateway:             p.GetGateway,
				ListGateway:            p.ListGateway,
				UpdateGateway:          p.UpdateGateway,
				DeleteGateway:          p.DeleteGateway,
				CreateRegistry:         p.CreateRegistry,
				GetRegistry:            p.GetRegistry,
				ListRegistry:           p.ListRegistry,
				UpdateRegistry:         p.UpdateRegistry,
				DeleteRegistry:         p.DeleteRegistry,
				TestRegistryConnection: p.TestRegistryConnection,
				ListRegistryTools:      p.ListRegistryTools,
				CreatePolicy:           p.CreatePolicy,
				GetPolicy:              p.GetPolicy,
				ListPolicy:             p.ListPolicy,
				UpdatePolicy:           p.UpdatePolicy,
				DeletePolicy:           p.DeletePolicy,
				GlobalPolicy:           p.GlobalPolicy,
				DuplicatePolicy:        p.DuplicatePolicy,
				CreateConsumer:         p.CreateConsumer,
				GetConsumer:            p.GetConsumer,
				ListConsumer:           p.ListConsumer,
				UpdateConsumer:         p.UpdateConsumer,
				DeleteConsumer:         p.DeleteConsumer,
				ConsumerAssociation:    p.ConsumerAssociation,
				CreateRole:             p.CreateRole,
				GetRole:                p.GetRole,
				ListRole:               p.ListRole,
				UpdateRole:             p.UpdateRole,
				DeleteRole:             p.DeleteRole,
				RoleAssociation:        p.RoleAssociation,
				CreateAuth:             p.CreateAuth,
				GetAuth:                p.GetAuth,
				ListAuth:               p.ListAuth,
				UpdateAuth:             p.UpdateAuth,
				DeleteAuth:             p.DeleteAuth,

				ListProvidersCatalog:  p.ListProvidersCatalog,
				ListModelsCatalog:     p.ListModelsCatalog,
				ListPoliciesCatalog:   p.ListPoliciesCatalog,
				ListMCPServersCatalog: p.ListMCPServersCatalog,

				GetTrace: p.GetTrace,

				ListConfigSyncConnections: p.ListConfigSyncConnections,
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
