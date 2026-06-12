package router

import (
	apihandler "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http"
	authhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/auth"
	cataloghttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/catalog"
	consumerhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/consumer"
	gatewayhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/gateway"
	policyhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/policy"
	registryhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/registry"
	rolehttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/role"
	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	"github.com/gofiber/fiber/v2"
	fiberSwagger "github.com/gofiber/swagger"
)

const (
	HealthPath            = "/healthz"
	ReadyPath             = "/readyz"
	VersionPath           = "/__/version"
	DocsPath              = "/docs/*"
	GatewaysPath          = "/v1/gateways"
	ProvidersCatalog      = "/v1/providers-catalog"
	ModelsCatalogPath     = "/v1/models-catalog"
	PoliciesCatalogPath   = "/v1/policies-catalog"
	MCPServersCatalogPath = "/v1/mcp-servers-catalog"
)

// AdminRouterDeps groups every handler mounted by the admin plane.
// Adding a new aggregate only adds a field here, not a positional
// argument to NewAdminRouter.
type AdminRouterDeps struct {
	MiddlewareTransport *middleware.Transport
	AdminAuth           *middleware.AdminAuthMiddleware
	HealthHandler       *apihandler.HealthHandler
	VersionHandler      *apihandler.VersionHandler

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
}

type adminRouter struct {
	deps AdminRouterDeps
}

func NewAdminRouter(deps AdminRouterDeps) ServerRouter {
	return &adminRouter{deps: deps}
}

func (r *adminRouter) BuildRoutes(app *fiber.App) error {
	installMiddlewares(app, r.deps.MiddlewareTransport)

	app.Get(HealthPath, r.deps.HealthHandler.Liveness)
	app.Get(ReadyPath, r.deps.HealthHandler.Readiness)
	app.Get(VersionPath, r.deps.VersionHandler.Handle)

	// Interactive API docs (Swagger UI + spec) served from the generated
	// `docs` package. Public on purpose so the contract is browsable without
	// an admin token; the documented endpoints stay behind AdminAuth below.
	app.Get(DocsPath, fiberSwagger.HandlerDefault)

	gw := app.Group(GatewaysPath, r.deps.AdminAuth.Middleware())
	gw.Post("", r.deps.CreateGateway.Handle)
	gw.Get("", r.deps.ListGateway.Handle)
	gw.Get("/:id", r.deps.GetGateway.Handle)
	gw.Put("/:id", r.deps.UpdateGateway.Handle)
	gw.Delete("/:id", r.deps.DeleteGateway.Handle)

	registries := gw.Group("/:gateway_id/registries")
	registries.Post("", r.deps.CreateRegistry.Handle)
	registries.Post("/test-connection", r.deps.TestRegistryConnection.Handle)
	registries.Get("", r.deps.ListRegistry.Handle)
	registries.Get("/:id", r.deps.GetRegistry.Handle)
	registries.Get("/:id/tools", r.deps.ListRegistryTools.Handle)
	registries.Put("/:id", r.deps.UpdateRegistry.Handle)
	registries.Delete("/:id", r.deps.DeleteRegistry.Handle)

	policies := gw.Group("/:gateway_id/policies")
	policies.Post("", r.deps.CreatePolicy.Handle)
	policies.Get("", r.deps.ListPolicy.Handle)
	policies.Get("/:id", r.deps.GetPolicy.Handle)
	policies.Put("/:id", r.deps.UpdatePolicy.Handle)
	policies.Delete("/:id", r.deps.DeletePolicy.Handle)
	policies.Post("/:id/global", r.deps.GlobalPolicy.SetGlobal)
	policies.Delete("/:id/global", r.deps.GlobalPolicy.UnsetGlobal)
	policies.Post("/:id/duplicate", r.deps.DuplicatePolicy.Handle)

	consumers := gw.Group("/:gateway_id/consumers")
	consumers.Post("", r.deps.CreateConsumer.Handle)
	consumers.Get("", r.deps.ListConsumer.Handle)
	consumers.Get("/:id", r.deps.GetConsumer.Handle)
	consumers.Put("/:id", r.deps.UpdateConsumer.Handle)
	consumers.Delete("/:id", r.deps.DeleteConsumer.Handle)
	consumers.Post("/:id/registries/:registry_id", r.deps.ConsumerAssociation.AttachRegistry)
	consumers.Delete("/:id/registries/:registry_id", r.deps.ConsumerAssociation.DetachRegistry)
	consumers.Post("/:id/roles/:role_id", r.deps.ConsumerAssociation.AttachRole)
	consumers.Delete("/:id/roles/:role_id", r.deps.ConsumerAssociation.DetachRole)
	consumers.Post("/:id/auths/:auth_id", r.deps.ConsumerAssociation.AttachAuth)
	consumers.Delete("/:id/auths/:auth_id", r.deps.ConsumerAssociation.DetachAuth)
	consumers.Post("/:id/policies/:policy_id", r.deps.ConsumerAssociation.AttachPolicy)
	consumers.Delete("/:id/policies/:policy_id", r.deps.ConsumerAssociation.DetachPolicy)

	roles := gw.Group("/:gateway_id/roles")
	roles.Post("", r.deps.CreateRole.Handle)
	roles.Get("", r.deps.ListRole.Handle)
	roles.Get("/:id", r.deps.GetRole.Handle)
	roles.Put("/:id", r.deps.UpdateRole.Handle)
	roles.Delete("/:id", r.deps.DeleteRole.Handle)
	roles.Post("/:role_id/registries/:registry_id", r.deps.RoleAssociation.AttachRegistry)
	roles.Delete("/:role_id/registries/:registry_id", r.deps.RoleAssociation.DetachRegistry)

	auths := gw.Group("/:gateway_id/auths")
	auths.Post("", r.deps.CreateAuth.Handle)
	auths.Get("", r.deps.ListAuth.Handle)
	auths.Get("/:id", r.deps.GetAuth.Handle)
	auths.Put("/:id", r.deps.UpdateAuth.Handle)
	auths.Delete("/:id", r.deps.DeleteAuth.Handle)

	app.Get(ProvidersCatalog, r.deps.AdminAuth.Middleware(), r.deps.ListProvidersCatalog.Handle)
	app.Get(ModelsCatalogPath, r.deps.AdminAuth.Middleware(), r.deps.ListModelsCatalog.Handle)
	app.Get(PoliciesCatalogPath, r.deps.AdminAuth.Middleware(), r.deps.ListPoliciesCatalog.Handle)
	app.Get(MCPServersCatalogPath, r.deps.AdminAuth.Middleware(), r.deps.ListMCPServersCatalog.Handle)

	return nil
}

func installMiddlewares(app *fiber.App, transport *middleware.Transport) {
	for _, h := range transport.GetMiddlewares() {
		app.Use(h)
	}
}
