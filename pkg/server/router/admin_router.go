package router

import (
	apihandler "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http"
	backendhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/backend"
	consumerhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/consumer"
	gatewayhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/gateway"
	policyhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	"github.com/gofiber/fiber/v2"
)

const (
	HealthPath   = "/healthz"
	ReadyPath    = "/readyz"
	VersionPath  = "/__/version"
	GatewaysPath = "/v1/gateways"
)

// AdminRouterDeps groups every handler mounted by the admin plane.
// Adding a new aggregate only adds a field here, not a positional
// argument to NewAdminRouter.
type AdminRouterDeps struct {
	MiddlewareTransport *middleware.Transport
	HealthHandler       *apihandler.HealthHandler
	VersionHandler      *apihandler.VersionHandler

	CreateGateway *gatewayhttp.CreateGatewayHandler
	GetGateway    *gatewayhttp.GetGatewayHandler
	ListGateway   *gatewayhttp.ListGatewayHandler
	UpdateGateway *gatewayhttp.UpdateGatewayHandler
	DeleteGateway *gatewayhttp.DeleteGatewayHandler

	CreateBackend *backendhttp.CreateBackendHandler
	GetBackend    *backendhttp.GetBackendHandler
	ListBackend   *backendhttp.ListBackendHandler
	UpdateBackend *backendhttp.UpdateBackendHandler
	DeleteBackend *backendhttp.DeleteBackendHandler

	CreatePolicy *policyhttp.CreatePolicyHandler
	GetPolicy    *policyhttp.GetPolicyHandler
	ListPolicy   *policyhttp.ListPolicyHandler
	UpdatePolicy *policyhttp.UpdatePolicyHandler
	DeletePolicy *policyhttp.DeletePolicyHandler

	CreateConsumer *consumerhttp.CreateConsumerHandler
	GetConsumer    *consumerhttp.GetConsumerHandler
	ListConsumer   *consumerhttp.ListConsumerHandler
	UpdateConsumer *consumerhttp.UpdateConsumerHandler
	DeleteConsumer *consumerhttp.DeleteConsumerHandler
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

	gw := app.Group(GatewaysPath)
	gw.Post("", r.deps.CreateGateway.Handle)
	gw.Get("", r.deps.ListGateway.Handle)
	gw.Get("/:id", r.deps.GetGateway.Handle)
	gw.Put("/:id", r.deps.UpdateGateway.Handle)
	gw.Delete("/:id", r.deps.DeleteGateway.Handle)

	backends := gw.Group("/:gateway_id/backends")
	backends.Post("", r.deps.CreateBackend.Handle)
	backends.Get("", r.deps.ListBackend.Handle)
	backends.Get("/:id", r.deps.GetBackend.Handle)
	backends.Put("/:id", r.deps.UpdateBackend.Handle)
	backends.Delete("/:id", r.deps.DeleteBackend.Handle)

	policies := gw.Group("/:gateway_id/policies")
	policies.Post("", r.deps.CreatePolicy.Handle)
	policies.Get("", r.deps.ListPolicy.Handle)
	policies.Get("/:id", r.deps.GetPolicy.Handle)
	policies.Put("/:id", r.deps.UpdatePolicy.Handle)
	policies.Delete("/:id", r.deps.DeletePolicy.Handle)

	consumers := gw.Group("/:gateway_id/consumers")
	consumers.Post("", r.deps.CreateConsumer.Handle)
	consumers.Get("", r.deps.ListConsumer.Handle)
	consumers.Get("/:id", r.deps.GetConsumer.Handle)
	consumers.Put("/:id", r.deps.UpdateConsumer.Handle)
	consumers.Delete("/:id", r.deps.DeleteConsumer.Handle)

	return nil
}

func installMiddlewares(app *fiber.App, transport *middleware.Transport) {
	for _, h := range transport.GetMiddlewares() {
		app.Use(h)
	}
}
