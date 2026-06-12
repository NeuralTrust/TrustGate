package router

import (
	apihandler "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http"
	mcphttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/mcp"
	oauthhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/oauth"
	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

type mcpRouter struct {
	baseTransport              *middleware.Transport
	authTransport              *middleware.Transport
	healthHandler              *apihandler.HealthHandler
	mcpHandler                 *mcphttp.Handler
	protectedResourceHandler   *oauthhttp.ProtectedResourceHandler
	authorizationServerHandler *oauthhttp.AuthorizationServerHandler
	registerHandler            *oauthhttp.RegisterHandler
	authorizeHandler           *oauthhttp.AuthorizeHandler
	callbackHandler            *oauthhttp.CallbackHandler
	tokenHandler               *oauthhttp.TokenHandler
	connectHandler             *oauthhttp.ConnectHandler
	jwksHandler                *oauthhttp.JWKSHandler
}

func NewMCPRouter(
	baseTransport *middleware.Transport,
	authTransport *middleware.Transport,
	healthHandler *apihandler.HealthHandler,
	mcpHandler *mcphttp.Handler,
	protectedResourceHandler *oauthhttp.ProtectedResourceHandler,
	authorizationServerHandler *oauthhttp.AuthorizationServerHandler,
	registerHandler *oauthhttp.RegisterHandler,
	authorizeHandler *oauthhttp.AuthorizeHandler,
	callbackHandler *oauthhttp.CallbackHandler,
	tokenHandler *oauthhttp.TokenHandler,
	connectHandler *oauthhttp.ConnectHandler,
	jwksHandler *oauthhttp.JWKSHandler,
) ServerRouter {
	return &mcpRouter{
		baseTransport:              baseTransport,
		authTransport:              authTransport,
		healthHandler:              healthHandler,
		mcpHandler:                 mcpHandler,
		protectedResourceHandler:   protectedResourceHandler,
		authorizationServerHandler: authorizationServerHandler,
		registerHandler:            registerHandler,
		authorizeHandler:           authorizeHandler,
		callbackHandler:            callbackHandler,
		tokenHandler:               tokenHandler,
		connectHandler:             connectHandler,
		jwksHandler:                jwksHandler,
	}
}

func (r *mcpRouter) BuildRoutes(app *fiber.App) error {
	app.Get(HealthPath, r.healthHandler.Liveness)
	app.Get(ReadyPath, r.healthHandler.Readiness)

	installMiddlewares(app, r.baseTransport)

	app.Get(oauthhttp.WellKnownProtectedResourcePath, r.protectedResourceHandler.Handle)
	app.Get(oauthhttp.WellKnownProtectedResourcePath+"/*", r.protectedResourceHandler.Handle)
	app.Get(oauthhttp.WellKnownAuthorizationServerPath, r.authorizationServerHandler.Handle)
	app.Post(oauthhttp.RegisterPath, r.registerHandler.Handle)
	app.Get(oauthhttp.AuthorizePath, r.authorizeHandler.Handle)
	app.Get(appoauth.CallbackPath, r.callbackHandler.Handle)
	app.Post(oauthhttp.TokenPath, r.tokenHandler.Handle)

	app.Get(oauthhttp.JWKSPath, r.jwksHandler.Handle)

	app.Get(oauthhttp.ConnectStartPath, r.connectHandler.Start)
	app.Get(oauthhttp.ConnectCallbackPath, r.connectHandler.Callback)
	app.Post(oauthhttp.DisconnectPath, r.connectHandler.Disconnect)
	app.Get("/+/connect", r.connectHandler.Page)

	app.Get("/*", r.mcpHandler.MethodNotAllowed)
	app.Delete("/*", r.mcpHandler.MethodNotAllowed)

	installMiddlewares(app, r.authTransport)
	app.Post("/*", r.mcpHandler.Handle)
	return nil
}
