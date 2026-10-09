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

package router

import (
	apihandler "github.com/NeuralTrust/TrustGate/pkg/api/handler/http"
	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	oauthhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

type mcpRouter struct {
	baseTransport              *middleware.Transport
	authTransport              *middleware.Transport
	opsMetrics                 *middleware.OpsMetricsMiddleware
	healthHandler              *apihandler.HealthHandler
	mcpHandler                 *mcphttp.Handler
	protectedResourceHandler   *oauthhttp.ProtectedResourceHandler
	authorizationServerHandler *oauthhttp.AuthorizationServerHandler
	registerHandler            *oauthhttp.RegisterHandler
	authorizeHandler           *oauthhttp.AuthorizeHandler
	callbackHandler            *oauthhttp.CallbackHandler
	tokenHandler               *oauthhttp.TokenHandler
	endUserConnectionsHandler  *oauthhttp.EndUserConnectionsHandler
	connectHandler             *oauthhttp.ConnectHandler
	configureHandler           *oauthhttp.ConfigureHandler
	jwksHandler                *oauthhttp.JWKSHandler
	whoAmIHandler              *mcphttp.WhoAmIHandler
	personalKeyHandler         *oauthhttp.PersonalKeyHandler
	modelRequestHandler        *oauthhttp.ModelRequestHandler
}

// MCPRouterOption adds an optional page to the MCP router.
type MCPRouterOption func(*mcpRouter)

// WithPersonalKeyHandler serves the MCP Store's personal key page.
func WithPersonalKeyHandler(h *oauthhttp.PersonalKeyHandler) MCPRouterOption {
	return func(r *mcpRouter) { r.personalKeyHandler = h }
}

// WithModelRequestHandler serves the MCP Store's model request page.
func WithModelRequestHandler(h *oauthhttp.ModelRequestHandler) MCPRouterOption {
	return func(r *mcpRouter) { r.modelRequestHandler = h }
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
	endUserConnectionsHandler *oauthhttp.EndUserConnectionsHandler,
	connectHandler *oauthhttp.ConnectHandler,
	configureHandler *oauthhttp.ConfigureHandler,
	jwksHandler *oauthhttp.JWKSHandler,
	whoAmIHandler *mcphttp.WhoAmIHandler,
	opsMetrics *middleware.OpsMetricsMiddleware,
	opts ...MCPRouterOption,
) ServerRouter {
	r := &mcpRouter{
		baseTransport:              baseTransport,
		authTransport:              authTransport,
		opsMetrics:                 opsMetrics,
		healthHandler:              healthHandler,
		mcpHandler:                 mcpHandler,
		protectedResourceHandler:   protectedResourceHandler,
		authorizationServerHandler: authorizationServerHandler,
		registerHandler:            registerHandler,
		authorizeHandler:           authorizeHandler,
		callbackHandler:            callbackHandler,
		tokenHandler:               tokenHandler,
		endUserConnectionsHandler:  endUserConnectionsHandler,
		connectHandler:             connectHandler,
		configureHandler:           configureHandler,
		jwksHandler:                jwksHandler,
		whoAmIHandler:              whoAmIHandler,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(r)
		}
	}
	return r
}

func (r *mcpRouter) BuildRoutes(app *fiber.App) error {
	if r.opsMetrics != nil {
		app.Use(r.opsMetrics.Middleware())
	}
	app.Get(HealthPath, r.healthHandler.Liveness)
	app.Get(HealthPathAlias, r.healthHandler.Liveness)
	app.Get(ReadyPath, r.healthHandler.Readiness)

	installMiddlewares(app, r.baseTransport)

	app.Get(oauthhttp.WellKnownProtectedResourcePath, r.protectedResourceHandler.Handle)
	app.Get(oauthhttp.WellKnownProtectedResourcePath+"/*", r.protectedResourceHandler.Handle)
	app.Get(oauthhttp.WellKnownAuthorizationServerPath, r.authorizationServerHandler.Handle)
	app.Post(oauthhttp.RegisterPath, r.registerHandler.Handle)
	// The RFC 7592 management URI authenticates with the registration access
	// token the registration response returned, not with the gateway's auth
	// chain, so it sits here on the base transport. It must also precede the
	// catch-all GET and DELETE routes below, which Fiber would otherwise match
	// first and answer with the MCP stream or a 405.
	app.Get(oauthhttp.RegisterClientPath, r.registerHandler.Read)
	app.Put(oauthhttp.RegisterClientPath, r.registerHandler.Update)
	app.Delete(oauthhttp.RegisterClientPath, r.registerHandler.Delete)
	app.Get(oauthhttp.AuthorizePath, r.authorizeHandler.Handle)
	app.Post(oauthhttp.AuthorizePath, r.authorizeHandler.Decide)
	app.Get(appoauth.CallbackPath, r.callbackHandler.Handle)
	app.Post(oauthhttp.TokenPath, r.tokenHandler.Handle)

	app.Get(oauthhttp.JWKSPath, r.jwksHandler.Handle)

	app.Get(oauthhttp.BrandAssetPath, oauthhttp.ServeBrandAsset)
	// Starting an upstream OAuth flow has side effects (a fresh state + an
	// authorize request the IdP records against the browser session), so the
	// connect page submits it as a POST: a GET link is fair game for browser
	// prefetching, and a prefetched start followed by the real click gives the
	// IdP two pending approvals — Linear then rejects the first callback with
	// "Invalid approval". A GET deep link gets a page that asks first.
	app.Get(oauthhttp.ConnectFinishPath, r.connectHandler.Finish)
	app.Post(oauthhttp.ConnectStartPath, r.connectHandler.Start)
	app.Get(oauthhttp.ConnectStartPath, r.connectHandler.Confirm)
	app.Get(oauthhttp.ConnectCallbackPath, r.connectHandler.Callback)
	app.Post(oauthhttp.DisconnectPath, r.connectHandler.Disconnect)
	if r.endUserConnectionsHandler != nil {
		app.Post("/:slug/connections/links", r.endUserConnectionsHandler.Link)
		app.Get("/:slug/connections", r.endUserConnectionsHandler.List)
	}
	// Ahead of the catch-all below, which would otherwise answer this as an
	// unserved path. It is the one question a client asks before it knows any
	// slug at all, so it carries none.
	if r.whoAmIHandler != nil {
		app.Get(mcphttp.WhoAmIPath, r.whoAmIHandler.Handle)
	}
	app.Get("/+/connect", r.connectHandler.Page)
	if r.configureHandler != nil {
		app.Get("/+/configure", r.configureHandler.Page)
		app.Post("/+/configure", r.configureHandler.Submit)
	}
	// The personal key page is reached by a Store link and a browser sign-in,
	// never by the auth chain: it sits ahead of the catch-alls below.
	if r.personalKeyHandler != nil {
		app.Get(appoauth.PersonalKeyReturnPath, r.personalKeyHandler.Return)
		app.Get(appoauth.PersonalKeyPagePath, r.personalKeyHandler.Page)
		app.Post(appoauth.PersonalKeyPagePath, r.personalKeyHandler.Act)
	}
	// So is the model request page: a Store link alone, like the MCP request form.
	if r.modelRequestHandler != nil {
		app.Get(appoauth.ModelRequestPagePath, r.modelRequestHandler.Page)
		app.Post(appoauth.ModelRequestPagePath, r.modelRequestHandler.Submit)
	}

	// The streamable-HTTP notification stream is a GET, so it has to be
	// registered before the catch-all 405 and carry authentication as route
	// middleware: a GET that is not asking for the event stream still answers
	// 405 without authenticating.
	app.Get("/*", r.mcpHandler.StreamRoute(r.authTransport.GetMiddlewares())...)
	app.Delete("/*", r.mcpHandler.NotServedHere)

	installMiddlewares(app, r.authTransport)
	app.Post("/*", r.mcpHandler.Handle)
	return nil
}
