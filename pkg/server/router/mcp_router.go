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
