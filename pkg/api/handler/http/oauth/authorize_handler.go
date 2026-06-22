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

package oauth

import (
	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

const AuthorizePath = "/oauth/authorize"

type AuthorizeHandler struct {
	proxy    appoauth.AuthProxy
	gateways resolver.GatewayResolver
}

func NewAuthorizeHandler(proxy appoauth.AuthProxy, gateways resolver.GatewayResolver) *AuthorizeHandler {
	return &AuthorizeHandler{proxy: proxy, gateways: gateways}
}

func (h *AuthorizeHandler) Handle(c *fiber.Ctx) error {
	req := appoauth.AuthorizeRequest{
		ResponseType:        c.Query("response_type"),
		ClientID:            c.Query("client_id"),
		RedirectURI:         c.Query("redirect_uri"),
		State:               c.Query("state"),
		Scope:               c.Query("scope"),
		CodeChallenge:       c.Query("code_challenge"),
		CodeChallengeMethod: c.Query("code_challenge_method"),
		Resource:            c.Query("resource"),
	}
	ctx := resolver.WithResolvedGateway(c, h.gateways)
	location, err := h.proxy.Authorize(ctx, c.BaseURL(), req)
	if err != nil {
		return writeOAuthError(c, err)
	}
	return c.Redirect(location, fiber.StatusFound)
}
