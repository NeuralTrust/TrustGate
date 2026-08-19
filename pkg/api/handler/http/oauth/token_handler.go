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
	"errors"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

const TokenPath = "/oauth/token" // #nosec G101 -- route path, not a credential

type TokenHandler struct {
	proxy    appoauth.AuthProxy
	gateways resolver.GatewayResolver
}

func NewTokenHandler(proxy appoauth.AuthProxy, gateways resolver.GatewayResolver) *TokenHandler {
	return &TokenHandler{proxy: proxy, gateways: gateways}
}

func (h *TokenHandler) Handle(c *fiber.Ctx) error {
	req := appoauth.TokenRequest{
		GrantType:    c.FormValue("grant_type"),
		Code:         c.FormValue("code"),
		RedirectURI:  c.FormValue("redirect_uri"),
		ClientID:     c.FormValue("client_id"),
		CodeVerifier: c.FormValue("code_verifier"),
		RefreshToken: c.FormValue("refresh_token"),
		Resource:     c.FormValue("resource"),
	}
	ctx := resolver.WithResolvedGateway(c, h.gateways)
	token, err := h.proxy.Exchange(ctx, c.BaseURL(), req)
	if err != nil {
		return writeOAuthError(c, err)
	}
	c.Set(fiber.HeaderCacheControl, "no-store")
	return httpio.WriteOK(c, token)
}

func writeOAuthError(c *fiber.Ctx, err error) error {
	var oe *appoauth.OAuthError
	if errors.As(err, &oe) {
		status := fiber.StatusBadRequest
		if oe.Code == "invalid_client" {
			status = fiber.StatusUnauthorized
		}
		return c.Status(status).JSON(oe)
	}
	if errors.Is(err, appoauth.ErrNoAuthorizationServer) || errors.Is(err, appoauth.ErrAmbiguousAuthorizationServer) {
		return c.Status(fiber.StatusNotFound).JSON(appoauth.OAuthError{Code: "invalid_request", Description: err.Error()})
	}
	return httpio.WriteError(c, err)
}
