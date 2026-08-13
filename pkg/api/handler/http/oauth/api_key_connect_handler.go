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
	"mime"
	"net/http"
	"net/url"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/oauth/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

type APIKeyConnectHandler struct {
	gateways resolver.GatewayResolver
	connect  appoauth.APIKeyConnectService
}

func NewAPIKeyConnectHandler(
	gateways resolver.GatewayResolver,
	connect appoauth.APIKeyConnectService,
) *APIKeyConnectHandler {
	return &APIKeyConnectHandler{
		gateways: gateways,
		connect:  connect,
	}
}

func (h *APIKeyConnectHandler) Get(c *fiber.Ctx) error {
	setAPIKeyConnectNoStore(c)

	gateway, err := h.gateways.Resolve(c)
	if err != nil {
		if errors.Is(err, appauth.ErrInvalidAuthRequest) {
			return writeAPIKeyConnectStatus(c, fiber.StatusNotFound)
		}
		return writeAPIKeyConnectStatus(c, fiber.StatusInternalServerError)
	}
	if gateway == nil {
		return writeAPIKeyConnectStatus(c, fiber.StatusNotFound)
	}

	slug := c.Params("slug")
	if err := h.connect.ValidateTarget(c.UserContext(), gateway.ID, slug); err != nil {
		if errors.Is(err, appoauth.ErrAPIKeyConnectUnauthorized) {
			return writeAPIKeyConnectStatus(c, fiber.StatusNotFound)
		}
		return writeAPIKeyConnectStatus(c, fiber.StatusInternalServerError)
	}

	if err := renderAPIKeyConnectPage(c, "/"+slug+"/connect"); err != nil {
		return writeAPIKeyConnectStatus(c, fiber.StatusInternalServerError)
	}
	return nil
}

func (h *APIKeyConnectHandler) Post(c *fiber.Ctx) error {
	setAPIKeyConnectNoStore(c)

	if !isFormURLEncoded(c.Get(fiber.HeaderContentType)) {
		return writeAPIKeyConnectStatus(c, fiber.StatusUnsupportedMediaType)
	}

	rawBody := c.Body()
	values, err := url.ParseQuery(string(rawBody))
	if err != nil {
		return writeAPIKeyConnectStatus(c, fiber.StatusBadRequest)
	}
	body := request.APIKeyConnectRequest{APIKey: values.Get("api_key")}

	gateway, err := h.gateways.Resolve(c)
	if err != nil {
		if errors.Is(err, appauth.ErrInvalidAuthRequest) {
			return writeAPIKeyConnectStatus(c, fiber.StatusUnauthorized)
		}
		return writeAPIKeyConnectStatus(c, fiber.StatusInternalServerError)
	}
	if gateway == nil {
		return writeAPIKeyConnectStatus(c, fiber.StatusUnauthorized)
	}

	slug := c.Params("slug")
	ticket, err := h.connect.CreateTicket(c.UserContext(), gateway.ID, slug, body.APIKey)
	if err != nil {
		if errors.Is(err, appoauth.ErrAPIKeyConnectUnauthorized) {
			return writeAPIKeyConnectStatus(c, fiber.StatusUnauthorized)
		}
		return writeAPIKeyConnectStatus(c, fiber.StatusInternalServerError)
	}

	location := "/" + slug + "/mcp/connect?ticket=" + url.QueryEscape(ticket)
	return c.Redirect(location, fiber.StatusSeeOther)
}

func isFormURLEncoded(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == fiber.MIMEApplicationForm
}

func setAPIKeyConnectNoStore(c *fiber.Ctx) {
	c.Set(fiber.HeaderCacheControl, "no-store")
}

func writeAPIKeyConnectStatus(c *fiber.Ctx, status int) error {
	return c.Status(status).SendString(http.StatusText(status))
}
