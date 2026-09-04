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
	"net/url"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

// ConfigureHandler serves the MCP-Store per-user configuration form: a hosted
// page, reached by a short-lived ticket, where a user enters a catalog server's
// URL variables (e.g. a Snowflake account URL, a Bright Data token). The ticket
// authorizes the write for its (gateway, principal, consumer, code); the browser
// itself is unauthenticated, exactly like the OAuth connect page.
type ConfigureHandler struct {
	configure appoauth.ConfigureService
}

func NewConfigureHandler(configure appoauth.ConfigureService) *ConfigureHandler {
	return &ConfigureHandler{configure: configure}
}

func (h *ConfigureHandler) Page(c *fiber.Ctx) error {
	setConfigureResponsePolicies(c)
	if h.configure == nil {
		return fiber.NewError(fiber.StatusNotFound, "configuration is not available here")
	}
	ticket := c.Query("ticket")
	if ticket == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "missing ticket: re-run the install to get a fresh configure link")
	}
	page, err := h.configure.Page(c.UserContext(), ticket)
	if err != nil {
		return h.pageError(c, err)
	}
	return renderConfigurePage(c, page)
}

func (h *ConfigureHandler) Submit(c *fiber.Ctx) error {
	setConfigureResponsePolicies(c)
	if h.configure == nil {
		return fiber.NewError(fiber.StatusNotFound, "configuration is not available here")
	}
	ticket := c.Query("ticket")
	if ticket == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "missing ticket: re-run the install to get a fresh configure link")
	}
	if !isFormURLEncoded(c.Get(fiber.HeaderContentType)) {
		return fiber.NewError(fiber.StatusUnsupportedMediaType, "expected application/x-www-form-urlencoded")
	}
	values, err := url.ParseQuery(string(c.Body()))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "malformed form body")
	}
	submitted := make(map[string]string, len(values))
	for key := range values {
		submitted[key] = values.Get(key)
	}
	page, err := h.configure.Submit(c.UserContext(), ticket, submitted)
	if err != nil {
		if errors.Is(err, appoauth.ErrConfigureInvalid) {
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		}
		return h.pageError(c, err)
	}
	return renderConfigurePage(c, page)
}

func (h *ConfigureHandler) pageError(c *fiber.Ctx, err error) error {
	if errors.Is(err, appoauth.ErrTicketNotFound) {
		return fiber.NewError(fiber.StatusUnauthorized, err.Error())
	}
	return err
}

func setConfigureResponsePolicies(c *fiber.Ctx) {
	c.Set(fiber.HeaderCacheControl, "no-store")
	c.Set("Referrer-Policy", "no-referrer")
}
