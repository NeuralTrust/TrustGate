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
	"strings"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

// Provider keys can contain slashes (e.g. "app.linear/mcp"), so these routes
// use a greedy wildcard segment instead of a single-segment :provider param.
const (
	ConnectStartPath    = "/oauth/connect/*"
	ConnectCallbackPath = "/oauth/callback/*"
	DisconnectPath      = "/oauth/disconnect/*"
)

type ConnectHandler struct {
	connect appoauth.ConnectService
}

func NewConnectHandler(connect appoauth.ConnectService) *ConnectHandler {
	return &ConnectHandler{connect: connect}
}

func (h *ConnectHandler) Page(c *fiber.Ctx) error {
	ticket := c.Query("ticket")
	if ticket == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "missing ticket: re-run the tool call to get a fresh connect link")
	}
	return h.showPage(c, ticket, "")
}

func (h *ConnectHandler) Start(c *fiber.Ctx) error {
	location, err := h.connect.Start(c.UserContext(), c.BaseURL(), c.Query("ticket"), providerParam(c))
	if err != nil {
		return h.pageError(c, err)
	}
	return c.Redirect(location, fiber.StatusFound)
}

func (h *ConnectHandler) Callback(c *fiber.Ctx) error {
	ticketID, err := h.connect.Callback(
		c.UserContext(), c.BaseURL(), providerParam(c),
		c.Query("state"), c.Query("code"), c.Query("error"), c.Query("error_description"),
	)
	if err != nil {
		if ticketID == "" {
			return h.pageError(c, err)
		}
		return h.showPage(c, ticketID, err.Error())
	}
	return h.showPage(c, ticketID, "")
}

func (h *ConnectHandler) Disconnect(c *fiber.Ctx) error {
	ticket := c.Query("ticket")
	if err := h.connect.Disconnect(c.UserContext(), ticket, providerParam(c)); err != nil {
		return h.pageError(c, err)
	}
	return h.showPage(c, ticket, "")
}

func providerParam(c *fiber.Ctx) string {
	return strings.TrimPrefix(c.Params("*"), "/")
}

func (h *ConnectHandler) showPage(c *fiber.Ctx, ticket, flash string) error {
	page, err := h.connect.Page(c.UserContext(), ticket)
	if err != nil {
		return h.pageError(c, err)
	}
	return renderConnectPage(c, page, ticket, flash)
}

func (h *ConnectHandler) pageError(c *fiber.Ctx, err error) error {
	if errors.Is(err, appoauth.ErrTicketNotFound) {
		return fiber.NewError(fiber.StatusUnauthorized, err.Error())
	}
	if errors.Is(err, appoauth.ErrProviderNotFound) {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	return err
}
