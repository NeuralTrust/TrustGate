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

package registry

import (
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/response"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

// SharedAccountHandler serves the upstream account an MCP instance holds for
// every caller: what it is, the page an admin walks to authorize it, and the
// button that drops it.
type SharedAccountHandler struct {
	accounts appregistry.SharedAccountService
}

func NewSharedAccountHandler(accounts appregistry.SharedAccountService) *SharedAccountHandler {
	return &SharedAccountHandler{accounts: accounts}
}

// Get godoc
// @Summary      Read an instance's shared upstream account
// @Description  Reports whether the account this MCP instance holds for every caller is connected.
// @Tags         registries
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"   format(uuid)
// @Param        id          path      string  true  "Registry id"  format(uuid)
// @Success      200         {object}  response.SharedAccountResponse
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/{id}/shared-account [get]
func (h *SharedAccountHandler) Get(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.RegistryKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	account, err := h.accounts.Status(c.UserContext(), gatewayID, id)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromSharedAccount(account))
}

// ConnectLink godoc
// @Summary      Start connecting an instance's shared upstream account
// @Description  Mints the connect page an administrator walks to authorize the account every caller of this instance uses.
// @Tags         registries
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"   format(uuid)
// @Param        id          path      string  true  "Registry id"  format(uuid)
// @Success      200         {object}  response.SharedAccountLinkResponse
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/{id}/shared-account/connect-link [post]
func (h *SharedAccountHandler) ConnectLink(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.RegistryKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	link, err := h.accounts.Link(c.UserContext(), gatewayID, id)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromSharedAccountLink(link))
}

// Disconnect godoc
// @Summary      Drop an instance's shared upstream account
// @Description  Forgets the stored account. Nothing is revoked upstream, but calls through this instance stop until it is connected again.
// @Tags         registries
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"   format(uuid)
// @Param        id          path      string  true  "Registry id"  format(uuid)
// @Success      204
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/{id}/shared-account [delete]
func (h *SharedAccountHandler) Disconnect(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.RegistryKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if err := h.accounts.Disconnect(c.UserContext(), gatewayID, id); err != nil {
		return httpio.WriteError(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}
