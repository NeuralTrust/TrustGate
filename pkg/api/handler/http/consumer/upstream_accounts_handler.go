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

package consumer

import (
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/consumer/response"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

// UpstreamAccountsHandler serves the upstream credentials of an MCP application:
// which of its bound servers carry their own credential, which want the
// application's account linked, and a link an admin can walk to link them.
type UpstreamAccountsHandler struct {
	accounts appoauth.ConsumerUpstreamAccounts
}

func NewUpstreamAccountsHandler(accounts appoauth.ConsumerUpstreamAccounts) *UpstreamAccountsHandler {
	return &UpstreamAccountsHandler{accounts: accounts}
}

// Get godoc
// @Summary      Read an MCP application's upstream accounts
// @Description  For an MCP consumer that acts as the application itself: per bound MCP server, its upstream auth mode, whether that server needs an account linked for the application, and — when it does — whether one is linked, for which account, and whether it needs reconnecting. The accounts belong to the consumer, so the answer does not depend on which credential the application authenticates with. Credential material is never returned.
// @Tags         consumers
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path   string  true   "Gateway id"   format(uuid)
// @Param        id          path   string  true   "Consumer id"  format(uuid)
// @Success      200  {object}  response.ConsumerUpstreamAccounts
// @Failure      400  {object}  httpio.ErrorBody
// @Failure      401  {object}  httpio.ErrorBody
// @Failure      404  {object}  httpio.ErrorBody
// @Failure      409  {object}  httpio.ErrorBody  "The consumer acts for users, so it holds no account of its own"
// @Router       /v1/gateways/{gateway_id}/consumers/{id}/upstream-accounts [get]
func (h *UpstreamAccountsHandler) Get(c *fiber.Ctx) error {
	gatewayID, consumerID, err := httpio.ParseGatewayScopedID[ids.ConsumerKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	state, err := h.accounts.State(c.UserContext(), gatewayID, consumerID)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.NewConsumerUpstreamAccounts(state))
}

// Link godoc
// @Summary      Mint a connect link for an MCP application's upstream accounts
// @Description  Returns a connect ticket an admin can open to link the application's own accounts on the servers that forward a stored credential — the same page the api-key self-service flow uses, without needing one of the application's credentials. Naming a registry narrows the ticket to that one server; omitting it covers every server of the application that forwards a credential. The ticket is pinned to this consumer and to those providers, revalidated on redemption, audited, and short-lived.
// @Tags         consumers
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id   path   string  true   "Gateway id"   format(uuid)
// @Param        id           path   string  true   "Consumer id"  format(uuid)
// @Param        registry_id  query  string  false  "Authorize only this bound MCP server"  format(uuid)
// @Success      201  {object}  response.ConsumerConnectLink
// @Failure      400  {object}  httpio.ErrorBody
// @Failure      401  {object}  httpio.ErrorBody
// @Failure      404  {object}  httpio.ErrorBody  "The consumer does not exist, or the registry is not bound to it"
// @Failure      409  {object}  httpio.ErrorBody  "The consumer acts for users, or the named server carries its own credential"
// @Router       /v1/gateways/{gateway_id}/consumers/{id}/upstream-accounts/link [post]
func (h *UpstreamAccountsHandler) Link(c *fiber.Ctx) error {
	gatewayID, consumerID, err := httpio.ParseGatewayScopedID[ids.ConsumerKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	registryID, err := optionalRegistryID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	link, err := h.accounts.Link(c.UserContext(), gatewayID, consumerID, registryID)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteCreated(c, response.NewConsumerConnectLink(link))
}

// optionalRegistryID reads ?registry_id=, absent meaning every server of the
// application that forwards a credential.
func optionalRegistryID(c *fiber.Ctx) (ids.RegistryID, error) {
	raw := strings.TrimSpace(c.Query("registry_id"))
	if raw == "" {
		return ids.RegistryID{}, nil
	}
	parsed, err := ids.Parse[ids.RegistryKind](raw)
	if err != nil {
		return ids.RegistryID{}, fmt.Errorf("invalid registry_id: %w", commonerrors.ErrValidation)
	}
	return parsed, nil
}
