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
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/consumer/response"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
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
// @Description  Returns a single-consumer connect ticket an admin can open to link the application's own accounts on the servers that forward a stored credential — the same page the api-key self-service flow uses, without needing one of the application's credentials. The ticket is pinned to this consumer and to the providers bound to it, revalidated on redemption, audited, and short-lived.
// @Tags         consumers
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path  string  true  "Gateway id"   format(uuid)
// @Param        id          path  string  true  "Consumer id"  format(uuid)
// @Success      201  {object}  response.ConsumerConnectLink
// @Failure      400  {object}  httpio.ErrorBody
// @Failure      401  {object}  httpio.ErrorBody
// @Failure      404  {object}  httpio.ErrorBody
// @Failure      409  {object}  httpio.ErrorBody  "The consumer acts for users, so it holds no account of its own"
// @Router       /v1/gateways/{gateway_id}/consumers/{id}/upstream-accounts/link [post]
func (h *UpstreamAccountsHandler) Link(c *fiber.Ctx) error {
	gatewayID, consumerID, err := httpio.ParseGatewayScopedID[ids.ConsumerKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	link, err := h.accounts.Link(c.UserContext(), gatewayID, consumerID)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteCreated(c, response.NewConsumerConnectLink(link))
}
