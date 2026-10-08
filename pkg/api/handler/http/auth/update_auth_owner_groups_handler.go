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

package auth

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/auth/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/auth/response"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

// UpdateAuthOwnerGroupsHandler records the directory groups of a personal
// key's owner.
type UpdateAuthOwnerGroupsHandler struct {
	setter appauth.OwnerGroupsSetter
	reach  appconsumer.AuthConsumers
}

// NewUpdateAuthOwnerGroupsHandler returns the handler; reach lists the
// consumers the key holds, which the response carries like every admin auth
// response.
func NewUpdateAuthOwnerGroupsHandler(setter appauth.OwnerGroupsSetter, reach appconsumer.AuthConsumers) *UpdateAuthOwnerGroupsHandler {
	return &UpdateAuthOwnerGroupsHandler{setter: setter, reach: reach}
}

// Handle godoc
// @Summary      Set the owner groups of a personal key
// @Description  Records the directory groups of a personal (owned) key's owner. The body is {"groups": ["<group>", ...]}; an empty list clears them. Names are trimmed, deduplicated and sorted; at most 512 groups of at most 256 characters each. On the MCP Store (/store/mcp) the key runs as its owner with these groups, so Store grants, Store access policies and MCP policies scoped to a group apply as they do to a signed-in session. The platform sends them whenever the owner's membership changes. The secret, the expiry, the budget and the consumers of the key do not change, and a rotation keeps the groups. An application key answers 422 application_key; an invalid body answers 422 validation_failed.
// @Tags         auths
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                                true  "Gateway id"  format(uuid)
// @Param        id          path      string                                true  "Auth id"     format(uuid)
// @Param        body        body      request.UpdateAuthOwnerGroupsRequest  true  "The owner's groups"
// @Success      200         {object}  response.AuthResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody  "An application key (application_key), or invalid groups (validation_failed)"
// @Router       /v1/gateways/{gateway_id}/auths/{id}/groups [put]
func (h *UpdateAuthOwnerGroupsHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.AuthKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req request.UpdateAuthOwnerGroupsRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}

	a, err := h.setter.SetOwnerGroups(c.UserContext(), appauth.SetOwnerGroupsInput{
		ID:        id,
		GatewayID: gatewayID,
		Groups:    req.Groups,
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	held, err := h.reach.ForAuths(c.UserContext(), gatewayID, []ids.AuthID{a.ID})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromAuthWithConsumers(a, held[a.ID]))
}
