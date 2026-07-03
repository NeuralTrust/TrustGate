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

package policy

import (
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/policy/response"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type GlobalPolicyHandler struct {
	scoper apppolicy.Scoper
}

func NewGlobalPolicyHandler(scoper apppolicy.Scoper) *GlobalPolicyHandler {
	return &GlobalPolicyHandler{scoper: scoper}
}

// SetGlobal godoc
// @Summary      Mark a policy as global
// @Description  Promotes a policy to gateway-wide scope (applies to every consumer).
// @Tags         policies
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Param        id          path      string  true  "Policy id"   format(uuid)
// @Success      200         {object}  response.PolicyResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/policies/{id}/global [post]
func (h *GlobalPolicyHandler) SetGlobal(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.PolicyKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	p, err := h.scoper.SetGlobal(c.UserContext(), gatewayID, id)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromPolicy(p))
}

// UnsetGlobal godoc
// @Summary      Clear a policy's global scope
// @Description  Demotes a global policy back to consumer-scoped (applies only to linked consumers).
// @Tags         policies
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Param        id          path      string  true  "Policy id"   format(uuid)
// @Success      200         {object}  response.PolicyResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/policies/{id}/global [delete]
func (h *GlobalPolicyHandler) UnsetGlobal(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.PolicyKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	p, err := h.scoper.UnsetGlobal(c.UserContext(), gatewayID, id)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromPolicy(p))
}
