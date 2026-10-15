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
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/gofiber/fiber/v2"
)

type MCPWidePolicyHandler struct {
	scoper   apppolicy.Scoper
	warner   apppolicy.Warner
	status   apppolicy.StatusEvaluator
	registry appplugins.Registry
}

func NewMCPWidePolicyHandler(scoper apppolicy.Scoper, warner apppolicy.Warner, status apppolicy.StatusEvaluator, registry appplugins.Registry) *MCPWidePolicyHandler {
	return &MCPWidePolicyHandler{scoper: scoper, warner: warner, status: status, registry: registry}
}

// SetMCPWide godoc
// @Summary      Mark a policy as MCP-wide
// @Description  Promotes a policy to run on every MCP consumer of the gateway and on the MCP Store, narrowed by its mcp_scope (groups, except_groups, registries, tools); a null mcp_scope means every MCP caller. It never runs on LLM or A2A consumers. Promoting clears global and removes the policy's consumer links in the same write; while the flag is set a consumer cannot be attached (422). The policy takes the all-consumers levels of its scope, the ones a global policy of that scope takes, so it answers 409 when another policy of the same plugin already holds one of them, global ones included. A policy that changed while it was being promoted also answers 409: reload it and retry. A retry that finds the policy already MCP-wide answers 200 with the policy as stored. A plugin without MCP support answers 422. Plugin state such as rate-limit counters is shared gateway-wide, as for a global policy. The response may carry non-blocking warnings.
// @Tags         policies
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Param        id          path      string  true  "Policy id"   format(uuid)
// @Success      200         {object}  response.PolicyResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody  "The gateway already runs this plugin at one of the levels the policy would take on every MCP consumer, or the policy changed while it was being promoted"
// @Failure      422         {object}  httpio.ErrorBody  "The plugin does not support MCP"
// @Router       /v1/gateways/{gateway_id}/policies/{id}/mcp-wide [post]
func (h *MCPWidePolicyHandler) SetMCPWide(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.PolicyKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	p, err := h.scoper.SetMCPWide(c.UserContext(), gatewayID, id)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromPolicyWithWarnings(p, overlapWarnings(c, h.warner, p), h.registry).WithStatus(h.evaluate(p)))
}

// UnsetMCPWide godoc
// @Summary      Clear a policy's MCP-wide placement
// @Description  Demotes an MCP-wide policy to a draft: it holds no consumer links, so it runs nowhere until a consumer is attached or it is promoted again. Clears only mcp_wide: a policy that is not MCP-wide is returned unchanged with 200, a global one included.
// @Tags         policies
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Param        id          path      string  true  "Policy id"   format(uuid)
// @Success      200         {object}  response.PolicyResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/policies/{id}/mcp-wide [delete]
func (h *MCPWidePolicyHandler) UnsetMCPWide(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.PolicyKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	p, err := h.scoper.UnsetMCPWide(c.UserContext(), gatewayID, id)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromPolicy(p, h.registry).WithStatus(h.evaluate(p)))
}

func (h *MCPWidePolicyHandler) evaluate(p *domain.Policy) (string, string) {
	status, message := h.status.Evaluate(p)
	return string(status), message
}
