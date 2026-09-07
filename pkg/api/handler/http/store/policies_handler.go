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

package store

import (
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	"github.com/gofiber/fiber/v2"
)

// PoliciesHandler serves the per-principal Store access policies of a gateway:
// which users and groups are on All / Selected / None. The gateway evaluates
// them live, so a change here applies to the next request.
type PoliciesHandler struct {
	policies appstore.PolicyService
}

func NewPoliciesHandler(policies appstore.PolicyService) *PoliciesHandler {
	return &PoliciesHandler{policies: policies}
}

type policyResponse struct {
	PrincipalType string `json:"principal_type"`
	PrincipalID   string `json:"principal_id"`
	Mode          string `json:"mode"`
}

type listPoliciesResponse struct {
	Items []policyResponse `json:"items"`
	Total int              `json:"total"`
}

// setPolicyRequest replaces one principal's level. An empty mode clears the
// policy so the gateway default applies again.
type setPolicyRequest struct {
	PrincipalType string `json:"principal_type"`
	PrincipalID   string `json:"principal_id"`
	Mode          string `json:"mode"`
}

// List godoc
// @Summary      List MCP Store access policies
// @Description  Returns every per-principal Store access level (open | curated | none) set on the gateway, for users and groups.
// @Tags         store
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Success      200         {object}  listPoliciesResponse
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/store/access-policies [get]
func (h *PoliciesHandler) List(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	policies, err := h.policies.ListPoliciesByGateway(c.UserContext(), gatewayID)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	out := listPoliciesResponse{Items: make([]policyResponse, 0, len(policies))}
	for _, p := range policies {
		if p == nil {
			continue
		}
		out.Items = append(out.Items, policyResponse{
			PrincipalType: string(p.PrincipalType), PrincipalID: p.PrincipalID, Mode: p.Mode,
		})
	}
	out.Total = len(out.Items)
	return httpio.WriteOK(c, out)
}

// Set godoc
// @Summary      Set an MCP Store access policy
// @Description  Sets a user's or group's Store access level on the gateway (open | curated | none); an empty mode clears it so the gateway default applies.
// @Tags         store
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string            true  "Gateway id"  format(uuid)
// @Param        body        body      setPolicyRequest  true  "The policy"
// @Success      200         {object}  policyResponse
// @Success      204         "Policy cleared"
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/store/access-policies [put]
func (h *PoliciesHandler) Set(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req setPolicyRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if strings.TrimSpace(req.PrincipalID) == "" {
		return httpio.WriteError(c, fmt.Errorf("principal_id is required: %w", commonerrors.ErrValidation))
	}
	policy, err := h.policies.Set(c.UserContext(), appstore.SetPolicyRequest{
		GatewayID:     gatewayID,
		PrincipalType: storeaccessdomain.PrincipalType(strings.ToLower(strings.TrimSpace(req.PrincipalType))),
		PrincipalID:   req.PrincipalID,
		Mode:          req.Mode,
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if policy == nil {
		return c.SendStatus(fiber.StatusNoContent)
	}
	return httpio.WriteOK(c, policyResponse{
		PrincipalType: string(policy.PrincipalType), PrincipalID: policy.PrincipalID, Mode: policy.Mode,
	})
}
