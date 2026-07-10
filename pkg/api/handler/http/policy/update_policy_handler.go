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
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/policy/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/policy/response"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type UpdatePolicyHandler struct {
	updater apppolicy.Updater
}

func NewUpdatePolicyHandler(updater apppolicy.Updater) *UpdatePolicyHandler {
	return &UpdatePolicyHandler{updater: updater}
}

// Handle godoc
// @Summary      Update a policy
// @Description  Updates an existing policy.
// @Tags         policies
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                       true  "Gateway id"  format(uuid)
// @Param        id          path      string                       true  "Policy id"   format(uuid)
// @Param        body        body      request.UpdatePolicyRequest  true  "Policy fields to update"
// @Success      200         {object}  response.PolicyResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/policies/{id} [put]
func (h *UpdatePolicyHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.PolicyKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}

	var req request.UpdatePolicyRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return httpio.WriteError(c, err)
	}

	p, err := h.updater.Update(c.UserContext(), apppolicy.UpdateInput{
		ID:          id,
		GatewayID:   gatewayID,
		Name:        req.Name,
		Description: req.Description,
		Slug:        req.Slug,
		Enabled:     req.Enabled,
		Priority:    req.Priority,
		Parallel:    req.Parallel,
		Settings:    req.Settings,
		Stages:      req.ToStages(),
		Mode:        req.ToMode(),
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromPolicy(p))
}
