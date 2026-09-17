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
	"github.com/gofiber/fiber/v2"
)

type CreatePolicyHandler struct {
	creator apppolicy.Creator
	warner  apppolicy.Warner
}

func NewCreatePolicyHandler(creator apppolicy.Creator, warner apppolicy.Warner) *CreatePolicyHandler {
	return &CreatePolicyHandler{creator: creator, warner: warner}
}

// Handle godoc
// @Summary      Create a policy
// @Description  Creates a new policy in a gateway. An optional mcp_scope narrows it to MCP registries, tools and principals; the response echoes the stored scope and may carry non-blocking warnings.
// @Tags         policies
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                       true  "Gateway id"  format(uuid)
// @Param        body        body      request.CreatePolicyRequest  true  "Policy to create"
// @Success      201         {object}  response.PolicyResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/policies [post]
func (h *CreatePolicyHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}

	var req request.CreatePolicyRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return httpio.WriteError(c, err)
	}
	scope, err := req.ToMCPScope()
	if err != nil {
		return httpio.WriteError(c, err)
	}

	p, err := h.creator.Create(c.UserContext(), apppolicy.CreateInput{
		GatewayID:   gatewayID,
		Name:        req.Name,
		Description: req.Description,
		Slug:        req.Slug,
		Enabled:     req.Enabled,
		Priority:    req.Priority,
		Parallel:    req.ParallelOrDefault(),
		Settings:    req.Settings,
		Stages:      req.ToStages(),
		Mode:        req.ToMode(),
		MCPScope:    scope,
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteCreated(c, response.FromPolicyWithWarnings(p, overlapWarnings(c, h.warner, p)))
}
