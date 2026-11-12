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
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/response"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/gofiber/fiber/v2"
)

type PreviewAgentCardHandler struct {
	cards appregistry.PreviewAgentCard
}

func NewPreviewAgentCardHandler(cards appregistry.PreviewAgentCard) *PreviewAgentCardHandler {
	return &PreviewAgentCardHandler{cards: cards}
}

// Handle godoc
// @Summary      Preview an agent card
// @Description  Resolves and reads the agent card an a2a_target names, and returns it with its digest and the A2A versions it offers. Writes nothing; credentials in the body are used for this read only.
// @Tags         registries
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                           true  "Gateway id"  format(uuid)
// @Param        body        body      request.PreviewAgentCardRequest  true  "Agent to read"
// @Success      200         {object}  response.PreviewAgentCardResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/preview-agent-card [post]
func (h *PreviewAgentCardHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req request.PreviewAgentCardRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	preview, err := h.cards.Preview(c.UserContext(), gatewayID, req.ToDomain())
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromAgentCardPreview(preview))
}
