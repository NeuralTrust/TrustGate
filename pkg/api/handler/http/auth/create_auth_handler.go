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

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/auth/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/auth/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/gofiber/fiber/v2"
)

type CreateAuthHandler struct {
	creator appauth.Creator
}

func NewCreateAuthHandler(creator appauth.Creator) *CreateAuthHandler {
	return &CreateAuthHandler{creator: creator}
}

// Handle godoc
// @Summary      Create an auth
// @Description  Creates a new auth in a gateway.
// @Tags         auths
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                     true  "Gateway id"  format(uuid)
// @Param        body        body      request.CreateAuthRequest  true  "Auth to create"
// @Success      201         {object}  response.AuthResponse
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Failure      409         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/auths [post]
func (h *CreateAuthHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := helpers.ParseGatewayID(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}

	var req request.CreateAuthRequest
	if err := c.BodyParser(&req); err != nil {
		return helpers.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return helpers.WriteError(c, err)
	}

	a, err := h.creator.Create(c.UserContext(), appauth.CreateInput{
		GatewayID: gatewayID,
		Name:      req.Name,
		Type:      domain.Type(req.Type),
		Enabled:   req.IsEnabled(),
		Config:    req.Config.ToDomain(),
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteCreated(c, response.FromCreatedAuth(a))
}
