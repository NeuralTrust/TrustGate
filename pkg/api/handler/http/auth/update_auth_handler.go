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
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/helpers"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type UpdateAuthHandler struct {
	updater appauth.Updater
}

func NewUpdateAuthHandler(updater appauth.Updater) *UpdateAuthHandler {
	return &UpdateAuthHandler{updater: updater}
}

// Handle godoc
// @Summary      Update an auth
// @Description  Updates an existing auth.
// @Tags         auths
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                     true  "Gateway id"  format(uuid)
// @Param        id          path      string                     true  "Auth id"     format(uuid)
// @Param        body        body      request.UpdateAuthRequest  true  "Auth fields to update"
// @Success      200         {object}  response.AuthResponse
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Failure      409         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/auths/{id} [put]
func (h *UpdateAuthHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID[ids.AuthKind](c)
	if err != nil {
		return helpers.WriteError(c, err)
	}

	var req request.UpdateAuthRequest
	if err := c.BodyParser(&req); err != nil {
		return helpers.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return helpers.WriteError(c, err)
	}

	a, err := h.updater.Update(c.UserContext(), appauth.UpdateInput{
		ID:        id,
		GatewayID: gatewayID,
		Name:      req.Name,
		Type:      req.ToType(),
		Enabled:   req.Enabled,
		Config:    req.ToConfig(),
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromAuth(a))
}
