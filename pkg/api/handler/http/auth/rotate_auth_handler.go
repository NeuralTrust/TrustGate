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

type RotateAuthHandler struct {
	rotator appauth.Rotator
	// reach answers which consumers hold this auth, as it does on get and list.
	// It matters more here than anywhere else: rotating cuts off whatever holds
	// the old secret, and this is the list of what that is.
	reach appconsumer.AuthConsumers
}

func NewRotateAuthHandler(rotator appauth.Rotator, reach appconsumer.AuthConsumers) *RotateAuthHandler {
	return &RotateAuthHandler{rotator: rotator, reach: reach}
}

// Handle godoc
// @Summary      Rotate an api key
// @Description  Replaces the secret of an api_key auth and returns the new one. The auth keeps its id, its name and every consumer it is attached to; the previous secret stops authenticating immediately. The new secret is returned once and is not retrievable afterwards.
// @Tags         auths
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Param        id          path      string                     true   "Auth id"     format(uuid)
// @Param        body        body      request.RotateAuthRequest  false  "Expiry for the new secret"
// @Success      200         {object}  response.AuthResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/auths/{id}/rotate [post]
func (h *RotateAuthHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.AuthKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	// The body is optional: rotating with none replaces the secret and leaves
	// the expiry where it was.
	var req request.RotateAuthRequest
	if len(c.Body()) > 0 {
		if err := c.BodyParser(&req); err != nil {
			return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
		}
		if err := req.Validate(); err != nil {
			return httpio.WriteError(c, err)
		}
	}

	a, err := h.rotator.Rotate(c.UserContext(), appauth.RotateInput{
		ID:        id,
		GatewayID: gatewayID,
		Expiry:    req.ToExpiry(),
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if h.reach == nil {
		return httpio.WriteOK(c, response.FromCreatedAuth(a))
	}
	held, err := h.reach.ForAuths(c.UserContext(), gatewayID, []ids.AuthID{a.ID})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromCreatedAuthWithConsumers(a, held[a.ID]))
}
