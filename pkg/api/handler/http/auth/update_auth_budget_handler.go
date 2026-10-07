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

// UpdateAuthBudgetHandler sets or clears the spending limit of a personal key.
type UpdateAuthBudgetHandler struct {
	setter appauth.BudgetSetter
	reach  appconsumer.AuthConsumers
}

// NewUpdateAuthBudgetHandler returns the handler; reach lists the consumers the
// key holds, which the response carries like every admin auth response.
func NewUpdateAuthBudgetHandler(setter appauth.BudgetSetter, reach appconsumer.AuthConsumers) *UpdateAuthBudgetHandler {
	return &UpdateAuthBudgetHandler{setter: setter, reach: reach}
}

// Handle godoc
// @Summary      Set the budget of a personal key
// @Description  Sets or clears the spending limit of a personal (owned) key. The body is {"max": <number>, "unit": "tokens" or "dollars", "time_window": "calendar_month" or "calendar_day"}, or null to clear the budget. max must be a finite number above zero, and a whole number of tokens when unit is tokens. Every token_rate_limiter policy with key_budgets that counts in that unit holds the key to this budget in place of its aggregate; a policy counting in the other unit keeps its own limit. The secret, the expiry and the consumers of the key do not change, and a rotation keeps the budget. An application key answers 422 application_key; an invalid body answers 422 validation_failed.
// @Tags         auths
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                           true  "Gateway id"  format(uuid)
// @Param        id          path      string                           true  "Auth id"     format(uuid)
// @Param        body        body      request.UpdateAuthBudgetRequest  true  "The budget, or null to clear it"
// @Success      200         {object}  response.AuthResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody  "An application key (application_key), or an invalid budget (validation_failed)"
// @Router       /v1/gateways/{gateway_id}/auths/{id}/budget [put]
func (h *UpdateAuthBudgetHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.AuthKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req *request.UpdateAuthBudgetRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}

	a, err := h.setter.SetBudget(c.UserContext(), appauth.SetBudgetInput{
		ID:        id,
		GatewayID: gatewayID,
		Budget:    req.ToBudget(),
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
