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

// Package keygroup serves the budgets of the directory groups whose members
// hold group keys.
package keygroup

import (
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/keygroup/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/keygroup/response"
	appkeygroup "github.com/NeuralTrust/TrustGate/pkg/app/keygroup"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/gofiber/fiber/v2"
)

// BudgetHandler lists, sets and clears the budgets of a gateway's groups.
type BudgetHandler struct {
	budgets appkeygroup.Budgets
}

// NewBudgetHandler returns the handler over budgets.
func NewBudgetHandler(budgets appkeygroup.Budgets) *BudgetHandler {
	return &BudgetHandler{budgets: budgets}
}

// List godoc
// @Summary      List the group budgets
// @Description  Returns the monthly budget of every directory group that has one on the gateway. A group budget holds the group keys (personal keys with a group_id) of the group on /store/v1: monthly_limit_usd caps the group's total, member_monthly_limit_usd each member's own spend through their key for the group, and member_overrides replaces that per-member limit for the members it names. A null limit is no limit.
// @Tags         key-groups
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Success      200         {object}  response.BudgetListResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      403         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody  "No such gateway"
// @Router       /v1/gateways/{gateway_id}/key-groups/budgets [get]
func (h *BudgetHandler) List(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	budgets, err := h.budgets.List(c.UserContext(), gatewayID)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromBudgets(budgets))
}

// Set godoc
// @Summary      Set a group's budget
// @Description  Creates or replaces the monthly budget of the directory group group_id (the console's DirectoryGroup id, the group_id its members' group keys carry). Limits are US dollars of priced cost over the UTC calendar month, reset on the 1st: monthly_limit_usd is the group's total, shared by every member; member_monthly_limit_usd is what each member may spend through their key for the group; member_overrides ({"<user id>": <dollars>}) replaces that per-member limit for the members it names. Null or absent is no limit, and at least one limit or override is required; a limit is a finite number of dollars, zero or more (zero allows no spend). A request is held to the first limit it has reached. action block answers such a request 429 budget_exceeded until the month turns; action alert lets it through and records the decision. Either way the console is told once per limit and month (event key_group_budget_reached on CONSOLE_EVENTS_URL). A replaced budget keeps the spend counted so far this month.
// @Tags         key-groups
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                    true  "Gateway id"  format(uuid)
// @Param        group_id    path      string                    true  "Directory group id"
// @Param        body        body      request.SetBudgetRequest  true  "The group's budget"
// @Success      200         {object}  response.BudgetResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      403         {object}  httpio.ErrorBody  "A service credential, or no access to the gateway"
// @Failure      404         {object}  httpio.ErrorBody  "No such gateway"
// @Failure      422         {object}  httpio.ErrorBody  "No limit, a negative or non-finite limit, or an action other than alert or block (validation_failed)"
// @Router       /v1/gateways/{gateway_id}/key-groups/{group_id}/budget [put]
func (h *BudgetHandler) Set(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req request.SetBudgetRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	budget, err := h.budgets.Set(c.UserContext(), appkeygroup.SetBudgetInput{
		GatewayID:             gatewayID,
		GroupID:               strings.TrimSpace(c.Params("group_id")),
		MonthlyLimitUSD:       req.MonthlyLimitUSD,
		MemberMonthlyLimitUSD: req.MemberMonthlyLimitUSD,
		MemberOverrides:       req.MemberOverrides,
		Action:                req.Action,
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromBudget(budget))
}

// Delete godoc
// @Summary      Clear a group's budget
// @Description  Removes the budget of the directory group group_id: its keys are no longer held to a group or member limit. The spend counted this month is kept, so a budget set again later in the month starts from it.
// @Tags         key-groups
// @Security     BearerAuth
// @Param        gateway_id  path  string  true  "Gateway id"  format(uuid)
// @Param        group_id    path  string  true  "Directory group id"
// @Success      204
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      403         {object}  httpio.ErrorBody  "A service credential, or no access to the gateway"
// @Failure      404         {object}  httpio.ErrorBody  "The group has no budget, or no such gateway"
// @Router       /v1/gateways/{gateway_id}/key-groups/{group_id}/budget [delete]
func (h *BudgetHandler) Delete(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if err := h.budgets.Delete(c.UserContext(), gatewayID, strings.TrimSpace(c.Params("group_id"))); err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteNoContent(c)
}
