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

// Package store holds the admin HTTP surface for the MCP Store: the install
// approval queue (list pending requests, approve, deny). Store curation itself
// rides on the registry (mcp_target.store); this package only decides the
// per-principal install requests that curation produces.
package store

import (
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	storerequest "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store/request"
	storeresponse "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store/response"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
)

type RequestsHandler struct {
	approver appstore.Approver
}

func NewRequestsHandler(approver appstore.Approver) *RequestsHandler {
	return &RequestsHandler{approver: approver}
}

func validateDecision(r storerequest.Decide) error {
	if strings.TrimSpace(r.PrincipalSub) == "" {
		return fmt.Errorf("principal_sub is required: %w", commonerrors.ErrValidation)
	}
	if strings.TrimSpace(r.Code) == "" && strings.TrimSpace(r.InstanceID) == "" {
		return fmt.Errorf("code or instance_id is required: %w", commonerrors.ErrValidation)
	}
	return nil
}

// List godoc
// @Summary      List pending Store install requests
// @Description  Returns the gateway's pending MCP Store install requests (oldest first) for admin approval.
// @Tags         store
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Success      200         {object}  storeresponse.PendingRequests
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/store/requests [get]
func (h *RequestsHandler) List(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	pending, err := h.approver.ListPending(c.UserContext(), gatewayID)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	out := storeresponse.PendingRequests{
		Items: make([]storeresponse.PendingRequest, 0, len(pending)),
		Total: len(pending),
	}
	for _, p := range pending {
		out.Items = append(out.Items, storeresponse.PendingRequest{
			InstanceID:   p.InstanceID,
			PrincipalSub: p.PrincipalSub,
			Code:         p.Code,
			Name:         p.Name,
			InstalledBy:  p.InstalledBy,
			Reason:       p.Reason,
			RequestedAt:  p.RequestedAt,
		})
	}
	return httpio.WriteOK(c, out)
}

// History godoc
// @Summary      List decided Store install requests
// @Description  Returns the gateway's approved and denied MCP Store install requests, newest decision first.
// @Tags         store
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Success      200         {object}  storeresponse.History
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/store/requests/history [get]
func (h *RequestsHandler) History(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	decided, err := h.approver.ListDecided(c.UserContext(), gatewayID)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	out := storeresponse.History{Items: make([]storeresponse.DecidedRequest, 0, len(decided)), Total: len(decided)}
	for _, d := range decided {
		row := storeresponse.DecidedRequest{
			InstanceID:   d.InstanceID,
			PrincipalSub: d.PrincipalSub,
			Code:         d.Code,
			Name:         d.Name,
			Reason:       d.Reason,
			Decision:     string(d.Decision),
			DecidedBy:    d.DecidedBy,
			DecidedAt:    d.DecidedAt,
			RequestedAt:  d.RequestedAt,
		}
		if !d.RegistryID.IsNil() {
			row.RegistryID = d.RegistryID.String()
		}
		out.Items = append(out.Items, row)
	}
	return httpio.WriteOK(c, out)
}

// Approve godoc
// @Summary      Approve a Store install request
// @Description  Shelves the server available (if needed), grants it to the requester (or to one of their groups via grant_to_group) and marks the request installed.
// @Tags         store
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string         true  "Gateway id"  format(uuid)
// @Param        body        body      storerequest.Decide  true  "Which install request"
// @Success      204         "Approved"
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody  "Server is not on the shelf; connect it first"
// @Router       /v1/gateways/{gateway_id}/store/requests/approve [post]
func (h *RequestsHandler) Approve(c *fiber.Ctx) error {
	gatewayID, req, err := h.parseDecide(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if err := h.approver.Approve(c.UserContext(), appstore.ApproveRequest{
		GatewayID:    gatewayID,
		PrincipalSub: req.PrincipalSub,
		Code:         req.Code,
		InstanceID:   req.InstanceID,
		ApprovedBy:   callerActor(c),
		GrantToGroup: req.GrantToGroup,
	}); err != nil {
		return httpio.WriteError(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Deny godoc
// @Summary      Deny a Store install request
// @Description  Marks the request revoked (kept for audit).
// @Tags         store
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string         true  "Gateway id"  format(uuid)
// @Param        body        body      storerequest.Decide  true  "Which install request"
// @Success      204         "Denied"
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/store/requests/deny [post]
func (h *RequestsHandler) Deny(c *fiber.Ctx) error {
	gatewayID, req, err := h.parseDecide(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if err := h.approver.Deny(c.UserContext(), appstore.DenyRequest{
		GatewayID:    gatewayID,
		PrincipalSub: req.PrincipalSub,
		Code:         req.Code,
		InstanceID:   req.InstanceID,
		DeniedBy:     callerActor(c),
	}); err != nil {
		return httpio.WriteError(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RequestsHandler) parseDecide(c *fiber.Ctx) (gatewayID ids.GatewayID, req storerequest.Decide, err error) {
	gid, err := httpio.ParseGatewayID(c)
	if err != nil {
		return gid, req, err
	}
	if err := c.BodyParser(&req); err != nil {
		return gid, req, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation)
	}
	if err := validateDecision(req); err != nil {
		return gid, req, err
	}
	return gid, req, nil
}

func callerActor(c *fiber.Ctx) string {
	if email, ok := c.Locals(string(infracontext.UserEmailContextKey)).(string); ok && email != "" {
		return email
	}
	if id, ok := c.Locals(string(infracontext.UserIDContextKey)).(string); ok {
		return id
	}
	return ""
}
