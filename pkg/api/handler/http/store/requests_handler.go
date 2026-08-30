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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
)

// RequestsHandler serves the Store install-approval queue.
type RequestsHandler struct {
	approver appstore.Approver
}

func NewRequestsHandler(approver appstore.Approver) *RequestsHandler {
	return &RequestsHandler{approver: approver}
}

// pendingRequestResponse is one row in the admin approval queue.
type pendingRequestResponse struct {
	PrincipalSub string    `json:"principal_sub"`
	Code         string    `json:"code"`
	Name         string    `json:"name"`
	InstalledBy  string    `json:"installed_by,omitempty"`
	RequestedAt  time.Time `json:"requested_at"`
}

type listRequestsResponse struct {
	Items []pendingRequestResponse `json:"items"`
	Total int                      `json:"total"`
}

// decideRequest is the shared body of approve/deny: which install request.
type decideRequest struct {
	PrincipalSub string `json:"principal_sub"`
	Code         string `json:"code"`
}

func (r decideRequest) validate() error {
	if strings.TrimSpace(r.PrincipalSub) == "" {
		return fmt.Errorf("principal_sub is required: %w", commonerrors.ErrValidation)
	}
	if strings.TrimSpace(r.Code) == "" {
		return fmt.Errorf("code is required: %w", commonerrors.ErrValidation)
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
// @Success      200         {object}  listRequestsResponse
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
	out := listRequestsResponse{
		Items: make([]pendingRequestResponse, 0, len(pending)),
		Total: len(pending),
	}
	for _, p := range pending {
		out.Items = append(out.Items, pendingRequestResponse{
			PrincipalSub: p.PrincipalSub,
			Code:         p.Code,
			Name:         p.Name,
			InstalledBy:  p.InstalledBy,
			RequestedAt:  p.RequestedAt,
		})
	}
	return httpio.WriteOK(c, out)
}

// Approve godoc
// @Summary      Approve a Store install request
// @Description  Shelves the server available (if needed) and marks the request installed.
// @Tags         store
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string         true  "Gateway id"  format(uuid)
// @Param        body        body      decideRequest  true  "Which install request"
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
		ApprovedBy:   callerActor(c),
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
// @Param        body        body      decideRequest  true  "Which install request"
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
		DeniedBy:     callerActor(c),
	}); err != nil {
		return httpio.WriteError(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RequestsHandler) parseDecide(c *fiber.Ctx) (gatewayID ids.GatewayID, req decideRequest, err error) {
	gid, err := httpio.ParseGatewayID(c)
	if err != nil {
		return gid, req, err
	}
	if err := c.BodyParser(&req); err != nil {
		return gid, req, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation)
	}
	if err := req.validate(); err != nil {
		return gid, req, err
	}
	return gid, req, nil
}

// callerActor is the acting admin, for audit (email, else user id).
func callerActor(c *fiber.Ctx) string {
	if email, ok := c.Locals(string(infracontext.UserEmailContextKey)).(string); ok && email != "" {
		return email
	}
	if id, ok := c.Locals(string(infracontext.UserIDContextKey)).(string); ok {
		return id
	}
	return ""
}
