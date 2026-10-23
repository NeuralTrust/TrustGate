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
	"context"
	"fmt"
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/auth/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/auth/response"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

// UpdateAuthOwnerGroupsHandler records the directory groups of a personal
// key's owner, then the same list on that owner's default-IdP sessions.
type UpdateAuthOwnerGroupsHandler struct {
	setter   appauth.OwnerGroupsSetter
	reach    appconsumer.AuthConsumers
	gateways appgateway.Finder
	sessions appoauth.SessionGroups
	logger   *slog.Logger
}

// NewUpdateAuthOwnerGroupsHandler returns the handler; reach lists the
// consumers the key holds, which the response carries like every admin auth
// response. gateways and sessions carry the same list onto default-IdP
// refresh records. A nil sessions skips that step.
func NewUpdateAuthOwnerGroupsHandler(
	setter appauth.OwnerGroupsSetter,
	reach appconsumer.AuthConsumers,
	gateways appgateway.Finder,
	sessions appoauth.SessionGroups,
	logger *slog.Logger,
) *UpdateAuthOwnerGroupsHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &UpdateAuthOwnerGroupsHandler{setter: setter, reach: reach, gateways: gateways, sessions: sessions, logger: logger}
}

// Handle godoc
// @Summary      Set the owner groups of a personal key
// @Description  Records the directory groups of a personal (owned) key's owner. The body is {"groups": ["<group>", ...], "email": "<owner email>", "group_name": "<group name>"}; an empty list clears the groups. Names are trimmed, deduplicated and sorted; at most 512 groups of at most 256 characters each. On the MCP Store (/store/mcp) the key runs as its owner with these groups, so Store grants, Store access policies and MCP policies scoped to a group apply as they do to a signed-in session. The platform sends them whenever the owner's membership changes. email is optional: when present it replaces the owner's email (empty clears it), which the key's calls are recorded under in requests and traces as a signed-in session's are; when absent it stays as it is. The secret, the expiry, the budget and the consumers of the key do not change, and a rotation keeps the groups. group_name is optional and only for a group key (a key with a group_id): it records the new directory name of the key's group after a rename, the name the MCP Store matches the key's access against; the group itself never changes. Sent for the owner's personal key it answers 422 personal_key. A group key's groups are its owner's, every group they belong to, like the personal key's. An application key answers 422 application_key; an invalid body answers 422 validation_failed.
// @Tags         auths
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                                true  "Gateway id"  format(uuid)
// @Param        id          path      string                                true  "Auth id"     format(uuid)
// @Param        body        body      request.UpdateAuthOwnerGroupsRequest  true  "The owner's groups"
// @Success      200         {object}  response.AuthResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody  "An application key (application_key), group_name on a personal key (personal_key), or invalid groups or group_name (validation_failed)"
// @Router       /v1/gateways/{gateway_id}/auths/{id}/groups [put]
func (h *UpdateAuthOwnerGroupsHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.AuthKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req request.UpdateAuthOwnerGroupsRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}

	a, err := h.setter.SetOwnerGroups(c.UserContext(), appauth.SetOwnerGroupsInput{
		ID:        id,
		GatewayID: gatewayID,
		Groups:    req.Groups,
		Email:     req.Email,
		GroupName: req.GroupName,
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	held, err := h.reach.ForAuths(c.UserContext(), gatewayID, []ids.AuthID{a.ID})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	// The key row is already stored. A session update that fails is logged
	// and left as it was; it does not fail this write and it does not undo it.
	h.syncSessions(c.UserContext(), gatewayID, a.OwnerID, a.OwnerGroups)
	return httpio.WriteOK(c, response.FromAuthWithConsumers(a, held[a.ID]))
}

func (h *UpdateAuthOwnerGroupsHandler) syncSessions(ctx context.Context, gatewayID ids.GatewayID, owner string, groups []string) {
	if h.sessions == nil || h.gateways == nil || owner == "" {
		return
	}
	gw, err := h.gateways.FindByID(ctx, gatewayID)
	if err != nil || gw == nil || gw.TenantID() == "" {
		h.logger.WarnContext(ctx, "owner groups: session update skipped",
			slog.String("gateway_id", gatewayID.String()),
			slog.String("subject", owner),
		)
		return
	}
	if _, err := h.sessions.ApplyDirectoryGroups(ctx, gw.TenantID(), gatewayID.String(), owner, groups); err != nil {
		h.logger.WarnContext(ctx, "owner groups: session update failed",
			slog.String("gateway_id", gatewayID.String()),
			slog.String("org", gw.TenantID()),
			slog.String("subject", owner),
		)
	}
}
