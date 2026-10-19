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
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/auth/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/common/strutil"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/gofiber/fiber/v2"
)

// UpdateSubjectGroupsHandler records directory groups on the default-IdP
// refresh records of one subject. It does not create a personal key.
type UpdateSubjectGroupsHandler struct {
	sessions appoauth.SessionGroups
	logger   *slog.Logger
}

// NewUpdateSubjectGroupsHandler returns the handler.
func NewUpdateSubjectGroupsHandler(sessions appoauth.SessionGroups, logger *slog.Logger) *UpdateSubjectGroupsHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &UpdateSubjectGroupsHandler{sessions: sessions, logger: logger}
}

// SubjectGroupsResponse is how many refresh records the call updated. Zero
// means the subject has none; that is success and writes nothing past the
// owner index lookup.
type SubjectGroupsResponse struct {
	Updated int `json:"updated"`
}

// Handle godoc
// @Summary      Set directory groups on a subject's default-IdP sessions
// @Description  Adds the given directory groups to the login claim on the default identity provider's refresh records for this gateway, the caller's tenant and the subject in the path. The body is {"groups": ["<group>", ...]}. The result is the union of that claim and this list, deduplicated. An empty list leaves the claim groups in place. Names are trimmed, deduplicated and sorted, with the same bounds as a personal key's owner groups. A subject with no refresh records answers 200 {"updated": 0} and does not write a session. The call does not change session expiry and does not revoke a session. Authentication is a console JWT, the same interactive identity required for PUT /auths/{id}/groups. A service credential is refused. The org matched on each record is the console token's tenant_id.
// @Tags         auths
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                              true  "Gateway id"  format(uuid)
// @Param        user_id     path      string                              true  "Platform user id (session subject)"
// @Param        body        body      request.UpdateSubjectGroupsRequest  true  "Directory groups"
// @Success      200         {object}  SubjectGroupsResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      403         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Failure      500         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/subjects/{user_id}/groups [put]
func (h *UpdateSubjectGroupsHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	org := middleware.AdminIdentityFromContext(c).TenantID
	if org == "" {
		return httpio.WriteError(c, fmt.Errorf("the caller's tenant is required: %w", commonerrors.ErrForbidden))
	}
	subject := c.Params("user_id")
	if !strutil.IsBoundedPrintable(subject, maxSubjectIDLen) {
		return httpio.WriteError(c, fmt.Errorf("user id is empty or not a plain identifier: %w", commonerrors.ErrValidation))
	}
	var req request.UpdateSubjectGroupsRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	groups, err := authdomain.NormalizeOwnerGroups(req.Groups)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if h.sessions == nil {
		return httpio.WriteError(c, fmt.Errorf("update subject groups: sessions are not configured"))
	}
	updated, err := h.sessions.ApplyDirectoryGroups(c.UserContext(), org, gatewayID.String(), subject, groups)
	if err != nil {
		h.logger.WarnContext(c.UserContext(), "subject groups: session update failed",
			slog.String("gateway_id", gatewayID.String()),
			slog.String("org", org),
			slog.String("subject", subject),
		)
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, SubjectGroupsResponse{Updated: updated})
}
