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

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/common/strutil"
	"github.com/gofiber/fiber/v2"
)

// maxSubjectIDLen matches the bound on a session subject taken from the IdP.
const maxSubjectIDLen = 256

// DeleteSubjectSessionsHandler removes one subject's default-IdP refresh
// records for the caller's tenant and the gateway in the path.
type DeleteSubjectSessionsHandler struct {
	sessions appoauth.SubjectSessions
	logger   *slog.Logger
}

// NewDeleteSubjectSessionsHandler returns the handler.
func NewDeleteSubjectSessionsHandler(sessions appoauth.SubjectSessions, logger *slog.Logger) *DeleteSubjectSessionsHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &DeleteSubjectSessionsHandler{sessions: sessions, logger: logger}
}

// SubjectSessionsResponse is how many refresh records the call removed. Zero
// means the subject has none; that is success.
type SubjectSessionsResponse struct {
	Revoked int `json:"revoked"`
}

// Handle godoc
// @Summary      Revoke a subject's default-IdP sessions
// @Description  Deletes the default identity provider's refresh records for this gateway, the caller's tenant and the subject in the path, and removes their owner-index entries. A subject with no records answers 200 {"revoked": 0}. Records for another org, gateway, subject or identity provider are left in place, as are personal keys, grants, installs and config. An access token already issued from one of these sessions keeps working until it expires. Authentication is the admin credential. The org matched on each record is the console token's tenant_id. A service credential is refused.
// @Tags         auths
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Param        user_id     path      string  true  "Platform user id (session subject)"
// @Success      200         {object}  SubjectSessionsResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      403         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Failure      500         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/subjects/{user_id}/sessions [delete]
func (h *DeleteSubjectSessionsHandler) Handle(c *fiber.Ctx) error {
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
	if h.sessions == nil {
		return httpio.WriteError(c, fmt.Errorf("revoke subject sessions: sessions are not configured"))
	}
	revoked, err := h.sessions.RevokeSubjectSessions(c.UserContext(), org, gatewayID.String(), subject)
	if err != nil {
		h.logger.WarnContext(c.UserContext(), "subject sessions: revoke failed",
			slog.String("gateway_id", gatewayID.String()),
			slog.String("org", org),
			slog.String("subject", subject),
		)
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, SubjectSessionsResponse{Revoked: revoked})
}
