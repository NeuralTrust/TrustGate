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

	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/common/strutil"
	sessionrevocation "github.com/NeuralTrust/TrustGate/pkg/domain/sessionrevocation"
	"github.com/gofiber/fiber/v2"
)

// maxSubjectIDLen matches the bound on a session subject taken from the IdP.
const maxSubjectIDLen = 256

// DeleteSubjectSessionsHandler removes one subject's default-IdP refresh
// records for the caller's tenant and the gateway in the path.
type DeleteSubjectSessionsHandler struct {
	sessions    appoauth.SubjectSessions
	revocations sessionrevocation.Store
	signaler    configsyncport.SnapshotSignaler
	logger      *slog.Logger
}

// NewDeleteSubjectSessionsHandler returns the handler. revocations is written
// before the Redis marker so a data plane that does not share this process's
// Redis still learns the revocation from the config snapshot. signaler wakes
// the snapshot dispatcher; nil leaves the dispatcher's backstop as the fallback.
func NewDeleteSubjectSessionsHandler(sessions appoauth.SubjectSessions, revocations sessionrevocation.Store, signaler configsyncport.SnapshotSignaler, logger *slog.Logger) *DeleteSubjectSessionsHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &DeleteSubjectSessionsHandler{sessions: sessions, revocations: revocations, signaler: signaler, logger: logger}
}

// SubjectSessionsResponse is how many refresh records the call removed. Zero
// means the subject has none; that is success.
type SubjectSessionsResponse struct {
	Revoked int `json:"revoked"`
}

// Handle godoc
// @Summary      Revoke a subject's default-IdP sessions
// @Description  Deletes the default identity provider's refresh records for this gateway, the caller's tenant and the subject in the path, and removes their owner-index entries. It records the revocation durably and in Redis, so a refresh record that was not in the index cannot be rotated into a new session, including on a data plane that keeps its own session store. The durable record is what the config snapshot carries; a data plane built before that snapshot field ignores the field and keeps serving until it is upgraded. A subject with no indexed records on this process answers 200 {"revoked": 0}; revoked counts records deleted here. Records for another org, gateway, subject or identity provider are left in place, as are personal keys, grants, installs and config. An access token already issued from one of these sessions keeps working until it expires. Authentication is the admin credential. The org matched on each record is the console token's tenant_id. A service credential is refused.
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
	if h.revocations == nil {
		return httpio.WriteError(c, fmt.Errorf("revoke subject sessions: revocation record is not configured"))
	}
	// The durable row is the source the data plane's snapshot is compiled
	// from. It is written first. A failure here is 500 and does not touch Redis.
	revokedAt := time.Now().UTC()
	if err := h.revocations.Upsert(c.UserContext(), gatewayID.String(), org, subject, revokedAt); err != nil {
		h.logger.WarnContext(c.UserContext(), "subject sessions: revocation record failed",
			slog.String("gateway_id", gatewayID.String()),
			slog.String("org", org),
			slog.String("subject", subject),
		)
		return httpio.WriteError(c, err)
	}
	if h.signaler != nil {
		h.signaler.Signal(c.UserContext())
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
