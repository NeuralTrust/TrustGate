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

package configsync

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/configsync/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appconfigsyncrevocation "github.com/NeuralTrust/TrustGate/pkg/app/configsyncrevocation"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/gofiber/fiber/v2"
)

// RevokeTokensHandler records config-sync token revocations for one gateway.
type RevokeTokensHandler struct {
	revoker appconfigsyncrevocation.Revoker
}

// NewRevokeTokensHandler returns the handler that delegates to revoker.
func NewRevokeTokensHandler(revoker appconfigsyncrevocation.Revoker) *RevokeTokensHandler {
	return &RevokeTokensHandler{revoker: revoker}
}

// Handle godoc
// @Summary      Revoke config-sync tokens
// @Description  Records revocations for the config-sync tokens of one gateway. jtis revokes the listed token identifiers. issued_before revokes every token of the gateway whose iat is strictly earlier than that unix time in seconds. Send either field or both. A token whose iat equals issued_before is not revoked, so send the iat of the replacement token as issued_before. jtis takes 1 to 100 entries of at most 128 bytes of printable UTF-8 each. issued_before must be greater than zero and at most 5 seconds in the future, which only absorbs clock skew. Repeating a request is safe, and a stored issued_before mark never moves backwards: it cannot be lowered or removed. Replicas pick up a revocation within one refresh interval. Only tokens bound to an instance through the instance_id claim can be revoked; the shared config-sync token cannot. Revoked tokens are refused only when the control plane runs with CONFIG_SYNC_TOKEN_REVOCATION_MODE=enforce; in shadow mode they are logged and counted. Authentication is a console JWT, and a service credential is refused.
// @Tags         config-sync
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                      true  "Gateway id"  format(uuid)
// @Param        body        body      request.RevokeTokensRequest  true  "Revocation"
// @Success      204         "No Content"
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      403         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Failure      500         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/config-sync/revocations [post]
func (h *RevokeTokensHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req request.RevokeTokensRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return httpio.WriteError(c, err)
	}
	var issuedBefore int64
	if req.IssuedBefore != nil {
		issuedBefore = *req.IssuedBefore
	}
	if err := h.revoker.Revoke(c.UserContext(), gatewayID.String(), req.JTIs, issuedBefore); err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteNoContent(c)
}
