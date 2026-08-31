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

package gateway

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/gateway/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/gateway/response"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type UpdateGatewayHandler struct {
	updater       appgateway.Updater
	finder        appgateway.Finder
	baseDomain    string
	mcpBaseDomain string
}

func NewUpdateGatewayHandler(updater appgateway.Updater, finder appgateway.Finder, baseDomain, mcpBaseDomain string) *UpdateGatewayHandler {
	return &UpdateGatewayHandler{updater: updater, finder: finder, baseDomain: baseDomain, mcpBaseDomain: mcpBaseDomain}
}

// Handle godoc
// @Summary      Update a gateway
// @Description  Updates an existing gateway. Tenant JWTs may not send entitlements (422). Platform tier downgrades that would leave the tenant over the new MaxInstances return 409 — delete excess gateways first.
// @Tags         gateways
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id       path      string                        true  "Gateway id"  format(uuid)
// @Param        gateway  body      request.UpdateGatewayRequest  true  "Gateway fields to update"
// @Success      200      {object}  response.GatewayResponse
// @Failure      400      {object}  httpio.ErrorBody
// @Failure      401      {object}  httpio.ErrorBody
// @Failure      404      {object}  httpio.ErrorBody
// @Failure      409      {object}  httpio.ErrorBody
// @Failure      422      {object}  httpio.ErrorBody
// @Router       /v1/gateways/{id} [put]
func (h *UpdateGatewayHandler) Handle(c *fiber.Ctx) error {
	id, err := httpio.ParseUUIDParam[ids.GatewayKind](c, "id")
	if err != nil {
		return httpio.WriteError(c, err)
	}

	var req request.UpdateGatewayRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return httpio.WriteError(c, err)
	}

	caller := tenantIDFromContext(c)
	if caller != "" {
		existing, err := h.finder.FindByID(c.UserContext(), id)
		if err != nil {
			return httpio.WriteError(c, err)
		}
		if !callerOwnsGateway(caller, existing) {
			return httpio.WriteError(c, domain.ErrNotFound)
		}
	}

	g, err := h.updater.Update(c.UserContext(), appgateway.UpdateInput{
		ID:              id,
		Slug:            req.Slug,
		Status:          req.Status,
		Domain:          req.Domain,
		TenantID:        caller,
		PlatformAdmin:   caller == "",
		Metadata:        req.Metadata,
		Telemetry:       req.Telemetry,
		ClientTLSConfig: req.ClientTLSConfig,
		SessionConfig:   req.SessionConfig,
		Entitlements:    req.Entitlements,
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromDomain(g, h.baseDomain, h.mcpBaseDomain))
}
