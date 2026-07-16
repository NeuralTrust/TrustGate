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
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
)

type CreateGatewayHandler struct {
	creator       appgateway.Creator
	baseDomain    string
	mcpBaseDomain string
}

func NewCreateGatewayHandler(creator appgateway.Creator, baseDomain, mcpBaseDomain string) *CreateGatewayHandler {
	return &CreateGatewayHandler{creator: creator, baseDomain: baseDomain, mcpBaseDomain: mcpBaseDomain}
}

// Handle godoc
// @Summary      Create a gateway
// @Description  Creates a new gateway. The slug is optional: when omitted the server generates a unique random slug. If provided it must be a lowercase DNS label and unique.
// @Tags         gateways
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway  body      request.CreateGatewayRequest  true  "Gateway to create"
// @Success      201      {object}  response.GatewayResponse
// @Failure      400      {object}  httpio.ErrorBody
// @Failure      401      {object}  httpio.ErrorBody
// @Failure      409      {object}  httpio.ErrorBody
// @Router       /v1/gateways [post]
func (h *CreateGatewayHandler) Handle(c *fiber.Ctx) error {
	var req request.CreateGatewayRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return httpio.WriteError(c, err)
	}

	g, err := h.creator.Create(c.UserContext(), appgateway.CreateInput{
		Slug:            req.Slug,
		Domain:          req.Domain,
		TenantID:        tenantIDFromContext(c),
		Metadata:        req.Metadata,
		Telemetry:       req.Telemetry,
		ClientTLSConfig: req.ClientTLSConfig,
		SessionConfig:   req.SessionConfig,
		Entitlements:    req.Entitlements,
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteCreated(c, response.FromDomain(g, h.baseDomain, h.mcpBaseDomain))
}

// tenantIDFromContext returns the tenant identifier stamped by the admin auth
// middleware from the JWT claim. It is empty when the token carries no tenant.
func tenantIDFromContext(c *fiber.Ctx) string {
	if v, ok := c.Locals(string(infracontext.TenantIDContextKey)).(string); ok {
		return v
	}
	return ""
}

// callerOwnsGateway reports whether a caller may act on the loaded gateway.
// A tenant-scoped caller only sees gateways stamped with its own tenant; a
// platform admin (empty tenant claim) sees every gateway.
func callerOwnsGateway(caller string, g *domain.Gateway) bool {
	return caller == "" || (g != nil && g.TenantID() == caller)
}
