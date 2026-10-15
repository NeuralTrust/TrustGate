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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/gateway/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/gateway/response"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
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
// @Description  Creates a new gateway. Ownership tenant_id is required (JWT claim, or body for platform admins). The slug is optional: when omitted the server generates a unique random slug. If provided it must be a lowercase DNS label and unique. Platform JWT create requires stamped entitlements (tier + caps); tenant JWTs must omit entitlements (422 if sent). With RATE_LIMIT_ENABLED, create returns 409 when the tenant is already at MaxInstances for the effective tier.
// @Tags         gateways
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway  body      request.CreateGatewayRequest  true  "Gateway to create"
// @Success      201      {object}  response.GatewayResponse
// @Failure      400      {object}  httpio.ErrorBody
// @Failure      401      {object}  httpio.ErrorBody
// @Failure      409      {object}  httpio.ErrorBody
// @Failure      422      {object}  httpio.ErrorBody
// @Router       /v1/gateways [post]
func (h *CreateGatewayHandler) Handle(c *fiber.Ctx) error {
	var req request.CreateGatewayRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return httpio.WriteError(c, err)
	}

	caller := middleware.AdminIdentityFromContext(c)
	effectiveTenant, err := resolveCreateTenantID(caller, req.TenantID)
	if err != nil {
		return httpio.WriteError(c, err)
	}

	g, err := h.creator.Create(c.UserContext(), appgateway.CreateInput{
		Slug:            req.Slug,
		Domain:          req.Domain,
		TenantID:        effectiveTenant,
		PlatformAdmin:   isPlatform(caller),
		Metadata:        req.Metadata,
		Telemetry:       req.Telemetry,
		ClientTLSConfig: req.ClientTLSConfig,
		SessionConfig:   req.SessionConfig,
		TrafficLabeling: req.TrafficLabeling,
		Entitlements:    req.Entitlements,
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteCreated(c, response.FromDomain(g, h.baseDomain, h.mcpBaseDomain))
}

// resolveCreateTenantID picks ownership tenant: a tenant caller always creates
// in its own tenant, only the platform may stamp the body tenant_id, and any
// other caller without a tenant is refused.
func resolveCreateTenantID(caller middleware.AdminIdentity, bodyTenant string) (string, error) {
	bodyTenant = strings.TrimSpace(bodyTenant)
	if isPlatform(caller) {
		if bodyTenant == "" {
			return "", fmt.Errorf("tenant_id is required: %w", commonerrors.ErrValidation)
		}
		return bodyTenant, nil
	}
	if caller.TenantID == "" {
		return "", fmt.Errorf("caller has no tenant: %w", commonerrors.ErrForbidden)
	}
	if bodyTenant != "" && bodyTenant != caller.TenantID {
		return "", fmt.Errorf("tenant_id does not match authenticated tenant: %w", commonerrors.ErrValidation)
	}
	return caller.TenantID, nil
}

func isPlatform(caller middleware.AdminIdentity) bool {
	return caller.Kind == middleware.AdminIdentityPlatform
}

// callerOwnsGateway reports whether a caller may act on the loaded gateway.
// The platform sees every gateway; any other caller only sees gateways stamped
// with its own, non-empty tenant.
func callerOwnsGateway(caller middleware.AdminIdentity, g *domain.Gateway) bool {
	if isPlatform(caller) {
		return true
	}
	return caller.TenantID != "" && g != nil && g.TenantID() == caller.TenantID
}
