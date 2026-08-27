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

package tenant

import (
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
)

// RestampEntitlementsRequest carries one plan stamp to apply across a tenant.
type RestampEntitlementsRequest struct {
	Entitlements *domain.Entitlements `json:"entitlements"`
}

// RestampEntitlementsResponse reports what the re-stamp touched. OverCap says the
// tenant now has more gateways than the plan allows; the stamp was still applied,
// so it is a warning for the operator rather than a failure.
type RestampEntitlementsResponse struct {
	TenantID     string `json:"tenant_id"`
	Stamped      int    `json:"stamped"`
	MaxInstances int    `json:"max_instances,omitempty"`
	OverCap      bool   `json:"over_cap"`
}

type RestampEntitlementsHandler struct {
	restamper appgateway.EntitlementsRestamper
}

func NewRestampEntitlementsHandler(restamper appgateway.EntitlementsRestamper) *RestampEntitlementsHandler {
	return &RestampEntitlementsHandler{restamper: restamper}
}

// Handle godoc
// @Summary      Re-stamp plan entitlements across a tenant
// @Description  Applies one entitlements stamp to every gateway of the tenant, for the control plane to call after a plan change. Platform JWT only (no tenant claim); a tenant JWT receives 422. Only the entitlements block is written — slug, metadata and telemetry are left untouched, so a re-stamp can never revert an edit made in the runtime. A downgrade is applied even when the tenant already has more gateways than the new MaxInstances: the response reports over_cap so the caller can warn, but the stamp is not refused, since refusing would strand every gateway of the tenant on the old plan. Idempotent.
// @Tags         tenants
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        tenant_id  path      string                       true  "Tenant id"
// @Param        request    body      RestampEntitlementsRequest   true  "Entitlements stamp"
// @Success      200        {object}  RestampEntitlementsResponse
// @Failure      400        {object}  map[string]interface{}
// @Failure      422        {object}  map[string]interface{}
// @Router       /v1/tenants/{tenant_id}/entitlements [put]
func (h *RestampEntitlementsHandler) Handle(c *fiber.Ctx) error {
	// Stamping crosses tenants by nature, so it stays platform-only: the same rule
	// the per-gateway PUT applies to its entitlements block.
	if caller := tenantIDFromContext(c); caller != "" {
		return httpio.WriteError(c, fmt.Errorf(
			"entitlements may only be stamped by platform admins: %w", commonerrors.ErrValidation))
	}

	target := strings.TrimSpace(c.Params("tenant_id"))
	if target == "" {
		return httpio.WriteError(c, fmt.Errorf("tenant_id is required: %w", commonerrors.ErrValidation))
	}

	var req RestampEntitlementsRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if req.Entitlements == nil {
		return httpio.WriteError(c, fmt.Errorf(
			"entitlements is required: %w", commonerrors.ErrValidation))
	}

	result, err := h.restamper.RestampTenant(c.UserContext(), target, *req.Entitlements)
	if err != nil {
		return httpio.WriteError(c, err)
	}

	return httpio.WriteOK(c, RestampEntitlementsResponse{
		TenantID:     target,
		Stamped:      result.Stamped,
		MaxInstances: result.MaxInstances,
		OverCap:      result.OverCap,
	})
}

func tenantIDFromContext(c *fiber.Ctx) string {
	if v, ok := c.Locals(string(infracontext.TenantIDContextKey)).(string); ok {
		return v
	}
	return ""
}
