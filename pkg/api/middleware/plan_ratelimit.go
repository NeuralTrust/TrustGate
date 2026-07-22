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

package middleware

import (
	"errors"
	"log/slog"

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
)

// PlanRateLimitMiddleware enforces plan burst/quota on authenticated admin API routes.
type PlanRateLimitMiddleware struct {
	limiter  ratelimitapp.Checker
	gateways appgateway.Finder
	logger   *slog.Logger
}

func NewPlanRateLimitMiddleware(limiter ratelimitapp.Checker, gateways appgateway.Finder, logger *slog.Logger) *PlanRateLimitMiddleware {
	if logger == nil {
		logger = slog.Default()
	}
	return &PlanRateLimitMiddleware{limiter: limiter, gateways: gateways, logger: logger}
}

// ForGateway charges the gateway from path params gateway_id (nested) or id (CRUD).
func (m *PlanRateLimitMiddleware) ForGateway() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if m == nil || m.limiter == nil {
			return c.Next()
		}
		// Platform JWT (empty tenant) stamps entitlements; do not meter those writes.
		if tenantID, _ := c.Locals(string(infracontext.TenantIDContextKey)).(string); tenantID == "" {
			return c.Next()
		}
		gatewayID, ok := pathGatewayID(c)
		if !ok {
			return c.Next()
		}
		return m.enforce(c, gatewayID)
	}
}

// ForTenant charges against one of the tenant's gateway instances (list/create / catalogs).
func (m *PlanRateLimitMiddleware) ForTenant() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if m == nil || m.limiter == nil || m.gateways == nil {
			return c.Next()
		}
		tenantID, _ := c.Locals(string(infracontext.TenantIDContextKey)).(string)
		if tenantID == "" {
			return c.Next()
		}
		items, _, err := m.gateways.List(c.Context(), domain.ListFilter{TenantID: tenantID, Page: 1, Size: 1})
		if err != nil || len(items) == 0 || items[0] == nil || items[0].ID.IsNil() {
			return c.Next()
		}
		return m.enforce(c, items[0].ID)
	}
}

func (m *PlanRateLimitMiddleware) enforce(c *fiber.Ctx, gatewayID ids.GatewayID) error {
	if err := m.limiter.Check(c.Context(), gatewayID); err != nil {
		var limited *ratelimitapp.Exceeded
		if errors.As(err, &limited) {
			for k, vals := range limited.Headers() {
				if len(vals) > 0 {
					c.Set(k, vals[0])
				}
			}
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error":  "rate limit exceeded",
				"reason": limited.Reason,
			})
		}
		if errors.Is(err, ratelimitapp.ErrUnavailable) {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
				"error": "rate limit entitlements unavailable",
			})
		}
		m.logger.Error("plan rate limit check failed", slog.Any("error", err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to enforce rate limit",
		})
	}
	return c.Next()
}

func pathGatewayID(c *fiber.Ctx) (ids.GatewayID, bool) {
	if raw := c.Params("gateway_id"); raw != "" {
		id, err := ids.Parse[ids.GatewayKind](raw)
		if err != nil || id.IsNil() {
			return ids.GatewayID{}, false
		}
		return id, true
	}
	if raw := c.Params("id"); raw != "" {
		id, err := ids.Parse[ids.GatewayKind](raw)
		if err != nil || id.IsNil() {
			return ids.GatewayID{}, false
		}
		return id, true
	}
	return ids.GatewayID{}, false
}
