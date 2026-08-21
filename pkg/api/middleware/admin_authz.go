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
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/gofiber/fiber/v2"
)

// AdminAuthzMiddleware authorizes an authenticated admin caller against the
// gateway addressed by the request. Authentication alone only proves who the
// caller is; without this guard a tenant that knows another tenant's gateway id
// could reach its sub-resources, since those handlers trust the path parameter.
type AdminAuthzMiddleware struct {
	logger   *slog.Logger
	gateways appgateway.Finder
}

func NewAdminAuthzMiddleware(logger *slog.Logger, gateways appgateway.Finder) *AdminAuthzMiddleware {
	return &AdminAuthzMiddleware{logger: logger, gateways: gateways}
}

// RequireGatewayAccess guards every route nested under a :gateway_id. It
// enforces, in order: the service credential's gateway binding, the scope for
// the resource and method, and the tenant that owns the gateway.
func (m *AdminAuthzMiddleware) RequireGatewayAccess(resource AdminResource) fiber.Handler {
	return func(c *fiber.Ctx) error {
		identity := AdminIdentityFromContext(c)
		gatewayID, err := httpio.ParseGatewayID(c)
		if err != nil {
			return httpio.WriteError(c, err)
		}

		if identity.IsService() {
			if identity.GatewayID != gatewayID.String() {
				return m.forbidden(c, identity, "credential is bound to another gateway")
			}
			if scope := RequiredScope(resource, c.Method()); !identity.HasScope(scope) {
				return m.forbidden(c, identity, "missing scope "+scope)
			}
		}

		if identity.Kind == AdminIdentityPlatform {
			return c.Next()
		}

		g, err := m.gateways.FindByID(c.UserContext(), gatewayID)
		if err != nil {
			return httpio.WriteError(c, err)
		}
		if g.TenantID() != identity.TenantID {
			// Answering 404 here keeps a foreign gateway indistinguishable from
			// one that does not exist, so ids cannot be probed across tenants.
			return m.notFound(c, identity)
		}
		return c.Next()
	}
}

// RequireGatewayCollectionAccess guards the /v1/gateways collection and the
// single-gateway routes. Tenant ownership on those routes is already enforced by
// the handlers; what is added here is that a service credential may only ever
// address the one gateway it was issued for, and may never create or delete one.
func (m *AdminAuthzMiddleware) RequireGatewayCollectionAccess() fiber.Handler {
	return func(c *fiber.Ctx) error {
		identity := AdminIdentityFromContext(c)
		if !identity.IsService() {
			return c.Next()
		}

		id := c.Params("id")
		if id == "" {
			return m.forbidden(c, identity, "credential cannot manage the gateway collection")
		}
		if c.Method() == fiber.MethodDelete {
			return m.forbidden(c, identity, "credential cannot delete a gateway")
		}
		if id != identity.GatewayID {
			return m.forbidden(c, identity, "credential is bound to another gateway")
		}
		if scope := RequiredScope(ResourceGateways, c.Method()); !identity.HasScope(scope) {
			return m.forbidden(c, identity, "missing scope "+scope)
		}
		return c.Next()
	}
}

// RequireInteractiveIdentity rejects service credentials on routes that are not
// gateway-scoped (catalogs, playground traces, config-sync). A machine
// credential is deliberately narrow: anything it cannot be bound to a gateway
// for is out of its reach.
func (m *AdminAuthzMiddleware) RequireInteractiveIdentity() fiber.Handler {
	return func(c *fiber.Ctx) error {
		identity := AdminIdentityFromContext(c)
		if identity.IsService() {
			return m.forbidden(c, identity, "credential is limited to its gateway")
		}
		return c.Next()
	}
}

func (m *AdminAuthzMiddleware) forbidden(c *fiber.Ctx, identity AdminIdentity, reason string) error {
	m.logDenial(c, identity, reason)
	return c.Status(fiber.StatusForbidden).JSON(httpio.ErrorBody{
		Error:   "forbidden",
		Message: "Not allowed for this gateway",
	})
}

func (m *AdminAuthzMiddleware) notFound(c *fiber.Ctx, identity AdminIdentity) error {
	m.logDenial(c, identity, "gateway belongs to another tenant")
	return c.Status(fiber.StatusNotFound).JSON(httpio.ErrorBody{Error: "not_found"})
}

func (m *AdminAuthzMiddleware) logDenial(c *fiber.Ctx, identity AdminIdentity, reason string) {
	if m.logger == nil {
		return
	}
	m.logger.LogAttrs(c.UserContext(), slog.LevelWarn, "admin authorization denied",
		slog.String("reason", reason),
		slog.String("identity_kind", string(identity.Kind)),
		slog.String("subject", identity.Subject),
		slog.String("tenant_id", identity.TenantID),
		slog.String("gateway_id", c.Params("gateway_id")),
		slog.String("method", c.Method()),
		slog.String("path", c.Path()),
		slog.String("request_id", c.Get(fiber.HeaderXRequestID)),
	)
}
