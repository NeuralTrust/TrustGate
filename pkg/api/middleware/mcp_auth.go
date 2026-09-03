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

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	identitydomain "github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

// Identity is the MCP-plane authentication result: the auth record that
// matched plus the verified principal (carrying the raw token for
// passthrough/exchange flows).
type Identity struct {
	GatewayID ids.GatewayID
	AuthID    ids.AuthID
	Principal *identitydomain.Principal
}

type IdentityResolver interface {
	Resolve(c *fiber.Ctx) (Identity, error)
}

// MCPAuthMiddleware guards the MCP server plane. Unlike the proxy-plane
// AuthMiddleware (slug-routed, role-aware), it authenticates via the chain
// resolver (mTLS > bearer > API key) and scopes the request to the gateway
// the matched auth record belongs to.
type MCPAuthMiddleware struct {
	resolver   IdentityResolver
	dataFinder appconsumer.DataFinder
	gateways   appgateway.Finder
}

func NewMCPAuthMiddleware(
	identityResolver IdentityResolver,
	dataFinder appconsumer.DataFinder,
	gateways appgateway.Finder,
) *MCPAuthMiddleware {
	return &MCPAuthMiddleware{
		resolver:   identityResolver,
		dataFinder: dataFinder,
		gateways:   gateways,
	}
}

func (m *MCPAuthMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		identity, err := m.resolver.Resolve(c)
		if err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, "unauthenticated")
		}
		gw, err := m.gateways.FindByID(c.UserContext(), identity.GatewayID)
		if err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, "unauthenticated")
		}
		if err := enforceDefaultIdPTenant(identity, gw); err != nil {
			return err
		}
		data, err := m.dataFinder.FindByGateway(c.UserContext(), identity.GatewayID)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "failed to load gateway data")
		}
		m.attach(c, identity, gw, data)
		return c.Next()
	}
}

// enforceDefaultIdPTenant stops a user of one tenant reaching another tenant's
// gateway through the built-in default identity provider. The default IdP is a
// platform-wide singleton with a cross-tenant issuer, so — unlike a gateway's
// own oauth2 auth, which is scoped to that gateway — its session is only bound
// to the addressed gateway (gwid), not to the user's org. Here we require the
// session's org claim to match the gateway's stamped tenant.
//
// The check applies only to default-IdP sessions on tenant-stamped (cloud)
// gateways. A self-hosted gateway carries no tenant_id and has no cross-tenant
// surface, so it is left untouched.
func enforceDefaultIdPTenant(identity Identity, gw *gatewaydomain.Gateway) error {
	if identity.AuthID != appauth.DefaultIdPAuthID() {
		return nil
	}
	tenant := gw.TenantID()
	if tenant == "" {
		return nil
	}
	if identity.Principal == nil || identity.Principal.Org() != tenant {
		// TEMP DEBUG (store tenant): surface both sides of the mismatch so we can
		// tell a wrong-org login from a gateway stamped with the wrong tenant_id.
		principalOrg := ""
		if identity.Principal != nil {
			principalOrg = identity.Principal.Org()
		}
		slog.Warn("TEMP DEBUG store-tenant: default-IdP tenant mismatch",
			slog.String("principal_org", principalOrg),
			slog.String("gateway_tenant_id", tenant),
			slog.String("gateway_id", gw.ID.String()))
		return fiber.NewError(fiber.StatusForbidden, "identity does not belong to this gateway's tenant")
	}
	return nil
}

func (m *MCPAuthMiddleware) attach(c *fiber.Ctx, identity Identity, gw *gatewaydomain.Gateway, data *appconsumer.Data) {
	c.Locals(string(appconsumer.GatewayIDKey), identity.GatewayID)
	c.Locals(string(appconsumer.AuthIDKey), identity.AuthID)
	c.Locals(string(appconsumer.ConsumerDataKey), data)
	ctx := appconsumer.WithGatewayID(c.UserContext(), identity.GatewayID)
	ctx = appconsumer.WithAuthID(ctx, identity.AuthID)
	ctx = appconsumer.WithData(ctx, data)
	ctx = appgateway.WithGateway(ctx, gw)
	if identity.Principal != nil {
		ctx = identitydomain.WithPrincipal(ctx, identity.Principal)
	}
	c.SetUserContext(ctx)
}
