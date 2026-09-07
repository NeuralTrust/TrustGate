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

package middleware_test

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appgatewaymocks "github.com/NeuralTrust/TrustGate/pkg/app/gateway/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func gatewayOwnedBy(id ids.GatewayID, tenant string) *domain.Gateway {
	now := time.Now().UTC()
	g := domain.Rehydrate(id, "prod", "active", "", nil, nil, nil, now, now)
	g.Metadata = map[string]string{domain.MetadataTenantIDKey: tenant}
	return g
}

func identityMiddleware(identity middleware.AdminIdentity) fiber.Handler {
	return func(c *fiber.Ctx) error {
		middleware.StoreAdminIdentity(c, identity)
		return c.Next()
	}
}

func serviceIdentity(gatewayID, tenant string, scopes ...string) middleware.AdminIdentity {
	return middleware.AdminIdentity{
		Kind:      middleware.AdminIdentityService,
		TenantID:  tenant,
		GatewayID: gatewayID,
		Subject:   "service-account:cred-1",
		Scopes:    scopes,
	}
}

func newAuthzApp(
	t *testing.T,
	identity middleware.AdminIdentity,
	finder *appgatewaymocks.Finder,
) *fiber.App {
	t.Helper()
	authz := middleware.NewAdminAuthzMiddleware(slog.New(slog.NewTextHandler(io.Discard, nil)), finder)

	app := fiber.New()
	app.Use(identityMiddleware(identity))
	ok := func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) }

	consumers := app.Group("/v1/gateways/:gateway_id/consumers", authz.RequireGatewayAccess(middleware.ResourceConsumers))
	consumers.Get("", ok)
	consumers.Post("", ok)

	gateways := app.Group("/v1/gateways")
	collection := authz.RequireGatewayCollectionAccess()
	gateways.Post("", collection, ok)
	gateways.Get("", collection, ok)
	gateways.Get("/:id", collection, ok)
	gateways.Delete("/:id", collection, ok)

	app.Get("/v1/models-catalog", authz.RequireInteractiveIdentity(), ok)
	return app
}

func do(t *testing.T, app *fiber.App, method, target string) int {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest(method, target, nil), -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestRequireGatewayAccess_HumanCallerFromAnotherTenantCannotReachSubResources(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.GatewayKind]()
	finder := appgatewaymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, id).Return(gatewayOwnedBy(id, "acme"), nil).Once()

	app := newAuthzApp(t, middleware.AdminIdentity{Kind: middleware.AdminIdentityHuman, TenantID: "globex"}, finder)

	require.Equal(t, fiber.StatusNotFound, do(t, app, fiber.MethodGet, "/v1/gateways/"+id.String()+"/consumers"))
}

func TestRequireGatewayAccess_HumanOwnerReachesSubResources(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.GatewayKind]()
	finder := appgatewaymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, id).Return(gatewayOwnedBy(id, "acme"), nil).Once()

	app := newAuthzApp(t, middleware.AdminIdentity{Kind: middleware.AdminIdentityHuman, TenantID: "acme"}, finder)

	require.Equal(t, fiber.StatusOK, do(t, app, fiber.MethodPost, "/v1/gateways/"+id.String()+"/consumers"))
}

func TestRequireGatewayAccess_PlatformIdentitySkipsTenantLookup(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.GatewayKind]()
	finder := appgatewaymocks.NewFinder(t)

	app := newAuthzApp(t, middleware.AdminIdentity{Kind: middleware.AdminIdentityPlatform}, finder)

	require.Equal(t, fiber.StatusOK, do(t, app, fiber.MethodGet, "/v1/gateways/"+id.String()+"/consumers"))
	finder.AssertNotCalled(t, "FindByID", mock.Anything, mock.Anything)
}

func TestRequireGatewayAccess_ServiceCredentialCannotCrossGateways(t *testing.T) {
	t.Parallel()
	bound := ids.New[ids.GatewayKind]()
	other := ids.New[ids.GatewayKind]()
	finder := appgatewaymocks.NewFinder(t)

	app := newAuthzApp(t, serviceIdentity(bound.String(), "acme", "consumers:write"), finder)

	require.Equal(t, fiber.StatusForbidden, do(t, app, fiber.MethodPost, "/v1/gateways/"+other.String()+"/consumers"))
	finder.AssertNotCalled(t, "FindByID", mock.Anything, mock.Anything)
}

func TestRequireGatewayAccess_ServiceCredentialNeedsMatchingScope(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.GatewayKind]()
	finder := appgatewaymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, id).Return(gatewayOwnedBy(id, "acme"), nil).Once()

	app := newAuthzApp(t, serviceIdentity(id.String(), "acme", "consumers:read"), finder)

	require.Equal(t, fiber.StatusForbidden, do(t, app, fiber.MethodPost, "/v1/gateways/"+id.String()+"/consumers"))
	require.Equal(t, fiber.StatusOK, do(t, app, fiber.MethodGet, "/v1/gateways/"+id.String()+"/consumers"))
}

func TestRequireGatewayAccess_ServiceCredentialStillCheckedAgainstGatewayTenant(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.GatewayKind]()
	finder := appgatewaymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, id).Return(gatewayOwnedBy(id, "globex"), nil).Once()

	app := newAuthzApp(t, serviceIdentity(id.String(), "acme", "consumers:write"), finder)

	require.Equal(t, fiber.StatusNotFound, do(t, app, fiber.MethodPost, "/v1/gateways/"+id.String()+"/consumers"))
}

func TestRequireGatewayCollectionAccess_ServiceCredentialLimits(t *testing.T) {
	t.Parallel()
	bound := ids.New[ids.GatewayKind]()
	other := ids.New[ids.GatewayKind]()
	finder := appgatewaymocks.NewFinder(t)

	app := newAuthzApp(t, serviceIdentity(bound.String(), "acme", "gateways:read", "gateways:write"), finder)

	require.Equal(t, fiber.StatusForbidden, do(t, app, fiber.MethodPost, "/v1/gateways"))
	require.Equal(t, fiber.StatusForbidden, do(t, app, fiber.MethodGet, "/v1/gateways"))
	require.Equal(t, fiber.StatusForbidden, do(t, app, fiber.MethodDelete, "/v1/gateways/"+bound.String()))
	require.Equal(t, fiber.StatusForbidden, do(t, app, fiber.MethodGet, "/v1/gateways/"+other.String()))
	require.Equal(t, fiber.StatusOK, do(t, app, fiber.MethodGet, "/v1/gateways/"+bound.String()))
}

func TestRequireGatewayCollectionAccess_ConsoleCallerUnaffected(t *testing.T) {
	t.Parallel()
	finder := appgatewaymocks.NewFinder(t)
	app := newAuthzApp(t, middleware.AdminIdentity{Kind: middleware.AdminIdentityHuman, TenantID: "acme"}, finder)

	require.Equal(t, fiber.StatusOK, do(t, app, fiber.MethodPost, "/v1/gateways"))
	require.Equal(t, fiber.StatusOK, do(t, app, fiber.MethodGet, "/v1/gateways"))
}

func TestRequireInteractiveIdentity_DeniesServiceCredential(t *testing.T) {
	t.Parallel()
	finder := appgatewaymocks.NewFinder(t)
	id := ids.New[ids.GatewayKind]()

	serviceApp := newAuthzApp(t, serviceIdentity(id.String(), "acme", "consumers:write"), finder)
	require.Equal(t, fiber.StatusForbidden, do(t, serviceApp, fiber.MethodGet, "/v1/models-catalog"))

	consoleApp := newAuthzApp(t, middleware.AdminIdentity{Kind: middleware.AdminIdentityHuman, TenantID: "acme"}, finder)
	require.Equal(t, fiber.StatusOK, do(t, consoleApp, fiber.MethodGet, "/v1/models-catalog"))
}

func TestRequireGatewayAccess_InvalidGatewayIDRejected(t *testing.T) {
	t.Parallel()
	finder := appgatewaymocks.NewFinder(t)
	app := newAuthzApp(t, middleware.AdminIdentity{Kind: middleware.AdminIdentityHuman, TenantID: "acme"}, finder)

	require.Equal(t, fiber.StatusBadRequest, do(t, app, fiber.MethodGet, "/v1/gateways/not-a-uuid/consumers"))
}
