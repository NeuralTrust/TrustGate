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

package gateway_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gatewayhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/gateway"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appgatewaymocks "github.com/NeuralTrust/TrustGate/pkg/app/gateway/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func tenantMiddleware(tenant string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if tenant != "" {
			c.Locals(string(infracontext.TenantIDContextKey), tenant)
		}
		return c.Next()
	}
}

func ownedGateway(id ids.GatewayID, tenant string) *domain.Gateway {
	now := time.Now().UTC()
	g := domain.Rehydrate(id, "prod", "active", "", nil, nil, nil, now, now)
	if tenant != "" {
		g.Metadata = map[string]string{domain.MetadataTenantIDKey: tenant}
	}
	return g
}

func TestGetGatewayHandler_TenantMismatch_ReturnsNotFound(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.GatewayKind]()
	finder := appgatewaymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, id).Return(ownedGateway(id, "acme"), nil).Once()

	app := fiber.New()
	app.Use(tenantMiddleware("globex"))
	app.Get("/:id", gatewayhttp.NewGetGatewayHandler(finder, "gw.local", "mcp.local").Handle)

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/"+id.String(), nil), -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, fiber.StatusNotFound, resp.StatusCode)
}

func TestGetGatewayHandler_SameTenant_ReturnsOK(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.GatewayKind]()
	finder := appgatewaymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, id).Return(ownedGateway(id, "acme"), nil).Once()

	app := fiber.New()
	app.Use(tenantMiddleware("acme"))
	app.Get("/:id", gatewayhttp.NewGetGatewayHandler(finder, "gw.local", "mcp.local").Handle)

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/"+id.String(), nil), -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestGetGatewayHandler_PlatformAdmin_SeesTenantGateway(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.GatewayKind]()
	finder := appgatewaymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, id).Return(ownedGateway(id, "acme"), nil).Once()

	app := fiber.New()
	app.Use(tenantMiddleware(""))
	app.Get("/:id", gatewayhttp.NewGetGatewayHandler(finder, "gw.local", "mcp.local").Handle)

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/"+id.String(), nil), -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestUpdateGatewayHandler_TenantMismatch_ReturnsNotFound(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.GatewayKind]()
	updater := appgatewaymocks.NewUpdater(t)
	finder := appgatewaymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, id).Return(ownedGateway(id, "acme"), nil).Once()

	app := fiber.New()
	app.Use(tenantMiddleware("globex"))
	app.Put("/:id", gatewayhttp.NewUpdateGatewayHandler(updater, finder, "gw.local", "mcp.local").Handle)

	req := httptest.NewRequest(http.MethodPut, "/"+id.String(), strings.NewReader(`{"status":"paused"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, fiber.StatusNotFound, resp.StatusCode)
	updater.AssertNotCalled(t, "Update", mock.Anything, mock.Anything)
}

func TestDeleteGatewayHandler_TenantMismatch_ReturnsNotFound(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.GatewayKind]()
	deleter := appgatewaymocks.NewDeleter(t)
	finder := appgatewaymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, id).Return(ownedGateway(id, "acme"), nil).Once()

	app := fiber.New()
	app.Use(tenantMiddleware("globex"))
	app.Delete("/:id", gatewayhttp.NewDeleteGatewayHandler(deleter, finder).Handle)

	resp, err := app.Test(httptest.NewRequest(http.MethodDelete, "/"+id.String(), nil), -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, fiber.StatusNotFound, resp.StatusCode)
	deleter.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
}

func TestDeleteGatewayHandler_SameTenant_Deletes(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.GatewayKind]()
	deleter := appgatewaymocks.NewDeleter(t)
	finder := appgatewaymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, id).Return(ownedGateway(id, "acme"), nil).Once()
	deleter.EXPECT().Delete(mock.Anything, id).Return(nil).Once()

	app := fiber.New()
	app.Use(tenantMiddleware("acme"))
	app.Delete("/:id", gatewayhttp.NewDeleteGatewayHandler(deleter, finder).Handle)

	resp, err := app.Test(httptest.NewRequest(http.MethodDelete, "/"+id.String(), nil), -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, fiber.StatusNoContent, resp.StatusCode)
}

func TestListGatewayHandler_TenantCaller_FiltersByTenant(t *testing.T) {
	t.Parallel()
	finder := appgatewaymocks.NewFinder(t)
	finder.EXPECT().
		List(mock.Anything, mock.MatchedBy(func(f domain.ListFilter) bool {
			return f.TenantID == "acme"
		})).
		Return([]*domain.Gateway{}, 0, nil).
		Once()

	app := fiber.New()
	app.Use(tenantMiddleware("acme"))
	app.Get("/", gatewayhttp.NewListGatewayHandler(finder, "gw.local", "mcp.local").Handle)

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/", nil), -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestCreateGatewayHandler_PlatformAdmin_UsesBodyTenantID(t *testing.T) {
	t.Parallel()
	creator := appgatewaymocks.NewCreator(t)
	creator.EXPECT().
		Create(mock.Anything, mock.MatchedBy(func(in appgateway.CreateInput) bool {
			return in.TenantID == "acme" &&
				in.PlatformAdmin &&
				in.Entitlements != nil &&
				in.Entitlements.Tier == "standard"
		})).
		Return(ownedGateway(ids.New[ids.GatewayKind](), "acme"), nil).
		Once()

	app := fiber.New()
	app.Use(tenantMiddleware(""))
	app.Post("/", gatewayhttp.NewCreateGatewayHandler(creator, "gw.local", "mcp.local").Handle)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(
		`{"slug":"prod","tenant_id":"acme","entitlements":{"tier":"standard","burst_per_min":300,"quota_per_month":100000,"max_instances":5}}`,
	))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, fiber.StatusCreated, resp.StatusCode)
}

func TestCreateGatewayHandler_PlatformAdmin_MissingBodyTenant_Rejected(t *testing.T) {
	t.Parallel()
	creator := appgatewaymocks.NewCreator(t)

	app := fiber.New()
	app.Use(tenantMiddleware(""))
	app.Post("/", gatewayhttp.NewCreateGatewayHandler(creator, "gw.local", "mcp.local").Handle)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"slug":"prod"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, fiber.StatusUnprocessableEntity, resp.StatusCode)
	creator.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestCreateGatewayHandler_TenantJWT_BodyTenantMismatch_Rejected(t *testing.T) {
	t.Parallel()
	creator := appgatewaymocks.NewCreator(t)

	app := fiber.New()
	app.Use(tenantMiddleware("acme"))
	app.Post("/", gatewayhttp.NewCreateGatewayHandler(creator, "gw.local", "mcp.local").Handle)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(
		`{"slug":"prod","tenant_id":"globex"}`,
	))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, fiber.StatusUnprocessableEntity, resp.StatusCode)
	creator.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestCreateGatewayHandler_TenantJWT_MatchingBodyTenant_Allowed(t *testing.T) {
	t.Parallel()
	creator := appgatewaymocks.NewCreator(t)
	creator.EXPECT().
		Create(mock.Anything, mock.MatchedBy(func(in appgateway.CreateInput) bool {
			return in.TenantID == "acme" && !in.PlatformAdmin
		})).
		Return(ownedGateway(ids.New[ids.GatewayKind](), "acme"), nil).
		Once()

	app := fiber.New()
	app.Use(tenantMiddleware("acme"))
	app.Post("/", gatewayhttp.NewCreateGatewayHandler(creator, "gw.local", "mcp.local").Handle)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(
		`{"slug":"prod","tenant_id":"acme"}`,
	))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, fiber.StatusCreated, resp.StatusCode)
}
