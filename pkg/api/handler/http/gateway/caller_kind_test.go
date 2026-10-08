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

	gatewayhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appgatewaymocks "github.com/NeuralTrust/TrustGate/pkg/app/gateway/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const stampedBody = `{"status":"paused","entitlements":{"tier":"standard","burst_per_min":300,"quota_per_month":100000,"max_instances":5}}`

func untenantedHuman() fiber.Handler {
	return callerMiddleware(middleware.AdminIdentity{Kind: middleware.AdminIdentityHuman})
}

func serviceCaller(tenant string, gatewayID ids.GatewayID) fiber.Handler {
	return callerMiddleware(middleware.AdminIdentity{
		Kind:      middleware.AdminIdentityService,
		TenantID:  tenant,
		GatewayID: gatewayID.String(),
	})
}

func doJSON(t *testing.T, app *fiber.App, method, path, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestUpdateGatewayHandler_Platform_ActsAcrossTenantsWithPlatformPowers(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.GatewayKind]()
	updater := appgatewaymocks.NewUpdater(t)
	finder := appgatewaymocks.NewFinder(t)
	updater.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(in appgateway.UpdateInput) bool {
			return in.ID == id && in.PlatformAdmin && in.TenantID == "" && in.Entitlements != nil
		})).
		Return(ownedGateway(id, "acme"), nil).
		Once()

	app := fiber.New()
	app.Use(platformCaller())
	app.Put("/:id", gatewayhttp.NewUpdateGatewayHandler(updater, finder, "gw.local", "mcp.local").Handle)

	resp := doJSON(t, app, http.MethodPut, "/"+id.String(), stampedBody)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	finder.AssertNotCalled(t, "FindByID", mock.Anything, mock.Anything)
}

func TestUpdateGatewayHandler_TenantCaller_StaysScoped(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.GatewayKind]()
	updater := appgatewaymocks.NewUpdater(t)
	finder := appgatewaymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, id).Return(ownedGateway(id, "acme"), nil).Once()
	updater.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(in appgateway.UpdateInput) bool {
			return in.ID == id && !in.PlatformAdmin && in.TenantID == "acme"
		})).
		Return(ownedGateway(id, "acme"), nil).
		Once()

	app := fiber.New()
	app.Use(humanCaller("acme"))
	app.Put("/:id", gatewayhttp.NewUpdateGatewayHandler(updater, finder, "gw.local", "mcp.local").Handle)

	resp := doJSON(t, app, http.MethodPut, "/"+id.String(), `{"status":"paused"}`)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestUpdateGatewayHandler_ServiceCaller_StaysScoped(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.GatewayKind]()
	updater := appgatewaymocks.NewUpdater(t)
	finder := appgatewaymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, id).Return(ownedGateway(id, "acme"), nil).Once()
	updater.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(in appgateway.UpdateInput) bool {
			return !in.PlatformAdmin && in.TenantID == "acme"
		})).
		Return(ownedGateway(id, "acme"), nil).
		Once()

	app := fiber.New()
	app.Use(serviceCaller("acme", id))
	app.Put("/:id", gatewayhttp.NewUpdateGatewayHandler(updater, finder, "gw.local", "mcp.local").Handle)

	resp := doJSON(t, app, http.MethodPut, "/"+id.String(), `{"status":"paused"}`)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestUpdateGatewayHandler_NonPlatformCallerWithoutTenantStaysScoped(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.GatewayKind]()
	updater := appgatewaymocks.NewUpdater(t)
	finder := appgatewaymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, id).Return(ownedGateway(id, "acme"), nil).Once()

	app := fiber.New()
	app.Use(untenantedHuman())
	app.Put("/:id", gatewayhttp.NewUpdateGatewayHandler(updater, finder, "gw.local", "mcp.local").Handle)

	resp := doJSON(t, app, http.MethodPut, "/"+id.String(), stampedBody)
	require.Equal(t, fiber.StatusNotFound, resp.StatusCode)
	updater.AssertNotCalled(t, "Update", mock.Anything, mock.Anything)
}

func TestUpdateGatewayHandler_HumanWithoutTenant_CannotClaimUntenantedGateway(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.GatewayKind]()
	updater := appgatewaymocks.NewUpdater(t)
	finder := appgatewaymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, id).Return(ownedGateway(id, ""), nil).Once()

	app := fiber.New()
	app.Use(untenantedHuman())
	app.Put("/:id", gatewayhttp.NewUpdateGatewayHandler(updater, finder, "gw.local", "mcp.local").Handle)

	resp := doJSON(t, app, http.MethodPut, "/"+id.String(), `{"status":"paused"}`)
	require.Equal(t, fiber.StatusNotFound, resp.StatusCode)
	updater.AssertNotCalled(t, "Update", mock.Anything, mock.Anything)
}

func TestDeleteGatewayHandler_Platform_DeletesAnyTenantGateway(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.GatewayKind]()
	deleter := appgatewaymocks.NewDeleter(t)
	finder := appgatewaymocks.NewFinder(t)
	deleter.EXPECT().Delete(mock.Anything, id).Return(nil).Once()

	app := fiber.New()
	app.Use(platformCaller())
	app.Delete("/:id", gatewayhttp.NewDeleteGatewayHandler(deleter, finder).Handle)

	resp := doJSON(t, app, http.MethodDelete, "/"+id.String(), "")
	require.Equal(t, fiber.StatusNoContent, resp.StatusCode)
	finder.AssertNotCalled(t, "FindByID", mock.Anything, mock.Anything)
}

func TestDeleteGatewayHandler_NonPlatformCallerWithoutTenantStaysScoped(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.GatewayKind]()
	deleter := appgatewaymocks.NewDeleter(t)
	finder := appgatewaymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, id).Return(ownedGateway(id, "acme"), nil).Once()

	app := fiber.New()
	app.Use(untenantedHuman())
	app.Delete("/:id", gatewayhttp.NewDeleteGatewayHandler(deleter, finder).Handle)

	resp := doJSON(t, app, http.MethodDelete, "/"+id.String(), "")
	require.Equal(t, fiber.StatusNotFound, resp.StatusCode)
	deleter.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
}

func TestGetGatewayHandler_NonPlatformCallerWithoutTenantStaysScoped(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.GatewayKind]()
	finder := appgatewaymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, id).Return(ownedGateway(id, "acme"), nil).Once()

	app := fiber.New()
	app.Use(untenantedHuman())
	app.Get("/:id", gatewayhttp.NewGetGatewayHandler(finder, "gw.local", "mcp.local").Handle)

	resp := doJSON(t, app, http.MethodGet, "/"+id.String(), "")
	require.Equal(t, fiber.StatusNotFound, resp.StatusCode)
}

func TestListGatewayHandler_Platform_ListsEveryTenant(t *testing.T) {
	t.Parallel()
	finder := appgatewaymocks.NewFinder(t)
	finder.EXPECT().
		List(mock.Anything, mock.MatchedBy(func(f domain.ListFilter) bool {
			return f.TenantID == ""
		})).
		Return([]*domain.Gateway{}, 0, nil).
		Once()

	app := fiber.New()
	app.Use(platformCaller())
	app.Get("/", gatewayhttp.NewListGatewayHandler(finder, "gw.local", "mcp.local").Handle)

	resp := doJSON(t, app, http.MethodGet, "/", "")
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestListGatewayHandler_HumanWithoutTenant_IsRefused(t *testing.T) {
	t.Parallel()
	finder := appgatewaymocks.NewFinder(t)

	app := fiber.New()
	app.Use(untenantedHuman())
	app.Get("/", gatewayhttp.NewListGatewayHandler(finder, "gw.local", "mcp.local").Handle)

	resp := doJSON(t, app, http.MethodGet, "/", "")
	require.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	finder.AssertNotCalled(t, "List", mock.Anything, mock.Anything)
}

func TestCreateGatewayHandler_HumanWithoutTenant_CannotStampBodyTenant(t *testing.T) {
	t.Parallel()
	creator := appgatewaymocks.NewCreator(t)

	app := fiber.New()
	app.Use(untenantedHuman())
	app.Post("/", gatewayhttp.NewCreateGatewayHandler(creator, "gw.local", "mcp.local").Handle)

	resp := doJSON(t, app, http.MethodPost, "/",
		`{"slug":"prod","tenant_id":"acme","entitlements":{"tier":"standard","burst_per_min":300,"quota_per_month":100000,"max_instances":5}}`)
	require.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	creator.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestCreateGatewayHandler_TenantCaller_IsNotPlatform(t *testing.T) {
	t.Parallel()
	creator := appgatewaymocks.NewCreator(t)
	creator.EXPECT().
		Create(mock.Anything, mock.MatchedBy(func(in appgateway.CreateInput) bool {
			return in.TenantID == "acme" && !in.PlatformAdmin
		})).
		Return(ownedGateway(ids.New[ids.GatewayKind](), "acme"), nil).
		Once()

	app := fiber.New()
	app.Use(humanCaller("acme"))
	app.Post("/", gatewayhttp.NewCreateGatewayHandler(creator, "gw.local", "mcp.local").Handle)

	resp := doJSON(t, app, http.MethodPost, "/", `{"slug":"prod"}`)
	require.Equal(t, fiber.StatusCreated, resp.StatusCode)
}
