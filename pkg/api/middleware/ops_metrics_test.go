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
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

type recordingOps struct {
	enabled bool
	request o11y.Request
	count   int
}

func (r *recordingOps) Enabled() bool {
	return r.enabled
}

func (r *recordingOps) RecordRequest(_ context.Context, req o11y.Request) {
	r.request = req
	r.count++
}

func TestOpsMetricsMiddlewareRecordsOnlyBoundedValues(t *testing.T) {
	recorder := &recordingOps{enabled: true}
	app := fiber.New()
	app.Use(NewOpsMetricsMiddleware(recorder, o11y.PlaneAdmin).Middleware())
	app.Get("/v1/gateways/:id", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusForbidden)
	})

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/v1/gateways/customer-id", nil))
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, 1, recorder.count)
	require.Equal(t, o11y.PlaneAdmin, recorder.request.Plane)
	require.Equal(t, o11y.RouteAdminGateways, recorder.request.Route)
	require.Equal(t, "GET", recorder.request.Method)
	require.Equal(t, "4xx", recorder.request.StatusClass)
	require.Equal(t, o11y.OutcomeDeniedForbidden, recorder.request.Outcome)
	require.NotContains(t, string(recorder.request.Route), "customer-id")
}

func TestOpsMetricsMiddlewareDisabledIsPassthrough(t *testing.T) {
	recorder := &recordingOps{}
	app := fiber.New()
	app.Use(NewOpsMetricsMiddleware(recorder, o11y.PlaneProxy).Middleware())
	app.Post("/*", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/private/path", nil))
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, 0, recorder.count)
}

func TestOpsMetricsMiddlewarePrefersBoundedLogicalOutcome(t *testing.T) {
	recorder := &recordingOps{enabled: true}
	app := fiber.New()
	app.Use(NewOpsMetricsMiddleware(recorder, o11y.PlaneMCP).Middleware())
	app.Post("/*", func(c *fiber.Ctx) error {
		SetOpsOutcome(c, o11y.OutcomeDeniedPolicy)
		return c.SendStatus(fiber.StatusOK)
	})

	resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/rpc/private-id", nil))
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, o11y.OutcomeDeniedPolicy, recorder.request.Outcome)
	require.Equal(t, o11y.RouteMCPRPC, recorder.request.Route)
}

func TestClassifyRouteUsesLinearEnums(t *testing.T) {
	tests := []struct {
		name  string
		plane o11y.Plane
		path  string
		want  o11y.Route
	}{
		{name: "health", plane: o11y.PlaneProxy, path: "/readyz", want: o11y.RouteHealth},
		{name: "version", plane: o11y.PlaneAdmin, path: "/__/version", want: o11y.RouteVersion},
		{name: "gateway id", plane: o11y.PlaneAdmin, path: "/v1/gateways/secret-id", want: o11y.RouteAdminGateways},
		{name: "gateway prefix boundary", plane: o11y.PlaneAdmin, path: "/v1/gateways-raw", want: o11y.RouteOther},
		{name: "catalog", plane: o11y.PlaneAdmin, path: "/v1/models-catalog", want: o11y.RouteAdminCatalog},
		{name: "config sync", plane: o11y.PlaneAdmin, path: "/v1/config-sync/connections", want: o11y.RouteAdminConfigSync},
		{name: "docs", plane: o11y.PlaneAdmin, path: "/docs/index.html", want: o11y.RouteAdminDocs},
		{name: "proxy", plane: o11y.PlaneProxy, path: "/tenant/private", want: o11y.RouteProxyForward},
		{name: "mcp rpc", plane: o11y.PlaneMCP, path: "/tenant/rpc", want: o11y.RouteMCPRPC},
		{name: "mcp oauth", plane: o11y.PlaneMCP, path: "/oauth/token", want: o11y.RouteMCPOAuth},
		{name: "version is admin only", plane: o11y.PlaneProxy, path: "/__/version", want: o11y.RouteProxyForward},
		{name: "other", plane: o11y.PlaneAdmin, path: "/unknown/id", want: o11y.RouteOther},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, classifyRoute(tc.plane, tc.path))
		})
	}
}

func TestClassifyOutcomeUsesLinearEnums(t *testing.T) {
	tests := []struct {
		route  o11y.Route
		status int
		want   o11y.Outcome
	}{
		{route: o11y.RouteHealth, status: 503, want: o11y.OutcomeProbe},
		{route: o11y.RouteProxyForward, status: 200, want: o11y.OutcomeAllowed},
		{route: o11y.RouteProxyForward, status: 401, want: o11y.OutcomeDeniedAuth},
		{route: o11y.RouteProxyForward, status: 403, want: o11y.OutcomeDeniedForbidden},
		{route: o11y.RouteProxyForward, status: 429, want: o11y.OutcomeDeniedThrottled},
		{route: o11y.RouteProxyForward, status: 404, want: o11y.OutcomeClientError},
		{route: o11y.RouteProxyForward, status: 500, want: o11y.OutcomeServerError},
	}
	for _, tc := range tests {
		require.Equal(t, tc.want, classifyOutcome(tc.route, tc.status))
	}
}
